"""
Regression tests for a batch of runtime/CI fixes in the daemon code.

Each test class pins one previously-broken behaviour so it cannot silently
regress. No test needs root, network access or nftables; anything that would
reach the network is mocked.

Covered fixes:
- EventType members referenced by other modules but never defined
- CgroupLimitsConfig.to_cgroup_limits() assigning to non-existent attributes
- subscribe() calling .append on a dict in three security detectors
- get_prompt_injection_detector() updating attributes the class never reads
- SIEMIntegration.log_security_error() passing an unknown keyword
- threat-intel lookups building URLs from unvalidated "IP" strings
- OllamaClient accepting non-http(s) endpoints
- HTTPShipper shipping to non-http(s) endpoints
- EncryptionChecker.is_path_encrypted() calling .parents on a str
- TripwireSystem.simulate_violation() building EnvironmentState wrongly
- NetworkAttestor.is_vpn_connected() returning None
- DynamicMACPolicyManager.mac_system returning None
- SignedEventLogger.log_event() rejecting reasoning_chain=
- handle_error defined twice in error_handling
"""

import dataclasses
import inspect
import json
import logging
import os
import re
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.event_logger import BoundaryEvent, EventType
from daemon.enforcement.disk_encryption import (
    EncryptionChecker,
    EncryptionStatus,
    EncryptionType,
    VolumeInfo,
)
from daemon.enforcement.dynamic_mac_policy import (
    AppArmorPolicyGenerator,
    DynamicMACPolicyManager,
    MACSystem,
    SELinuxPolicyGenerator,
)
from daemon.external_integrations.siem.log_shipper import (
    HTTPShipper,
    ShipperConfig,
    ShipperProtocol,
)
from daemon.monitoring_report import OllamaClient, OllamaConfig
from daemon.policy_engine import BoundaryMode
from daemon.sandbox.cgroups import CgroupLimits
from daemon.sandbox.profile_config import CgroupLimitsConfig
from daemon.security import prompt_injection
from daemon.security.network_attestation import NetworkAttestor
from daemon.security.prompt_injection import get_prompt_injection_detector
from daemon.security.rag_injection import RAGInjectionDetector
from daemon.security.response_guardrails import ResponseGuardrails
from daemon.security.siem_integration import (
    SecurityEvent,
    SecurityEventCategory,
    SecurityEventSeverity,
    SIEMConfig,
    SIEMIntegration,
)
from daemon.security.threat_intel import ThreatIntelConfig, ThreatIntelMonitor
from daemon.security.tool_validator import ToolOutputValidator
from daemon.signed_event_logger import SignedEventLogger
from daemon.tripwires import TripwireSystem, TripwireViolation, ViolationType
from daemon.utils import error_handling
from daemon.utils.error_handling import ErrorCategory, ErrorContext, ErrorSeverity


# ---------------------------------------------------------------------------
# 1. EventType members that other modules reference
# ---------------------------------------------------------------------------

NEW_EVENT_TYPE_MEMBERS = [
    "DETECTION",
    "SECURITY_EVENT",
    "SECURITY_VIOLATION",
    "SECURITY_ALERT",
    "ENFORCEMENT",
    "NETWORK_ACTIVITY",
]


@pytest.mark.unit
class TestEventTypeMembers:
    """Members used by security/enforcement modules must exist on EventType."""

    @pytest.mark.parametrize("name", NEW_EVENT_TYPE_MEMBERS)
    def test_member_exists_with_lowercase_string_value(self, name):
        member = getattr(EventType, name)  # AttributeError before the fix
        assert isinstance(member, EventType)
        assert isinstance(member.value, str)
        assert member.value, "value must be non-empty"
        assert member.value == member.value.lower()
        # Value lookup must return the very same member (no enum aliasing)
        assert EventType(member.value) is member

    def test_new_member_values_are_distinct(self):
        values = [getattr(EventType, n).value for n in NEW_EVENT_TYPE_MEMBERS]
        assert len(set(values)) == len(values)

    def test_all_event_type_values_unique(self):
        values = [m.value for m in EventType]
        assert len(set(values)) == len(values)
        # An aliased duplicate would be hidden from iteration; __members__ is not.
        assert len(EventType.__members__) == len(values)


# ---------------------------------------------------------------------------
# 2. CgroupLimitsConfig -> CgroupLimits attribute names
# ---------------------------------------------------------------------------

PHANTOM_CGROUP_ATTRS = (
    "memory_max", "memory_high", "cpu_max", "cpu_period", "io_rbps_max", "io_wbps_max",
)


@pytest.mark.unit
class TestCgroupLimitsConfigConversion:
    """Limits must land on the real CgroupLimits fields, not phantom attributes."""

    def _limits(self):
        cfg = CgroupLimitsConfig.from_dict(
            {"memory_max": "512M", "cpu_percent": 50, "pids_max": 10}
        )
        return cfg.to_cgroup_limits()

    def test_limits_land_on_real_cgroup_limits_fields(self):
        limits = self._limits()
        assert isinstance(limits, CgroupLimits)
        assert limits.memory_max_bytes == 512 * 1024 * 1024
        assert limits.memory_high_bytes is None
        assert limits.cpu_period_us == 100000
        assert limits.cpu_quota_us == 50000  # 50% of a 100ms period
        assert limits.pids_max == 10

    def test_no_phantom_attributes_created(self):
        limits = self._limits()
        declared = {f.name for f in dataclasses.fields(CgroupLimits)}
        assert set(vars(limits)) <= declared, (
            f"unexpected attributes on CgroupLimits: {set(vars(limits)) - declared}"
        )
        for phantom in PHANTOM_CGROUP_ATTRS:
            assert phantom not in vars(limits)

    def test_memory_high_maps_to_memory_high_bytes(self):
        limits = CgroupLimitsConfig(memory_high="1G").to_cgroup_limits()
        assert limits.memory_high_bytes == 1024 ** 3
        assert limits.memory_max_bytes is None

    def test_io_limits_log_warning_and_are_not_applied(self, caplog):
        cfg = CgroupLimitsConfig(io_max_read="50M", io_max_write="10M")
        with caplog.at_level(logging.WARNING, logger="daemon.sandbox.profile_config"):
            limits = cfg.to_cgroup_limits()

        warnings = [
            r for r in caplog.records
            if r.levelno == logging.WARNING and "io_max" in r.getMessage()
        ]
        assert warnings, "expected a warning that io_max_read/io_max_write cannot be applied"
        assert limits.io_max == []
        assert "io_rbps_max" not in vars(limits)
        assert "io_wbps_max" not in vars(limits)

    def test_no_io_warning_without_io_limits(self, caplog):
        with caplog.at_level(logging.WARNING, logger="daemon.sandbox.profile_config"):
            CgroupLimitsConfig(memory_max="64M").to_cgroup_limits()
        assert not [r for r in caplog.records if "io_max" in r.getMessage()]


# ---------------------------------------------------------------------------
# 3. subscribe() on the three security detectors
# ---------------------------------------------------------------------------

def _noop_callback(_result):
    return None


@pytest.mark.security
class TestSubscribeStoresCallbackInDict:
    """subscribe() used to call .append on a dict; it must key by id(callback)."""

    @pytest.mark.parametrize(
        "factory",
        [ToolOutputValidator, RAGInjectionDetector],
        ids=["tool_validator", "rag_injection"],
    )
    def test_subscribe_registers_callback(self, factory):
        obj = factory()
        assert isinstance(obj._callbacks, dict)

        obj.subscribe(_noop_callback)  # AttributeError: 'dict' has no 'append' before fix

        assert _noop_callback in obj._callbacks.values()
        assert obj._callbacks[id(_noop_callback)] is _noop_callback

    @pytest.mark.parametrize(
        "factory",
        [ToolOutputValidator, RAGInjectionDetector],
        ids=["tool_validator", "rag_injection"],
    )
    def test_subscribe_twice_does_not_duplicate(self, factory):
        obj = factory()
        obj.subscribe(_noop_callback)
        obj.subscribe(_noop_callback)
        assert list(obj._callbacks.values()).count(_noop_callback) == 1

    def test_response_guardrails_callbacks_is_dict(self):
        # The .append-on-dict bug is gone: the store is a dict keyed by id().
        assert isinstance(ResponseGuardrails()._callbacks, dict)

    @pytest.mark.xfail(
        strict=True,
        raises=AttributeError,
        reason="ResponseGuardrails.__init__ never sets self._lock (only _callback_lock), "
               "so subscribe() still raises AttributeError; remove this marker once fixed",
    )
    def test_response_guardrails_subscribe_registers_callback(self):
        obj = ResponseGuardrails()
        obj.subscribe(_noop_callback)
        assert _noop_callback in obj._callbacks.values()


# ---------------------------------------------------------------------------
# 4. get_prompt_injection_detector() updates the attributes the class reads
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_prompt_detector_singleton():
    """Reset the module-level singleton around a test to avoid cross-test leakage."""
    saved = prompt_injection._detector_instance
    prompt_injection._detector_instance = None
    try:
        yield
    finally:
        prompt_injection._detector_instance = saved


@pytest.mark.security
class TestPromptInjectionSingletonAccessor:

    def test_second_call_updates_public_attributes(self, isolated_prompt_detector_singleton):
        first_logger = MagicMock(name="first_logger")
        second_logger = MagicMock(name="second_logger")
        engine = MagicMock(name="policy_engine")

        detector = get_prompt_injection_detector(event_logger=first_logger)
        assert detector.event_logger is first_logger
        assert detector.policy_engine is None

        again = get_prompt_injection_detector(event_logger=second_logger, policy_engine=engine)

        assert again is detector
        assert detector.event_logger is second_logger
        assert detector.policy_engine is engine
        # The buggy accessor wrote these names, which nothing ever reads.
        assert not hasattr(detector, "_event_logger")
        assert not hasattr(detector, "_policy_engine")

    def test_none_arguments_leave_existing_configuration(self, isolated_prompt_detector_singleton):
        logger_ = MagicMock(name="logger")
        detector = get_prompt_injection_detector(event_logger=logger_)
        get_prompt_injection_detector()
        assert detector.event_logger is logger_


# ---------------------------------------------------------------------------
# 5. SIEMIntegration.log_security_error()
# ---------------------------------------------------------------------------

def _offline_siem() -> SIEMIntegration:
    """SIEMIntegration with a disabled connector and no name resolution."""
    with patch("daemon.security.siem_integration.socket.gethostbyname", return_value="127.0.0.1"):
        return SIEMIntegration(SIEMConfig(enabled=False))


@pytest.mark.security
class TestSIEMLogSecurityError:
    """log_security_error() used to pass source_component= to _create_event (TypeError)."""

    def test_component_goes_into_event_details(self):
        siem = _offline_siem()
        with patch.object(siem, "_send_event") as send:
            siem.log_security_error(error_type="x", error_message="boom", component="comp")

        send.assert_called_once()
        event = send.call_args[0][0]
        assert isinstance(event, SecurityEvent)
        assert event.details["component"] == "comp"
        assert event.event_type == "security_error_x"
        assert event.message == "Security error: boom"
        assert event.outcome == "error"
        assert event.category == SecurityEventCategory.SYSTEM_ERROR
        assert event.severity == SecurityEventSeverity.HIGH
        assert event.source_component == "boundary-daemon"

    def test_details_are_merged_and_component_defaults(self):
        siem = _offline_siem()
        with patch.object(siem, "_send_event") as send:
            siem.log_security_error(error_type="y", error_message="m", details={"k": "v"})

        event = send.call_args[0][0]
        assert event.details == {"k": "v", "component": "boundary-daemon"}

    def test_full_send_path_with_disabled_connector_does_not_raise(self):
        siem = _offline_siem()
        siem.log_security_error(error_type="z", error_message="no crash", component="comp")


# ---------------------------------------------------------------------------
# 6. Threat-intel lookups validate the IP before building a URL
# ---------------------------------------------------------------------------

def _threat_monitor_with_keys() -> ThreatIntelMonitor:
    return ThreatIntelMonitor(
        ThreatIntelConfig(abuseipdb_api_key="test-key", virustotal_api_key="test-key")
    )


@pytest.mark.security
class TestThreatIntelIpValidation:
    LOOKUPS = ["_check_abuseipdb", "_check_virustotal"]
    BAD_IPS = ["1.2.3.4/../evil", "1.2.3.4?x=1", "1.2.3.4#frag", "not-an-ip", ""]

    @pytest.mark.parametrize("method", LOOKUPS)
    @pytest.mark.parametrize("bad_ip", BAD_IPS)
    def test_non_ip_never_reaches_urlopen(self, method, bad_ip):
        monitor = _threat_monitor_with_keys()
        assert monitor._can_make_api_call()  # rate limit is not what stops the call

        with patch("urllib.request.urlopen") as urlopen:
            result = getattr(monitor, method)(bad_ip)

        assert result is None
        urlopen.assert_not_called()

    @pytest.mark.parametrize("method", LOOKUPS)
    def test_valid_ip_still_performs_lookup(self, method):
        monitor = _threat_monitor_with_keys()
        response = MagicMock()
        response.read.return_value = b"{}"

        with patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value = response
            getattr(monitor, method)("1.2.3.4")

        urlopen.assert_called_once()
        request = urlopen.call_args[0][0]
        assert request.full_url.endswith("1.2.3.4")
        assert request.full_url.startswith("https://")


# ---------------------------------------------------------------------------
# 7. OllamaClient endpoint scheme validation
# ---------------------------------------------------------------------------

@pytest.mark.security
class TestOllamaClientEndpointScheme:

    @pytest.mark.parametrize(
        "endpoint",
        ["file:///etc/passwd", "ftp://example.invalid", "gopher://example.invalid", "/etc/passwd"],
    )
    def test_api_url_rejects_non_http_endpoint(self, endpoint):
        client = OllamaClient(OllamaConfig(endpoint=endpoint))
        with pytest.raises(ValueError):
            client._api_url("/api/tags")

    def test_api_url_accepts_http_and_https(self):
        http = OllamaClient(OllamaConfig(endpoint="http://localhost:11434"))
        assert http._api_url("/api/tags") == "http://localhost:11434/api/tags"
        https = OllamaClient(OllamaConfig(endpoint="HTTPS://ollama.local"))
        assert https._api_url("/x") == "HTTPS://ollama.local/x"

    def test_is_available_returns_false_for_file_endpoint(self):
        client = OllamaClient(OllamaConfig(endpoint="file:///etc/passwd"))
        with patch("urllib.request.urlopen") as urlopen:
            result = client.is_available()
        assert result is False
        urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# 8. HTTPShipper endpoint scheme validation
# ---------------------------------------------------------------------------

@pytest.mark.security
class TestHTTPShipperEndpointScheme:

    @pytest.mark.parametrize(
        "endpoint",
        ["file:///tmp/exfil", "ftp://example.invalid/x", "", "siem.local:8080/ingest"],
    )
    def test_non_http_endpoint_is_refused(self, endpoint):
        cfg = ShipperConfig(protocol=ShipperProtocol.HTTP, http_endpoint=endpoint, compress=False)
        shipper = HTTPShipper(cfg)

        with patch("urllib.request.urlopen") as urlopen:
            result = shipper._ship_batch([{"event": "x"}])

        assert result is False
        urlopen.assert_not_called()

    def test_http_endpoint_is_posted(self):
        cfg = ShipperConfig(
            protocol=ShipperProtocol.HTTP, http_endpoint="http://siem.local/ingest", compress=False
        )
        response = MagicMock()
        response.status = 200

        with patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value = response
            result = HTTPShipper(cfg)._ship_batch([{"event": "x"}])

        assert result is True
        urlopen.assert_called_once()
        request = urlopen.call_args[0][0]
        assert request.full_url == "http://siem.local/ingest"
        assert request.get_method() == "POST"


# ---------------------------------------------------------------------------
# 9. EncryptionChecker.is_path_encrypted() with a str path
# ---------------------------------------------------------------------------

def _volume(mount_point: str, status: EncryptionStatus) -> VolumeInfo:
    return VolumeInfo(
        device="/dev/mapper/root",
        mount_point=mount_point,
        encryption_type=EncryptionType.LUKS2,
        status=status,
    )


@pytest.mark.unit
class TestIsPathEncryptedAcceptsStr:
    """is_path_encrypted() used to call .parents on the raw str (AttributeError)."""

    def _checker(self, *volumes):
        checker = EncryptionChecker()
        patcher = patch.object(checker, "check_all_volumes", return_value=list(volumes))
        return checker, patcher

    def test_str_path_under_encrypted_root(self):
        checker, patcher = self._checker(_volume("/", EncryptionStatus.ENCRYPTED))
        with patcher:
            assert checker.is_path_encrypted("/tmp/x") is True

    def test_str_path_under_unencrypted_root(self):
        checker, patcher = self._checker(_volume("/", EncryptionStatus.NOT_ENCRYPTED))
        with patcher:
            assert checker.is_path_encrypted("/tmp/x") is False

    def test_str_path_equal_to_mount_point(self):
        checker, patcher = self._checker(_volume("/", EncryptionStatus.ENCRYPTED))
        with patcher:
            assert checker.is_path_encrypted("/") is True

    def test_str_path_outside_any_volume(self):
        checker, patcher = self._checker(_volume("/nonexistent-mount", EncryptionStatus.ENCRYPTED))
        with patcher:
            assert checker.is_path_encrypted("/tmp/x") is False


# ---------------------------------------------------------------------------
# 10. TripwireSystem.simulate_violation()
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSimulateViolation:
    """simulate_violation() used to build EnvironmentState without required fields."""

    def test_returns_tripwire_violation(self):
        system = TripwireSystem(event_logger=MagicMock())

        violation = system.simulate_violation(
            ViolationType.DAEMON_TAMPERING, "simulated for regression test", BoundaryMode.OPEN
        )

        assert isinstance(violation, TripwireViolation)
        assert violation.violation_type is ViolationType.DAEMON_TAMPERING
        assert violation.details == "simulated for regression test"
        assert violation.current_mode is BoundaryMode.OPEN
        assert violation.auto_lockdown is True
        assert isinstance(violation.environment_snapshot, dict)
        assert violation.environment_snapshot["network"] == "offline"
        assert violation.environment_snapshot["usb_devices"] == []
        assert violation in system.get_violations()

    def test_registered_callback_receives_simulated_violation(self):
        system = TripwireSystem(event_logger=MagicMock())
        callback = MagicMock()
        system.register_callback(callback)

        violation = system.simulate_violation(
            ViolationType.SUSPICIOUS_PROCESS, "callback check", BoundaryMode.RESTRICTED
        )

        callback.assert_called_once_with(violation)


# ---------------------------------------------------------------------------
# 11. NetworkAttestor.is_vpn_connected() returns a bool
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestIsVpnConnectedReturnsBool:

    def test_false_without_attestation_result(self):
        attestor = NetworkAttestor()
        result = attestor.is_vpn_connected()
        assert result is False  # was None before the fix

    def test_false_when_result_has_no_vpn(self):
        attestor = NetworkAttestor()
        attestor._current_result = MagicMock(vpn_connection=None)
        assert attestor.is_vpn_connected() is False

    def test_true_when_result_has_vpn(self):
        attestor = NetworkAttestor()
        attestor._current_result = MagicMock(vpn_connection=MagicMock())
        assert attestor.is_vpn_connected() is True


# ---------------------------------------------------------------------------
# 12. DynamicMACPolicyManager.mac_system never returns None
# ---------------------------------------------------------------------------

def _no_mac_available():
    return (
        patch.object(SELinuxPolicyGenerator, "is_available", return_value=False),
        patch.object(AppArmorPolicyGenerator, "is_available", return_value=False),
    )


@pytest.mark.unit
class TestMacSystemNeverNone:

    def test_nothing_detected_yields_mac_system_none(self):
        selinux, apparmor = _no_mac_available()
        with selinux, apparmor:
            manager = DynamicMACPolicyManager()

        assert manager.mac_system is MACSystem.NONE
        assert manager.is_available is False
        assert manager.get_status()["mac_system"] == "none"

    def test_property_coerces_unset_state(self):
        selinux, apparmor = _no_mac_available()
        with selinux, apparmor:
            manager = DynamicMACPolicyManager()

        manager._mac_system = None
        assert manager.mac_system is MACSystem.NONE
        assert isinstance(manager.mac_system, MACSystem)


# ---------------------------------------------------------------------------
# 13. SignedEventLogger.log_event(reasoning_chain=...)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSignedEventLoggerReasoningChain:

    def test_log_event_accepts_reasoning_chain_keyword(self, tmp_path):
        log_path = tmp_path / "events.log"
        key_path = tmp_path / "keys" / "signing.key"
        signed_logger = SignedEventLogger(str(log_path), str(key_path))

        event = signed_logger.log_event(
            EventType.DETECTION,
            "regression event",
            {"source": "test"},
            reasoning_chain={"why": "test"},
        )

        assert isinstance(event, BoundaryEvent)
        assert event.reasoning_chain == {"why": "test"}
        assert event.metadata == {"source": "test"}

        log_lines = [line for line in log_path.read_text().splitlines() if line.strip()]
        assert len(log_lines) == 1
        assert json.loads(log_lines[0])["reasoning_chain"] == {"why": "test"}

        sig_path = tmp_path / "events.log.sig"
        sig_lines = [line for line in sig_path.read_text().splitlines() if line.strip()]
        assert len(sig_lines) == 1
        assert json.loads(sig_lines[0])["event_id"] == event.event_id

    def test_verify_signatures_without_reasoning_chain(self, tmp_path):
        signed_logger = SignedEventLogger(str(tmp_path / "events.log"), str(tmp_path / "key"))
        signed_logger.log_event(EventType.DETECTION, "plain event", {"source": "test"})
        valid, error = signed_logger.verify_signatures()
        assert valid, error

    def test_verify_signatures_with_reasoning_chain(self, tmp_path):
        signed_logger = SignedEventLogger(str(tmp_path / "events.log"), str(tmp_path / "key"))
        signed_logger.log_event(
            EventType.DETECTION, "reasoned event", {"source": "test"}, reasoning_chain={"why": "test"}
        )
        valid, error = signed_logger.verify_signatures()
        assert valid, error


# ---------------------------------------------------------------------------
# 14. handle_error / _handle_error_base in error_handling
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestHandleErrorDefinition:

    def test_public_handle_error_accepts_forward_to_siem(self):
        params = inspect.signature(error_handling.handle_error).parameters
        assert "forward_to_siem" in params
        assert params["forward_to_siem"].default is True

    def test_base_implementation_exists_and_is_distinct(self):
        assert callable(error_handling._handle_error_base)
        assert error_handling._handle_error_base is not error_handling.handle_error
        base_params = inspect.signature(error_handling._handle_error_base).parameters
        assert "forward_to_siem" not in base_params

    def test_handle_error_defined_exactly_once(self):
        source = inspect.getsource(error_handling)
        assert len(re.findall(r"^def handle_error\(", source, re.MULTILINE)) == 1
        assert len(re.findall(r"^def _handle_error_base\(", source, re.MULTILINE)) == 1

    def test_handle_error_runs_with_forwarding_disabled(self):
        error = ValueError("boom")
        ctx = error_handling.handle_error(
            error, "regression_op", category=ErrorCategory.UNKNOWN, forward_to_siem=False
        )
        assert isinstance(ctx, ErrorContext)
        assert ctx.error is error
        assert ctx.operation == "regression_op"

    def test_security_error_is_forwarded_with_component(self):
        siem = _offline_siem()
        with patch.object(siem, "_send_event") as send, \
                patch.object(error_handling, "_siem_integration", siem):
            error_handling.handle_error(
                RuntimeError("boom"),
                "guarded_op",
                category=ErrorCategory.SECURITY,
                severity=ErrorSeverity.ERROR,
                forward_to_siem=True,
            )

        send.assert_called_once()
        event = send.call_args[0][0]
        assert event.details["component"] == "guarded_op"
        assert event.event_type == "security_error_RuntimeError"
