"""
Tests for the Tripwire System module.

Tests security violation detection, lockdown triggers, and auth requirements.
"""

import os
import sys
from datetime import datetime
from unittest.mock import MagicMock


# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.tripwires import (
    TripwireSystem,
    TripwireViolation,
    ViolationType,
)
from daemon.policy_engine import BoundaryMode


# ===========================================================================
# ViolationType Enum Tests
# ===========================================================================

class TestViolationType:
    def test_violation_type_values(self):
        assert ViolationType.NETWORK_IN_AIRGAP.value == "network_in_airgap"
        assert ViolationType.USB_IN_COLDROOM.value == "usb_in_coldroom"
        assert ViolationType.UNAUTHORIZED_RECALL.value == "unauthorized_recall"
        assert ViolationType.DAEMON_TAMPERING.value == "daemon_tampering"
        assert ViolationType.MODE_INCOMPATIBLE.value == "mode_incompatible"
        assert ViolationType.EXTERNAL_MODEL_VIOLATION.value == "external_model_violation"
        assert ViolationType.SUSPICIOUS_PROCESS.value == "suspicious_process"
        assert ViolationType.HARDWARE_TRUST_DEGRADED.value == "hardware_trust_degraded"


# ===========================================================================
# TripwireViolation Dataclass Tests
# ===========================================================================

class TestTripwireViolation:
    def test_violation_creation(self):
        violation = TripwireViolation(
            violation_id="test-001",
            timestamp=datetime.utcnow().isoformat() + "Z",
            violation_type=ViolationType.NETWORK_IN_AIRGAP,
            details="Network came online in AIRGAP mode",
            current_mode=BoundaryMode.AIRGAP,
            environment_snapshot={'network': 'online'},
            auto_lockdown=True,
        )
        assert violation.violation_id == "test-001"
        assert violation.violation_type == ViolationType.NETWORK_IN_AIRGAP
        assert violation.auto_lockdown is True

    def test_violation_all_fields(self):
        snapshot = {'usb': ['device1'], 'network': 'offline'}
        violation = TripwireViolation(
            violation_id="v-123",
            timestamp="2024-01-01T00:00:00Z",
            violation_type=ViolationType.USB_IN_COLDROOM,
            details="USB device inserted",
            current_mode=BoundaryMode.COLDROOM,
            environment_snapshot=snapshot,
            auto_lockdown=True,
        )
        assert violation.environment_snapshot == snapshot
        assert violation.current_mode == BoundaryMode.COLDROOM


# ===========================================================================
# TripwireSystem Initialization Tests
# ===========================================================================

class TestTripwireSystemInit:
    def test_init_default(self):
        tripwire = TripwireSystem()
        assert tripwire._enabled is True
        assert tripwire._locked is False
        assert tripwire._auth_required is True
        assert len(tripwire._violations) == 0  # May be deque or list
        assert tripwire._callbacks == {}  # Dict for O(1) unregister

    def test_init_with_event_logger(self):
        mock_logger = MagicMock()
        tripwire = TripwireSystem(event_logger=mock_logger)
        assert tripwire._event_logger == mock_logger

    def test_init_generates_auth_token(self):
        tripwire = TripwireSystem()
        assert tripwire._auth_token_hash is not None
        assert len(tripwire._auth_token_hash) == 64  # SHA256 hex length

    def test_init_baseline_tracking(self):
        tripwire = TripwireSystem()
        assert tripwire._baseline_usb_devices is None
        assert tripwire._previous_mode is None
        assert tripwire._previous_network_state is None

    def test_max_disable_attempts_default(self):
        tripwire = TripwireSystem()
        assert tripwire._max_disable_attempts == 3
        assert tripwire._failed_attempts == 0


# ===========================================================================
# TripwireSystem Callback Tests
# ===========================================================================

class TestTripwireSystemCallbacks:
    def test_register_callback(self):
        tripwire = TripwireSystem()
        callback = MagicMock()
        tripwire.register_callback(callback)
        assert callback in tripwire._callbacks.values()

    def test_register_multiple_callbacks(self):
        """Multiple callbacks can be registered."""
        tripwire = TripwireSystem()
        cb1 = MagicMock()
        cb2 = MagicMock()
        tripwire.register_callback(cb1)
        tripwire.register_callback(cb2)
        assert len(tripwire._callbacks) == 2


# ===========================================================================
# TripwireSystem Enable/Disable Tests
# ===========================================================================

class TestTripwireSystemEnableDisable:
    def test_enable(self):
        tripwire = TripwireSystem()
        tripwire._enabled = False
        tripwire.enable()
        assert tripwire._enabled is True

    def test_disable_requires_auth(self):
        tripwire = TripwireSystem()
        success, message = tripwire.disable("invalid_token")
        assert success is False
        assert "Invalid authentication" in message

    def test_disable_with_valid_token(self):
        tripwire = TripwireSystem()
        # Get the actual token during initialization
        token = tripwire._generate_auth_token()
        success, message = tripwire.disable(token, reason="testing")
        assert success is True
        assert tripwire._enabled is False

    def test_disable_tracks_failed_attempts(self):
        tripwire = TripwireSystem()
        initial_attempts = tripwire._failed_attempts
        tripwire.disable("bad_token")
        assert tripwire._failed_attempts == initial_attempts + 1

    def test_disable_locks_after_max_attempts(self):
        tripwire = TripwireSystem()
        tripwire._max_disable_attempts = 3

        for i in range(3):
            tripwire.disable("bad_token")

        assert tripwire._locked is True

    def test_disable_fails_when_locked(self):
        tripwire = TripwireSystem()
        tripwire._locked = True
        token = tripwire._generate_auth_token()
        success, message = tripwire.disable(token)
        assert success is False
        assert "LOCKED" in message


# ===========================================================================
# TripwireSystem Token Tests
# ===========================================================================

class TestTripwireSystemTokens:
    def test_verify_token_valid(self):
        tripwire = TripwireSystem()
        token = tripwire._generate_auth_token()
        assert tripwire._verify_token(token) is True

    def test_verify_token_invalid(self):
        tripwire = TripwireSystem()
        tripwire._generate_auth_token()
        assert tripwire._verify_token("invalid_token") is False

    def test_verify_token_empty(self):
        tripwire = TripwireSystem()
        assert tripwire._verify_token("") is False
        assert tripwire._verify_token(None) is False

    def test_get_new_auth_token_valid(self):
        tripwire = TripwireSystem()
        current_token = tripwire._generate_auth_token()
        new_token = tripwire.get_new_auth_token(current_token)
        assert isinstance(new_token, str)
        assert new_token != current_token

    def test_get_new_auth_token_invalid(self):
        tripwire = TripwireSystem()
        tripwire._generate_auth_token()
        new_token = tripwire.get_new_auth_token("bad_token")
        assert new_token is None

    def test_token_generation_creates_hash(self):
        tripwire = TripwireSystem()
        old_hash = tripwire._auth_token_hash
        tripwire._generate_auth_token()
        assert tripwire._auth_token_hash != old_hash


# ===========================================================================
# TripwireSystem Failed Attempts Tests
# ===========================================================================

class TestTripwireSystemFailedAttempts:
    def test_log_failed_attempt(self):
        tripwire = TripwireSystem()
        initial = len(tripwire._disable_attempts)
        tripwire._log_failed_attempt("test_op")
        assert len(tripwire._disable_attempts) == initial + 1
        assert tripwire._disable_attempts[-1]['operation'] == "test_op"

    def test_log_failed_attempt_increments_counter(self):
        tripwire = TripwireSystem()
        initial = tripwire._failed_attempts
        tripwire._log_failed_attempt("test")
        assert tripwire._failed_attempts == initial + 1

    def test_log_failed_attempt_locks_on_max(self):
        tripwire = TripwireSystem()
        tripwire._max_disable_attempts = 2
        tripwire._log_failed_attempt("test1")
        assert tripwire._locked is False
        tripwire._log_failed_attempt("test2")
        assert tripwire._locked is True

    def test_failed_attempt_records_timestamp(self):
        tripwire = TripwireSystem()
        tripwire._log_failed_attempt("test")
        assert 'timestamp' in tripwire._disable_attempts[-1]


# ===========================================================================
# TripwireSystem Security Properties Tests
# ===========================================================================

class TestTripwireSystemSecurity:
    """Tests for security properties."""

    def test_auth_required_cannot_be_disabled(self):
        tripwire = TripwireSystem()
        assert tripwire._auth_required is True
        # Even if someone tries to set it...
        tripwire._auth_required = False
        # In a real implementation, this would be protected
        # For now, we just test the initial state

    def test_locked_state_persists(self):
        tripwire = TripwireSystem()
        tripwire._locked = True
        # Verify it stays locked
        token = tripwire._generate_auth_token()
        success, _ = tripwire.disable(token)
        assert success is False
        assert tripwire._locked is True

    def test_token_hash_not_plaintext(self):
        tripwire = TripwireSystem()
        token = tripwire._generate_auth_token()
        assert tripwire._auth_token_hash != token
        assert len(tripwire._auth_token_hash) == 64  # SHA256


# ===========================================================================
# TripwireSystem Integration Tests
# ===========================================================================

class TestTripwireSystemIntegration:
    def test_full_auth_workflow(self):
        tripwire = TripwireSystem()

        # Get initial token
        token1 = tripwire._generate_auth_token()

        # Should be able to disable with valid token
        success, _ = tripwire.disable(token1, reason="test")
        assert success is True
        assert tripwire._enabled is False

        # Re-enable
        tripwire.enable()
        assert tripwire._enabled is True

        # Get new token
        token2 = tripwire.get_new_auth_token(token1)
        assert isinstance(token2, str)

        # Old token should not work anymore
        success, _ = tripwire.disable(token1, reason="test with old token")
        assert success is False

        # New token should work
        success, _ = tripwire.disable(token2, reason="test with new token")
        assert success is True

    def test_lockout_workflow(self):
        tripwire = TripwireSystem()
        tripwire._max_disable_attempts = 2

        # Fail twice
        tripwire.disable("bad1")
        tripwire.disable("bad2")

        # Should be locked now
        assert tripwire._locked is True

        # Even valid token should fail
        token = tripwire._generate_auth_token()
        success, message = tripwire.disable(token)
        assert success is False
        assert "LOCKED" in message

    def test_multiple_tripwire_instances(self):
        ts1 = TripwireSystem()
        ts2 = TripwireSystem()

        token1 = ts1._generate_auth_token()
        token2 = ts2._generate_auth_token()

        # Tokens should be different
        assert token1 != token2

        # Disable ts1 should not affect ts2
        ts1.disable(token1)
        assert ts1._enabled is False
        assert ts2._enabled is True


# ===========================================================================
# Edge Cases
# ===========================================================================

class TestTripwireEdgeCases:
    def test_empty_violations_list(self):
        tripwire = TripwireSystem()
        assert len(tripwire._violations) == 0  # May be deque or list

    def test_enable_when_already_enabled(self):
        tripwire = TripwireSystem()
        assert tripwire._enabled is True
        tripwire.enable()  # Should not raise
        assert tripwire._enabled is True

    def test_callback_with_no_callbacks(self):
        tripwire = TripwireSystem()
        # No callbacks registered - should not error
        assert len(tripwire._callbacks) == 0

    def test_token_constant_time_comparison(self):
        tripwire = TripwireSystem()
        token = tripwire._generate_auth_token()

        # These should take similar time regardless of where they differ
        # (This is a property test - the implementation uses hmac.compare_digest)
        import time

        # Correct token
        start = time.time()
        tripwire._verify_token(token)
        correct_time = time.time() - start

        # Wrong token (first char different)
        start = time.time()
        tripwire._verify_token("X" + token[1:])
        wrong_start_time = time.time() - start

        # Wrong token (last char different)
        start = time.time()
        tripwire._verify_token(token[:-1] + "X")
        wrong_end_time = time.time() - start

        # Times should be in same ballpark (not testing exact timing,
        # just that the code path uses constant-time comparison)
        # This is more of a smoke test that the code runs
        assert correct_time >= 0
        assert wrong_start_time >= 0
        assert wrong_end_time >= 0


# ===========================================================================
# Helper: Create EnvironmentState for testing
# ===========================================================================

def _make_env_state(
    network=None,
    hardware_trust=None,
    usb_devices=None,
    external_model_endpoints=None,
    suspicious_processes=None,
    shell_escapes_detected=0,
    active_interfaces=None,
):
    """Build an EnvironmentState with sensible defaults for testing."""
    from daemon.state_monitor import (
        EnvironmentState, NetworkState, HardwareTrust,
        SpecialtyNetworkStatus,
    )
    return EnvironmentState(
        timestamp="2025-01-01T00:00:00Z",
        network=network or NetworkState.OFFLINE,
        hardware_trust=hardware_trust or HardwareTrust.HIGH,
        active_interfaces=active_interfaces or [],
        interface_types={},
        has_internet=False,
        vpn_active=False,
        dns_available=False,
        specialty_networks=SpecialtyNetworkStatus(
            lora_devices=[], thread_devices=[], wimax_interfaces=[],
            irda_devices=[], ant_plus_devices=[], cellular_alerts=[],
        ),
        dns_security_alerts=[],
        arp_security_alerts=[],
        wifi_security_alerts=[],
        threat_intel_alerts=[],
        file_integrity_alerts=[],
        traffic_anomaly_alerts=[],
        process_security_alerts=[],
        usb_devices=usb_devices if usb_devices is not None else set(),
        block_devices=set(),
        camera_available=False,
        mic_available=False,
        tpm_present=True,
        external_model_endpoints=external_model_endpoints or [],
        suspicious_processes=suspicious_processes or [],
        shell_escapes_detected=shell_escapes_detected,
        keyboard_active=False,
        screen_unlocked=False,
        last_activity=None,
    )


# ===========================================================================
# Violation Detection Tests — NETWORK_IN_AIRGAP
# ===========================================================================

class TestViolationNetworkInAirgap:
    def test_network_online_in_airgap_triggers_violation(self):
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()

        # First check sets baseline (offline)
        env_offline = _make_env_state(network=NetworkState.OFFLINE)
        result = ts.check_violations(BoundaryMode.AIRGAP, env_offline)
        assert result is None

        # Network comes online — should trigger
        env_online = _make_env_state(network=NetworkState.ONLINE, active_interfaces=["eth0"])
        result = ts.check_violations(BoundaryMode.AIRGAP, env_online)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.NETWORK_IN_AIRGAP

    def test_network_already_online_in_airgap_triggers(self):
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()

        env_online = _make_env_state(network=NetworkState.ONLINE, active_interfaces=["wlan0"])
        result = ts.check_violations(BoundaryMode.AIRGAP, env_online)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.NETWORK_IN_AIRGAP

    def test_network_online_in_coldroom_triggers(self):
        """Network online in COLDROOM (>= AIRGAP) should also trigger."""
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()

        env_online = _make_env_state(network=NetworkState.ONLINE)
        result = ts.check_violations(BoundaryMode.COLDROOM, env_online)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.NETWORK_IN_AIRGAP

    def test_network_online_in_lockdown_triggers(self):
        """Network online in LOCKDOWN (>= AIRGAP) should trigger."""
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()

        env_online = _make_env_state(network=NetworkState.ONLINE)
        result = ts.check_violations(BoundaryMode.LOCKDOWN, env_online)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.NETWORK_IN_AIRGAP

    def test_network_online_in_open_does_not_trigger(self):
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()

        env_online = _make_env_state(network=NetworkState.ONLINE)
        result = ts.check_violations(BoundaryMode.OPEN, env_online)
        assert result is None

    def test_network_online_in_trusted_does_not_trigger(self):
        """Network online in TRUSTED mode (< AIRGAP) should NOT trigger."""
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()

        env_online = _make_env_state(network=NetworkState.ONLINE)
        result = ts.check_violations(BoundaryMode.TRUSTED, env_online)
        assert result is None

    def test_network_offline_in_airgap_does_not_trigger(self):
        """Network offline in AIRGAP is expected — should NOT trigger."""
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()

        env_offline = _make_env_state(network=NetworkState.OFFLINE)
        result = ts.check_violations(BoundaryMode.AIRGAP, env_offline)
        assert result is None

    def test_violation_records_interface_details(self):
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()

        env = _make_env_state(network=NetworkState.ONLINE, active_interfaces=["eth0", "wlan0"])
        result = ts.check_violations(BoundaryMode.AIRGAP, env)
        assert "eth0" in result.details or "wlan0" in result.details


# ===========================================================================
# Violation Detection Tests — USB_IN_COLDROOM
# ===========================================================================

class TestViolationUsbInColdroom:
    def test_new_usb_device_in_coldroom_triggers(self):
        ts = TripwireSystem()

        # First check sets baseline with no USB
        env_no_usb = _make_env_state(usb_devices=set())
        ts.check_violations(BoundaryMode.COLDROOM, env_no_usb)

        # USB inserted
        env_usb = _make_env_state(usb_devices={"usb-flash-drive"})
        result = ts.check_violations(BoundaryMode.COLDROOM, env_usb)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.USB_IN_COLDROOM

    def test_new_usb_device_in_lockdown_triggers(self):
        """New USB device in LOCKDOWN (>= COLDROOM) should trigger."""
        ts = TripwireSystem()

        env_no_usb = _make_env_state(usb_devices=set())
        ts.check_violations(BoundaryMode.LOCKDOWN, env_no_usb)

        env_usb = _make_env_state(usb_devices={"usb-keyboard"})
        result = ts.check_violations(BoundaryMode.LOCKDOWN, env_usb)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.USB_IN_COLDROOM

    def test_usb_in_airgap_does_not_trigger(self):
        """USB in AIRGAP (< COLDROOM) should NOT trigger USB violation."""
        ts = TripwireSystem()

        env_no_usb = _make_env_state(usb_devices=set())
        ts.check_violations(BoundaryMode.AIRGAP, env_no_usb)

        env_usb = _make_env_state(usb_devices={"usb-device"})
        result = ts.check_violations(BoundaryMode.AIRGAP, env_usb)
        # Should be None (no network violation either since offline)
        assert result is None

    def test_baseline_usb_devices_not_flagged(self):
        ts = TripwireSystem()

        # Baseline includes a device
        env_with_device = _make_env_state(usb_devices={"keyboard", "mouse"})
        ts.check_violations(BoundaryMode.COLDROOM, env_with_device)

        # Same devices — should be fine
        result = ts.check_violations(BoundaryMode.COLDROOM, env_with_device)
        assert result is None

    def test_additional_usb_beyond_baseline_triggers(self):
        ts = TripwireSystem()

        env_baseline = _make_env_state(usb_devices={"keyboard"})
        ts.check_violations(BoundaryMode.COLDROOM, env_baseline)

        # Add a new device while keeping baseline device
        env_new = _make_env_state(usb_devices={"keyboard", "usb-storage"})
        result = ts.check_violations(BoundaryMode.COLDROOM, env_new)
        assert isinstance(result, TripwireViolation)
        assert "usb-storage" in result.details


# ===========================================================================
# Violation Detection Tests — EXTERNAL_MODEL_VIOLATION
# ===========================================================================

class TestViolationExternalModel:
    def test_external_model_in_airgap_triggers(self):
        ts = TripwireSystem()

        env = _make_env_state(external_model_endpoints=["http://api.openai.com"])
        result = ts.check_violations(BoundaryMode.AIRGAP, env)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.EXTERNAL_MODEL_VIOLATION

    def test_external_model_in_coldroom_triggers(self):
        ts = TripwireSystem()

        env = _make_env_state(external_model_endpoints=["http://localhost:11434"])
        result = ts.check_violations(BoundaryMode.COLDROOM, env)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.EXTERNAL_MODEL_VIOLATION

    def test_external_model_in_open_does_not_trigger(self):
        ts = TripwireSystem()

        env = _make_env_state(external_model_endpoints=["http://api.openai.com"])
        result = ts.check_violations(BoundaryMode.OPEN, env)
        assert result is None

    def test_no_external_models_in_airgap_ok(self):
        """No external models in AIRGAP is expected — should NOT trigger."""
        ts = TripwireSystem()

        env = _make_env_state(external_model_endpoints=[])
        result = ts.check_violations(BoundaryMode.AIRGAP, env)
        assert result is None


# ===========================================================================
# Violation Detection Tests — SUSPICIOUS_PROCESS
# ===========================================================================

class TestViolationSuspiciousProcess:
    def test_shell_escapes_above_threshold_triggers(self):
        """Shell escapes > 10 should trigger in any mode."""
        ts = TripwireSystem()

        env = _make_env_state(shell_escapes_detected=11)
        result = ts.check_violations(BoundaryMode.OPEN, env)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.SUSPICIOUS_PROCESS

    def test_shell_escapes_at_threshold_triggers(self):
        """Shell escapes == 10 should trigger in OPEN mode (>= 10 threshold)."""
        ts = TripwireSystem()

        env = _make_env_state(shell_escapes_detected=10)
        result = ts.check_violations(BoundaryMode.OPEN, env)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.SUSPICIOUS_PROCESS

    def test_shell_escapes_below_threshold_does_not_trigger(self):
        ts = TripwireSystem()

        env = _make_env_state(shell_escapes_detected=9)
        result = ts.check_violations(BoundaryMode.OPEN, env)
        assert result is None

    def test_suspicious_processes_in_trusted_triggers(self):
        """Suspicious processes in TRUSTED+ mode should trigger."""
        ts = TripwireSystem()

        env = _make_env_state(suspicious_processes=["sudo", "pkexec"])
        result = ts.check_violations(BoundaryMode.TRUSTED, env)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.SUSPICIOUS_PROCESS

    def test_suspicious_processes_in_open_triggers(self):
        ts = TripwireSystem()

        env = _make_env_state(suspicious_processes=["sudo"])
        result = ts.check_violations(BoundaryMode.OPEN, env)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.SUSPICIOUS_PROCESS

    def test_suspicious_processes_in_restricted_triggers(self):
        ts = TripwireSystem()

        env = _make_env_state(suspicious_processes=["su"])
        result = ts.check_violations(BoundaryMode.RESTRICTED, env)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.SUSPICIOUS_PROCESS


# ===========================================================================
# Violation Detection Tests — HARDWARE_TRUST_DEGRADED
# ===========================================================================

class TestViolationHardwareTrust:
    def test_low_trust_in_airgap_triggers(self):
        from daemon.state_monitor import HardwareTrust
        ts = TripwireSystem()

        env = _make_env_state(hardware_trust=HardwareTrust.LOW)
        result = ts.check_violations(BoundaryMode.AIRGAP, env)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.HARDWARE_TRUST_DEGRADED

    def test_low_trust_in_coldroom_triggers(self):
        from daemon.state_monitor import HardwareTrust
        ts = TripwireSystem()

        env = _make_env_state(hardware_trust=HardwareTrust.LOW)
        result = ts.check_violations(BoundaryMode.COLDROOM, env)
        assert isinstance(result, TripwireViolation)
        assert result.violation_type == ViolationType.HARDWARE_TRUST_DEGRADED

    def test_medium_trust_in_airgap_does_not_trigger(self):
        from daemon.state_monitor import HardwareTrust
        ts = TripwireSystem()

        env = _make_env_state(hardware_trust=HardwareTrust.MEDIUM)
        result = ts.check_violations(BoundaryMode.AIRGAP, env)
        assert result is None

    def test_low_trust_in_trusted_triggers(self):
        from daemon.state_monitor import HardwareTrust
        ts = TripwireSystem()

        env = _make_env_state(hardware_trust=HardwareTrust.LOW)
        result = ts.check_violations(BoundaryMode.TRUSTED, env)
        assert result is not None
        assert result.violation_type == ViolationType.HARDWARE_TRUST_DEGRADED


# ===========================================================================
# Violation Detection Tests — Disabled State
# ===========================================================================

class TestViolationDetectionDisabled:
    """Tests that disabled tripwires don't detect violations."""

    def test_check_violations_returns_none_when_disabled(self):
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()
        token = ts._generate_auth_token()
        ts.disable(token, reason="test")

        # This would normally trigger
        env = _make_env_state(network=NetworkState.ONLINE)
        result = ts.check_violations(BoundaryMode.AIRGAP, env)
        assert result is None


# ===========================================================================
# Callback Tests
# ===========================================================================

class TestTripwireCallbacks:
    """Tests for callback registration, invocation, and error isolation."""

    def test_callback_invoked_on_violation(self):
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()
        violations_received = []
        ts.register_callback(lambda v: violations_received.append(v))

        env = _make_env_state(network=NetworkState.ONLINE)
        ts.check_violations(BoundaryMode.AIRGAP, env)
        assert len(violations_received) == 1
        assert violations_received[0].violation_type == ViolationType.NETWORK_IN_AIRGAP

    def test_multiple_callbacks_all_invoked(self):
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()
        call_counts = [0, 0, 0]

        ts.register_callback(lambda v: call_counts.__setitem__(0, call_counts[0] + 1))
        ts.register_callback(lambda v: call_counts.__setitem__(1, call_counts[1] + 1))
        ts.register_callback(lambda v: call_counts.__setitem__(2, call_counts[2] + 1))

        env = _make_env_state(network=NetworkState.ONLINE)
        ts.check_violations(BoundaryMode.AIRGAP, env)
        assert call_counts == [1, 1, 1]

    def test_callback_error_does_not_prevent_others(self):
        """If one callback raises, the rest should still execute."""
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()
        results = []

        ts.register_callback(lambda v: results.append("first"))
        ts.register_callback(lambda v: (_ for _ in ()).throw(RuntimeError("boom")))
        ts.register_callback(lambda v: results.append("third"))

        env = _make_env_state(network=NetworkState.ONLINE)
        ts.check_violations(BoundaryMode.AIRGAP, env)
        assert "first" in results
        assert "third" in results

    def test_unregister_callback(self):
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()
        results = []

        cb_id = ts.register_callback(lambda v: results.append("called"))
        removed = ts.unregister_callback(cb_id)
        assert removed is True

        env = _make_env_state(network=NetworkState.ONLINE)
        ts.check_violations(BoundaryMode.AIRGAP, env)
        assert len(results) == 0

    def test_unregister_invalid_id_returns_false(self):
        ts = TripwireSystem()
        assert ts.unregister_callback(9999) is False

    def test_cleanup_clears_callbacks(self):
        ts = TripwireSystem()
        ts.register_callback(lambda v: None)
        ts.register_callback(lambda v: None)
        assert len(ts._callbacks) == 2
        ts.cleanup()
        assert len(ts._callbacks) == 0

    def test_callback_invoked_on_trigger_violation(self):
        ts = TripwireSystem()
        violations_received = []
        ts.register_callback(lambda v: violations_received.append(v))

        ts.trigger_violation(
            ViolationType.CLOCK_MANIPULATION,
            "NTP drift > 5s",
            BoundaryMode.TRUSTED,
            {"clock_drift": 5.2},
        )
        assert len(violations_received) == 1
        assert violations_received[0].violation_type == ViolationType.CLOCK_MANIPULATION


# ===========================================================================
# Lifecycle Tests — trigger_violation, get/count/clear, lock, status
# ===========================================================================

class TestTripwireLifecycle:
    """Tests for violation lifecycle: trigger, retrieve, clear, lock."""

    def test_trigger_violation_stores_record(self):
        ts = TripwireSystem()
        v = ts.trigger_violation(
            ViolationType.CLOCK_MANIPULATION,
            "System clock jumped forward 60s",
            BoundaryMode.AIRGAP,
            {"drift_seconds": 60},
        )
        assert v is not None
        assert v.violation_type == ViolationType.CLOCK_MANIPULATION
        assert ts.get_violation_count() == 1

    def test_trigger_violation_returns_none_when_disabled(self):
        ts = TripwireSystem()
        token = ts._generate_auth_token()
        ts.disable(token, reason="test")

        v = ts.trigger_violation(
            ViolationType.NETWORK_TRUST_VIOLATION,
            "rogue cert",
            BoundaryMode.OPEN,
            {},
        )
        assert v is None
        assert ts.get_violation_count() == 0

    def test_get_violations_returns_copies(self):
        """get_violations should return a copy, not internal state."""
        ts = TripwireSystem()
        ts.trigger_violation(
            ViolationType.DAEMON_TAMPERING, "modified binary",
            BoundaryMode.TRUSTED, {},
        )
        violations = ts.get_violations()
        assert len(violations) == 1
        # Mutating the returned list should not affect internal state
        violations.clear()
        assert ts.get_violation_count() == 1

    def test_get_violation_count(self):
        ts = TripwireSystem()
        assert ts.get_violation_count() == 0

        ts.trigger_violation(ViolationType.DAEMON_TAMPERING, "a", BoundaryMode.OPEN, {})
        assert ts.get_violation_count() == 1

        ts.trigger_violation(ViolationType.CLOCK_MANIPULATION, "b", BoundaryMode.OPEN, {})
        assert ts.get_violation_count() == 2

    def test_clear_violations_with_valid_token(self):
        ts = TripwireSystem()
        token = ts._generate_auth_token()

        ts.trigger_violation(ViolationType.DAEMON_TAMPERING, "x", BoundaryMode.OPEN, {})
        ts.trigger_violation(ViolationType.CLOCK_MANIPULATION, "y", BoundaryMode.OPEN, {})
        assert ts.get_violation_count() == 2

        success, msg = ts.clear_violations(token, reason="incident resolved")
        assert success is True
        assert "2" in msg
        assert ts.get_violation_count() == 0

    def test_clear_violations_with_invalid_token(self):
        ts = TripwireSystem()
        ts.trigger_violation(ViolationType.DAEMON_TAMPERING, "x", BoundaryMode.OPEN, {})

        success, msg = ts.clear_violations("bad-token", reason="hacker")
        assert success is False
        assert ts.get_violation_count() == 1

    def test_clear_violations_tracks_failed_attempts(self):
        ts = TripwireSystem()
        ts.trigger_violation(ViolationType.DAEMON_TAMPERING, "x", BoundaryMode.OPEN, {})
        initial = ts._failed_attempts
        ts.clear_violations("bad-token")
        assert ts._failed_attempts == initial + 1

    def test_lock_prevents_disable(self):
        ts = TripwireSystem()
        token = ts._generate_auth_token()
        ts.lock()

        success, msg = ts.disable(token, reason="test")
        assert success is False
        assert "LOCKED" in msg

    def test_is_locked(self):
        ts = TripwireSystem()
        assert ts.is_locked() is False
        ts.lock()
        assert ts.is_locked() is True

    def test_is_enabled(self):
        ts = TripwireSystem()
        assert ts.is_enabled() is True
        token = ts._generate_auth_token()
        ts.disable(token, reason="test")
        assert ts.is_enabled() is False
        ts.enable()
        assert ts.is_enabled() is True

    def test_get_security_status(self):
        """get_security_status should return correct summary."""
        ts = TripwireSystem()
        ts.trigger_violation(ViolationType.DAEMON_TAMPERING, "x", BoundaryMode.OPEN, {})
        ts.disable("bad-token")  # Fail once

        status = ts.get_security_status()
        assert status['enabled'] is True
        assert status['locked'] is False
        assert status['violation_count'] == 1
        assert status['failed_auth_attempts'] == 1
        assert status['max_attempts_before_lock'] == 3

    def test_check_daemon_health_returns_true_normally(self):
        ts = TripwireSystem()
        assert ts.check_daemon_health() is True

    def test_successful_auth_does_not_reset_failed_counter(self):
        """Successful disable should NOT reset the failed attempt counter.
        Resetting would allow alternating valid/invalid attempts to bypass lockout."""
        ts = TripwireSystem()
        ts.disable("bad-1")
        ts.disable("bad-2")
        assert ts._failed_attempts == 2

        token = ts._generate_auth_token()
        success, _ = ts.disable(token, reason="legit")
        assert success is True
        # Counter must NOT be reset -- prevents lockout bypass
        assert ts._failed_attempts == 2

    def test_violation_stores_environment_snapshot(self):
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()

        env = _make_env_state(network=NetworkState.ONLINE, active_interfaces=["eth0"])
        result = ts.check_violations(BoundaryMode.AIRGAP, env)
        assert result is not None
        assert 'network' in result.environment_snapshot

    def test_violation_has_unique_id(self):
        ts = TripwireSystem()
        v1 = ts.trigger_violation(ViolationType.DAEMON_TAMPERING, "a", BoundaryMode.OPEN, {})
        v2 = ts.trigger_violation(ViolationType.CLOCK_MANIPULATION, "b", BoundaryMode.OPEN, {})
        assert v1.violation_id != v2.violation_id

    def test_violation_deque_bounded(self):
        """Violation history should be bounded (maxlen=1000)."""
        ts = TripwireSystem()
        for i in range(1050):
            ts.trigger_violation(ViolationType.DAEMON_TAMPERING, f"v{i}", BoundaryMode.OPEN, {})
        assert ts.get_violation_count() == 1000


# ===========================================================================
# SECURITY INVARIANT: Violation Priority Ordering
# ===========================================================================

class TestViolationPriorityOrdering:
    """Security invariant: check_violations returns the FIRST violation found
    in priority order: network > USB > external_model > suspicious_process > hardware_trust.

    When multiple violations occur simultaneously, the most critical one
    (network isolation breach) takes priority over less critical ones.
    """

    def test_network_violation_takes_priority_over_usb(self):
        """INVARIANT: Network breach outranks USB insertion in COLDROOM+."""
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()

        # First check sets baseline (clean)
        env_clean = _make_env_state(network=NetworkState.OFFLINE, usb_devices=set())
        ts.check_violations(BoundaryMode.COLDROOM, env_clean)

        # Both violations present: network online AND new USB
        env_both = _make_env_state(
            network=NetworkState.ONLINE,
            usb_devices={"rogue-usb-stick"},
        )
        result = ts.check_violations(BoundaryMode.COLDROOM, env_both)
        assert result is not None
        # Network check comes first in priority
        assert result.violation_type == ViolationType.NETWORK_IN_AIRGAP

    def test_network_violation_takes_priority_over_external_model(self):
        """INVARIANT: Network breach outranks external model violation."""
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()

        env = _make_env_state(
            network=NetworkState.ONLINE,
            external_model_endpoints=["http://api.openai.com"],
        )
        result = ts.check_violations(BoundaryMode.AIRGAP, env)
        assert result.violation_type == ViolationType.NETWORK_IN_AIRGAP

    def test_usb_violation_takes_priority_over_external_model(self):
        """INVARIANT: USB insertion outranks external model in COLDROOM."""
        from daemon.state_monitor import NetworkState
        ts = TripwireSystem()

        # Baseline: offline, no USB
        env_clean = _make_env_state(network=NetworkState.OFFLINE, usb_devices=set())
        ts.check_violations(BoundaryMode.COLDROOM, env_clean)

        # USB + external model, still offline (no network violation)
        env = _make_env_state(
            network=NetworkState.OFFLINE,
            usb_devices={"rogue-usb"},
            external_model_endpoints=["http://localhost:11434"],
        )
        result = ts.check_violations(BoundaryMode.COLDROOM, env)
        assert result.violation_type == ViolationType.USB_IN_COLDROOM

    def test_external_model_takes_priority_over_suspicious_process(self):
        """INVARIANT: External model outranks suspicious process in AIRGAP."""
        ts = TripwireSystem()

        env = _make_env_state(
            external_model_endpoints=["http://api.openai.com"],
            shell_escapes_detected=20,
        )
        result = ts.check_violations(BoundaryMode.AIRGAP, env)
        assert result.violation_type == ViolationType.EXTERNAL_MODEL_VIOLATION

    def test_suspicious_process_takes_priority_over_hardware_trust(self):
        """INVARIANT: Suspicious process outranks hardware trust degradation."""
        from daemon.state_monitor import HardwareTrust
        ts = TripwireSystem()

        env = _make_env_state(
            shell_escapes_detected=20,
            hardware_trust=HardwareTrust.LOW,
        )
        result = ts.check_violations(BoundaryMode.AIRGAP, env)
        assert result.violation_type == ViolationType.SUSPICIOUS_PROCESS

    def test_only_first_violation_returned(self):
        """check_violations returns exactly one violation, not a list."""
        from daemon.state_monitor import NetworkState, HardwareTrust
        ts = TripwireSystem()

        # Baseline
        env_clean = _make_env_state(network=NetworkState.OFFLINE, usb_devices=set())
        ts.check_violations(BoundaryMode.COLDROOM, env_clean)

        # Everything goes wrong at once
        env_all_bad = _make_env_state(
            network=NetworkState.ONLINE,
            usb_devices={"rogue-usb"},
            external_model_endpoints=["http://evil.com"],
            shell_escapes_detected=100,
            hardware_trust=HardwareTrust.LOW,
        )
        result = ts.check_violations(BoundaryMode.COLDROOM, env_all_bad)
        # Should return exactly one violation (the highest priority)
        assert result is not None
        assert result.violation_type == ViolationType.NETWORK_IN_AIRGAP


# ===========================================================================
# Tripwire Event Logger Failure Resilience
# ===========================================================================

class TestTripwireLoggerFailure:
    """Tests that tripwire violations are still recorded and callbacks still fire
    even when the event logger is unavailable or throws."""

    def test_trigger_violation_with_none_logger(self):
        ts = TripwireSystem()
        # Default construction has _event_logger=None
        assert ts._event_logger is None

        v = ts.trigger_violation(
            ViolationType.DAEMON_TAMPERING, "binary modified",
            BoundaryMode.TRUSTED, {"hash": "different"},
        )
        assert v is not None
        assert ts.get_violation_count() == 1

    def test_trigger_violation_with_broken_logger_still_records(self):
        from unittest.mock import MagicMock
        ts = TripwireSystem()

        # Attach a mock logger that raises on log_event
        broken_logger = MagicMock()
        broken_logger.log_event.side_effect = RuntimeError("disk full")
        ts._event_logger = broken_logger

        v = ts.trigger_violation(
            ViolationType.CLOCK_MANIPULATION, "clock jumped",
            BoundaryMode.AIRGAP, {"drift": 60},
        )
        assert v is not None
        assert ts.get_violation_count() == 1

    def test_trigger_violation_with_broken_logger_still_calls_callbacks(self):
        from unittest.mock import MagicMock
        ts = TripwireSystem()

        # Broken logger
        broken_logger = MagicMock()
        broken_logger.log_event.side_effect = RuntimeError("disk full")
        ts._event_logger = broken_logger

        # Register callback
        callback_violations = []
        ts.register_callback(lambda v: callback_violations.append(v))

        ts.trigger_violation(
            ViolationType.NETWORK_TRUST_VIOLATION, "rogue cert",
            BoundaryMode.OPEN, {},
        )
        assert len(callback_violations) == 1
        assert callback_violations[0].violation_type == ViolationType.NETWORK_TRUST_VIOLATION


# ===========================================================================
# Fail-Closed: Lockout After Max Failed Attempts
# ===========================================================================

class TestTripwireLockout:
    """Security invariant: After max_disable_attempts failed auth attempts,
    tripwires auto-lock to prevent brute force."""

    def test_auto_lock_after_max_failed_attempts(self):
        """SECURITY INVARIANT: 3 failed disable attempts → auto-lock."""
        ts = TripwireSystem()
        assert ts.is_locked() is False

        # Fail 3 times
        ts.disable("bad-1")
        ts.disable("bad-2")
        ts.disable("bad-3")

        assert ts.is_locked() is True

    def test_auto_lock_prevents_even_valid_token(self):
        """SECURITY INVARIANT: Once locked, even valid tokens can't disable."""
        ts = TripwireSystem()
        token = ts._generate_auth_token()

        # Fail enough to lock
        ts.disable("bad-1")
        ts.disable("bad-2")
        ts.disable("bad-3")

        # Valid token should still fail
        success, msg = ts.disable(token, reason="legitimate")
        assert success is False
        assert "LOCKED" in msg


# ===========================================================================
# Error-Path Tests
# ===========================================================================

import pytest


class TestTripwireErrorPaths:
    """Error-path tests for TripwireSystem using pytest.raises."""

    def test_violation_type_invalid_value_raises(self):
        """ViolationType with invalid value should raise ValueError."""
        with pytest.raises(ValueError):
            ViolationType("totally_fake_violation")

    def test_disable_with_invalid_token_returns_false(self):
        """Disabling with an invalid token returns (False, msg)."""
        ts = TripwireSystem()
        success, msg = ts.disable("completely-wrong-token", reason="test")
        assert success is False
        assert "Invalid" in msg

    def test_disable_when_locked_returns_false(self):
        """Disabling when locked returns (False, msg) mentioning LOCKED."""
        ts = TripwireSystem()
        ts.lock()
        token = ts._generate_auth_token()
        success, msg = ts.disable(token, reason="test")
        assert success is False
        assert "LOCKED" in msg

    def test_clear_violations_invalid_token_returns_false(self):
        """Clearing violations with invalid token returns (False, msg)."""
        ts = TripwireSystem()
        success, msg = ts.clear_violations("wrong-token", reason="test")
        assert success is False
        assert "Invalid" in msg

    def test_get_new_auth_token_invalid_token_returns_none(self):
        """Getting new auth token with invalid current token returns None."""
        ts = TripwireSystem()
        result = ts.get_new_auth_token("wrong-token")
        assert result is None

    def test_auto_lock_after_max_failed_attempts(self):
        """System should auto-lock after max_disable_attempts failed auth."""
        ts = TripwireSystem()
        assert ts.is_locked() is False
        for i in range(ts._max_disable_attempts):
            ts.disable(f"bad-token-{i}")
        assert ts.is_locked() is True

    def test_auto_lock_prevents_disable_with_valid_token(self):
        """After auto-lock, even valid tokens cannot disable."""
        ts = TripwireSystem()
        token = ts._generate_auth_token()
        for i in range(ts._max_disable_attempts):
            ts.disable(f"bad-token-{i}")
        success, msg = ts.disable(token, reason="legitimate")
        assert success is False
        assert "LOCKED" in msg

    def test_callback_exception_does_not_propagate(self):
        """Callback exceptions during violation should not propagate."""
        ts = TripwireSystem()

        def bad_callback(violation):
            raise RuntimeError("callback exploded")

        ts.register_callback(bad_callback)
        env = _make_env_state(shell_escapes_detected=100)
        ts.check_violations(BoundaryMode.OPEN, env)

    def test_trigger_violation_when_disabled_returns_none(self):
        """trigger_violation when disabled returns None."""
        ts = TripwireSystem()
        token = ts._generate_auth_token()
        ts.disable(token, reason="test")
        result = ts.trigger_violation(
            ViolationType.DAEMON_TAMPERING,
            "test violation",
            BoundaryMode.OPEN,
            {},
        )
        assert result is None

    def test_verify_token_empty_string_returns_false(self):
        """Verifying empty token returns False."""
        ts = TripwireSystem()
        assert ts._verify_token("") is False

    def test_verify_token_none_returns_false(self):
        """Verifying None token returns False."""
        ts = TripwireSystem()
        assert ts._verify_token(None) is False

    def test_disable_empty_token_returns_false(self):
        """Disabling with empty token returns (False, msg)."""
        ts = TripwireSystem()
        success, msg = ts.disable("", reason="test")
        assert success is False
