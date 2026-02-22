"""
Tests for Operator Observability — ROADMAP item §6.

Tests cover:
1. Decision tracing — why a specific policy decision was made
2. Integration health registry — which systems are checking in
3. Operator snapshot — unified view of daemon state
4. Evidence bundle export — compliance/incident response packages
5. Log chain verification through the console
6. Decision log querying and filtering
7. Tripwire status visibility
8. Mode rationale display
"""

import json
import os
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime

from daemon.event_logger import EventLogger, EventType
from daemon.policy_engine import (
    PolicyEngine,
    BoundaryMode,
    Operator,
    PolicyDecision,
    PolicyRequest,
    MemoryClass,
)
from daemon.state_monitor import (
    EnvironmentState,
    NetworkState,
    HardwareTrust,
    SpecialtyNetworkStatus,
)
from daemon.tripwires import TripwireSystem
from daemon.operator_observability import (
    OperatorConsole,
    IntegrationHealthRegistry,
    DecisionTrace,
    TraceVerdict,
    trace_policy_decision,
)


def _make_env(**overrides) -> EnvironmentState:
    defaults = dict(
        timestamp=datetime.utcnow().isoformat() + "Z",
        network=NetworkState.ONLINE,
        hardware_trust=HardwareTrust.MEDIUM,
        active_interfaces=[],
        interface_types={},
        has_internet=True,
        vpn_active=False,
        dns_available=True,
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
        usb_devices=set(),
        block_devices=set(),
        camera_available=False,
        mic_available=False,
        tpm_present=False,
        external_model_endpoints=[],
        suspicious_processes=[],
        shell_escapes_detected=0,
        keyboard_active=True,
        screen_unlocked=True,
        last_activity=None,
    )
    defaults.update(overrides)
    return EnvironmentState(**defaults)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="obs_test_")
    yield d
    import shutil
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def event_logger(temp_dir):
    log_file = os.path.join(temp_dir, "test_chain.log")
    return EventLogger(log_file, secure_permissions=False)


@pytest.fixture
def policy_engine():
    engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
    yield engine
    engine.cleanup()


@pytest.fixture
def env_state():
    return _make_env()


class FakeLockdownManager:
    """Minimal lockdown manager for testing."""
    def get_lockdown_info(self):
        return {"lockdown_active": False}


class FakeStateMonitor:
    """Minimal state monitor for testing."""
    def __init__(self, env_state):
        self._state = env_state

    def get_current_state(self):
        return self._state


class FakeDaemon:
    """
    Minimal daemon-like object for testing the OperatorConsole.

    Provides just the attributes that OperatorConsole accesses.
    """
    def __init__(self, policy_engine, event_logger, env_state=None):
        self.policy_engine = policy_engine
        self.event_logger = event_logger
        self.tripwire_system = TripwireSystem()
        self.lockdown_manager = FakeLockdownManager()
        self.signed_logging = False
        self.redundant_logging = False
        self._mode_frozen_reason = None
        self._running = True

        if env_state is None:
            env_state = _make_env()

        self.state_monitor = FakeStateMonitor(env_state)
        self.network_enforcer = None
        self.sandbox_bridge_enabled = False
        self.sandbox_bridge = None
        self.sandbox_telemetry = None

    def get_status(self):
        return {
            "running": self._running,
            "boundary_state": self.policy_engine.get_current_state().to_dict(),
            "event_count": self.event_logger.get_event_count(),
        }


@pytest.fixture
def fake_daemon(policy_engine, event_logger, env_state):
    return FakeDaemon(policy_engine, event_logger, env_state)


@pytest.fixture
def console(fake_daemon):
    return OperatorConsole(fake_daemon)


# ---------------------------------------------------------------------------
# Test: Decision Tracing
# ---------------------------------------------------------------------------


class TestDecisionTracing:
    @pytest.mark.unit
    def test_trace_recall_allow(self, console, env_state):
        request = PolicyRequest(
            request_type="recall",
            memory_class=MemoryClass.PUBLIC,
        )
        trace = console.trace_decision(request, env_state)

        assert trace.decision == "allow"
        assert trace.verdict == TraceVerdict.RECALL_MODE_SUFFICIENT.name
        assert trace.request_type == "recall"
        assert trace.mode == "OPEN"
        assert len(trace.steps) > 0

    @pytest.mark.unit
    def test_trace_recall_deny(self, console, env_state):
        request = PolicyRequest(
            request_type="recall",
            memory_class=MemoryClass.SECRET,
        )
        trace = console.trace_decision(request, env_state)

        assert trace.decision == "deny"
        assert trace.verdict == TraceVerdict.RECALL_MODE_INSUFFICIENT.name

    @pytest.mark.unit
    def test_trace_recall_no_memory_class(self, console, env_state):
        """Trace a recall request with no memory class — fail closed."""
        request = PolicyRequest(request_type="recall", memory_class=None)
        trace = console.trace_decision(request, env_state)

        assert trace.decision == "deny"
        assert trace.verdict == TraceVerdict.FAIL_CLOSED.name

    @pytest.mark.unit
    def test_trace_tool_allow_open(self, console, env_state):
        """OPEN mode allows all tools."""
        request = PolicyRequest(
            request_type="tool",
            tool_name="wget",
            requires_network=True,
        )
        trace = console.trace_decision(request, env_state)

        assert trace.decision == "allow"
        assert trace.verdict == TraceVerdict.TOOL_ALLOWED.name

    @pytest.mark.unit
    def test_trace_tool_deny_airgap_network(self, fake_daemon, env_state):
        """AIRGAP denies network tools."""
        fake_daemon.policy_engine.transition_mode(
            BoundaryMode.AIRGAP, Operator.HUMAN, "test"
        )
        console = OperatorConsole(fake_daemon)

        request = PolicyRequest(
            request_type="tool",
            tool_name="curl",
            requires_network=True,
        )
        trace = console.trace_decision(request, env_state)

        assert trace.decision == "deny"
        assert trace.verdict == TraceVerdict.TOOL_MODE_RESTRICTION.name
        assert trace.mode == "AIRGAP"

    @pytest.mark.unit
    def test_trace_tool_usb_ceremony(self, fake_daemon, env_state):
        """RESTRICTED mode requires ceremony for USB."""
        fake_daemon.policy_engine.transition_mode(
            BoundaryMode.RESTRICTED, Operator.HUMAN, "test"
        )
        console = OperatorConsole(fake_daemon)

        request = PolicyRequest(
            request_type="tool",
            requires_usb=True,
        )
        trace = console.trace_decision(request, env_state)

        assert trace.decision == "require_ceremony"
        assert trace.verdict == TraceVerdict.TOOL_CEREMONY_REQUIRED.name

    @pytest.mark.unit
    def test_trace_lockdown_denies_all(self, fake_daemon, env_state):
        """LOCKDOWN denies everything."""
        fake_daemon.policy_engine.transition_mode(
            BoundaryMode.LOCKDOWN, Operator.HUMAN, "emergency"
        )
        console = OperatorConsole(fake_daemon)

        request = PolicyRequest(
            request_type="recall",
            memory_class=MemoryClass.PUBLIC,
        )
        trace = console.trace_decision(request, env_state)

        assert trace.decision == "deny"
        assert trace.verdict == TraceVerdict.MODE_LOCKDOWN.name

    @pytest.mark.unit
    def test_trace_model_airgap_blocked(self, fake_daemon, env_state):
        """AIRGAP blocks external models."""
        fake_daemon.policy_engine.transition_mode(
            BoundaryMode.AIRGAP, Operator.HUMAN, "test"
        )
        console = OperatorConsole(fake_daemon)

        request = PolicyRequest(request_type="model")
        trace = console.trace_decision(request, env_state)

        assert trace.decision == "deny"
        assert trace.verdict == TraceVerdict.MODEL_MODE_BLOCKED.name

    @pytest.mark.unit
    def test_trace_io_coldroom_filesystem_blocked(self, fake_daemon, env_state):
        """COLDROOM blocks filesystem IO."""
        fake_daemon.policy_engine.transition_mode(
            BoundaryMode.COLDROOM, Operator.HUMAN, "test"
        )
        console = OperatorConsole(fake_daemon)

        request = PolicyRequest(
            request_type="io",
            requires_filesystem=True,
        )
        trace = console.trace_decision(request, env_state)

        assert trace.decision == "deny"
        assert trace.verdict == TraceVerdict.IO_MODE_BLOCKED.name

    @pytest.mark.unit
    def test_trace_unknown_request_type(self, console, env_state):
        """Unknown request types fail closed."""
        request = PolicyRequest(request_type="foobar")
        trace = console.trace_decision(request, env_state)

        assert trace.decision == "deny"
        assert trace.verdict == TraceVerdict.UNKNOWN_REQUEST_TYPE.name

    @pytest.mark.unit
    def test_trace_explain_readable(self, console, env_state):
        request = PolicyRequest(
            request_type="recall",
            memory_class=MemoryClass.SECRET,
        )
        trace = console.trace_decision(request, env_state)

        explanation = trace.explain()
        assert "deny" in explanation.lower()
        assert "SECRET" in explanation
        assert "Reasoning:" in explanation

    @pytest.mark.unit
    def test_trace_to_dict(self, console, env_state):
        request = PolicyRequest(
            request_type="recall",
            memory_class=MemoryClass.PUBLIC,
        )
        trace = console.trace_decision(request, env_state)

        d = trace.to_dict()
        assert d["request_type"] == "recall"
        assert d["decision"] == "allow"
        assert "steps" in d
        # Must be JSON-serializable
        json.dumps(d)


# ---------------------------------------------------------------------------
# Test: Integration Health Registry
# ---------------------------------------------------------------------------


class TestIntegrationHealthRegistry:
    @pytest.mark.unit
    def test_check_in(self):
        registry = IntegrationHealthRegistry(silent_threshold_seconds=60)
        registry.check_in("memory-vault", request_type="recall", decision="allow")

        active = registry.get_active()
        assert len(active) == 1
        assert active[0].integration_name == "memory-vault"
        assert active[0].checkin_count == 1

    @pytest.mark.unit
    def test_multiple_checkins(self):
        registry = IntegrationHealthRegistry()
        registry.check_in("agent-os", request_type="tool")
        registry.check_in("agent-os", request_type="tool")
        registry.check_in("agent-os", request_type="recall")

        active = registry.get_active()
        assert len(active) == 1
        assert active[0].checkin_count == 3
        assert active[0].last_request_type == "recall"

    @pytest.mark.unit
    def test_expected_integration_silent(self):
        """Pre-registered integrations that never check in show as silent."""
        registry = IntegrationHealthRegistry()
        registry.expect("memory-vault")
        registry.expect("agent-os")

        silent = registry.get_silent()
        assert len(silent) == 2

        active = registry.get_active()
        assert len(active) == 0

    @pytest.mark.unit
    def test_expected_then_checkin(self):
        """Expected integration becomes active after check-in."""
        registry = IntegrationHealthRegistry(silent_threshold_seconds=60)
        registry.expect("memory-vault")

        # Initially silent
        assert len(registry.get_silent()) == 1

        # Check in
        registry.check_in("memory-vault", request_type="recall")

        # Now active
        assert len(registry.get_active()) == 1
        assert len(registry.get_silent()) == 0

    @pytest.mark.unit
    def test_silent_after_threshold(self):
        """Integration goes silent after threshold expires."""
        registry = IntegrationHealthRegistry(silent_threshold_seconds=0.1)
        registry.check_in("test-integration")

        # Should be active immediately
        assert len(registry.get_active()) == 1

        # Wait for threshold
        time.sleep(0.2)

        # Now silent
        assert len(registry.get_silent()) == 1
        assert len(registry.get_active()) == 0

    @pytest.mark.unit
    def test_get_status(self):
        registry = IntegrationHealthRegistry(silent_threshold_seconds=60)
        registry.expect("vault")
        registry.check_in("agent-os", request_type="tool", decision="allow")

        status = registry.get_status()
        assert status["total_integrations"] == 2
        assert status["active_count"] == 1
        assert status["silent_count"] == 1
        assert status["expected_count"] == 1
        assert len(status["active"]) == 1
        assert len(status["silent"]) == 1


# ---------------------------------------------------------------------------
# Test: Operator Snapshot
# ---------------------------------------------------------------------------


class TestOperatorSnapshot:
    @pytest.mark.unit
    def test_snapshot_has_required_sections(self, console):
        """Snapshot should have all five ROADMAP §6 sections."""
        snapshot = console.get_operator_snapshot()

        assert "mode" in snapshot
        assert "recent_decisions" in snapshot
        assert "tripwire_status" in snapshot
        assert "log_health" in snapshot
        assert "integration_health" in snapshot
        assert "timestamp" in snapshot

    @pytest.mark.unit
    def test_mode_section_has_rationale(self, console):
        snapshot = console.get_operator_snapshot()
        mode = snapshot["mode"]

        assert "current_mode" in mode
        assert "rationale" in mode
        assert "operator" in mode
        assert "last_transition" in mode
        assert "environment_compatible" in mode
        assert mode["current_mode"] == "OPEN"

    @pytest.mark.unit
    def test_tripwire_section(self, console):
        snapshot = console.get_operator_snapshot()
        tripwires = snapshot["tripwire_status"]

        assert "enabled" in tripwires
        assert "armed_count" in tripwires
        assert "fired_count" in tripwires
        assert "armed" in tripwires
        assert "fired" in tripwires
        assert tripwires["enabled"] is True
        assert tripwires["armed_count"] > 0
        assert tripwires["fired_count"] == 0

    @pytest.mark.unit
    def test_log_health_section(self, console):
        snapshot = console.get_operator_snapshot()
        log_health = snapshot["log_health"]

        assert "event_count" in log_health
        assert "signed_logging" in log_health
        assert "chain_last_verified" in log_health

    @pytest.mark.unit
    def test_mode_frozen_shown(self, fake_daemon):
        """When mode is frozen, snapshot should show it."""
        fake_daemon._mode_frozen_reason = "Clock manipulation detected"
        console = OperatorConsole(fake_daemon)

        snapshot = console.get_operator_snapshot()
        assert snapshot["mode"]["mode_frozen"] is True
        assert "Clock manipulation" in snapshot["mode"]["rationale"]

    @pytest.mark.unit
    def test_snapshot_serializable(self, console):
        """Snapshot must be JSON-serializable."""
        snapshot = console.get_operator_snapshot()
        json.dumps(snapshot, default=str)


# ---------------------------------------------------------------------------
# Test: Log Chain Verification
# ---------------------------------------------------------------------------


class TestLogChainVerification:
    @pytest.mark.unit
    def test_verify_chain_initially(self, console, event_logger):
        event_logger.log_event(EventType.INFO, "test event")
        valid, msg = console.verify_log_chain()

        assert valid is True
        assert "valid" in msg.lower()
        assert console._chain_last_verified is not None
        assert console._chain_last_valid is True

    @pytest.mark.unit
    def test_verify_chain_shown_in_snapshot(self, console, event_logger):
        """After verification, snapshot should show result."""
        event_logger.log_event(EventType.INFO, "test")
        console.verify_log_chain()

        snapshot = console.get_operator_snapshot()
        assert snapshot["log_health"]["chain_last_verified"] is not None
        assert snapshot["log_health"]["chain_valid"] is True


# ---------------------------------------------------------------------------
# Test: Decision Log Querying
# ---------------------------------------------------------------------------


class TestDecisionLogQuerying:
    @pytest.mark.unit
    def test_query_by_request_type(self, console, env_state):
        """Query decisions filtered by request type."""
        # Log some decisions
        console.trace_decision(
            PolicyRequest(request_type="recall", memory_class=MemoryClass.PUBLIC),
            env_state,
        )
        console.trace_decision(
            PolicyRequest(request_type="tool", requires_network=True),
            env_state,
        )
        console.trace_decision(
            PolicyRequest(request_type="recall", memory_class=MemoryClass.INTERNAL),
            env_state,
        )

        recalls = console.query_decisions(request_type="recall")
        assert len(recalls) == 2

        tools = console.query_decisions(request_type="tool")
        assert len(tools) == 1

    @pytest.mark.unit
    def test_query_by_decision(self, console, env_state):
        """Query decisions filtered by outcome."""
        console.trace_decision(
            PolicyRequest(request_type="recall", memory_class=MemoryClass.PUBLIC),
            env_state,
        )
        console.trace_decision(
            PolicyRequest(request_type="recall", memory_class=MemoryClass.SECRET),
            env_state,
        )

        allows = console.query_decisions(decision="allow")
        denies = console.query_decisions(decision="deny")

        assert len(allows) == 1
        assert len(denies) == 1

    @pytest.mark.unit
    def test_decision_stats(self, console, env_state):
        for mc in [MemoryClass.PUBLIC, MemoryClass.PUBLIC, MemoryClass.SECRET]:
            console.trace_decision(
                PolicyRequest(request_type="recall", memory_class=mc),
                env_state,
            )

        stats = console.get_decision_stats()
        assert stats["total"] == 3
        assert stats["by_decision"]["allow"] == 2
        assert stats["by_decision"]["deny"] == 1
        assert stats["by_type"]["recall"] == 3

    @pytest.mark.unit
    def test_decision_log_bounded(self, console, env_state):
        console._max_decision_log = 5

        for i in range(10):
            console.trace_decision(
                PolicyRequest(request_type="recall", memory_class=MemoryClass.PUBLIC),
                env_state,
            )

        assert len(console._decision_log) <= 5


# ---------------------------------------------------------------------------
# Test: Evidence Bundle Export
# ---------------------------------------------------------------------------


class TestEvidenceBundleExport:
    @pytest.mark.unit
    def test_export_bundle_dict(self, console, event_logger, env_state):
        event_logger.log_event(EventType.MODE_CHANGE, "test event")
        console.trace_decision(
            PolicyRequest(request_type="recall", memory_class=MemoryClass.PUBLIC),
            env_state,
        )

        bundle = console.export_evidence_bundle()

        assert "bundle_metadata" in bundle
        assert "daemon_status" in bundle
        assert "operator_snapshot" in bundle
        assert "log_chain_verification" in bundle
        assert "events" in bundle
        assert "decision_traces" in bundle
        assert "tripwire_violations" in bundle
        assert "integration_health" in bundle
        assert "bundle_hash" in bundle

    @pytest.mark.unit
    def test_export_bundle_to_file(self, console, event_logger, temp_dir, env_state):
        event_logger.log_event(EventType.INFO, "evidence test")
        console.trace_decision(
            PolicyRequest(request_type="recall", memory_class=MemoryClass.PUBLIC),
            env_state,
        )

        bundle = console.export_evidence_bundle(output_dir=temp_dir)

        assert "bundle_file" in bundle
        assert os.path.exists(bundle["bundle_file"])

        # Must be valid JSON
        with open(bundle["bundle_file"]) as f:
            loaded = json.load(f)

        assert loaded["bundle_metadata"]["generator"] == "boundary-daemon/operator-observability"

    @pytest.mark.unit
    def test_bundle_has_integrity_hash(self, console, event_logger):
        event_logger.log_event(EventType.INFO, "hash test")
        bundle = console.export_evidence_bundle()

        assert "bundle_hash" in bundle
        assert len(bundle["bundle_hash"]) == 64  # SHA-256 hex

    @pytest.mark.unit
    def test_bundle_includes_chain_verification(self, console, event_logger):
        event_logger.log_event(EventType.INFO, "chain test")
        bundle = console.export_evidence_bundle()

        assert bundle["log_chain_verification"]["valid"] is True
        assert "verified_at" in bundle["log_chain_verification"]

    @pytest.mark.unit
    def test_bundle_serializable(self, console, event_logger):
        """Entire bundle must be JSON-serializable."""
        event_logger.log_event(EventType.INFO, "serial test")
        bundle = console.export_evidence_bundle()

        # Should not raise
        json.dumps(bundle, default=str)


# ---------------------------------------------------------------------------
# Test: TraceVerdict coverage across all policy paths
# ---------------------------------------------------------------------------


class TestTraceVerdictCoverage:
    """Ensure trace_policy_decision covers all policy paths."""

    @pytest.mark.unit
    @pytest.mark.parametrize("memory_class,mode,expected_decision", [
        (MemoryClass.PUBLIC, BoundaryMode.OPEN, "allow"),
        (MemoryClass.CONFIDENTIAL, BoundaryMode.OPEN, "deny"),
        (MemoryClass.CONFIDENTIAL, BoundaryMode.RESTRICTED, "allow"),
        (MemoryClass.SECRET, BoundaryMode.RESTRICTED, "deny"),
        (MemoryClass.SECRET, BoundaryMode.TRUSTED, "allow"),
        (MemoryClass.TOP_SECRET, BoundaryMode.TRUSTED, "deny"),
        (MemoryClass.TOP_SECRET, BoundaryMode.AIRGAP, "allow"),
        (MemoryClass.CROWN_JEWEL, BoundaryMode.AIRGAP, "deny"),
        (MemoryClass.CROWN_JEWEL, BoundaryMode.COLDROOM, "allow"),
    ])
    def test_recall_truth_table_traced(
        self, memory_class, mode, expected_decision, env_state
    ):
        engine = PolicyEngine(initial_mode=mode)
        request = PolicyRequest(
            request_type="recall",
            memory_class=memory_class,
        )
        trace = trace_policy_decision(engine, request, env_state)

        assert trace.decision == expected_decision
        assert trace.mode == mode.name
        assert len(trace.steps) >= 2  # LOCKDOWN check + dispatch + eval
        engine.cleanup()

    @pytest.mark.unit
    def test_model_open_online_allow(self, env_state):
        """OPEN + online = allow external models."""
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        request = PolicyRequest(request_type="model")
        trace = trace_policy_decision(engine, request, env_state)

        assert trace.decision == "allow"
        engine.cleanup()

    @pytest.mark.unit
    def test_model_open_offline_deny(self):
        """OPEN + offline = deny external models (no network)."""
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        offline_env = _make_env(network=NetworkState.OFFLINE, has_internet=False)
        request = PolicyRequest(request_type="model")
        trace = trace_policy_decision(engine, request, offline_env)

        assert trace.decision == "deny"
        assert trace.verdict == TraceVerdict.MODEL_NETWORK_REQUIRED.name
        engine.cleanup()


# ---------------------------------------------------------------------------
# Test: Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases for operator observability."""

    @pytest.mark.unit
    def test_snapshot_with_no_decisions(self, console):
        snapshot = console.get_operator_snapshot()
        assert snapshot["recent_decisions"]["total_logged"] == 0

    @pytest.mark.unit
    def test_empty_registry_status(self):
        registry = IntegrationHealthRegistry()
        status = registry.get_status()
        assert status["total_integrations"] == 0
        assert status["active_count"] == 0
        assert status["silent_count"] == 0

    @pytest.mark.unit
    def test_record_decision_external(self, console):
        """Can record a pre-built trace."""
        trace = DecisionTrace(
            request_type="recall",
            mode="OPEN",
            mode_value=0,
            decision="allow",
            verdict="RECALL_MODE_SUFFICIENT",
        )
        console.record_decision(trace)

        assert len(console._decision_log) == 1

    @pytest.mark.unit
    def test_bundle_default_time_range(self, console, event_logger):
        event_logger.log_event(EventType.INFO, "range test")
        bundle = console.export_evidence_bundle()

        time_range = bundle["bundle_metadata"]["time_range"]
        assert "start" in time_range
        assert "end" in time_range
