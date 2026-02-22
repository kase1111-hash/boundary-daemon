"""
Tests for the Sandbox Enforcement Bridge — ROADMAP item §5.

Tests cover:
1. EnforcementBridge lifecycle (activate/deactivate)
2. Automatic profile tightening on mode escalation
3. Conservative behavior on mode de-escalation (no loosening)
4. LOCKDOWN terminates all sandboxes
5. Telemetry violation recording and hash-chain integration
6. Sandbox.tighten_profile() method
7. EventType additions for sandbox events
8. Bridge stats and enforcement history
9. Edge cases: no sandboxes, already-compliant profiles, bridge re-activation
"""

import os
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.event_logger import EventLogger, EventType
from daemon.policy_engine import PolicyEngine, BoundaryMode, Operator

from daemon.sandbox.sandbox_manager import (
    SandboxManager,
    SandboxProfile,
    Sandbox,
    SandboxState,
    SandboxError,
)
from daemon.sandbox.enforcement_bridge import (
    SandboxEnforcementBridge,
    EnforcementConsumer,
    EnforcementAction,
    EnforcementResult,
)
from daemon.sandbox.telemetry import (
    SandboxTelemetryCollector,
    SandboxViolation,
    ViolationType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_log_dir():
    d = tempfile.mkdtemp(prefix="boundary_test_")
    yield d
    import shutil
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def event_logger(temp_log_dir):
    log_file = os.path.join(temp_log_dir, "test_chain.log")
    return EventLogger(log_file, secure_permissions=False)


@pytest.fixture
def policy_engine():
    engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
    yield engine
    engine.cleanup()


@pytest.fixture
def sandbox_manager(policy_engine):
    manager = SandboxManager(policy_engine=policy_engine)
    yield manager
    # Don't call cleanup() — it tries to use cgroups/firewall which aren't available


@pytest.fixture
def telemetry(event_logger):
    collector = SandboxTelemetryCollector(
        event_logger=event_logger,
        poll_interval=60.0,  # Long interval — we'll test manually
    )
    yield collector
    collector.stop()


@pytest.fixture
def bridge(sandbox_manager, policy_engine, event_logger, telemetry):
    b = SandboxEnforcementBridge(
        sandbox_manager=sandbox_manager,
        policy_engine=policy_engine,
        event_logger=event_logger,
        telemetry=telemetry,
    )
    yield b
    b.deactivate()


# ---------------------------------------------------------------------------
# Test: New EventTypes for sandbox
# ---------------------------------------------------------------------------


class TestSandboxEventTypes:
    @pytest.mark.unit
    def test_sandbox_enforcement_event_type_exists(self):
        assert hasattr(EventType, "SANDBOX_ENFORCEMENT")
        assert EventType.SANDBOX_ENFORCEMENT.value == "sandbox_enforcement"

    @pytest.mark.unit
    def test_sandbox_violation_event_type_exists(self):
        assert hasattr(EventType, "SANDBOX_VIOLATION")
        assert EventType.SANDBOX_VIOLATION.value == "sandbox_violation"

    @pytest.mark.unit
    def test_sandbox_tightened_event_type_exists(self):
        assert hasattr(EventType, "SANDBOX_TIGHTENED")
        assert EventType.SANDBOX_TIGHTENED.value == "sandbox_tightened"

    @pytest.mark.unit
    def test_sandbox_terminated_event_type_exists(self):
        assert hasattr(EventType, "SANDBOX_TERMINATED")
        assert EventType.SANDBOX_TERMINATED.value == "sandbox_terminated"

    @pytest.mark.unit
    def test_sandbox_events_loggable(self, event_logger):
        event_logger.log_event(
            EventType.SANDBOX_ENFORCEMENT,
            "Bridge activated",
            metadata={"mode": 0},
        )
        event_logger.log_event(
            EventType.SANDBOX_VIOLATION,
            "Seccomp kill in sandbox-1",
            metadata={"syscall": "ptrace"},
        )
        event_logger.log_event(
            EventType.SANDBOX_TIGHTENED,
            "Profile tightened: minimal -> airgap",
            metadata={"sandbox_id": "s1"},
        )
        event_logger.log_event(
            EventType.SANDBOX_TERMINATED,
            "Sandbox terminated on LOCKDOWN",
            metadata={"count": 3},
        )

        # Chain must still be valid
        is_valid, error = event_logger.verify_chain()
        assert is_valid, f"Chain broken: {error}"
        assert event_logger.get_event_count() == 4


# ---------------------------------------------------------------------------
# Test: EnforcementBridge lifecycle
# ---------------------------------------------------------------------------


class TestBridgeLifecycle:
    """Test bridge activation, deactivation, and re-activation."""

    @pytest.mark.unit
    def test_activate(self, bridge):
        assert not bridge.is_active
        result = bridge.activate()
        assert result is True
        assert bridge.is_active

    @pytest.mark.unit
    def test_activate_idempotent(self, bridge):
        bridge.activate()
        result = bridge.activate()  # Second activation
        assert result is True
        assert bridge.is_active

    @pytest.mark.unit
    def test_deactivate(self, bridge):
        bridge.activate()
        bridge.deactivate()
        assert not bridge.is_active

    @pytest.mark.unit
    def test_deactivate_when_not_active(self, bridge):
        bridge.deactivate()  # Should not raise
        assert not bridge.is_active

    @pytest.mark.unit
    def test_reactivate_after_deactivate(self, bridge):
        bridge.activate()
        bridge.deactivate()
        result = bridge.activate()
        assert result is True
        assert bridge.is_active

    @pytest.mark.unit
    def test_activate_without_policy_engine(self, sandbox_manager, event_logger):
        bridge = SandboxEnforcementBridge(
            sandbox_manager=sandbox_manager,
            policy_engine=None,
            event_logger=event_logger,
        )
        result = bridge.activate()
        assert result is False
        assert not bridge.is_active

    @pytest.mark.unit
    def test_get_enforcement_status(self, bridge):
        bridge.activate()
        status = bridge.get_enforcement_status()
        assert status["active"] is True
        assert status["mode"] == 0  # OPEN
        assert status["contexts"] == 0
        assert "contexts_by_state" in status

    @pytest.mark.unit
    def test_get_stats(self, bridge):
        bridge.activate()
        stats = bridge.get_stats()
        assert stats["active"] is True
        assert stats["current_mode"] == 0
        assert stats["total_enforcements"] == 0
        assert "by_action" in stats


# ---------------------------------------------------------------------------
# Test: Automatic profile tightening on mode escalation
# ---------------------------------------------------------------------------


class TestModeEscalation:
    @pytest.mark.unit
    def test_escalation_tightens_profile(self, bridge, policy_engine, sandbox_manager):
        """When mode escalates, sandbox profiles should tighten."""
        bridge.activate()

        # Create a sandbox at OPEN (mode=0)
        profile = SandboxProfile.from_boundary_mode(0)
        sandbox = sandbox_manager.create_sandbox(
            name="test-sandbox",
            profile=profile,
            skip_ceremony=True,
        )
        assert sandbox.profile.name == "minimal"

        # Escalate to AIRGAP (mode=3)
        policy_engine.transition_mode(
            BoundaryMode.AIRGAP, Operator.HUMAN, "testing"
        )

        # Sandbox should have been tightened
        assert sandbox.profile.name == "airgap"

    @pytest.mark.unit
    def test_escalation_skips_compliant_sandboxes(
        self, bridge, policy_engine, sandbox_manager
    ):
        bridge.activate()

        # Create a sandbox already at AIRGAP level
        profile = SandboxProfile.from_boundary_mode(3)
        sandbox = sandbox_manager.create_sandbox(
            name="strict-sandbox",
            profile=profile,
            skip_ceremony=True,
        )

        # Escalate to AIRGAP — should be no-op
        result = bridge.on_mode_escalation(0, 3, "testing")
        assert result.action == EnforcementAction.TIGHTEN
        assert result.success is True
        assert sandbox.profile.name == "airgap"  # unchanged

    @pytest.mark.unit
    def test_escalation_records_history(self, bridge, policy_engine, sandbox_manager):
        bridge.activate()

        profile = SandboxProfile.from_boundary_mode(0)
        sandbox_manager.create_sandbox(
            name="history-test", profile=profile, skip_ceremony=True
        )

        policy_engine.transition_mode(
            BoundaryMode.RESTRICTED, Operator.HUMAN, "test escalation"
        )

        history = bridge.get_enforcement_history(limit=10)
        assert len(history) >= 1
        assert history[0].action == EnforcementAction.TIGHTEN

    @pytest.mark.unit
    def test_multi_step_escalation(self, bridge, policy_engine, sandbox_manager):
        bridge.activate()

        profile = SandboxProfile.from_boundary_mode(0)
        sandbox = sandbox_manager.create_sandbox(
            name="multi-step", profile=profile, skip_ceremony=True
        )

        # OPEN -> RESTRICTED
        policy_engine.transition_mode(
            BoundaryMode.RESTRICTED, Operator.HUMAN, "step 1"
        )
        assert sandbox.profile.name == "restricted"

        # RESTRICTED -> TRUSTED
        policy_engine.transition_mode(
            BoundaryMode.TRUSTED, Operator.HUMAN, "step 2"
        )
        assert sandbox.profile.name == "trusted"

        # TRUSTED -> AIRGAP
        policy_engine.transition_mode(
            BoundaryMode.AIRGAP, Operator.HUMAN, "step 3"
        )
        assert sandbox.profile.name == "airgap"


# ---------------------------------------------------------------------------
# Test: Conservative de-escalation (no loosening)
# ---------------------------------------------------------------------------


class TestModeDeescalation:
    @pytest.mark.unit
    def test_deescalation_keeps_strict_profile(
        self, bridge, policy_engine, sandbox_manager
    ):
        bridge.activate()

        # Create sandbox at OPEN
        profile = SandboxProfile.from_boundary_mode(0)
        sandbox = sandbox_manager.create_sandbox(
            name="sticky-sandbox", profile=profile, skip_ceremony=True
        )

        # Escalate to AIRGAP
        policy_engine.transition_mode(
            BoundaryMode.AIRGAP, Operator.HUMAN, "escalate"
        )
        assert sandbox.profile.name == "airgap"

        # De-escalate back to OPEN
        policy_engine.transition_mode(
            BoundaryMode.OPEN, Operator.HUMAN, "de-escalate"
        )

        # Sandbox should still be airgap — NOT loosened
        assert sandbox.profile.name == "airgap"

    @pytest.mark.unit
    def test_deescalation_result_is_no_change(self, bridge):
        result = bridge.on_mode_deescalation(3, 1, "de-escalation")
        assert result.action == EnforcementAction.NO_CHANGE
        assert result.success is True
        assert result.affected_count == 0


# ---------------------------------------------------------------------------
# Test: LOCKDOWN terminates everything
# ---------------------------------------------------------------------------


class TestLockdown:
    @pytest.mark.unit
    def test_lockdown_terminates_sandboxes(
        self, bridge, policy_engine, sandbox_manager
    ):
        bridge.activate()

        # Create some sandboxes
        for i in range(3):
            sandbox_manager.create_sandbox(
                name=f"lockdown-test-{i}",
                profile=SandboxProfile.from_boundary_mode(0),
                skip_ceremony=True,
            )

        assert len(sandbox_manager._sandboxes) == 3

        # Trigger LOCKDOWN
        result = bridge.on_lockdown("emergency")
        assert result.action == EnforcementAction.TERMINATE
        assert result.success is True
        assert result.affected_count == 3

    @pytest.mark.unit
    def test_lockdown_via_mode_transition(
        self, bridge, policy_engine, sandbox_manager
    ):
        bridge.activate()

        sandbox_manager.create_sandbox(
            name="lockdown-via-transition",
            profile=SandboxProfile.from_boundary_mode(0),
            skip_ceremony=True,
        )

        # Transition to LOCKDOWN
        policy_engine.transition_mode(
            BoundaryMode.LOCKDOWN, Operator.HUMAN, "emergency"
        )

        # Bridge should have logged the enforcement
        history = bridge.get_enforcement_history(limit=10)
        assert any(r.action == EnforcementAction.TERMINATE for r in history)

    @pytest.mark.unit
    def test_lockdown_logs_to_hash_chain(
        self, bridge, event_logger, sandbox_manager, policy_engine
    ):
        bridge.activate()

        sandbox_manager.create_sandbox(
            name="chain-test",
            profile=SandboxProfile.from_boundary_mode(0),
            skip_ceremony=True,
        )

        initial_count = event_logger.get_event_count()

        policy_engine.transition_mode(
            BoundaryMode.LOCKDOWN, Operator.HUMAN, "chain test"
        )

        # Should have logged enforcement events
        assert event_logger.get_event_count() > initial_count

        # Chain should still be valid
        is_valid, error = event_logger.verify_chain()
        assert is_valid, f"Chain broken: {error}"


# ---------------------------------------------------------------------------
# Test: Sandbox.tighten_profile()
# ---------------------------------------------------------------------------


class TestSandboxTightenProfile:
    @pytest.mark.unit
    def test_tighten_created_sandbox(self, sandbox_manager):
        """Tightening a CREATED sandbox just swaps the profile."""
        sandbox = sandbox_manager.create_sandbox(
            name="tighten-created",
            profile=SandboxProfile.from_boundary_mode(0),
            skip_ceremony=True,
        )
        assert sandbox.state == SandboxState.CREATED
        assert sandbox.profile.name == "minimal"

        new_profile = SandboxProfile.from_boundary_mode(3)
        result = sandbox.tighten_profile(new_profile, reason="test")
        assert result is True
        assert sandbox.profile.name == "airgap"

    @pytest.mark.unit
    def test_tighten_emits_event(self, sandbox_manager):
        events = []

        def callback(event_type, data):
            events.append((event_type, data))

        manager = SandboxManager(
            policy_engine=sandbox_manager._policy_engine,
            event_callback=callback,
        )

        sandbox = manager.create_sandbox(
            name="event-test",
            profile=SandboxProfile.from_boundary_mode(0),
            skip_ceremony=True,
        )

        sandbox.tighten_profile(
            SandboxProfile.from_boundary_mode(2), reason="event test"
        )

        tighten_events = [e for e in events if e[0] == "sandbox_tightened"]
        assert len(tighten_events) == 1
        assert tighten_events[0][1]["old_profile"] == "minimal"
        assert tighten_events[0][1]["new_profile"] == "trusted"


# ---------------------------------------------------------------------------
# Test: Telemetry
# ---------------------------------------------------------------------------


class TestTelemetry:
    @pytest.mark.unit
    def test_report_seccomp_kill(self, telemetry):
        telemetry.track_sandbox("s1", profile_name="airgap", boundary_mode=3)
        v = telemetry.report_seccomp_kill("s1", syscall_nr=101, syscall_name="ptrace")
        assert v.violation_type == ViolationType.SECCOMP_KILL
        assert v.sandbox_id == "s1"
        assert v.severity == "high"
        assert v.boundary_mode == 3

    @pytest.mark.unit
    def test_report_oom_kill(self, telemetry):
        telemetry.track_sandbox("s2", profile_name="trusted", boundary_mode=2)
        v = telemetry.report_oom_kill("s2", memory_bytes=1024 * 1024 * 512, limit_bytes=1024 * 1024 * 256)
        assert v.violation_type == ViolationType.OOM_KILL
        assert v.metadata["memory_bytes"] == 1024 * 1024 * 512

    @pytest.mark.unit
    def test_report_firewall_block(self, telemetry):
        telemetry.track_sandbox("s3")
        v = telemetry.report_firewall_block("s3", destination="evil.com", port=443)
        assert v.violation_type == ViolationType.FIREWALL_BLOCK
        assert v.metadata["destination"] == "evil.com"

    @pytest.mark.unit
    def test_report_resource_limit(self, telemetry):
        telemetry.track_sandbox("s4")
        v = telemetry.report_resource_limit("s4", "pids", current_value=500, limit_value=500)
        assert v.violation_type == ViolationType.PID_LIMIT

    @pytest.mark.unit
    def test_violation_logged_to_hash_chain(self, telemetry, event_logger):
        initial_count = event_logger.get_event_count()

        telemetry.report_seccomp_kill("chain-test", syscall_name="mount")

        assert event_logger.get_event_count() > initial_count

        is_valid, error = event_logger.verify_chain()
        assert is_valid, f"Chain broken after violation logging: {error}"

    @pytest.mark.unit
    def test_get_violations_filtered(self, telemetry):
        telemetry.track_sandbox("filter-test")
        telemetry.report_seccomp_kill("filter-test", syscall_name="ptrace")
        telemetry.report_oom_kill("filter-test")
        telemetry.report_firewall_block("other-sandbox")

        # Filter by sandbox
        v1 = telemetry.get_violations(sandbox_id="filter-test")
        assert len(v1) == 2

        # Filter by type
        v2 = telemetry.get_violations(violation_type=ViolationType.SECCOMP_KILL)
        assert len(v2) == 1

    @pytest.mark.unit
    def test_get_stats(self, telemetry):
        telemetry.track_sandbox("stats-test")
        telemetry.report_seccomp_kill("stats-test")
        telemetry.report_oom_kill("stats-test")

        stats = telemetry.get_stats()
        assert stats["total_violations"] == 2
        assert stats["tracked_sandboxes"] == 1
        assert "SECCOMP_KILL" in stats["by_type"]
        assert "OOM_KILL" in stats["by_type"]

    @pytest.mark.unit
    def test_violation_callback(self):
        violations = []

        collector = SandboxTelemetryCollector(
            violation_callback=lambda v: violations.append(v),
        )
        collector.report_seccomp_kill("cb-test")

        assert len(violations) == 1
        assert violations[0].violation_type == ViolationType.SECCOMP_KILL

    @pytest.mark.unit
    def test_untrack_sandbox(self, telemetry):
        telemetry.track_sandbox("tracked")
        assert "tracked" in telemetry._tracked
        telemetry.untrack_sandbox("tracked")
        assert "tracked" not in telemetry._tracked


# ---------------------------------------------------------------------------
# Test: EnforcementConsumer protocol
# ---------------------------------------------------------------------------


class TestEnforcementConsumerProtocol:
    @pytest.mark.unit
    def test_bridge_implements_consumer(self, bridge):
        assert isinstance(bridge, EnforcementConsumer)

    @pytest.mark.unit
    def test_consumer_methods_exist(self, bridge):
        assert callable(getattr(bridge, "on_mode_escalation", None))
        assert callable(getattr(bridge, "on_mode_deescalation", None))
        assert callable(getattr(bridge, "on_lockdown", None))
        assert callable(getattr(bridge, "get_enforcement_status", None))


# ---------------------------------------------------------------------------
# Test: SandboxProfile.from_boundary_mode coverage
# ---------------------------------------------------------------------------


class TestProfileBoundaryModeMapping:
    @pytest.mark.unit
    @pytest.mark.parametrize("mode,expected_name", [
        (0, "minimal"),
        (1, "restricted"),
        (2, "trusted"),
        (3, "airgap"),
        (4, "coldroom"),
        (5, "lockdown"),
    ])
    def test_mode_to_profile_mapping(self, mode, expected_name):
        profile = SandboxProfile.from_boundary_mode(mode)
        assert profile.name == expected_name

    @pytest.mark.unit
    def test_strictness_ordering(self):
        profiles = [SandboxProfile.from_boundary_mode(m) for m in range(6)]

        # Network should be disabled at AIRGAP and above
        assert not profiles[0].network_disabled  # OPEN
        assert not profiles[1].network_disabled   # RESTRICTED
        assert not profiles[2].network_disabled   # TRUSTED
        assert profiles[3].network_disabled       # AIRGAP
        assert profiles[4].network_disabled       # COLDROOM
        assert profiles[5].network_disabled       # LOCKDOWN

    @pytest.mark.unit
    def test_lockdown_is_maximally_restrictive(self):
        profile = SandboxProfile.from_boundary_mode(5)
        assert profile.readonly_filesystem is True
        assert profile.network_disabled is True
        assert profile.max_processes == 1
        assert profile.max_runtime_seconds == 1


# ---------------------------------------------------------------------------
# Test: Hash chain integrity across enforcement events
# ---------------------------------------------------------------------------


class TestHashChainIntegrity:
    @pytest.mark.unit
    def test_chain_valid_after_full_lifecycle(
        self, bridge, policy_engine, sandbox_manager, event_logger
    ):
        """
        Full lifecycle: create sandbox, escalate, tighten, lockdown, verify chain.
        """
        bridge.activate()

        # Create sandboxes
        for i in range(3):
            sandbox_manager.create_sandbox(
                name=f"chain-lifecycle-{i}",
                profile=SandboxProfile.from_boundary_mode(0),
                skip_ceremony=True,
            )

        # Escalate through modes
        policy_engine.transition_mode(
            BoundaryMode.RESTRICTED, Operator.HUMAN, "step 1"
        )
        policy_engine.transition_mode(
            BoundaryMode.AIRGAP, Operator.HUMAN, "step 2"
        )
        policy_engine.transition_mode(
            BoundaryMode.LOCKDOWN, Operator.HUMAN, "emergency"
        )

        # Verify the chain is intact
        is_valid, error = event_logger.verify_chain()
        assert is_valid, f"Hash chain broken: {error}"

        # Should have multiple events (bridge activation + mode transitions)
        assert event_logger.get_event_count() >= 5


# ---------------------------------------------------------------------------
# Test: Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and error conditions."""

    @pytest.mark.unit
    def test_escalation_with_no_sandboxes(self, bridge):
        bridge.activate()
        result = bridge.on_mode_escalation(0, 3, "no sandboxes")
        assert result.success is True
        assert result.affected_count == 0

    @pytest.mark.unit
    def test_lockdown_with_no_sandboxes(self, bridge):
        bridge.activate()
        result = bridge.on_lockdown("no sandboxes")
        assert result.success is True
        assert result.affected_count == 0

    @pytest.mark.unit
    def test_same_mode_transition_ignored(
        self, bridge, policy_engine, sandbox_manager
    ):
        bridge.activate()

        sandbox_manager.create_sandbox(
            name="same-mode",
            profile=SandboxProfile.from_boundary_mode(0),
            skip_ceremony=True,
        )

        initial_history_len = len(bridge.get_enforcement_history())

        # Transition to same mode — _on_mode_transition should return early
        # We have to call it directly since PolicyEngine changes the mode
        bridge._on_mode_transition(
            BoundaryMode.OPEN, BoundaryMode.OPEN, Operator.HUMAN, "no-op"
        )

        # No new enforcement actions
        assert len(bridge.get_enforcement_history()) == initial_history_len

    @pytest.mark.unit
    def test_enforcement_history_limit(self, bridge):
        bridge._max_history = 5
        bridge.activate()

        for i in range(10):
            bridge.on_mode_escalation(i, i + 1, f"test-{i}")

        assert len(bridge._enforcement_history) <= 5

    @pytest.mark.unit
    def test_telemetry_max_violations(self):
        collector = SandboxTelemetryCollector()
        collector._max_violations = 5

        for i in range(10):
            collector.report_seccomp_kill(f"overflow-{i}")

        assert len(collector._violations) <= 5
        assert collector._violation_count == 10  # Total count still tracked

    @pytest.mark.unit
    def test_bridge_without_event_logger(self, sandbox_manager, policy_engine):
        """Bridge should work (with reduced logging) without event logger."""
        bridge = SandboxEnforcementBridge(
            sandbox_manager=sandbox_manager,
            policy_engine=policy_engine,
            event_logger=None,  # No event logger
        )
        bridge.activate()

        result = bridge.on_mode_escalation(0, 3, "no logger")
        assert result.success is True

        bridge.deactivate()

    @pytest.mark.unit
    def test_telemetry_without_event_logger(self):
        """Telemetry should work without event logger (local recording only)."""
        collector = SandboxTelemetryCollector(event_logger=None)
        v = collector.report_seccomp_kill("no-logger")
        assert v.violation_type == ViolationType.SECCOMP_KILL
        assert collector._violation_count == 1


# ---------------------------------------------------------------------------
# Test: SandboxManager integration
# ---------------------------------------------------------------------------


class TestSandboxManagerIntegration:
    @pytest.mark.unit
    def test_set_enforcement_bridge(self, sandbox_manager, bridge):
        sandbox_manager.set_enforcement_bridge(bridge)
        assert sandbox_manager._enforcement_bridge is bridge

    @pytest.mark.unit
    def test_set_telemetry(self, sandbox_manager, telemetry):
        sandbox_manager.set_telemetry(telemetry)
        assert sandbox_manager._telemetry is telemetry

    @pytest.mark.unit
    def test_stats_include_bridge(self, sandbox_manager, bridge):
        sandbox_manager.set_enforcement_bridge(bridge)
        bridge.activate()

        stats = sandbox_manager.get_stats()
        assert "enforcement_bridge" in stats
        assert stats["enforcement_bridge"]["active"] is True

    @pytest.mark.unit
    def test_stats_include_telemetry(self, sandbox_manager, telemetry):
        sandbox_manager.set_telemetry(telemetry)

        stats = sandbox_manager.get_stats()
        assert "telemetry" in stats
        assert "total_violations" in stats["telemetry"]

    @pytest.mark.unit
    def test_create_sandbox_registers_telemetry(self, sandbox_manager, telemetry):
        sandbox_manager.set_telemetry(telemetry)

        sandbox_manager.create_sandbox(
            name="telemetry-reg",
            profile=SandboxProfile.from_boundary_mode(0),
            skip_ceremony=True,
        )

        assert "telemetry-reg" in telemetry._tracked


# ---------------------------------------------------------------------------
# PARAMETRIZED TESTS - Added for comprehensive coverage
# ---------------------------------------------------------------------------


class TestParametrizedEnforcementActionValues:
    """Parametrized: All EnforcementAction enum members."""

    ACTION_VALUES = [
        (EnforcementAction.TIGHTEN, 1),
        (EnforcementAction.LOOSEN, 2),
        (EnforcementAction.TERMINATE, 3),
        (EnforcementAction.NO_CHANGE, 4),
        (EnforcementAction.FAILED, 5),
    ]

    @pytest.mark.unit
    @pytest.mark.parametrize("action,expected_value", ACTION_VALUES,
        ids=[a.name for a, _ in ACTION_VALUES])
    def test_action_value(self, action, expected_value):
        """Each EnforcementAction should have its expected int value."""
        assert action.value == expected_value


class TestParametrizedModeToProfileMapping:
    """Parametrized: Every BoundaryMode maps to a named sandbox profile."""

    PROFILE_MAP = [
        (0, "minimal"),
        (1, "restricted"),
        (2, "trusted"),
        (3, "airgap"),
        (4, "coldroom"),
        (5, "lockdown"),
    ]

    @pytest.mark.unit
    @pytest.mark.parametrize("mode,profile_name", PROFILE_MAP,
        ids=[f"mode{m}->{p}" for m, p in PROFILE_MAP])
    def test_mode_profile(self, mode, profile_name):
        """SandboxProfile.from_boundary_mode returns correct profile name."""
        profile = SandboxProfile.from_boundary_mode(mode)
        assert profile.name == profile_name


class TestParametrizedEscalationTightensToTarget:
    """Parametrized: Mode escalation tightens sandbox profiles to target mode."""

    ESCALATION_CASES = [
        (0, 1, "restricted"),
        (0, 2, "trusted"),
        (0, 3, "airgap"),
        (0, 4, "coldroom"),
        (1, 3, "airgap"),
        (2, 4, "coldroom"),
    ]

    @pytest.mark.unit
    @pytest.mark.parametrize("from_mode,to_mode,expected_profile", ESCALATION_CASES,
        ids=[f"{f}->{t}" for f, t, _ in ESCALATION_CASES])
    def test_escalation_profile(self, from_mode, to_mode, expected_profile,
                                 bridge, sandbox_manager):
        """Sandbox profile should be tightened to match target mode."""
        bridge.activate()
        profile = SandboxProfile.from_boundary_mode(from_mode)
        sandbox = sandbox_manager.create_sandbox(
            name=f"esc-{from_mode}-{to_mode}",
            profile=profile,
            skip_ceremony=True,
        )
        bridge.on_mode_escalation(from_mode, to_mode, "test")
        assert sandbox.profile.name == expected_profile


class TestParametrizedDeescalationPreservesProfile:
    """Parametrized: De-escalation always returns NO_CHANGE."""

    DEESCALATION_CASES = [
        (3, 0),
        (3, 1),
        (3, 2),
        (4, 0),
        (4, 1),
        (2, 0),
    ]

    @pytest.mark.unit
    @pytest.mark.parametrize("from_mode,to_mode", DEESCALATION_CASES,
        ids=[f"{f}->{t}" for f, t in DEESCALATION_CASES])
    def test_deescalation_no_change(self, from_mode, to_mode, bridge):
        """De-escalation should always return NO_CHANGE."""
        bridge.activate()
        result = bridge.on_mode_deescalation(from_mode, to_mode, "de-esc")
        assert result.action == EnforcementAction.NO_CHANGE
        assert result.success is True
        assert result.affected_count == 0


class TestParametrizedLockdownProfileProperties:
    """Parametrized: LOCKDOWN profile properties are maximally restrictive."""

    LOCKDOWN_CHECKS = [
        ("readonly_filesystem", True),
        ("network_disabled", True),
        ("max_processes", 1),
        ("max_runtime_seconds", 1),
    ]

    @pytest.mark.unit
    @pytest.mark.parametrize("attr,expected", LOCKDOWN_CHECKS,
        ids=[a for a, _ in LOCKDOWN_CHECKS])
    def test_lockdown_profile_property(self, attr, expected):
        """LOCKDOWN profile attributes should be maximally restrictive."""
        profile = SandboxProfile.from_boundary_mode(5)
        assert getattr(profile, attr) == expected


class TestParametrizedNetworkDisabledByMode:
    """Parametrized: Network disabled at AIRGAP and above."""

    NETWORK_CASES = [
        (0, False),  # OPEN
        (1, False),  # RESTRICTED
        (2, False),  # TRUSTED
        (3, True),   # AIRGAP
        (4, True),   # COLDROOM
        (5, True),   # LOCKDOWN
    ]

    @pytest.mark.unit
    @pytest.mark.parametrize("mode,expected_disabled", NETWORK_CASES,
        ids=[f"mode{m}" for m, _ in NETWORK_CASES])
    def test_network_disabled(self, mode, expected_disabled):
        """Network should be disabled at AIRGAP and above."""
        profile = SandboxProfile.from_boundary_mode(mode)
        assert profile.network_disabled == expected_disabled


class TestParametrizedTelemetryViolationTypes:
    """Parametrized: Telemetry violation reporting for all types."""

    @pytest.mark.unit
    @pytest.mark.parametrize("vtype", list(ViolationType),
        ids=[v.name for v in ViolationType])
    def test_violation_type_has_value(self, vtype):
        """Each ViolationType should have a positive int value."""
        assert isinstance(vtype.value, int)
        assert vtype.value > 0


class TestParametrizedBridgeEscalationWithNoSandboxes:
    """Parametrized: Escalation with no sandboxes succeeds for any target mode."""

    @pytest.mark.unit
    @pytest.mark.parametrize("target_mode", [1, 2, 3, 4, 5],
        ids=[f"mode{m}" for m in [1, 2, 3, 4, 5]])
    def test_escalation_no_sandboxes(self, target_mode, bridge):
        """Escalation with no sandboxes should succeed with 0 affected."""
        bridge.activate()
        result = bridge.on_mode_escalation(0, target_mode, "test")
        assert result.success is True
        assert result.affected_count == 0
