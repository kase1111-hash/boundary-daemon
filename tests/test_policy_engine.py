"""
Tests for daemon/policy_engine.py - Boundary Mode and Policy Enforcement

Tests cover:
- Boundary mode transitions
- Policy evaluation for different request types
- Memory class to mode mapping
- Environment compatibility checks
- Thread safety
- Edge cases and error handling
"""

import os
import sys
import threading
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.policy_engine import (
    PolicyEngine, BoundaryMode, BoundaryState, PolicyRequest,
    PolicyDecision, MemoryClass, Operator
)
from daemon.state_monitor import (
    NetworkState, HardwareTrust, EnvironmentState, SpecialtyNetworkStatus
)


@pytest.fixture
def mock_env_state() -> EnvironmentState:
    return EnvironmentState(
        timestamp=datetime.utcnow().isoformat() + "Z",
        network=NetworkState.OFFLINE,
        hardware_trust=HardwareTrust.HIGH,
        active_interfaces=[],
        interface_types={},
        has_internet=False,
        vpn_active=False,
        dns_available=False,
        specialty_networks=SpecialtyNetworkStatus(
            lora_devices=[],
            thread_devices=[],
            wimax_interfaces=[],
            irda_devices=[],
            ant_plus_devices=[],
            cellular_alerts=[]
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
        tpm_present=True,
        external_model_endpoints=[],
        suspicious_processes=[],
        shell_escapes_detected=0,
        keyboard_active=True,
        screen_unlocked=True,
        last_activity=None
    )


@pytest.fixture
def online_env_state(mock_env_state) -> EnvironmentState:
    mock_env_state.network = NetworkState.ONLINE
    mock_env_state.has_internet = True
    mock_env_state.active_interfaces = ['eth0']
    return mock_env_state


@pytest.fixture
def vpn_env_state(mock_env_state) -> EnvironmentState:
    mock_env_state.network = NetworkState.ONLINE
    mock_env_state.has_internet = True
    mock_env_state.vpn_active = True
    mock_env_state.active_interfaces = ['tun0', 'eth0']
    return mock_env_state


class TestBoundaryMode:
    @pytest.mark.unit
    def test_mode_ordering(self):
        assert BoundaryMode.OPEN < BoundaryMode.RESTRICTED
        assert BoundaryMode.RESTRICTED < BoundaryMode.TRUSTED
        assert BoundaryMode.TRUSTED < BoundaryMode.AIRGAP
        assert BoundaryMode.AIRGAP < BoundaryMode.COLDROOM
        assert BoundaryMode.COLDROOM < BoundaryMode.LOCKDOWN

    @pytest.mark.unit
    def test_mode_values(self):
        assert BoundaryMode.OPEN.value == 0
        assert BoundaryMode.RESTRICTED.value == 1
        assert BoundaryMode.TRUSTED.value == 2
        assert BoundaryMode.AIRGAP.value == 3
        assert BoundaryMode.COLDROOM.value == 4
        assert BoundaryMode.LOCKDOWN.value == 5


class TestPolicyEngineInitialization:
    @pytest.mark.unit
    def test_default_initialization(self):
        engine = PolicyEngine()
        assert engine.get_current_mode() == BoundaryMode.OPEN

    @pytest.mark.unit
    def test_custom_initial_mode(self):
        engine = PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)
        assert engine.get_current_mode() == BoundaryMode.RESTRICTED

    @pytest.mark.unit
    def test_get_current_state(self, policy_engine):
        state = policy_engine.get_current_state()
        assert isinstance(state, BoundaryState)
        assert state.mode == BoundaryMode.OPEN
        assert isinstance(state.network, NetworkState)
        assert isinstance(state.hardware_trust, HardwareTrust)


class TestModeTransitions:
    @pytest.mark.unit
    def test_transition_success(self, policy_engine):
        success, msg = policy_engine.transition_mode(
            BoundaryMode.RESTRICTED,
            Operator.HUMAN,
            "Manual upgrade"
        )
        assert success is True
        assert policy_engine.get_current_mode() == BoundaryMode.RESTRICTED
        assert "RESTRICTED" in msg

    @pytest.mark.unit
    def test_transition_callback(self, policy_engine):
        callback_calls = []

        def callback(old_mode, new_mode, operator, reason):
            callback_calls.append((old_mode, new_mode, operator, reason))

        policy_engine.register_transition_callback(callback)
        policy_engine.transition_mode(
            BoundaryMode.TRUSTED,
            Operator.SYSTEM,
            "Auto-upgrade"
        )

        assert len(callback_calls) == 1
        assert callback_calls[0][0] == BoundaryMode.OPEN
        assert callback_calls[0][1] == BoundaryMode.TRUSTED
        assert callback_calls[0][2] == Operator.SYSTEM

    @pytest.mark.unit
    def test_lockdown_exit_requires_human(self, policy_engine_lockdown):
        success, msg = policy_engine_lockdown.transition_mode(
            BoundaryMode.OPEN,
            Operator.SYSTEM,
            "System recovery"
        )
        assert success is False
        assert "human" in msg.lower()
        assert policy_engine_lockdown.get_current_mode() == BoundaryMode.LOCKDOWN

    @pytest.mark.unit
    def test_lockdown_exit_with_human(self, policy_engine_lockdown):
        success, msg = policy_engine_lockdown.transition_mode(
            BoundaryMode.OPEN,
            Operator.HUMAN,
            "Manual recovery"
        )
        assert success is True
        assert policy_engine_lockdown.get_current_mode() == BoundaryMode.OPEN

    @pytest.mark.unit
    def test_transition_all_modes(self, policy_engine):
        modes = [
            BoundaryMode.RESTRICTED,
            BoundaryMode.TRUSTED,
            BoundaryMode.AIRGAP,
            BoundaryMode.COLDROOM,
            BoundaryMode.LOCKDOWN,
            BoundaryMode.OPEN,  # Back to open (requires human)
        ]

        for mode in modes:
            success, _ = policy_engine.transition_mode(
                mode,
                Operator.HUMAN,  # Human to allow LOCKDOWN exit
                f"Transition to {mode.name}"
            )
            assert success is True
            assert policy_engine.get_current_mode() == mode


class TestMemoryRecallPolicy:
    @pytest.mark.unit
    def test_public_memory_in_open_mode(self, policy_engine, mock_env_state):
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.PUBLIC
        )
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_confidential_memory_denied_in_open(self, policy_engine, mock_env_state):
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.CONFIDENTIAL
        )
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_confidential_memory_allowed_in_restricted(
        self, policy_engine_restricted, mock_env_state
    ):
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.CONFIDENTIAL
        )
        decision = policy_engine_restricted.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_secret_memory_requires_trusted(self, policy_engine, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.SECRET
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_top_secret_requires_airgap(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.TOP_SECRET
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_crown_jewel_requires_coldroom(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.CROWN_JEWEL
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_recall_with_none_memory_class(self, policy_engine, mock_env_state):
        request = PolicyRequest(
            request_type='recall',
            memory_class=None
        )
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_all_memory_denied_in_lockdown(self, policy_engine_lockdown, mock_env_state):
        for mem_class in MemoryClass:
            request = PolicyRequest(
                request_type='recall',
                memory_class=mem_class
            )
            decision = policy_engine_lockdown.evaluate_policy(request, mock_env_state)
            assert decision == PolicyDecision.DENY


class TestToolPolicy:
    @pytest.mark.unit
    def test_basic_tool_allowed_in_open(self, policy_engine, mock_env_state):
        request = PolicyRequest(
            request_type='tool',
            tool_name='file_read',
            requires_network=False,
            requires_filesystem=True
        )
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_network_tool_denied_in_airgap(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='tool',
            tool_name='http_request',
            requires_network=True
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_usb_tool_denied_in_airgap(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='tool',
            tool_name='usb_read',
            requires_usb=True
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_filesystem_allowed_in_airgap(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='tool',
            tool_name='file_write',
            requires_filesystem=True
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_all_io_denied_in_coldroom(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)

        # Network
        request = PolicyRequest(request_type='tool', requires_network=True)
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

        # Filesystem
        request = PolicyRequest(request_type='tool', requires_filesystem=True)
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

        # USB
        request = PolicyRequest(request_type='tool', requires_usb=True)
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

    @pytest.mark.unit
    def test_usb_requires_ceremony_in_restricted(
        self, policy_engine_restricted, mock_env_state
    ):
        request = PolicyRequest(
            request_type='tool',
            tool_name='usb_write',
            requires_usb=True
        )
        decision = policy_engine_restricted.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.REQUIRE_CEREMONY

    @pytest.mark.unit
    def test_network_tool_in_trusted_offline(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
        mock_env_state.network = NetworkState.OFFLINE

        request = PolicyRequest(
            request_type='tool',
            tool_name='http_request',
            requires_network=True
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_network_tool_in_trusted_with_vpn(self, vpn_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)

        request = PolicyRequest(
            request_type='tool',
            tool_name='http_request',
            requires_network=True
        )
        decision = engine.evaluate_policy(request, vpn_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_network_tool_in_trusted_without_vpn(self, online_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)

        request = PolicyRequest(
            request_type='tool',
            tool_name='http_request',
            requires_network=True
        )
        decision = engine.evaluate_policy(request, online_env_state)
        assert decision == PolicyDecision.DENY


class TestModelPolicy:
    @pytest.mark.unit
    def test_model_allowed_in_open_online(self, policy_engine, online_env_state):
        request = PolicyRequest(request_type='model')
        decision = policy_engine.evaluate_policy(request, online_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_model_denied_in_open_offline(self, policy_engine, mock_env_state):
        request = PolicyRequest(request_type='model')
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_model_denied_in_airgap(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(request_type='model')
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_model_denied_in_coldroom(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(request_type='model')
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY


class TestIOPolicy:
    @pytest.mark.unit
    def test_filesystem_denied_in_coldroom(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(
            request_type='io',
            requires_filesystem=True
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_network_denied_in_airgap(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='io',
            requires_network=True
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_io_allowed_in_open(self, policy_engine, mock_env_state):
        request = PolicyRequest(
            request_type='io',
            requires_network=True,
            requires_filesystem=True
        )
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW


class TestUnknownRequests:
    @pytest.mark.unit
    def test_unknown_request_type_denied(self, policy_engine, mock_env_state):
        """Test that unknown request types are denied (fail-closed)."""
        request = PolicyRequest(request_type='unknown')
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_invalid_request_type_denied(self, policy_engine, mock_env_state):
        request = PolicyRequest(request_type='')
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY


class TestMinimumModeForMemory:
    @pytest.mark.unit
    def test_public_minimum_mode(self, policy_engine):
        mode = policy_engine.get_minimum_mode_for_memory(MemoryClass.PUBLIC)
        assert mode == BoundaryMode.OPEN

    @pytest.mark.unit
    def test_internal_minimum_mode(self, policy_engine):
        mode = policy_engine.get_minimum_mode_for_memory(MemoryClass.INTERNAL)
        assert mode == BoundaryMode.OPEN

    @pytest.mark.unit
    def test_confidential_minimum_mode(self, policy_engine):
        mode = policy_engine.get_minimum_mode_for_memory(MemoryClass.CONFIDENTIAL)
        assert mode == BoundaryMode.RESTRICTED

    @pytest.mark.unit
    def test_secret_minimum_mode(self, policy_engine):
        mode = policy_engine.get_minimum_mode_for_memory(MemoryClass.SECRET)
        assert mode == BoundaryMode.TRUSTED

    @pytest.mark.unit
    def test_top_secret_minimum_mode(self, policy_engine):
        mode = policy_engine.get_minimum_mode_for_memory(MemoryClass.TOP_SECRET)
        assert mode == BoundaryMode.AIRGAP

    @pytest.mark.unit
    def test_crown_jewel_minimum_mode(self, policy_engine):
        mode = policy_engine.get_minimum_mode_for_memory(MemoryClass.CROWN_JEWEL)
        assert mode == BoundaryMode.COLDROOM


class TestEnvironmentCompatibility:
    @pytest.mark.unit
    def test_airgap_compatible_offline(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        is_compatible, violation = engine.check_mode_environment_compatibility(
            mock_env_state
        )
        assert is_compatible is True
        assert violation is None

    @pytest.mark.unit
    def test_airgap_incompatible_online(self, online_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        is_compatible, violation = engine.check_mode_environment_compatibility(
            online_env_state
        )
        assert is_compatible is False
        assert "Network came online" in violation

    @pytest.mark.unit
    def test_open_mode_always_compatible(self, policy_engine, online_env_state):
        is_compatible, violation = policy_engine.check_mode_environment_compatibility(
            online_env_state
        )
        assert is_compatible is True


class TestThreadSafety:
    @pytest.mark.unit
    def test_concurrent_policy_evaluation(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        results = []

        def evaluate():
            for _ in range(50):
                request = PolicyRequest(
                    request_type='recall',
                    memory_class=MemoryClass.PUBLIC
                )
                decision = engine.evaluate_policy(request, mock_env_state)
                results.append(decision)

        threads = [threading.Thread(target=evaluate) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should be ALLOW
        assert len(results) == 500
        assert all(d == PolicyDecision.ALLOW for d in results)

    @pytest.mark.unit
    def test_concurrent_mode_transitions(self):
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        transition_results = []

        def transition_loop():
            for mode in [BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED,
                        BoundaryMode.OPEN]:
                success, _ = engine.transition_mode(mode, Operator.HUMAN, "test")
                transition_results.append(success)

        threads = [threading.Thread(target=transition_loop) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All transitions should succeed
        assert len(transition_results) == 15
        assert all(r is True for r in transition_results)


class TestBoundaryStateToDict:
    @pytest.mark.unit
    def test_state_to_dict(self, policy_engine):
        state = policy_engine.get_current_state()
        d = state.to_dict()

        assert d['mode'] == 'open'
        assert 'network' in d
        assert 'hardware_trust' in d
        assert 'last_transition' in d
        assert 'operator' in d


class TestToolPolicyMultiIO:
    @pytest.mark.unit
    def test_network_and_filesystem_denied_in_coldroom(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(
            request_type='tool',
            requires_network=True,
            requires_filesystem=True,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

    @pytest.mark.unit
    def test_network_and_usb_denied_in_coldroom(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(
            request_type='tool',
            requires_network=True,
            requires_usb=True,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

    @pytest.mark.unit
    def test_all_three_io_denied_in_coldroom(self, mock_env_state):
        """COLDROOM should deny tool requiring network + filesystem + USB."""
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(
            request_type='tool',
            requires_network=True,
            requires_filesystem=True,
            requires_usb=True,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

    @pytest.mark.unit
    def test_no_io_allowed_in_coldroom(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(
            request_type='tool',
            tool_name='display_message',
            requires_network=False,
            requires_filesystem=False,
            requires_usb=False,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_network_and_usb_denied_in_airgap(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='tool',
            requires_network=True,
            requires_usb=True,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

    @pytest.mark.unit
    def test_filesystem_and_usb_denied_in_airgap(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='tool',
            requires_filesystem=True,
            requires_usb=True,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

    @pytest.mark.unit
    def test_filesystem_only_allowed_in_airgap(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(
            request_type='tool',
            requires_filesystem=True,
            requires_network=False,
            requires_usb=False,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_network_and_filesystem_denied_in_trusted_online_no_vpn(
        self, online_env_state
    ):
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
        request = PolicyRequest(
            request_type='tool',
            requires_network=True,
            requires_filesystem=True,
        )
        assert engine.evaluate_policy(request, online_env_state) == PolicyDecision.DENY

    @pytest.mark.unit
    def test_network_and_filesystem_allowed_in_trusted_with_vpn(
        self, vpn_env_state
    ):
        """TRUSTED with VPN should allow tools requiring network + filesystem."""
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
        request = PolicyRequest(
            request_type='tool',
            requires_network=True,
            requires_filesystem=True,
        )
        assert engine.evaluate_policy(request, vpn_env_state) == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_all_io_allowed_in_open(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        request = PolicyRequest(
            request_type='tool',
            requires_network=True,
            requires_filesystem=True,
            requires_usb=True,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_usb_and_filesystem_ceremony_in_restricted(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)
        request = PolicyRequest(
            request_type='tool',
            requires_usb=True,
            requires_filesystem=True,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.REQUIRE_CEREMONY


class TestLockdownDeniesAll:
    """LOCKDOWN mode must deny every request type — this is the fail-deadly guarantee."""

    @pytest.mark.security
    def test_lockdown_denies_recall(self, mock_env_state):
        """LOCKDOWN denies all recall requests regardless of memory class."""
        engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
        for mem_class in MemoryClass:
            request = PolicyRequest(request_type='recall', memory_class=mem_class)
            decision = engine.evaluate_policy(request, mock_env_state)
            assert decision == PolicyDecision.DENY, (
                f"LOCKDOWN should deny recall of {mem_class.name}"
            )

    @pytest.mark.security
    def test_lockdown_denies_tool_no_io(self, mock_env_state):
        """LOCKDOWN denies tool requests even with no IO requirements."""
        engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
        request = PolicyRequest(request_type='tool', tool_name='display')
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

    @pytest.mark.security
    def test_lockdown_denies_tool_with_io(self, mock_env_state):
        """LOCKDOWN denies tool requests with IO requirements."""
        engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
        request = PolicyRequest(
            request_type='tool',
            requires_network=True,
            requires_filesystem=True,
            requires_usb=True,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

    @pytest.mark.security
    def test_lockdown_denies_model(self, online_env_state):
        """LOCKDOWN denies model access even when online."""
        engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
        request = PolicyRequest(request_type='model')
        assert engine.evaluate_policy(request, online_env_state) == PolicyDecision.DENY

    @pytest.mark.security
    def test_lockdown_denies_io(self, mock_env_state):
        """LOCKDOWN denies IO requests."""
        engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
        request = PolicyRequest(request_type='io', requires_filesystem=True)
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

    @pytest.mark.security
    def test_lockdown_denies_unknown(self, mock_env_state):
        """LOCKDOWN denies unknown request types."""
        engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
        request = PolicyRequest(request_type='something_new')
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY


class TestModelPolicyGaps:
    @pytest.mark.unit
    def test_model_in_restricted_online(self, online_env_state):
        """RESTRICTED online should allow model access (mode <= RESTRICTED and online)."""
        engine = PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)
        request = PolicyRequest(request_type='model')
        decision = engine.evaluate_policy(request, online_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_model_in_restricted_offline(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)
        request = PolicyRequest(request_type='model')
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_model_in_trusted_online_with_vpn(self, vpn_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
        request = PolicyRequest(request_type='model')
        decision = engine.evaluate_policy(request, vpn_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_model_in_trusted_online_no_vpn(self, online_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
        request = PolicyRequest(request_type='model')
        decision = engine.evaluate_policy(request, online_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_model_in_trusted_offline_denied(self, mock_env_state):
        """TRUSTED offline should DENY model access (can't reach external models offline).

        SECURITY: External model access requires network connectivity.
        Offline state cannot reach external models regardless of trust level.
        Only VPN-connected TRUSTED mode should allow external model access.
        """
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
        request = PolicyRequest(request_type='model')
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.unit
    def test_model_in_coldroom(self, mock_env_state):
        """COLDROOM should deny model access (mode >= AIRGAP)."""
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(request_type='model')
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY


class TestIOPolicyGaps:
    @pytest.mark.unit
    def test_usb_denied_in_airgap(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(request_type='io', requires_usb=True)
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY

    @pytest.mark.unit
    def test_filesystem_allowed_in_airgap(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
        request = PolicyRequest(request_type='io', requires_filesystem=True)
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_no_io_allowed_in_coldroom(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(request_type='io')
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_network_io_allowed_in_trusted(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
        request = PolicyRequest(request_type='io', requires_network=True)
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.ALLOW

    @pytest.mark.unit
    def test_all_io_allowed_in_open(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        request = PolicyRequest(
            request_type='io',
            requires_network=True,
            requires_filesystem=True,
            requires_usb=True,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.ALLOW


class TestUpdateEnvironment:
    @pytest.mark.unit
    def test_update_environment_sets_network(self, policy_engine, mock_env_state):
        mock_env_state.network = NetworkState.ONLINE
        policy_engine.update_environment(mock_env_state)
        state = policy_engine.get_current_state()
        assert state.network == NetworkState.ONLINE

    @pytest.mark.unit
    def test_update_environment_sets_hardware_trust(self, policy_engine, mock_env_state):
        mock_env_state.hardware_trust = HardwareTrust.LOW
        policy_engine.update_environment(mock_env_state)
        state = policy_engine.get_current_state()
        assert state.hardware_trust == HardwareTrust.LOW

    @pytest.mark.unit
    def test_update_environment_sets_external_models(self, policy_engine, mock_env_state):
        mock_env_state.external_model_endpoints = ['api.openai.com']
        policy_engine.update_environment(mock_env_state)
        state = policy_engine.get_current_state()
        assert state.external_models is True

    @pytest.mark.unit
    def test_update_environment_clears_external_models(self, policy_engine, mock_env_state):
        mock_env_state.external_model_endpoints = []
        policy_engine.update_environment(mock_env_state)
        state = policy_engine.get_current_state()
        assert state.external_models is False

    @pytest.mark.unit
    def test_update_environment_does_not_change_mode(self, policy_engine, mock_env_state):
        policy_engine.transition_mode(BoundaryMode.AIRGAP, Operator.HUMAN, "test")
        mock_env_state.network = NetworkState.ONLINE
        policy_engine.update_environment(mock_env_state)
        assert policy_engine.get_current_mode() == BoundaryMode.AIRGAP


class TestCallbackManagement:
    @pytest.mark.unit
    def test_unregister_callback(self, policy_engine):
        calls = []
        cb_id = policy_engine.register_transition_callback(
            lambda old, new, op, reason: calls.append(1)
        )
        policy_engine.unregister_transition_callback(cb_id)
        policy_engine.transition_mode(BoundaryMode.RESTRICTED, Operator.HUMAN, "test")
        assert len(calls) == 0

    @pytest.mark.unit
    def test_unregister_invalid_id_returns_false(self, policy_engine):
        assert policy_engine.unregister_transition_callback(9999) is False

    @pytest.mark.unit
    def test_cleanup_clears_callbacks(self, policy_engine):
        policy_engine.register_transition_callback(lambda *args: None)
        policy_engine.register_transition_callback(lambda *args: None)
        policy_engine.cleanup()
        assert len(policy_engine._transition_callbacks) == 0

    @pytest.mark.unit
    def test_callback_error_isolation(self, policy_engine):
        calls = []

        def bad_callback(old, new, op, reason):
            raise RuntimeError("boom")

        def good_callback(old, new, op, reason):
            calls.append((old, new))

        policy_engine.register_transition_callback(bad_callback)
        policy_engine.register_transition_callback(good_callback)
        policy_engine.transition_mode(BoundaryMode.RESTRICTED, Operator.HUMAN, "test")
        assert len(calls) == 1


class TestRecallPolicyTruthTable:
    """Exhaustive test of the recall policy decision matrix.

    Security invariant: MemoryClass(N) requires BoundaryMode >= required_mode(N).
    This truth table documents every combination so any change to the mapping
    breaks a test with an obvious name.
    """

    # Expected decision for (mode, memory_class) → ALLOW or DENY
    # Format: (BoundaryMode, MemoryClass, expected_decision)
    TRUTH_TABLE = [
        # PUBLIC (required: OPEN) — accessible in any mode
        (BoundaryMode.OPEN, MemoryClass.PUBLIC, PolicyDecision.ALLOW),
        (BoundaryMode.RESTRICTED, MemoryClass.PUBLIC, PolicyDecision.ALLOW),
        (BoundaryMode.TRUSTED, MemoryClass.PUBLIC, PolicyDecision.ALLOW),
        (BoundaryMode.AIRGAP, MemoryClass.PUBLIC, PolicyDecision.ALLOW),
        (BoundaryMode.COLDROOM, MemoryClass.PUBLIC, PolicyDecision.ALLOW),
        # INTERNAL (required: OPEN) — same as PUBLIC
        (BoundaryMode.OPEN, MemoryClass.INTERNAL, PolicyDecision.ALLOW),
        (BoundaryMode.RESTRICTED, MemoryClass.INTERNAL, PolicyDecision.ALLOW),
        (BoundaryMode.TRUSTED, MemoryClass.INTERNAL, PolicyDecision.ALLOW),
        (BoundaryMode.AIRGAP, MemoryClass.INTERNAL, PolicyDecision.ALLOW),
        (BoundaryMode.COLDROOM, MemoryClass.INTERNAL, PolicyDecision.ALLOW),
        # CONFIDENTIAL (required: RESTRICTED)
        (BoundaryMode.OPEN, MemoryClass.CONFIDENTIAL, PolicyDecision.DENY),
        (BoundaryMode.RESTRICTED, MemoryClass.CONFIDENTIAL, PolicyDecision.ALLOW),
        (BoundaryMode.TRUSTED, MemoryClass.CONFIDENTIAL, PolicyDecision.ALLOW),
        (BoundaryMode.AIRGAP, MemoryClass.CONFIDENTIAL, PolicyDecision.ALLOW),
        (BoundaryMode.COLDROOM, MemoryClass.CONFIDENTIAL, PolicyDecision.ALLOW),
        # SECRET (required: TRUSTED)
        (BoundaryMode.OPEN, MemoryClass.SECRET, PolicyDecision.DENY),
        (BoundaryMode.RESTRICTED, MemoryClass.SECRET, PolicyDecision.DENY),
        (BoundaryMode.TRUSTED, MemoryClass.SECRET, PolicyDecision.ALLOW),
        (BoundaryMode.AIRGAP, MemoryClass.SECRET, PolicyDecision.ALLOW),
        (BoundaryMode.COLDROOM, MemoryClass.SECRET, PolicyDecision.ALLOW),
        # TOP_SECRET (required: AIRGAP)
        (BoundaryMode.OPEN, MemoryClass.TOP_SECRET, PolicyDecision.DENY),
        (BoundaryMode.RESTRICTED, MemoryClass.TOP_SECRET, PolicyDecision.DENY),
        (BoundaryMode.TRUSTED, MemoryClass.TOP_SECRET, PolicyDecision.DENY),
        (BoundaryMode.AIRGAP, MemoryClass.TOP_SECRET, PolicyDecision.ALLOW),
        (BoundaryMode.COLDROOM, MemoryClass.TOP_SECRET, PolicyDecision.ALLOW),
        # CROWN_JEWEL (required: COLDROOM)
        (BoundaryMode.OPEN, MemoryClass.CROWN_JEWEL, PolicyDecision.DENY),
        (BoundaryMode.RESTRICTED, MemoryClass.CROWN_JEWEL, PolicyDecision.DENY),
        (BoundaryMode.TRUSTED, MemoryClass.CROWN_JEWEL, PolicyDecision.DENY),
        (BoundaryMode.AIRGAP, MemoryClass.CROWN_JEWEL, PolicyDecision.DENY),
        (BoundaryMode.COLDROOM, MemoryClass.CROWN_JEWEL, PolicyDecision.ALLOW),
    ]

    @pytest.mark.security
    @pytest.mark.parametrize("mode,mem_class,expected", TRUTH_TABLE,
        ids=[f"{m.name}-{mc.name}" for m, mc, _ in TRUTH_TABLE])
    def test_recall_decision(self, mode, mem_class, expected, mock_env_state):
        """Verify recall decision for every (mode, memory_class) pair."""
        engine = PolicyEngine(initial_mode=mode)
        request = PolicyRequest(request_type='recall', memory_class=mem_class)
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == expected, (
            f"SECURITY INVARIANT VIOLATED: {mode.name} + {mem_class.name} "
            f"should be {expected.value}, got {decision.value}"
        )


class TestModeMonotonicity:
    """Security invariant: higher modes are never MORE permissive than lower modes.

    For any request R and environment E, if mode_a < mode_b, then:
    - If mode_b ALLOWs R, mode_a must also ALLOW R
    - Equivalently: if mode_a DENYs R, mode_b must also DENY R

    This is the fundamental safety guarantee of the mode hierarchy.
    """

    @pytest.mark.security
    def test_recall_monotonicity(self, mock_env_state):
        """Higher modes never deny recall that lower modes allow."""
        modes = [BoundaryMode.OPEN, BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED,
                 BoundaryMode.AIRGAP, BoundaryMode.COLDROOM]

        for mem_class in MemoryClass:
            allowed_modes = []
            for mode in modes:
                engine = PolicyEngine(initial_mode=mode)
                request = PolicyRequest(request_type='recall', memory_class=mem_class)
                decision = engine.evaluate_policy(request, mock_env_state)
                if decision == PolicyDecision.ALLOW:
                    allowed_modes.append(mode)

            # All allowed modes should be contiguous from some threshold upward
            if allowed_modes:
                min_allowed = min(allowed_modes)
                for mode in modes:
                    if mode >= min_allowed:
                        assert mode in allowed_modes, (
                            f"MONOTONICITY VIOLATED: {mem_class.name} allowed in "
                            f"{min_allowed.name} but denied in higher {mode.name}"
                        )

    @pytest.mark.security
    def test_tool_network_monotonicity(self, mock_env_state):
        """SECURITY INVARIANT: If a network tool is denied in mode X,
        it must be denied in all modes > X."""
        modes = [BoundaryMode.OPEN, BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED,
                 BoundaryMode.AIRGAP, BoundaryMode.COLDROOM]

        request = PolicyRequest(request_type='tool', requires_network=True)
        first_deny = None
        for mode in modes:
            engine = PolicyEngine(initial_mode=mode)
            decision = engine.evaluate_policy(request, mock_env_state)
            if decision == PolicyDecision.DENY:
                first_deny = mode
            elif first_deny is not None:
                # Found an ALLOW after a DENY — monotonicity violated
                assert False, (
                    f"MONOTONICITY VIOLATED: network tool denied in "
                    f"{first_deny.name} but allowed in higher {mode.name}"
                )

    @pytest.mark.security
    def test_tool_usb_policy_shape(self, mock_env_state):
        """Document the USB tool policy across all modes.

        USB policy is intentionally non-monotonic between RESTRICTED and TRUSTED:
        - RESTRICTED adds a ceremony requirement (paranoid about USB)
        - TRUSTED removes it (environment verified, USB is safe)
        - AIRGAP+ denies USB entirely

        This is correct: TRUSTED means "environment is verified" which
        is a different trust model than RESTRICTED's "be cautious."
        """
        expected = {
            BoundaryMode.OPEN: PolicyDecision.ALLOW,
            BoundaryMode.RESTRICTED: PolicyDecision.REQUIRE_CEREMONY,
            BoundaryMode.TRUSTED: PolicyDecision.ALLOW,
            BoundaryMode.AIRGAP: PolicyDecision.DENY,
            BoundaryMode.COLDROOM: PolicyDecision.DENY,
        }
        request = PolicyRequest(request_type='tool', requires_usb=True)
        for mode, expected_decision in expected.items():
            engine = PolicyEngine(initial_mode=mode)
            decision = engine.evaluate_policy(request, mock_env_state)
            assert decision == expected_decision, (
                f"USB tool in {mode.name}: expected {expected_decision.value}, "
                f"got {decision.value}"
            )

    @pytest.mark.security
    def test_usb_strict_monotonicity_airgap_and_above(self, mock_env_state):
        """SECURITY INVARIANT: From AIRGAP upward, USB is always denied."""
        request = PolicyRequest(request_type='tool', requires_usb=True)
        for mode in [BoundaryMode.AIRGAP, BoundaryMode.COLDROOM]:
            engine = PolicyEngine(initial_mode=mode)
            assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.DENY, (
                f"SECURITY INVARIANT: USB must be denied in {mode.name}"
            )

    @pytest.mark.security
    def test_model_monotonicity(self, mock_env_state):
        """SECURITY INVARIANT: Model access restrictions escalate with mode."""
        modes = [BoundaryMode.OPEN, BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED,
                 BoundaryMode.AIRGAP, BoundaryMode.COLDROOM]

        request = PolicyRequest(request_type='model')
        # For offline env: OPEN denies (needs network), RESTRICTED denies,
        # TRUSTED allows (offline is safe), AIRGAP denies, COLDROOM denies
        # This is NOT strictly monotonic for offline because TRUSTED allows
        # what RESTRICTED denies. That's by design (TRUSTED = verified offline).
        # We test that AIRGAP and above always deny.
        for mode in [BoundaryMode.AIRGAP, BoundaryMode.COLDROOM]:
            engine = PolicyEngine(initial_mode=mode)
            decision = engine.evaluate_policy(request, mock_env_state)
            assert decision == PolicyDecision.DENY, (
                f"SECURITY INVARIANT: model access should be denied in {mode.name}"
            )


class TestFailClosedEdgeCases:
    """Tests verifying fail-closed behavior with malformed or edge-case inputs."""

    @pytest.mark.security
    def test_none_memory_class_denied(self, policy_engine, mock_env_state):
        """FAIL-CLOSED: None memory class must be denied, not crash."""
        request = PolicyRequest(request_type='recall', memory_class=None)
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    @pytest.mark.security
    def test_tool_no_requirements_allowed_in_open(self, policy_engine, mock_env_state):
        request = PolicyRequest(
            request_type='tool',
            requires_network=False,
            requires_filesystem=False,
            requires_usb=False,
        )
        decision = policy_engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.ALLOW

    @pytest.mark.security
    def test_tool_no_requirements_allowed_in_coldroom(self, mock_env_state):
        """COLDROOM allows tools with no IO (keyboard/display only)."""
        engine = PolicyEngine(initial_mode=BoundaryMode.COLDROOM)
        request = PolicyRequest(
            request_type='tool',
            requires_network=False,
            requires_filesystem=False,
            requires_usb=False,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.ALLOW

    @pytest.mark.security
    def test_trusted_filesystem_without_network_allowed(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
        request = PolicyRequest(
            request_type='tool',
            requires_filesystem=True,
            requires_network=False,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.ALLOW

    @pytest.mark.security
    def test_trusted_usb_without_network_allowed(self, mock_env_state):
        engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
        request = PolicyRequest(
            request_type='tool',
            requires_usb=True,
            requires_network=False,
        )
        assert engine.evaluate_policy(request, mock_env_state) == PolicyDecision.ALLOW


class TestPolicyEngineErrorPaths:
    """Error-path tests for PolicyEngine using pytest.raises."""

    def test_invalid_boundary_mode_value_raises(self):
        """Creating a BoundaryMode with invalid int value raises ValueError."""
        with pytest.raises(ValueError):
            BoundaryMode(99)

    def test_invalid_memory_class_value_raises(self):
        """Creating a MemoryClass with invalid int value raises ValueError."""
        with pytest.raises(ValueError):
            MemoryClass(99)

    def test_invalid_operator_value_raises(self):
        """Creating an Operator with invalid string raises ValueError."""
        with pytest.raises(ValueError):
            Operator("robot")

    def test_invalid_policy_decision_value_raises(self):
        """Creating a PolicyDecision with invalid string raises ValueError."""
        with pytest.raises(ValueError):
            PolicyDecision("maybe")

    def test_boundary_mode_name_case_sensitivity(self):
        """BoundaryMode should not accept lowercase string values."""
        with pytest.raises(ValueError):
            BoundaryMode("open")

    def test_evaluate_policy_unknown_request_type_denies(self, mock_env_state):
        """Unknown request_type should return DENY (fail-closed)."""
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        request = PolicyRequest(request_type='unknown_type')
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    def test_evaluate_policy_empty_request_type_denies(self, mock_env_state):
        """Empty request_type should return DENY."""
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        request = PolicyRequest(request_type='')
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    def test_evaluate_policy_none_memory_class_denies(self, mock_env_state):
        """Recall with None memory_class should return DENY."""
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        request = PolicyRequest(request_type='recall', memory_class=None)
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    def test_evaluate_policy_custom_policy_crash_denies(self, mock_env_state):
        """Custom policy evaluation crash should result in DENY (fail-closed)."""
        from unittest.mock import MagicMock
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        engine._custom_policies = MagicMock()
        request = PolicyRequest(request_type='recall', memory_class=MemoryClass.PUBLIC)
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY

    def test_transition_callback_exception_does_not_propagate(self):
        """Exceptions in transition callbacks should be caught."""
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)

        def bad_callback(old, new, operator, reason):
            raise RuntimeError("callback exploded")

        engine.register_transition_callback(bad_callback)
        success, msg = engine.transition_mode(
            BoundaryMode.RESTRICTED, Operator.HUMAN, "test"
        )
        assert success is True

    def test_boundary_state_missing_all_fields_raises(self):
        """BoundaryState with no fields raises TypeError."""
        with pytest.raises(TypeError):
            BoundaryState()

    def test_boundary_state_missing_some_fields_raises(self):
        """BoundaryState with only mode raises TypeError."""
        with pytest.raises(TypeError):
            BoundaryState(mode=BoundaryMode.OPEN)

    def test_policy_decision_empty_string_raises(self):
        """PolicyDecision('') raises ValueError."""
        with pytest.raises(ValueError):
            PolicyDecision("")

    def test_memory_class_negative_raises(self):
        """MemoryClass with negative value raises ValueError."""
        with pytest.raises(ValueError):
            MemoryClass(-1)

    def test_boundary_mode_none_raises(self):
        """BoundaryMode(None) raises ValueError."""
        with pytest.raises(ValueError):
            BoundaryMode(None)


class TestParametrizedLockdownDeniesAllRequestTypes:
    """Parametrized: LOCKDOWN must deny every request type unconditionally."""

    @pytest.mark.security
    @pytest.mark.parametrize("request_type", [
        "recall", "tool", "model", "io", "unknown", "", "shell", "admin",
    ], ids=lambda x: f"req-{x or 'empty'}")
    def test_lockdown_denies_request_type(self, request_type, mock_env_state):
        """LOCKDOWN denies all request types including unknown ones."""
        engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
        request = PolicyRequest(request_type=request_type)
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY, (
            f"LOCKDOWN must deny request_type={request_type!r}"
        )


class TestParametrizedMemoryClassMinimumMode:
    """Parametrized: MemoryClass -> minimum BoundaryMode mapping."""

    MEMORY_MODE_MAP = [
        (MemoryClass.PUBLIC, BoundaryMode.OPEN),
        (MemoryClass.INTERNAL, BoundaryMode.OPEN),
        (MemoryClass.CONFIDENTIAL, BoundaryMode.RESTRICTED),
        (MemoryClass.SECRET, BoundaryMode.TRUSTED),
        (MemoryClass.TOP_SECRET, BoundaryMode.AIRGAP),
        (MemoryClass.CROWN_JEWEL, BoundaryMode.COLDROOM),
    ]

    @pytest.mark.unit
    @pytest.mark.parametrize("mem_class,expected_mode", MEMORY_MODE_MAP,
        ids=[f"{mc.name}->{bm.name}" for mc, bm in MEMORY_MODE_MAP])
    def test_minimum_mode_for_memory(self, mem_class, expected_mode):
        """get_minimum_mode_for_memory returns correct mode for each class."""
        engine = PolicyEngine()
        assert engine.get_minimum_mode_for_memory(mem_class) == expected_mode


class TestParametrizedModeTransitionFromLockdown:
    """Parametrized: LOCKDOWN exit requires HUMAN operator for all target modes."""

    @pytest.mark.security
    @pytest.mark.parametrize("target_mode", [
        BoundaryMode.OPEN, BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED,
        BoundaryMode.AIRGAP, BoundaryMode.COLDROOM,
    ], ids=[m.name for m in [
        BoundaryMode.OPEN, BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED,
        BoundaryMode.AIRGAP, BoundaryMode.COLDROOM,
    ]])
    def test_system_cannot_exit_lockdown(self, target_mode, mock_env_state):
        """SYSTEM operator cannot exit LOCKDOWN to any mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
        success, msg = engine.transition_mode(target_mode, Operator.SYSTEM, "auto")
        assert success is False, (
            f"SYSTEM should not exit LOCKDOWN to {target_mode.name}"
        )

    @pytest.mark.unit
    @pytest.mark.parametrize("target_mode", [
        BoundaryMode.OPEN, BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED,
        BoundaryMode.AIRGAP, BoundaryMode.COLDROOM,
    ], ids=[m.name for m in [
        BoundaryMode.OPEN, BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED,
        BoundaryMode.AIRGAP, BoundaryMode.COLDROOM,
    ]])
    def test_human_can_exit_lockdown(self, target_mode, mock_env_state):
        """HUMAN operator can exit LOCKDOWN to any non-LOCKDOWN mode."""
        engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
        success, msg = engine.transition_mode(target_mode, Operator.HUMAN, "recovery")
        assert success is True, (
            f"HUMAN should exit LOCKDOWN to {target_mode.name}"
        )
        assert engine.get_current_mode() == target_mode


class TestParametrizedModeDowngradeRequiresHuman:
    """Parametrized: Mode downgrades require HUMAN operator."""

    DOWNGRADE_CASES = [
        (BoundaryMode.COLDROOM, BoundaryMode.AIRGAP),
        (BoundaryMode.COLDROOM, BoundaryMode.OPEN),
        (BoundaryMode.AIRGAP, BoundaryMode.TRUSTED),
        (BoundaryMode.AIRGAP, BoundaryMode.OPEN),
        (BoundaryMode.TRUSTED, BoundaryMode.RESTRICTED),
        (BoundaryMode.TRUSTED, BoundaryMode.OPEN),
        (BoundaryMode.RESTRICTED, BoundaryMode.OPEN),
    ]

    @pytest.mark.security
    @pytest.mark.parametrize("from_mode,to_mode", DOWNGRADE_CASES,
        ids=[f"{f.name}->{t.name}" for f, t in DOWNGRADE_CASES])
    def test_system_cannot_downgrade(self, from_mode, to_mode):
        """SYSTEM operator cannot downgrade mode."""
        engine = PolicyEngine(initial_mode=from_mode)
        success, msg = engine.transition_mode(to_mode, Operator.SYSTEM, "auto")
        assert success is False, (
            f"SYSTEM should not downgrade {from_mode.name} -> {to_mode.name}"
        )


class TestParametrizedToolBlockedAlways:
    """Parametrized: Blocked tools are denied in ALL modes."""

    BLOCKED_TOOLS = ['raw_shell', 'arbitrary_exec', 'kernel_module_load',
                     'ptrace_attach', 'debug_attach']

    @pytest.mark.security
    @pytest.mark.parametrize("tool_name", BLOCKED_TOOLS)
    @pytest.mark.parametrize("mode", [
        BoundaryMode.OPEN, BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED,
        BoundaryMode.AIRGAP, BoundaryMode.COLDROOM,
    ], ids=[m.name for m in [
        BoundaryMode.OPEN, BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED,
        BoundaryMode.AIRGAP, BoundaryMode.COLDROOM,
    ]])
    def test_blocked_tool_denied(self, tool_name, mode, mock_env_state):
        """Blocked tools must be denied in every mode."""
        engine = PolicyEngine(initial_mode=mode)
        request = PolicyRequest(request_type='tool', tool_name=tool_name)
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == PolicyDecision.DENY, (
            f"Blocked tool {tool_name} should be DENY in {mode.name}"
        )


class TestParametrizedIOPolicyMatrix:
    """Parametrized: IO policy across modes and requirement types."""

    IO_MATRIX = [
        (BoundaryMode.COLDROOM, True, False, False, PolicyDecision.DENY),
        (BoundaryMode.COLDROOM, False, True, False, PolicyDecision.DENY),
        (BoundaryMode.COLDROOM, False, False, True, PolicyDecision.DENY),
        (BoundaryMode.COLDROOM, False, False, False, PolicyDecision.ALLOW),
        (BoundaryMode.AIRGAP, True, False, False, PolicyDecision.DENY),
        (BoundaryMode.AIRGAP, False, False, True, PolicyDecision.DENY),
        (BoundaryMode.AIRGAP, False, True, False, PolicyDecision.ALLOW),
        (BoundaryMode.AIRGAP, False, False, False, PolicyDecision.ALLOW),
        (BoundaryMode.TRUSTED, True, True, True, PolicyDecision.ALLOW),
        (BoundaryMode.RESTRICTED, True, True, True, PolicyDecision.ALLOW),
        (BoundaryMode.OPEN, True, True, True, PolicyDecision.ALLOW),
    ]

    @pytest.mark.unit
    @pytest.mark.parametrize("mode,net,fs,usb,expected", IO_MATRIX,
        ids=[f"{m.name}-net{n}-fs{f}-usb{u}" for m, n, f, u, _ in IO_MATRIX])
    def test_io_policy(self, mode, net, fs, usb, expected, mock_env_state):
        """IO decision for every (mode, requirement) combination."""
        engine = PolicyEngine(initial_mode=mode)
        request = PolicyRequest(
            request_type='io',
            requires_network=net,
            requires_filesystem=fs,
            requires_usb=usb,
        )
        decision = engine.evaluate_policy(request, mock_env_state)
        assert decision == expected, (
            f"IO in {mode.name}: net={net} fs={fs} usb={usb} "
            f"expected {expected.value}, got {decision.value}"
        )
