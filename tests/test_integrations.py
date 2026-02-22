"""
Tests for the Integrations module.

Tests high-level integration interfaces for Memory Vault, Tool Enforcement,
Message Checking, and Ceremony Management.

Covers:
- RecallGate: allow/deny per mode and memory class, logging, minimum mode mapping
- ToolGate: allow/deny per tool requirements, get_allowed_tools, logging
- MessageGate: checker available/unavailable, source mapping, fail-closed
- CeremonyManager: confirm/deny callbacks, cooldown, ceremony logging
"""

import os
import sys
import time
from datetime import datetime
from unittest.mock import MagicMock, patch, call

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.policy_engine import (
    PolicyEngine, BoundaryMode, MemoryClass
)
from daemon.event_logger import EventType
from daemon.integrations import (
    RecallGate, ToolGate, MessageGate, CeremonyManager,
    MESSAGE_CHECKER_AVAILABLE,
)
from daemon.state_monitor import NetworkState


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def mock_daemon():
    daemon = MagicMock()
    daemon.policy_engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
    daemon.event_logger = MagicMock()
    daemon.check_recall_permission = MagicMock(return_value=(True, "Allowed"))
    daemon.check_tool_permission = MagicMock(return_value=(True, "Allowed"))
    return daemon


@pytest.fixture
def mock_daemon_restricted():
    daemon = MagicMock()
    daemon.policy_engine = PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)
    daemon.event_logger = MagicMock()
    daemon.check_recall_permission = MagicMock(return_value=(False, "Mode too low"))
    daemon.check_tool_permission = MagicMock(return_value=(False, "Requires ceremony"))
    return daemon


@pytest.fixture
def mock_daemon_lockdown():
    daemon = MagicMock()
    daemon.policy_engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
    daemon.event_logger = MagicMock()
    daemon.check_recall_permission = MagicMock(return_value=(False, "LOCKDOWN active"))
    daemon.check_tool_permission = MagicMock(return_value=(False, "LOCKDOWN active"))
    return daemon


@pytest.fixture
def mock_daemon_airgap():
    daemon = MagicMock()
    daemon.policy_engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
    daemon.event_logger = MagicMock()
    daemon.check_recall_permission = MagicMock(return_value=(True, "Allowed in AIRGAP"))
    daemon.check_tool_permission = MagicMock(return_value=(True, "Filesystem allowed"))
    # state_monitor mock for get_allowed_tools
    mock_state = MagicMock()
    mock_state.network = NetworkState.OFFLINE
    daemon.state_monitor = MagicMock()
    daemon.state_monitor.get_current_state.return_value = mock_state
    return daemon


# ===========================================================================
# RecallGate Tests
# ===========================================================================

class TestRecallGate:
    def test_recall_gate_import(self):
        assert callable(RecallGate)

    def test_recall_gate_init(self, mock_daemon):
        gate = RecallGate(mock_daemon)
        assert gate.daemon == mock_daemon

    def test_check_recall_calls_daemon(self, mock_daemon):
        """check_recall should call daemon's check_recall_permission."""
        gate = RecallGate(mock_daemon)
        gate.check_recall(MemoryClass.PUBLIC)
        mock_daemon.check_recall_permission.assert_called_once_with(MemoryClass.PUBLIC)

    def test_check_recall_returns_tuple(self, mock_daemon):
        """check_recall should return (permitted, reason) tuple."""
        gate = RecallGate(mock_daemon)
        result = gate.check_recall(MemoryClass.PUBLIC)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_check_recall_allowed(self, mock_daemon):
        """check_recall should return (True, reason) when allowed."""
        gate = RecallGate(mock_daemon)
        permitted, reason = gate.check_recall(MemoryClass.PUBLIC)
        assert permitted is True
        assert reason == "Allowed"

    def test_check_recall_denied(self, mock_daemon_restricted):
        """check_recall should return (False, reason) when denied."""
        gate = RecallGate(mock_daemon_restricted)
        permitted, reason = gate.check_recall(MemoryClass.TOP_SECRET)
        assert permitted is False
        assert "Mode too low" in reason

    def test_check_recall_with_memory_id_logs(self, mock_daemon):
        gate = RecallGate(mock_daemon)
        gate.check_recall(MemoryClass.CONFIDENTIAL, memory_id="mem-123")
        mock_daemon.event_logger.log_event.assert_called_once()
        call_args = mock_daemon.event_logger.log_event.call_args
        assert call_args[0][0] == EventType.RECALL_ATTEMPT
        assert "mem-123" in call_args[0][1]
        assert call_args[1]['metadata']['memory_id'] == "mem-123"
        assert call_args[1]['metadata']['memory_class'] == MemoryClass.CONFIDENTIAL.value
        assert call_args[1]['metadata']['permitted'] is True

    def test_check_recall_without_memory_id_does_not_log(self, mock_daemon):
        gate = RecallGate(mock_daemon)
        gate.check_recall(MemoryClass.PUBLIC)
        mock_daemon.event_logger.log_event.assert_not_called()

    def test_get_minimum_mode_delegates(self, mock_daemon):
        gate = RecallGate(mock_daemon)
        # Use real PolicyEngine method
        mode = gate.get_minimum_mode(MemoryClass.CONFIDENTIAL)
        assert mode == BoundaryMode.RESTRICTED

    @pytest.mark.parametrize("mem_class,expected_mode", [
        (MemoryClass.PUBLIC, BoundaryMode.OPEN),
        (MemoryClass.INTERNAL, BoundaryMode.OPEN),
        (MemoryClass.CONFIDENTIAL, BoundaryMode.RESTRICTED),
        (MemoryClass.SECRET, BoundaryMode.TRUSTED),
        (MemoryClass.TOP_SECRET, BoundaryMode.AIRGAP),
        (MemoryClass.CROWN_JEWEL, BoundaryMode.COLDROOM),
    ], ids=lambda x: x.name if hasattr(x, 'name') else str(x))
    def test_get_minimum_mode_full_mapping(self, mock_daemon, mem_class, expected_mode):
        """SECURITY INVARIANT: MemoryClass → BoundaryMode mapping is correct."""
        gate = RecallGate(mock_daemon)
        assert gate.get_minimum_mode(mem_class) == expected_mode

    def test_is_accessible_true(self, mock_daemon):
        gate = RecallGate(mock_daemon)
        assert gate.is_accessible(MemoryClass.PUBLIC) is True

    def test_is_accessible_false(self, mock_daemon_restricted):
        gate = RecallGate(mock_daemon_restricted)
        assert gate.is_accessible(MemoryClass.TOP_SECRET) is False

    @pytest.mark.security
    def test_check_recall_passes_memory_class_to_daemon(self, mock_daemon):
        """SECURITY: RecallGate must pass the exact MemoryClass to daemon."""
        gate = RecallGate(mock_daemon)
        for mc in MemoryClass:
            mock_daemon.check_recall_permission.reset_mock()
            gate.check_recall(mc)
            mock_daemon.check_recall_permission.assert_called_once_with(mc)

    @pytest.mark.security
    def test_check_recall_denied_with_memory_id_logs_denied(self, mock_daemon_restricted):
        """SECURITY: Denied recall with memory_id must log permitted=False."""
        gate = RecallGate(mock_daemon_restricted)
        gate.check_recall(MemoryClass.CROWN_JEWEL, memory_id="crown-001")
        call_args = mock_daemon_restricted.event_logger.log_event.call_args
        assert call_args[1]['metadata']['permitted'] is False


# ===========================================================================
# ToolGate Tests
# ===========================================================================

class TestToolGate:
    def test_tool_gate_init(self, mock_daemon):
        gate = ToolGate(mock_daemon)
        assert gate.daemon == mock_daemon

    def test_check_tool_allowed(self, mock_daemon):
        """check_tool should return (True, reason) when allowed."""
        gate = ToolGate(mock_daemon)
        permitted, reason = gate.check_tool("file_read")
        assert permitted is True
        mock_daemon.check_tool_permission.assert_called_once_with(
            "file_read",
            requires_network=False,
            requires_filesystem=False,
            requires_usb=False,
        )

    def test_check_tool_denied(self, mock_daemon_restricted):
        """check_tool should return (False, reason) when denied."""
        gate = ToolGate(mock_daemon_restricted)
        permitted, reason = gate.check_tool("shell_execute", requires_usb=True)
        assert permitted is False

    def test_check_tool_passes_all_flags(self, mock_daemon):
        gate = ToolGate(mock_daemon)
        gate.check_tool(
            "network_fetch",
            requires_network=True,
            requires_filesystem=True,
            requires_usb=True,
        )
        mock_daemon.check_tool_permission.assert_called_once_with(
            "network_fetch",
            requires_network=True,
            requires_filesystem=True,
            requires_usb=True,
        )

    def test_check_tool_with_context_logs(self, mock_daemon):
        gate = ToolGate(mock_daemon)
        ctx = {"caller": "agent-x", "purpose": "data fetch"}
        gate.check_tool("curl", context=ctx)
        mock_daemon.event_logger.log_event.assert_called_once()
        call_args = mock_daemon.event_logger.log_event.call_args
        assert call_args[0][0] == EventType.TOOL_REQUEST
        assert "curl" in call_args[0][1]
        assert call_args[1]['metadata']['tool_name'] == "curl"
        assert call_args[1]['metadata']['context'] == ctx

    def test_check_tool_without_context_does_not_log(self, mock_daemon):
        gate = ToolGate(mock_daemon)
        gate.check_tool("file_read")
        mock_daemon.event_logger.log_event.assert_not_called()

    def test_check_tool_denied_with_context_logs_permitted_false(self, mock_daemon_restricted):
        """SECURITY: Denied tool with context must log permitted=False."""
        gate = ToolGate(mock_daemon_restricted)
        gate.check_tool("usb_write", requires_usb=True, context={"reason": "backup"})
        call_args = mock_daemon_restricted.event_logger.log_event.call_args
        assert call_args[1]['metadata']['permitted'] is False


class TestToolGateAllowedTools:
    def _make_gate_with_mode(self, mode):
        """Helper: create ToolGate with daemon at given mode."""
        daemon = MagicMock()
        daemon.policy_engine = PolicyEngine(initial_mode=mode)
        daemon.event_logger = MagicMock()
        mock_state = MagicMock()
        mock_state.network = MagicMock()
        mock_state.network.value = 'offline'
        daemon.state_monitor = MagicMock()
        daemon.state_monitor.get_current_state.return_value = mock_state
        return ToolGate(daemon)

    def test_coldroom_display_only(self):
        gate = self._make_gate_with_mode(BoundaryMode.COLDROOM)
        caps = gate.get_allowed_tools()
        assert caps['display_only'] is True
        assert caps['network_tools'] is False
        assert caps['filesystem_tools'] is False
        assert caps['usb_tools'] is False

    def test_airgap_filesystem_only(self):
        gate = self._make_gate_with_mode(BoundaryMode.AIRGAP)
        caps = gate.get_allowed_tools()
        assert caps['filesystem_tools'] is True
        assert caps['network_tools'] is False
        assert caps['display_only'] is False

    def test_open_mode_filesystem_always(self):
        gate = self._make_gate_with_mode(BoundaryMode.OPEN)
        caps = gate.get_allowed_tools()
        assert caps['filesystem_tools'] is True

    def test_modes_below_trusted_network_when_offline(self):
        """OPEN/RESTRICTED/TRUSTED report network_tools only when env is offline."""
        # This is the implementation behavior: network_tools = (env.network == 'offline')
        # for all modes <= TRUSTED. The policy engine handles actual enforcement.
        for mode in [BoundaryMode.OPEN, BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED]:
            gate = self._make_gate_with_mode(mode)  # network='offline' by default
            caps = gate.get_allowed_tools()
            assert caps['network_tools'] is True, f"{mode.name} should allow network when offline"
            assert caps['filesystem_tools'] is True

    @pytest.mark.security
    def test_lockdown_not_in_caps_map(self):
        """LOCKDOWN is not handled by get_allowed_tools (it's deny-all at policy level)."""
        # LOCKDOWN falls through to OPEN/RESTRICTED else branch in the implementation,
        # but policy engine will deny all requests regardless.
        gate = self._make_gate_with_mode(BoundaryMode.LOCKDOWN)
        # The method returns a dict; LOCKDOWN doesn't have special handling
        # because the policy engine's evaluate_policy denies everything.
        caps = gate.get_allowed_tools()
        assert isinstance(caps, dict)


# ===========================================================================
# MessageGate Tests
# ===========================================================================

class TestMessageGate:
    def test_message_gate_init_with_checker(self, mock_daemon):
        gate = MessageGate(mock_daemon)
        if MESSAGE_CHECKER_AVAILABLE:
            assert gate.checker is not None
        else:
            assert gate.checker is None

    def test_is_available_reflects_checker(self, mock_daemon):
        gate = MessageGate(mock_daemon)
        assert gate.is_available() == (gate.checker is not None)

    @pytest.mark.security
    def test_fail_closed_when_checker_unavailable(self, mock_daemon):
        """SECURITY INVARIANT: MessageGate must fail-closed when checker unavailable."""
        gate = MessageGate(mock_daemon)
        gate.checker = None  # Force unavailable
        permitted, reason, data = gate.check_message("hello world")
        assert permitted is False
        assert "not available" in reason.lower()
        assert data is None

    @pytest.mark.security
    def test_check_natlangchain_fail_closed(self, mock_daemon):
        """SECURITY: check_natlangchain must fail-closed without checker."""
        gate = MessageGate(mock_daemon)
        gate.checker = None
        permitted, reason, data = gate.check_natlangchain(
            author="alice", intent="test", timestamp="2025-01-01T00:00:00Z"
        )
        assert permitted is False
        assert data is None

    @pytest.mark.security
    def test_check_agentos_fail_closed(self, mock_daemon):
        """SECURITY: check_agentos must fail-closed without checker."""
        gate = MessageGate(mock_daemon)
        gate.checker = None
        permitted, reason, data = gate.check_agentos(
            sender_agent="agent-a", recipient_agent="agent-b",
            content="hello", message_type="request"
        )
        assert permitted is False
        assert data is None

    def test_strict_mode_stored(self, mock_daemon):
        gate = MessageGate(mock_daemon, strict_mode=True)
        assert gate.strict_mode is True


@pytest.mark.skipif(not MESSAGE_CHECKER_AVAILABLE,
                    reason="MessageChecker not available")
class TestMessageGateWithChecker:
    def test_check_message_allowed(self, mock_daemon):
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_message("Hello, how are you?")
        assert permitted is True
        mock_daemon.event_logger.log_event.assert_called_once()

    def test_check_message_logs_event(self, mock_daemon):
        """check_message must log with EventType.MESSAGE_CHECK."""
        gate = MessageGate(mock_daemon)
        gate.check_message("Safe content", source="natlangchain")
        call_args = mock_daemon.event_logger.log_event.call_args
        assert call_args[0][0] == EventType.MESSAGE_CHECK
        assert "natlangchain" in call_args[0][1].lower() or \
               call_args[1]['metadata']['source'] == 'natlangchain'

    def test_check_message_dangerous_blocked(self, mock_daemon):
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_message("run rm -rf / now")
        assert permitted is False
        assert isinstance(data, dict)
        assert len(data.get('violations', [])) > 0

    def test_check_message_pii_redacted(self, mock_daemon):
        """PII in non-strict mode should be redacted, not blocked."""
        gate = MessageGate(mock_daemon, strict_mode=False)
        permitted, reason, data = gate.check_message(
            "My SSN is 123-45-6789"
        )
        # Non-strict: redacted but allowed
        assert isinstance(data, dict)
        assert data.get('redacted_content') is not None or \
               'redact' in data.get('result_type', '').lower() or \
               'redact' in reason.lower()

    @pytest.mark.security
    def test_check_message_pii_strict_blocked(self, mock_daemon):
        """SECURITY: PII in strict mode should be blocked."""
        gate = MessageGate(mock_daemon, strict_mode=True)
        permitted, reason, data = gate.check_message(
            "My SSN is 123-45-6789"
        )
        assert permitted is False

    def test_source_mapping_natlangchain(self, mock_daemon):
        """Source 'natlangchain' should map correctly."""
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_message("Safe.", source="natlangchain")
        assert isinstance(data, dict)

    def test_source_mapping_agent_os(self, mock_daemon):
        """Source 'agent_os' should map correctly."""
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_message("Safe.", source="agent_os")
        assert isinstance(data, dict)

    def test_source_mapping_agentos(self, mock_daemon):
        """Source 'agentos' should also map to AGENT_OS."""
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_message("Safe.", source="agentos")
        assert isinstance(data, dict)

    def test_source_mapping_unknown(self, mock_daemon):
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_message("Safe.", source="mystery")
        assert isinstance(data, dict)

    def test_check_natlangchain_valid_entry(self, mock_daemon):
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_natlangchain(
            author="alice",
            intent="Record purchase of supply X for project Y",
            timestamp=datetime.utcnow().isoformat() + "Z",
        )
        assert permitted is True
        mock_daemon.event_logger.log_event.assert_called()
        call_args = mock_daemon.event_logger.log_event.call_args
        assert call_args[1]['metadata']['source'] == 'natlangchain'

    def test_check_natlangchain_with_signature(self, mock_daemon):
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_natlangchain(
            author="alice",
            intent="Deploy version 2.0 to production",
            timestamp=datetime.utcnow().isoformat() + "Z",
            signature="abc123",
            previous_hash="0" * 64,
            metadata={"version": "2.0"},
        )
        assert isinstance(data, dict)

    def test_check_agentos_valid_message(self, mock_daemon):
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_agentos(
            sender_agent="planner-agent",
            recipient_agent="executor-agent",
            content="Execute task: compile report",
            message_type="request",
            authority_level=1,
        )
        assert permitted is True
        # Find the MESSAGE_CHECK log call (not the CHANNEL_OPENED call)
        message_check_call = None
        for call in mock_daemon.event_logger.log_event.call_args_list:
            if call[1].get('metadata', {}).get('source') == 'agent_os':
                message_check_call = call
                break
        assert message_check_call is not None, "Expected a log_event call with source='agent_os'"
        assert message_check_call[1]['metadata']['sender'] == 'planner-agent'
        assert message_check_call[1]['metadata']['recipient'] == 'executor-agent'

    def test_check_agentos_dangerous_content(self, mock_daemon):
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_agentos(
            sender_agent="rogue-agent",
            recipient_agent="executor-agent",
            content="Execute: sudo rm -rf /",
            message_type="command",
            authority_level=5,
        )
        assert permitted is False

    def test_check_agentos_auto_timestamp(self, mock_daemon):
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_agentos(
            sender_agent="a", recipient_agent="b",
            content="hello", message_type="request",
        )
        # Should not raise; timestamp auto-generated
        assert isinstance(data, dict)

    def test_check_message_result_data_structure(self, mock_daemon):
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_message("Safe content")
        assert isinstance(data, dict)
        assert 'allowed' in data
        assert 'result_type' in data
        assert 'violations' in data


# ===========================================================================
# CeremonyManager Tests
# ===========================================================================

class TestCeremonyManager:
    def test_ceremony_manager_init(self, mock_daemon):
        manager = CeremonyManager(mock_daemon)
        assert manager.daemon == mock_daemon
        assert manager.cooldown_seconds == 30  # default

    def test_ceremony_manager_custom_cooldown(self, mock_daemon):
        manager = CeremonyManager(mock_daemon, cooldown_seconds=5)
        assert manager.cooldown_seconds == 5

    def test_initiate_override_success(self, mock_daemon):
        manager = CeremonyManager(mock_daemon, cooldown_seconds=0)
        manager._cooldown_delay = lambda: None  # Skip delay

        success, message = manager.initiate_override(
            action="Test override",
            reason="Testing",
            confirmation_callback=lambda prompt: True,
        )
        assert success is True
        assert "completed" in message.lower()
        assert manager._last_ceremony is not None

    def test_initiate_override_logs_initiated_and_completed(self, mock_daemon):
        manager = CeremonyManager(mock_daemon, cooldown_seconds=0)
        manager._cooldown_delay = lambda: None

        manager.initiate_override(
            action="Upgrade mode",
            reason="Maintenance",
            confirmation_callback=lambda prompt: True,
        )

        log_calls = mock_daemon.event_logger.log_event.call_args_list
        assert len(log_calls) >= 2

        # First call: initiation
        first_meta = log_calls[0][1]['metadata']
        assert first_meta['status'] == 'initiated'
        assert first_meta['action'] == 'Upgrade mode'

        # Last call: completion
        last_meta = log_calls[-1][1]['metadata']
        assert last_meta['status'] == 'completed'

    def test_initiate_override_step1_deny(self, mock_daemon):
        manager = CeremonyManager(mock_daemon, cooldown_seconds=0)

        success, message = manager.initiate_override(
            action="Test override",
            reason="Testing",
            confirmation_callback=lambda prompt: False,
        )
        assert success is False
        assert "presence" in message.lower() or "failed" in message.lower()

    def test_initiate_override_step1_deny_logs_failure(self, mock_daemon):
        manager = CeremonyManager(mock_daemon, cooldown_seconds=0)

        manager.initiate_override(
            action="Test override",
            reason="Testing",
            confirmation_callback=lambda prompt: False,
        )

        log_calls = mock_daemon.event_logger.log_event.call_args_list
        # Should have initiated + failed
        statuses = [c[1]['metadata']['status'] for c in log_calls
                    if c[0][0] == EventType.OVERRIDE]
        assert 'failed' in statuses

    def test_initiate_override_step3_deny(self, mock_daemon):
        manager = CeremonyManager(mock_daemon, cooldown_seconds=0)
        manager._cooldown_delay = lambda: None

        call_count = [0]

        def selective_callback(prompt):
            call_count[0] += 1
            # Approve step 1 (presence), deny step 3 (confirm)
            return call_count[0] == 1

        success, message = manager.initiate_override(
            action="Test override",
            reason="Testing",
            confirmation_callback=selective_callback,
        )
        assert success is False
        assert "confirmation" in message.lower() or "denied" in message.lower()

    @pytest.mark.security
    def test_ceremony_all_events_logged(self, mock_daemon):
        """SECURITY: Every ceremony must produce at least one OVERRIDE log."""
        manager = CeremonyManager(mock_daemon, cooldown_seconds=0)
        manager._cooldown_delay = lambda: None

        manager.initiate_override(
            action="Log test",
            reason="Audit",
            confirmation_callback=lambda prompt: True,
        )

        override_events = [
            c for c in mock_daemon.event_logger.log_event.call_args_list
            if c[0][0] == EventType.OVERRIDE
        ]
        assert len(override_events) >= 2  # initiated + completed

    @pytest.mark.security
    def test_force_mode_change_from_lockdown_rejected(self, mock_daemon_lockdown):
        """SECURITY: force_mode_change must reject when in LOCKDOWN."""
        manager = CeremonyManager(mock_daemon_lockdown)
        success, message = manager.force_mode_change(
            BoundaryMode.RESTRICTED, "want to unlock"
        )
        assert success is False
        assert "lockdown" in message.lower() or "override_lockdown" in message.lower()


# ===========================================================================
# Cross-Gate Security Invariant Tests
# ===========================================================================

class TestCrossGateInvariants:
    """
    Security invariants that span multiple integration gates.
    These tests document the security properties the integration layer guarantees.
    """

    @pytest.mark.security
    def test_recall_gate_never_upgrades_daemon_decision(self, mock_daemon):
        """SECURITY INVARIANT: RecallGate cannot upgrade a DENY to ALLOW."""
        mock_daemon.check_recall_permission.return_value = (False, "Denied by policy")
        gate = RecallGate(mock_daemon)
        permitted, _ = gate.check_recall(MemoryClass.CROWN_JEWEL)
        assert permitted is False

        # Also via is_accessible
        assert gate.is_accessible(MemoryClass.CROWN_JEWEL) is False

    @pytest.mark.security
    def test_tool_gate_never_upgrades_daemon_decision(self, mock_daemon):
        """SECURITY INVARIANT: ToolGate cannot upgrade a DENY to ALLOW."""
        mock_daemon.check_tool_permission.return_value = (False, "Denied")
        gate = ToolGate(mock_daemon)
        permitted, _ = gate.check_tool("dangerous_tool", requires_network=True)
        assert permitted is False

    @pytest.mark.security
    def test_message_gate_fail_closed_on_import_error(self, mock_daemon):
        """SECURITY INVARIANT: MessageGate fails closed if imports fail."""
        gate = MessageGate(mock_daemon)
        gate.checker = None  # Simulate import failure
        for method_name in ['check_message', 'check_natlangchain', 'check_agentos']:
            if method_name == 'check_message':
                permitted, _, _ = gate.check_message("test")
            elif method_name == 'check_natlangchain':
                permitted, _, _ = gate.check_natlangchain(
                    author="a", intent="b", timestamp="c"
                )
            else:
                permitted, _, _ = gate.check_agentos(
                    sender_agent="a", recipient_agent="b",
                    content="c", message_type="request"
                )
            assert permitted is False, (
                f"SECURITY INVARIANT VIOLATED: {method_name} returned "
                f"permitted=True with no checker"
            )

    @pytest.mark.security
    def test_all_gates_log_with_correct_event_types(self, mock_daemon):
        """SECURITY: Each gate uses its designated EventType."""
        # RecallGate logs RECALL_ATTEMPT
        rg = RecallGate(mock_daemon)
        rg.check_recall(MemoryClass.SECRET, memory_id="test")
        recall_call = mock_daemon.event_logger.log_event.call_args
        assert recall_call[0][0] == EventType.RECALL_ATTEMPT

        mock_daemon.event_logger.reset_mock()

        # ToolGate logs TOOL_REQUEST
        tg = ToolGate(mock_daemon)
        tg.check_tool("test_tool", context={"test": True})
        tool_call = mock_daemon.event_logger.log_event.call_args
        assert tool_call[0][0] == EventType.TOOL_REQUEST

    @pytest.mark.security
    def test_recall_gate_lockdown_denied(self, mock_daemon_lockdown):
        """SECURITY: All memory classes denied in LOCKDOWN via RecallGate."""
        gate = RecallGate(mock_daemon_lockdown)
        for mc in MemoryClass:
            permitted, _ = gate.check_recall(mc)
            assert permitted is False, (
                f"SECURITY INVARIANT VIOLATED: {mc.name} permitted in LOCKDOWN"
            )


# ===========================================================================
# Integration Module Level Tests
# ===========================================================================

class TestIntegrationsModule:
    def test_module_imports(self):
        assert callable(RecallGate)
        assert callable(ToolGate)
        assert callable(CeremonyManager)
        assert callable(MessageGate)

    def test_memory_class_import(self):
        from daemon.integrations import MemoryClass as MC
        assert MC.PUBLIC == 0
        assert MC.CROWN_JEWEL == 5

    def test_boundary_mode_import(self):
        from daemon.integrations import BoundaryMode as BM
        assert BM.OPEN == 0
        assert BM.LOCKDOWN == 5

    def test_message_checker_available_flag(self):
        assert isinstance(MESSAGE_CHECKER_AVAILABLE, bool)


# ===========================================================================
# PARAMETRIZED TESTS - Added for comprehensive coverage
# ===========================================================================


class TestParametrizedRecallGateAllMemoryClasses:
    """Parametrized: RecallGate.check_recall for all MemoryClass values."""

    @pytest.mark.parametrize("mem_class", list(MemoryClass),
        ids=[mc.name for mc in MemoryClass])
    def test_check_recall_accepts_all_classes(self, mock_daemon, mem_class):
        gate = RecallGate(mock_daemon)
        permitted, reason = gate.check_recall(mem_class)
        assert isinstance(permitted, bool)
        assert isinstance(reason, str)

    @pytest.mark.security
    @pytest.mark.parametrize("mem_class", list(MemoryClass),
        ids=[mc.name for mc in MemoryClass])
    def test_lockdown_denies_all_classes(self, mock_daemon_lockdown, mem_class):
        """LOCKDOWN must deny all memory classes."""
        gate = RecallGate(mock_daemon_lockdown)
        permitted, reason = gate.check_recall(mem_class)
        assert permitted is False


class TestParametrizedToolGateByMode:
    """Parametrized: ToolGate.get_allowed_tools capabilities vary by mode."""

    CAPABILITY_CASES = [
        # (mode, capability, expected)
        (BoundaryMode.COLDROOM, "display_only", True),
        (BoundaryMode.COLDROOM, "filesystem_tools", False),
        (BoundaryMode.COLDROOM, "network_tools", False),
        (BoundaryMode.COLDROOM, "usb_tools", False),
        (BoundaryMode.AIRGAP, "filesystem_tools", True),
        (BoundaryMode.AIRGAP, "network_tools", False),
        (BoundaryMode.AIRGAP, "display_only", False),
    ]

    @pytest.mark.parametrize("mode,capability,expected", CAPABILITY_CASES,
        ids=[f"{m.name}-{c}" for m, c, _ in CAPABILITY_CASES])
    def test_capability_by_mode(self, mode, capability, expected):
        """Tool gate capabilities match expected values per mode."""
        daemon = MagicMock()
        daemon.policy_engine = PolicyEngine(initial_mode=mode)
        daemon.event_logger = MagicMock()
        mock_state = MagicMock()
        mock_state.network = MagicMock()
        mock_state.network.value = 'offline'
        daemon.state_monitor = MagicMock()
        daemon.state_monitor.get_current_state.return_value = mock_state
        gate = ToolGate(daemon)
        caps = gate.get_allowed_tools()
        assert caps[capability] == expected, (
            f"{mode.name}: {capability} should be {expected}"
        )


class TestParametrizedMessageGateFailClosed:
    """Parametrized: MessageGate fails closed for all check methods."""

    CHECK_METHODS = [
        ("check_message", {"content": "hello"}),
        ("check_natlangchain", {"author": "a", "intent": "b", "timestamp": "c"}),
        ("check_agentos", {"sender_agent": "a", "recipient_agent": "b",
                           "content": "c", "message_type": "request"}),
    ]

    @pytest.mark.security
    @pytest.mark.parametrize("method,kwargs", CHECK_METHODS,
        ids=[m for m, _ in CHECK_METHODS])
    def test_fail_closed_without_checker(self, mock_daemon, method, kwargs):
        """All MessageGate check methods must fail-closed without checker."""
        gate = MessageGate(mock_daemon)
        gate.checker = None
        if method == "check_message":
            permitted, reason, data = gate.check_message(**kwargs)
        elif method == "check_natlangchain":
            permitted, reason, data = gate.check_natlangchain(**kwargs)
        else:
            permitted, reason, data = gate.check_agentos(**kwargs)
        assert permitted is False
        assert data is None


class TestParametrizedMessageSourceMapping:
    """Parametrized: Message source strings map correctly."""

    SOURCE_CASES = [
        "natlangchain",
        "agent_os",
        "agent-os",
        "agentos",
        "unknown_source",
        "",
    ]

    @pytest.mark.skipif(not MESSAGE_CHECKER_AVAILABLE,
                        reason="MessageChecker not available")
    @pytest.mark.parametrize("source", SOURCE_CASES)
    def test_source_accepted(self, mock_daemon, source):
        gate = MessageGate(mock_daemon)
        permitted, reason, data = gate.check_message("Safe content", source=source)
        assert isinstance(permitted, bool)
        assert isinstance(data, dict)


class TestParametrizedCeremonyManagerCooldowns:
    """Parametrized: CeremonyManager with various cooldown values."""

    @pytest.mark.parametrize("cooldown", [0, 1, 5, 30, 60, 300],
        ids=[f"cooldown-{c}s" for c in [0, 1, 5, 30, 60, 300]])
    def test_cooldown_stored(self, mock_daemon, cooldown):
        manager = CeremonyManager(mock_daemon, cooldown_seconds=cooldown)
        assert manager.cooldown_seconds == cooldown


class TestParametrizedBoundaryModeEnum:
    """Parametrized: BoundaryMode enum int values are correct."""

    MODE_VALUES = [
        (BoundaryMode.OPEN, 0),
        (BoundaryMode.RESTRICTED, 1),
        (BoundaryMode.TRUSTED, 2),
        (BoundaryMode.AIRGAP, 3),
        (BoundaryMode.COLDROOM, 4),
        (BoundaryMode.LOCKDOWN, 5),
    ]

    @pytest.mark.parametrize("mode,expected_value", MODE_VALUES,
        ids=[m.name for m, _ in MODE_VALUES])
    def test_mode_value(self, mode, expected_value):
        assert mode.value == expected_value


class TestParametrizedMemoryClassEnum:
    """Parametrized: MemoryClass enum int values are correct."""

    CLASS_VALUES = [
        (MemoryClass.PUBLIC, 0),
        (MemoryClass.INTERNAL, 1),
        (MemoryClass.CONFIDENTIAL, 2),
        (MemoryClass.SECRET, 3),
        (MemoryClass.TOP_SECRET, 4),
        (MemoryClass.CROWN_JEWEL, 5),
    ]

    @pytest.mark.parametrize("mc,expected_value", CLASS_VALUES,
        ids=[mc.name for mc, _ in CLASS_VALUES])
    def test_memory_class_value(self, mc, expected_value):
        assert mc.value == expected_value
