"""
Policy Engine - Boundary Mode and Policy Enforcement
Manages boundary modes and evaluates policies for recall gating and tool restrictions.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, IntEnum
from typing import Optional, Dict, Tuple
import threading

from .state_monitor import NetworkState, HardwareTrust, EnvironmentState

logger = logging.getLogger(__name__)


class BoundaryMode(IntEnum):
    """
    Boundary modes define the trust level and restrictions.
    Higher numeric values = stricter security.
    """
    OPEN = 0         # Networked, low trust
    RESTRICTED = 1   # Network allowed, memory limited
    TRUSTED = 2      # Offline or verified LAN
    AIRGAP = 3       # Physically isolated
    COLDROOM = 4     # No IO except keyboard/display
    LOCKDOWN = 5     # Emergency freeze


class MemoryClass(IntEnum):
    """Memory classification levels (0-5)"""
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4
    CROWN_JEWEL = 5


class Operator(Enum):
    """Who initiated a mode transition"""
    HUMAN = "human"
    SYSTEM = "system"


class PolicyDecision(Enum):
    """Policy evaluation result"""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_CEREMONY = "require_ceremony"


@dataclass
class BoundaryState:
    """Complete boundary state"""
    mode: BoundaryMode
    network: NetworkState
    hardware_trust: HardwareTrust
    external_models: bool
    last_transition: str
    operator: Operator

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'mode': self.mode.name.lower(),
            'network': self.network.value,
            'hardware_trust': self.hardware_trust.value,
            'external_models': self.external_models,
            'last_transition': self.last_transition,
            'operator': self.operator.value
        }


@dataclass
class PolicyRequest:
    """Request for policy evaluation"""
    request_type: str  # 'recall', 'tool', 'model', 'io'
    memory_class: Optional[MemoryClass] = None
    tool_name: Optional[str] = None
    requires_network: bool = False
    requires_filesystem: bool = False
    requires_usb: bool = False


class PolicyEngine:
    """
    Evaluates policies based on (mode × signal × request) → decision.
    Enforces fail-closed, deterministic policies.

    Supports optional custom policy refinement via load_custom_policies().
    Custom rules can only tighten (ALLOW→CEREMONY, ALLOW→DENY), never loosen.
    """

    def __init__(self, initial_mode: BoundaryMode = BoundaryMode.OPEN):
        """Initialize policy engine with a starting mode"""
        self._state_lock = threading.Lock()
        self._boundary_state = BoundaryState(
            mode=initial_mode,
            network=NetworkState.OFFLINE,
            hardware_trust=HardwareTrust.MEDIUM,
            external_models=False,
            last_transition=datetime.utcnow().isoformat() + "Z",
            operator=Operator.SYSTEM
        )
        self._transition_callbacks: Dict[int, callable] = {}  # Use dict for O(1) unregister
        self._next_callback_id = 0
        self._callback_lock = threading.Lock()  # Protect callback modifications
        self._custom_policies = None  # Optional PolicySet for custom rules
        self._baseline_usb_devices = None  # Baseline USB device set for change detection

    def register_transition_callback(self, callback: callable) -> int:
        """
        Register callback for mode transitions.

        Args:
            callback: Function accepting (old_mode, new_mode, operator)

        Returns:
            Callback ID that can be used to unregister the callback
        """
        with self._callback_lock:
            callback_id = self._next_callback_id
            self._next_callback_id += 1
            self._transition_callbacks[callback_id] = callback
            return callback_id

    def unregister_transition_callback(self, callback_id: int) -> bool:
        """
        Unregister a previously registered transition callback.

        Args:
            callback_id: The ID returned from register_transition_callback

        Returns:
            True if callback was found and removed, False otherwise
        """
        with self._callback_lock:
            if callback_id in self._transition_callbacks:
                del self._transition_callbacks[callback_id]
                return True
            return False

    def load_custom_policies(self, policy_set) -> Tuple[bool, str]:
        """
        Load a custom PolicySet for policy refinement.

        Custom rules can only tighten decisions, never loosen them.
        The PolicySet is validated before loading; invalid policies are rejected.

        SECURITY: Validation and installation are atomic under _state_lock
        to prevent race conditions where evaluate_policy sees inconsistent state.

        Args:
            policy_set: A PolicySet instance from daemon.policy_language

        Returns:
            (success, message)
        """
        from .policy_language import validate_policy_set
        with self._state_lock:
            errors = validate_policy_set(policy_set)
            real_errors = [e for e in errors if e.severity == 'error']
            if real_errors:
                msgs = '; '.join(f"{e.rule_name}: {e.message}" for e in real_errors)
                return (False, f"Validation failed: {msgs}")
            self._custom_policies = policy_set
        return (True, f"Loaded {len(policy_set.rules)} custom rules")

    def clear_custom_policies(self):
        """Remove all custom policy rules."""
        with self._state_lock:
            self._custom_policies = None

    def get_custom_policies(self):
        """Get the currently loaded custom PolicySet, or None."""
        return self._custom_policies

    def cleanup(self):
        """Cleanup resources and clear callbacks to prevent memory leaks."""
        with self._callback_lock:
            self._transition_callbacks.clear()
        self._custom_policies = None

    def get_current_state(self) -> BoundaryState:
        """Get current boundary state"""
        with self._state_lock:
            return self._boundary_state

    def get_current_mode(self) -> BoundaryMode:
        """Get current boundary mode"""
        with self._state_lock:
            return self._boundary_state.mode

    def transition_mode(self, new_mode: BoundaryMode, operator: Operator,
                       reason: str = "") -> Tuple[bool, str]:
        """
        Transition to a new boundary mode.

        Args:
            new_mode: Target mode
            operator: Who initiated the transition
            reason: Reason for transition

        Returns:
            (success, message)
        """
        with self._state_lock:
            old_mode = self._boundary_state.mode

            # Cannot transition from LOCKDOWN without human intervention
            if old_mode == BoundaryMode.LOCKDOWN and operator != Operator.HUMAN:
                return (False, "Cannot exit LOCKDOWN mode without human intervention")

            # Prevent mode downgrades without human operator
            # (auto-escalation to LOCKDOWN is always OK)
            if new_mode < old_mode and new_mode != BoundaryMode.LOCKDOWN and operator != Operator.HUMAN:
                return (False, f"Cannot downgrade from {old_mode.name} to {new_mode.name} without human operator")

            # Apply the transition
            self._boundary_state.mode = new_mode
            self._boundary_state.last_transition = datetime.utcnow().isoformat() + "Z"
            self._boundary_state.operator = operator

            # Snapshot callbacks under lock
            with self._callback_lock:
                callbacks = list(self._transition_callbacks.values())

        # Fire callbacks OUTSIDE _state_lock to prevent deadlock
        for callback in callbacks:
            try:
                callback(old_mode, new_mode, operator, reason)
            except Exception as e:
                logger.error(f"Error in transition callback: {e}")

        return (True, f"Transitioned from {old_mode.name} to {new_mode.name}")

    def update_environment(self, env_state: EnvironmentState):
        """
        Update the boundary state with current environment.
        This is called by the daemon when environment changes are detected.

        Args:
            env_state: Current environment state from StateMonitor
        """
        with self._state_lock:
            self._boundary_state.network = env_state.network
            self._boundary_state.hardware_trust = env_state.hardware_trust
            self._boundary_state.external_models = len(env_state.external_model_endpoints) > 0

    def evaluate_policy(self, request: PolicyRequest, env_state: EnvironmentState,
                        agent: str = None) -> PolicyDecision:
        """
        Evaluate a policy request against current mode and environment.

        If custom policies are loaded, they refine the base decision
        (can tighten but never loosen).

        Args:
            request: The policy request to evaluate
            env_state: Current environment state
            agent: Optional agent identifier for per-agent custom rules

        Returns:
            PolicyDecision (ALLOW, DENY, or REQUIRE_CEREMONY)
        """
        with self._state_lock:
            current_mode = self._boundary_state.mode

            # LOCKDOWN mode: deny everything (custom rules cannot override)
            if current_mode == BoundaryMode.LOCKDOWN:
                return PolicyDecision.DENY

            # Normalize request type
            req_type = request.request_type.lower().strip() if request.request_type else ''

            # Base matrix evaluation
            if req_type == 'recall':
                base = self._evaluate_recall_policy(request, current_mode, env_state)
            elif req_type == 'tool':
                base = self._evaluate_tool_policy(request, current_mode, env_state)
            elif req_type == 'model':
                base = self._evaluate_model_policy(request, current_mode, env_state)
            elif req_type == 'io':
                base = self._evaluate_io_policy(request, current_mode, env_state)
            else:
                # Unknown request type: fail closed
                return PolicyDecision.DENY

            # Apply custom policy refinement if loaded
            if self._custom_policies is not None:
                try:
                    from .policy_language import (
                        EvaluationContext, evaluate_with_custom_policies
                    )
                    ctx = EvaluationContext.build(
                        current_mode, request, env_state, agent=agent,
                    )
                    return evaluate_with_custom_policies(base, self._custom_policies, ctx)
                except Exception as e:
                    logger.error(f"Custom policy evaluation error: {e}")
                    # Fail-closed: if custom evaluation crashes, deny
                    return PolicyDecision.DENY

            return base

    def _evaluate_recall_policy(self, request: PolicyRequest,
                               mode: BoundaryMode,
                               env_state: EnvironmentState) -> PolicyDecision:
        """
        Evaluate memory recall policy.

        Memory Class → Minimum Mode mapping:
        0-1: Open
        2: Restricted
        3: Trusted
        4: Air-Gap
        5: Cold Room
        """
        if request.memory_class is None:
            return PolicyDecision.DENY

        # Map memory class to minimum required mode
        required_mode_map = {
            MemoryClass.PUBLIC: BoundaryMode.OPEN,
            MemoryClass.INTERNAL: BoundaryMode.OPEN,
            MemoryClass.CONFIDENTIAL: BoundaryMode.RESTRICTED,
            MemoryClass.SECRET: BoundaryMode.TRUSTED,
            MemoryClass.TOP_SECRET: BoundaryMode.AIRGAP,
            MemoryClass.CROWN_JEWEL: BoundaryMode.COLDROOM,
        }

        required_mode = required_mode_map.get(request.memory_class, BoundaryMode.LOCKDOWN)

        # Current mode must be >= required mode
        if mode >= required_mode:
            return PolicyDecision.ALLOW
        else:
            return PolicyDecision.DENY

    # Tools that are always blocked regardless of mode
    BLOCKED_TOOLS = frozenset({
        'raw_shell', 'arbitrary_exec', 'kernel_module_load',
        'ptrace_attach', 'debug_attach',
    })

    # Tools that require RESTRICTED mode or higher
    RESTRICTED_TOOLS = frozenset({
        'file_write', 'file_delete', 'process_spawn',
        'network_connect', 'usb_mount',
    })

    def _evaluate_tool_policy(self, request: PolicyRequest,
                             mode: BoundaryMode,
                             env_state: EnvironmentState) -> PolicyDecision:
        """Evaluate tool execution policy based on mode restrictions"""

        # SECURITY: Check tool_name against blocked/restricted lists
        if request.tool_name:
            tool = request.tool_name.lower().strip()
            if tool in self.BLOCKED_TOOLS:
                return PolicyDecision.DENY
            if tool in self.RESTRICTED_TOOLS and mode < BoundaryMode.RESTRICTED:
                return PolicyDecision.REQUIRE_CEREMONY

        # COLDROOM: Minimal IO only
        if mode == BoundaryMode.COLDROOM:
            # Only allow display and keyboard
            if request.requires_network or request.requires_filesystem or request.requires_usb:
                return PolicyDecision.DENY
            return PolicyDecision.ALLOW

        # AIRGAP: No network, no USB
        if mode == BoundaryMode.AIRGAP:
            if request.requires_network or request.requires_usb:
                return PolicyDecision.DENY
            # Filesystem OK in airgap
            return PolicyDecision.ALLOW

        # TRUSTED: Offline or verified LAN only
        if mode == BoundaryMode.TRUSTED:
            # Check if we're actually offline
            if request.requires_network and env_state.network == NetworkState.ONLINE:
                # Allow if VPN active (trusted LAN)
                if not env_state.vpn_active:
                    return PolicyDecision.DENY
            return PolicyDecision.ALLOW

        # RESTRICTED: Limited tools
        if mode == BoundaryMode.RESTRICTED:
            # Some tools may require ceremony
            if request.requires_usb:
                return PolicyDecision.REQUIRE_CEREMONY
            return PolicyDecision.ALLOW

        # OPEN: Allow most things
        if mode == BoundaryMode.OPEN:
            return PolicyDecision.ALLOW

        # Default: fail closed
        return PolicyDecision.DENY

    def _evaluate_model_policy(self, request: PolicyRequest,
                               mode: BoundaryMode,
                               env_state: EnvironmentState) -> PolicyDecision:
        """Evaluate external model access policy"""

        # COLDROOM and AIRGAP: No external models
        if mode >= BoundaryMode.AIRGAP:
            return PolicyDecision.DENY

        # TRUSTED: External models only if VPN active
        # SECURITY: Offline state cannot reach external models, so deny.
        # Only allow when connected via VPN (trusted LAN).
        if mode == BoundaryMode.TRUSTED:
            if env_state.network == NetworkState.ONLINE and env_state.vpn_active:
                return PolicyDecision.ALLOW
            return PolicyDecision.DENY

        # RESTRICTED and OPEN: Allow with network
        if mode <= BoundaryMode.RESTRICTED:
            if env_state.network == NetworkState.ONLINE:
                return PolicyDecision.ALLOW
            return PolicyDecision.DENY

        return PolicyDecision.DENY

    def _evaluate_io_policy(self, request: PolicyRequest,
                           mode: BoundaryMode,
                           env_state: EnvironmentState) -> PolicyDecision:
        """Evaluate IO operation policy"""

        # COLDROOM: Minimal IO (keyboard/display only)
        if mode == BoundaryMode.COLDROOM:
            if request.requires_filesystem or request.requires_network or request.requires_usb:
                return PolicyDecision.DENY
            return PolicyDecision.ALLOW

        # AIRGAP: Filesystem OK, no network/USB
        if mode == BoundaryMode.AIRGAP:
            if request.requires_network or request.requires_usb:
                return PolicyDecision.DENY
            return PolicyDecision.ALLOW

        # Lower modes: generally permissive
        return PolicyDecision.ALLOW

    def check_mode_environment_compatibility(self, env_state: EnvironmentState) -> Tuple[bool, Optional[str]]:
        """
        Check if current environment is compatible with current mode.
        Returns (is_compatible, violation_reason)

        This is used for automatic tripwire detection.
        """
        with self._state_lock:
            mode = self._boundary_state.mode

            # AIRGAP mode violations
            if mode >= BoundaryMode.AIRGAP:
                if env_state.network == NetworkState.ONLINE:
                    return (False, "Network came online in AIRGAP+ mode")

            # COLDROOM mode violations
            if mode >= BoundaryMode.COLDROOM:
                # USB insertion
                added_usb, _ = self._get_usb_changes(env_state)
                if added_usb:
                    return (False, f"USB device inserted in COLDROOM mode: {added_usb}")

            # All checks passed
            return (True, None)

    def _get_usb_changes(self, env_state: EnvironmentState) -> Tuple[set, set]:
        """Detect USB device changes against baseline.

        Returns:
            (added_devices, removed_devices) as sets
        """
        current_devices = set(env_state.usb_devices) if env_state.usb_devices else set()
        if self._baseline_usb_devices is None:
            self._baseline_usb_devices = current_devices
            return (set(), set())
        added = current_devices - self._baseline_usb_devices
        removed = self._baseline_usb_devices - current_devices
        return (added, removed)

    def get_minimum_mode_for_memory(self, memory_class: MemoryClass) -> BoundaryMode:
        """Get the minimum boundary mode required for a memory class"""
        mode_map = {
            MemoryClass.PUBLIC: BoundaryMode.OPEN,
            MemoryClass.INTERNAL: BoundaryMode.OPEN,
            MemoryClass.CONFIDENTIAL: BoundaryMode.RESTRICTED,
            MemoryClass.SECRET: BoundaryMode.TRUSTED,
            MemoryClass.TOP_SECRET: BoundaryMode.AIRGAP,
            MemoryClass.CROWN_JEWEL: BoundaryMode.COLDROOM,
        }
        return mode_map.get(memory_class, BoundaryMode.LOCKDOWN)


if __name__ == '__main__':
    # Test the policy engine
    print("Testing Policy Engine...")

    engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)

    # Test recall policies at different modes
    for mode in [BoundaryMode.OPEN, BoundaryMode.RESTRICTED, BoundaryMode.AIRGAP]:
        engine.transition_mode(mode, Operator.HUMAN, "test")

        for mem_class in [MemoryClass.PUBLIC, MemoryClass.CONFIDENTIAL, MemoryClass.TOP_SECRET]:
            request = PolicyRequest(
                request_type='recall',
                memory_class=mem_class
            )

            # Create a mock environment state
            from state_monitor import EnvironmentState
            env = EnvironmentState(
                timestamp=datetime.utcnow().isoformat() + "Z",
                network=NetworkState.OFFLINE,
                hardware_trust=HardwareTrust.HIGH,
                active_interfaces=[],
                has_internet=False,
                vpn_active=False,
                dns_available=False,
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

            decision = engine.evaluate_policy(request, env)
            print(f"Mode: {mode.name:12} | Memory: {mem_class.name:15} | Decision: {decision.value}")

    print("\nPolicy engine test complete.")
