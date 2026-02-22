"""
Sandbox Enforcement Bridge — from cooperative to OS-level enforcement.

This module is the bridge between the policy engine's abstract decisions
and the kernel-level enforcement mechanisms in the sandbox. It provides:

1. Automatic profile tightening: When the boundary mode escalates,
   all running sandboxes have their profiles tightened to match.

2. EnforcementConsumer protocol: The reference interface for how any
   enforcement module should consume policy engine decisions.

3. Mode transition handling: Registers with the policy engine to react
   to mode changes in real-time.

The sandbox enforcement bridge proves three things:
- That boundary modes can translate into actual OS-level isolation
- That the daemon can move beyond "please respect my decisions"
  to "I will enforce my decisions"
- That the policy engine's abstractions map cleanly to kernel-level controls

Usage:
    from daemon.sandbox.enforcement_bridge import SandboxEnforcementBridge

    bridge = SandboxEnforcementBridge(
        sandbox_manager=manager,
        policy_engine=policy_engine,
        event_logger=event_logger,
    )
    bridge.activate()

    # Bridge now automatically tightens sandboxes on mode escalation.
    # To deactivate:
    bridge.deactivate()
"""

import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class EnforcementAction(Enum):
    """Actions an enforcement consumer can take in response to a mode change."""
    TIGHTEN = auto()      # Apply stricter controls
    LOOSEN = auto()       # Relax controls (only on explicit de-escalation)
    TERMINATE = auto()    # Shut down the enforced context
    NO_CHANGE = auto()    # Mode change doesn't affect this consumer
    FAILED = auto()       # Enforcement action attempted but failed


@dataclass
class EnforcementResult:
    """Result of an enforcement action."""
    action: EnforcementAction
    success: bool
    message: str
    old_mode: int = 0
    new_mode: int = 0
    affected_count: int = 0
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class EnforcementConsumer(ABC):
    """
    Reference interface for enforcement modules that consume policy decisions.

    Any module that translates policy engine decisions into OS-level
    enforcement should implement this interface. The sandbox module is the
    canonical implementation.

    The contract:
    1. on_mode_escalation() is called when the boundary mode increases
       (stricter). The consumer MUST tighten or terminate.
    2. on_mode_deescalation() is called when the mode decreases.
       The consumer MAY loosen controls.
    3. on_lockdown() is called on LOCKDOWN. The consumer MUST terminate
       or freeze all activity.
    4. get_enforcement_status() returns current enforcement state for audit.

    Fail-closed: If enforcement cannot be applied, the consumer must
    report failure. The bridge will log this as a violation.
    """

    @abstractmethod
    def on_mode_escalation(
        self, old_mode: int, new_mode: int, reason: str
    ) -> EnforcementResult:
        """
        React to mode escalation (mode number increased = stricter).

        Must tighten enforcement or terminate contexts that cannot
        be tightened. Fail-closed: return FAILED if unable to tighten.
        """
        ...

    @abstractmethod
    def on_mode_deescalation(
        self, old_mode: int, new_mode: int, reason: str
    ) -> EnforcementResult:
        """
        React to mode de-escalation (mode number decreased = less strict).

        May loosen enforcement. Conservative implementations should
        keep the tighter profile until contexts are recreated.
        """
        ...

    @abstractmethod
    def on_lockdown(self, reason: str) -> EnforcementResult:
        """
        React to LOCKDOWN mode.

        Must terminate or freeze all enforced contexts immediately.
        This is the emergency path — speed matters more than grace.
        """
        ...

    @abstractmethod
    def get_enforcement_status(self) -> Dict[str, Any]:
        """
        Return current enforcement state for audit logging.

        Must include at minimum:
        - 'active': bool (whether enforcement is currently applied)
        - 'mode': int (current enforced mode level)
        - 'contexts': int (number of enforced contexts)
        """
        ...


class SandboxEnforcementBridge(EnforcementConsumer):
    """
    Bridges the policy engine to the sandbox manager.

    When the boundary mode changes, this bridge:
    - Tightens running sandbox profiles on escalation
    - Terminates all sandboxes on LOCKDOWN
    - Logs all enforcement actions to the hash-chained event log
    - Reports enforcement failures as violations

    This is the reference implementation of EnforcementConsumer.
    Other enforcement modules (network, USB, process) should follow
    this same pattern.
    """

    def __init__(
        self,
        sandbox_manager: Any,   # SandboxManager — avoid circular import
        policy_engine: Any,     # PolicyEngine
        event_logger: Any,      # EventLogger
        telemetry: Optional[Any] = None,  # SandboxTelemetryCollector
    ):
        self._sandbox_manager = sandbox_manager
        self._policy_engine = policy_engine
        self._event_logger = event_logger
        self._telemetry = telemetry

        self._callback_id: Optional[int] = None
        self._active = False
        self._current_mode: int = 0
        self._lock = threading.Lock()

        # Enforcement history for audit
        self._enforcement_history: List[EnforcementResult] = []
        self._max_history = 1000

    # -- Lifecycle -----------------------------------------------------------

    def activate(self) -> bool:
        """
        Activate the bridge by registering with the policy engine.

        Returns True if successfully registered.
        """
        with self._lock:
            if self._active:
                logger.warning("Enforcement bridge already active")
                return True

            if not self._policy_engine:
                logger.error("Cannot activate bridge: no policy engine")
                return False

            # Get current mode
            try:
                self._current_mode = int(self._policy_engine.get_current_mode())
            except (AttributeError, TypeError):
                self._current_mode = 0

            # Register for mode transitions
            self._callback_id = self._policy_engine.register_transition_callback(
                self._on_mode_transition
            )
            self._active = True

            logger.info(
                f"Sandbox enforcement bridge activated "
                f"(mode={self._current_mode}, "
                f"sandboxes={len(self._sandbox_manager._sandboxes)})"
            )

            self._log_enforcement_event(
                "bridge_activated",
                f"Enforcement bridge activated at mode {self._current_mode}",
                {"mode": self._current_mode},
            )

            return True

    def deactivate(self) -> None:
        """Deactivate the bridge, removing the mode transition callback."""
        with self._lock:
            if not self._active:
                return

            if self._callback_id is not None and self._policy_engine:
                self._policy_engine.unregister_transition_callback(self._callback_id)
                self._callback_id = None

            self._active = False
            logger.info("Sandbox enforcement bridge deactivated")

            self._log_enforcement_event(
                "bridge_deactivated",
                "Enforcement bridge deactivated",
                {},
            )

    @property
    def is_active(self) -> bool:
        """Whether the bridge is currently active."""
        return self._active

    # -- EnforcementConsumer implementation ----------------------------------

    def on_mode_escalation(
        self, old_mode: int, new_mode: int, reason: str
    ) -> EnforcementResult:
        """Tighten all running sandboxes to match the new mode."""
        if new_mode >= 5:
            return self.on_lockdown(reason)

        results = []
        affected = 0

        with self._sandbox_manager._lock:
            sandboxes = list(self._sandbox_manager._sandboxes.values())

        for sandbox in sandboxes:
            try:
                tightened = self._tighten_sandbox(sandbox, new_mode, reason)
                if tightened:
                    affected += 1
                    results.append((sandbox.sandbox_id, True, "tightened"))
                else:
                    results.append((sandbox.sandbox_id, True, "already_compliant"))
            except (OSError, RuntimeError) as e:
                logger.error(
                    f"Failed to tighten sandbox {sandbox.sandbox_id}: {e}"
                )
                results.append((sandbox.sandbox_id, False, str(e)))

        failed = [r for r in results if not r[1]]
        success = len(failed) == 0

        result = EnforcementResult(
            action=EnforcementAction.TIGHTEN,
            success=success,
            message=(
                f"Tightened {affected} sandbox(es) to mode {new_mode}"
                if success
                else f"Failed to tighten {len(failed)} sandbox(es)"
            ),
            old_mode=old_mode,
            new_mode=new_mode,
            affected_count=affected,
            details={
                "results": [
                    {"id": r[0], "ok": r[1], "status": r[2]} for r in results
                ],
            },
        )

        self._record_result(result)

        if not success:
            self._log_enforcement_event(
                "enforcement_failure",
                f"Failed to enforce mode {new_mode} on {len(failed)} sandbox(es)",
                {
                    "old_mode": old_mode,
                    "new_mode": new_mode,
                    "failed_sandboxes": [r[0] for r in failed],
                },
            )

        return result

    def on_mode_deescalation(
        self, old_mode: int, new_mode: int, reason: str
    ) -> EnforcementResult:
        """
        On de-escalation, we do NOT loosen running sandboxes.

        This is a deliberate security choice: a sandbox created at a
        higher security level keeps that level until it exits. New
        sandboxes will be created at the new (lower) level.

        Rationale: loosening a running sandbox could expose data that
        was processed under stricter assumptions.
        """
        result = EnforcementResult(
            action=EnforcementAction.NO_CHANGE,
            success=True,
            message=(
                f"Mode de-escalated {old_mode}->{new_mode}; "
                f"existing sandboxes retain stricter profile"
            ),
            old_mode=old_mode,
            new_mode=new_mode,
            affected_count=0,
        )

        self._record_result(result)
        return result

    def on_lockdown(self, reason: str) -> EnforcementResult:
        """Terminate all running sandboxes immediately."""
        count = self._sandbox_manager.terminate_all(
            reason=f"LOCKDOWN: {reason}"
        )

        result = EnforcementResult(
            action=EnforcementAction.TERMINATE,
            success=True,
            message=f"LOCKDOWN: terminated {count} sandbox(es)",
            old_mode=self._current_mode,
            new_mode=5,
            affected_count=count,
        )

        self._record_result(result)

        self._log_enforcement_event(
            "lockdown_enforcement",
            f"LOCKDOWN enforced: terminated {count} sandbox(es)",
            {"reason": reason, "terminated_count": count},
        )

        return result

    def get_enforcement_status(self) -> Dict[str, Any]:
        """Return current enforcement state for audit."""
        with self._sandbox_manager._lock:
            sandbox_count = len(self._sandbox_manager._sandboxes)
            sandbox_states = {}
            for s in self._sandbox_manager._sandboxes.values():
                state_name = s.state.name
                sandbox_states[state_name] = sandbox_states.get(state_name, 0) + 1

        return {
            "active": self._active,
            "mode": self._current_mode,
            "contexts": sandbox_count,
            "contexts_by_state": sandbox_states,
            "enforcement_history_size": len(self._enforcement_history),
            "last_enforcement": (
                self._enforcement_history[-1].timestamp
                if self._enforcement_history
                else None
            ),
        }

    # -- Mode transition callback --------------------------------------------

    def _on_mode_transition(
        self, old_mode: Any, new_mode: Any, operator: Any, reason: str
    ) -> None:
        """
        Callback invoked by the policy engine on every mode transition.

        Signature matches PolicyEngine.register_transition_callback:
            callback(old_mode, new_mode, operator, reason)
        """
        old_val = int(old_mode)
        new_val = int(new_mode)

        with self._lock:
            self._current_mode = new_val

        if new_val > old_val:
            result = self.on_mode_escalation(old_val, new_val, reason)
        elif new_val < old_val:
            result = self.on_mode_deescalation(old_val, new_val, reason)
        else:
            return  # No actual change

        # Log the enforcement action
        self._log_enforcement_event(
            "sandbox_mode_enforcement",
            (
                f"Sandbox enforcement: {result.action.name} "
                f"({old_mode.name if hasattr(old_mode, 'name') else old_val}"
                f" -> {new_mode.name if hasattr(new_mode, 'name') else new_val})"
            ),
            {
                "old_mode": old_val,
                "new_mode": new_val,
                "action": result.action.name,
                "success": result.success,
                "affected_count": result.affected_count,
                "operator": str(operator),
                "reason": reason,
            },
        )

    # -- Internal helpers ----------------------------------------------------

    def _tighten_sandbox(
        self, sandbox: Any, new_mode: int, reason: str
    ) -> bool:
        """
        Tighten a single sandbox to match the new mode.

        Strategy:
        - If the sandbox's current profile is already at or above the
          new mode's strictness, do nothing.
        - If the sandbox is RUNNING, freeze it, update cgroup limits
          and firewall rules, then resume.
        - If the sandbox is CREATED (not yet running), just update
          the profile reference.

        Returns True if the sandbox was actually tightened.
        """
        from .sandbox_manager import SandboxProfile, SandboxState

        current_profile = sandbox.profile
        target_profile = SandboxProfile.from_boundary_mode(new_mode)

        # Check if tightening is needed by comparing profile strictness.
        # Profiles created from higher modes are stricter.
        if self._profile_is_at_least(current_profile, new_mode):
            return False  # Already compliant

        logger.info(
            f"Tightening sandbox {sandbox.sandbox_id}: "
            f"{current_profile.name} -> {target_profile.name}"
        )

        if sandbox.state == SandboxState.RUNNING:
            # Freeze, update limits, resume
            frozen = sandbox.pause()

            try:
                # Update cgroup limits (can be changed on running cgroup)
                if sandbox._cgroup_path and target_profile.cgroup_limits:
                    sandbox._cgroup_manager.set_limits(
                        sandbox._cgroup_path, target_profile.cgroup_limits
                    )

                # Update firewall rules
                if sandbox._sandbox_firewall and target_profile.network_policy:
                    sandbox._cleanup_firewall()
                    sandbox._profile = target_profile
                    sandbox._setup_firewall()
                else:
                    sandbox._profile = target_profile

            finally:
                if frozen:
                    sandbox.resume()

        elif sandbox.state == SandboxState.CREATED:
            # Not running yet — just swap the profile
            sandbox._profile = target_profile

        else:
            # STOPPED, PAUSED, FAILED — update profile for reference
            sandbox._profile = target_profile

        sandbox._emit_event("sandbox_tightened", {
            "old_profile": current_profile.name,
            "new_profile": target_profile.name,
            "new_mode": new_mode,
            "reason": reason,
        })

        return True

    def _profile_is_at_least(self, profile: Any, mode: int) -> bool:
        """
        Check if a profile is at least as strict as the given mode.

        Uses a name-to-strictness mapping derived from
        SandboxProfile.from_boundary_mode().
        """
        strictness = {
            "minimal": 0,
            "restricted": 1,
            "trusted": 2,
            "airgap": 3,
            "coldroom": 4,
            "lockdown": 5,
        }
        profile_level = strictness.get(profile.name, -1)
        return profile_level >= mode

    def _record_result(self, result: EnforcementResult) -> None:
        """Record an enforcement result in history."""
        self._enforcement_history.append(result)
        if len(self._enforcement_history) > self._max_history:
            self._enforcement_history = self._enforcement_history[-self._max_history:]

    def _log_enforcement_event(
        self, event_type_str: str, details: str, metadata: Dict
    ) -> None:
        """Log an enforcement event to the hash-chained event logger."""
        if not self._event_logger:
            return

        try:
            # Use SANDBOX_ENFORCEMENT event type if available,
            # fall back to INFO
            from ..event_logger import EventType

            if hasattr(EventType, "SANDBOX_ENFORCEMENT"):
                etype = EventType.SANDBOX_ENFORCEMENT
            else:
                etype = EventType.INFO

            metadata["enforcement_bridge"] = True
            metadata["event_subtype"] = event_type_str

            self._event_logger.log_event(etype, details, metadata=metadata)
        except (AttributeError, TypeError) as e:
            logger.error(f"Failed to log enforcement event: {e}")

    # -- Public query methods ------------------------------------------------

    def get_enforcement_history(
        self, limit: int = 50
    ) -> List[EnforcementResult]:
        """Get recent enforcement history (newest first)."""
        return list(reversed(self._enforcement_history[-limit:]))

    def get_stats(self) -> Dict[str, Any]:
        """Get bridge statistics."""
        total = len(self._enforcement_history)
        by_action = {}
        failures = 0
        for r in self._enforcement_history:
            by_action[r.action.name] = by_action.get(r.action.name, 0) + 1
            if not r.success:
                failures += 1

        return {
            "active": self._active,
            "current_mode": self._current_mode,
            "total_enforcements": total,
            "by_action": by_action,
            "failures": failures,
            "status": self.get_enforcement_status(),
        }
