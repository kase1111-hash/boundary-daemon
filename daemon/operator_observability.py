"""
Operator Observability — what people running this in production need to see and do.

This module addresses ROADMAP §6 by providing a unified operator-facing
observability layer that pulls together the daemon's monitoring infrastructure.

What Operators Need to Know:
1. Current boundary mode and WHY it's in that mode
2. Recent policy decisions and their outcomes
3. Tripwire status — what's armed, what's fired, what's been cleared
4. Event log health — is the chain intact, when was it last verified
5. Integration health — which systems are checking in, which have gone silent

What Operators Need to Do:
1. Query the event log for specific time ranges, event types, and outcomes
2. Understand why a specific policy decision was made (decision trace)
3. Export evidence bundles for compliance or incident response

Usage:
    from daemon.operator_observability import OperatorConsole

    console = OperatorConsole(daemon)
    snapshot = console.get_operator_snapshot()
    trace = console.trace_decision(request, env_state)
    bundle = console.export_evidence_bundle(start, end)
"""

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Policy Decision Tracing
# ---------------------------------------------------------------------------

class TraceVerdict(Enum):
    """Why a decision was reached."""
    MODE_LOCKDOWN = auto()          # LOCKDOWN denies everything
    RECALL_MODE_SUFFICIENT = auto() # Mode >= required for memory class
    RECALL_MODE_INSUFFICIENT = auto()
    TOOL_MODE_RESTRICTION = auto()  # Mode restricts this tool type
    TOOL_CEREMONY_REQUIRED = auto() # USB in RESTRICTED requires ceremony
    TOOL_ALLOWED = auto()
    MODEL_NETWORK_REQUIRED = auto() # External model needs network
    MODEL_MODE_BLOCKED = auto()     # Mode blocks external models
    IO_MODE_BLOCKED = auto()        # Mode blocks this IO type
    CUSTOM_POLICY_TIGHTENED = auto() # Custom rule tightened base decision
    UNKNOWN_REQUEST_TYPE = auto()   # Fail-closed: unknown request type
    FAIL_CLOSED = auto()            # Default deny


@dataclass
class DecisionTrace:
    """
    A complete trace of how a policy decision was made.

    Captures every condition evaluated, which rules applied, and
    the reasoning chain from request to final verdict.
    """
    request_type: str
    mode: str
    mode_value: int
    decision: str
    verdict: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    # The reasoning chain
    steps: List[Dict[str, Any]] = field(default_factory=list)

    # Request details
    memory_class: Optional[str] = None
    tool_name: Optional[str] = None
    requires_network: bool = False
    requires_filesystem: bool = False
    requires_usb: bool = False

    # Environment context
    network_state: Optional[str] = None
    vpn_active: bool = False

    # Custom policy info
    custom_policy_applied: bool = False
    custom_policy_name: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "request_type": self.request_type,
            "mode": self.mode,
            "mode_value": self.mode_value,
            "decision": self.decision,
            "verdict": self.verdict,
            "timestamp": self.timestamp,
            "steps": self.steps,
            "memory_class": self.memory_class,
            "tool_name": self.tool_name,
            "requires_network": self.requires_network,
            "requires_filesystem": self.requires_filesystem,
            "requires_usb": self.requires_usb,
            "network_state": self.network_state,
            "vpn_active": self.vpn_active,
            "custom_policy_applied": self.custom_policy_applied,
            "custom_policy_name": self.custom_policy_name,
        }

    def explain(self) -> str:
        """Human-readable explanation of the decision."""
        lines = [
            f"Decision: {self.decision} ({self.verdict})",
            f"Mode: {self.mode} ({self.mode_value})",
            f"Request: {self.request_type}",
        ]
        if self.memory_class:
            lines.append(f"Memory class: {self.memory_class}")
        if self.tool_name:
            lines.append(f"Tool: {self.tool_name}")

        lines.append("")
        lines.append("Reasoning:")
        for i, step in enumerate(self.steps, 1):
            check = step.get("check", "")
            result = step.get("result", "")
            lines.append(f"  {i}. {check} -> {result}")

        if self.custom_policy_applied:
            lines.append(f"\nCustom policy applied: {self.custom_policy_name}")

        return "\n".join(lines)


def trace_policy_decision(
    policy_engine: Any,
    request: Any,       # PolicyRequest
    env_state: Any,     # EnvironmentState
    agent: Optional[str] = None,
) -> DecisionTrace:
    """
    Evaluate a policy request and return a full decision trace.

    This wraps the policy engine's evaluate_policy() with instrumentation
    that captures the reasoning at each step.
    """
    from .policy_engine import BoundaryMode, PolicyDecision, MemoryClass
    from .state_monitor import NetworkState

    mode = policy_engine.get_current_mode()
    steps = []

    trace = DecisionTrace(
        request_type=request.request_type,
        mode=mode.name,
        mode_value=int(mode),
        decision="",
        verdict="",
        memory_class=request.memory_class.name if request.memory_class else None,
        tool_name=request.tool_name,
        requires_network=request.requires_network,
        requires_filesystem=request.requires_filesystem,
        requires_usb=request.requires_usb,
        network_state=env_state.network.value if env_state else None,
        vpn_active=getattr(env_state, 'vpn_active', False),
    )

    # LOCKDOWN denies everything — check first before evaluating specifics
    steps.append({
        "check": f"Is mode LOCKDOWN? (mode={mode.name})",
        "result": "yes — deny all" if mode == BoundaryMode.LOCKDOWN else "no — continue",
    })
    if mode == BoundaryMode.LOCKDOWN:
        trace.decision = PolicyDecision.DENY.value
        trace.verdict = TraceVerdict.MODE_LOCKDOWN.name
        trace.steps = steps
        return trace

    steps.append({
        "check": f"Request type: {request.request_type}",
        "result": f"evaluating {request.request_type} policy",
    })

    if request.request_type == 'recall':
        _trace_recall(trace, steps, request, mode, env_state)
    elif request.request_type == 'tool':
        _trace_tool(trace, steps, request, mode, env_state)
    elif request.request_type == 'model':
        _trace_model(trace, steps, request, mode, env_state)
    elif request.request_type == 'io':
        _trace_io(trace, steps, request, mode, env_state)
    else:
        steps.append({
            "check": f"Unknown request type: {request.request_type}",
            "result": "fail-closed — deny",
        })
        trace.decision = PolicyDecision.DENY.value
        trace.verdict = TraceVerdict.UNKNOWN_REQUEST_TYPE.name

    # Custom policies can only tighten the base decision, never loosen it
    custom_policies = policy_engine.get_custom_policies()
    if custom_policies is not None:
        steps.append({
            "check": f"Custom policies loaded ({len(custom_policies.rules)} rules)",
            "result": "checking for tightening",
        })
        # We don't re-run the custom evaluation here — just note it
        trace.custom_policy_applied = True
    else:
        steps.append({
            "check": "Custom policies loaded?",
            "result": "no — using base decision",
        })

    # Get actual decision from engine for consistency
    actual = policy_engine.evaluate_policy(request, env_state, agent=agent)
    if actual.value != trace.decision:
        # Custom policy changed the result
        steps.append({
            "check": f"Custom policy overrode base decision",
            "result": f"{trace.decision} -> {actual.value}",
        })
        trace.decision = actual.value
        trace.verdict = TraceVerdict.CUSTOM_POLICY_TIGHTENED.name

    trace.steps = steps
    return trace


def _trace_recall(trace, steps, request, mode, env_state):
    """Trace a recall policy decision."""
    from .policy_engine import BoundaryMode, PolicyDecision, MemoryClass

    if request.memory_class is None:
        steps.append({
            "check": "Memory class provided?",
            "result": "no — fail-closed deny",
        })
        trace.decision = PolicyDecision.DENY.value
        trace.verdict = TraceVerdict.FAIL_CLOSED.name
        return

    required_mode_map = {
        MemoryClass.PUBLIC: BoundaryMode.OPEN,
        MemoryClass.INTERNAL: BoundaryMode.OPEN,
        MemoryClass.CONFIDENTIAL: BoundaryMode.RESTRICTED,
        MemoryClass.SECRET: BoundaryMode.TRUSTED,
        MemoryClass.TOP_SECRET: BoundaryMode.AIRGAP,
        MemoryClass.CROWN_JEWEL: BoundaryMode.COLDROOM,
    }

    required = required_mode_map.get(request.memory_class, BoundaryMode.LOCKDOWN)

    steps.append({
        "check": f"Memory class {request.memory_class.name} requires mode >= {required.name} ({int(required)})",
        "result": f"current mode {mode.name} ({int(mode)}) {'>=  — allow' if mode >= required else '< — deny'}",
    })

    if mode >= required:
        trace.decision = PolicyDecision.ALLOW.value
        trace.verdict = TraceVerdict.RECALL_MODE_SUFFICIENT.name
    else:
        trace.decision = PolicyDecision.DENY.value
        trace.verdict = TraceVerdict.RECALL_MODE_INSUFFICIENT.name


def _trace_tool(trace, steps, request, mode, env_state):
    """Trace a tool policy decision."""
    from .policy_engine import BoundaryMode, PolicyDecision
    from .state_monitor import NetworkState

    if mode == BoundaryMode.COLDROOM:
        needs = []
        if request.requires_network:
            needs.append("network")
        if request.requires_filesystem:
            needs.append("filesystem")
        if request.requires_usb:
            needs.append("USB")

        if needs:
            steps.append({
                "check": f"COLDROOM: tool requires {', '.join(needs)}",
                "result": "deny — COLDROOM allows keyboard/display only",
            })
            trace.decision = PolicyDecision.DENY.value
            trace.verdict = TraceVerdict.TOOL_MODE_RESTRICTION.name
        else:
            steps.append({
                "check": "COLDROOM: tool has no IO requirements",
                "result": "allow",
            })
            trace.decision = PolicyDecision.ALLOW.value
            trace.verdict = TraceVerdict.TOOL_ALLOWED.name
        return

    if mode == BoundaryMode.AIRGAP:
        if request.requires_network or request.requires_usb:
            blocked = "network" if request.requires_network else "USB"
            steps.append({
                "check": f"AIRGAP: tool requires {blocked}",
                "result": f"deny — AIRGAP blocks {blocked}",
            })
            trace.decision = PolicyDecision.DENY.value
            trace.verdict = TraceVerdict.TOOL_MODE_RESTRICTION.name
        else:
            steps.append({
                "check": "AIRGAP: tool requires filesystem only",
                "result": "allow — filesystem OK in AIRGAP",
            })
            trace.decision = PolicyDecision.ALLOW.value
            trace.verdict = TraceVerdict.TOOL_ALLOWED.name
        return

    if mode == BoundaryMode.TRUSTED:
        if request.requires_network and env_state.network.value == "online":
            vpn = getattr(env_state, 'vpn_active', False)
            steps.append({
                "check": f"TRUSTED: tool requires network, network is online, VPN={'active' if vpn else 'inactive'}",
                "result": "allow — VPN provides trusted LAN" if vpn else "deny — no VPN, untrusted network",
            })
            if not vpn:
                trace.decision = PolicyDecision.DENY.value
                trace.verdict = TraceVerdict.TOOL_MODE_RESTRICTION.name
                return
        steps.append({
            "check": f"TRUSTED: tool allowed",
            "result": "allow",
        })
        trace.decision = PolicyDecision.ALLOW.value
        trace.verdict = TraceVerdict.TOOL_ALLOWED.name
        return

    if mode == BoundaryMode.RESTRICTED:
        if request.requires_usb:
            steps.append({
                "check": "RESTRICTED: tool requires USB",
                "result": "require ceremony — USB needs ceremony in RESTRICTED",
            })
            trace.decision = PolicyDecision.REQUIRE_CEREMONY.value
            trace.verdict = TraceVerdict.TOOL_CEREMONY_REQUIRED.name
        else:
            steps.append({
                "check": "RESTRICTED: no USB requirement",
                "result": "allow",
            })
            trace.decision = PolicyDecision.ALLOW.value
            trace.verdict = TraceVerdict.TOOL_ALLOWED.name
        return

    # OPEN
    steps.append({
        "check": "OPEN: all tools allowed",
        "result": "allow",
    })
    trace.decision = PolicyDecision.ALLOW.value
    trace.verdict = TraceVerdict.TOOL_ALLOWED.name


def _trace_model(trace, steps, request, mode, env_state):
    """Trace a model policy decision."""
    from .policy_engine import BoundaryMode, PolicyDecision
    from .state_monitor import NetworkState

    if mode >= BoundaryMode.AIRGAP:
        steps.append({
            "check": f"Mode {mode.name}: external models blocked (AIRGAP+)",
            "result": "deny",
        })
        trace.decision = PolicyDecision.DENY.value
        trace.verdict = TraceVerdict.MODEL_MODE_BLOCKED.name
        return

    if mode == BoundaryMode.TRUSTED:
        online = env_state.network.value == "online"
        vpn = getattr(env_state, 'vpn_active', False)
        if online and not vpn:
            steps.append({
                "check": "TRUSTED: online without VPN",
                "result": "deny — untrusted network for external models",
            })
            trace.decision = PolicyDecision.DENY.value
            trace.verdict = TraceVerdict.MODEL_MODE_BLOCKED.name
        else:
            steps.append({
                "check": f"TRUSTED: network={'online' if online else 'offline'}, VPN={'active' if vpn else 'inactive'}",
                "result": "allow",
            })
            trace.decision = PolicyDecision.ALLOW.value
            trace.verdict = TraceVerdict.TOOL_ALLOWED.name
        return

    # RESTRICTED or OPEN
    if env_state.network.value == "online":
        steps.append({
            "check": f"{mode.name}: network online",
            "result": "allow — external models OK with network",
        })
        trace.decision = PolicyDecision.ALLOW.value
        trace.verdict = TraceVerdict.TOOL_ALLOWED.name
    else:
        steps.append({
            "check": f"{mode.name}: network offline",
            "result": "deny — external models need network",
        })
        trace.decision = PolicyDecision.DENY.value
        trace.verdict = TraceVerdict.MODEL_NETWORK_REQUIRED.name


def _trace_io(trace, steps, request, mode, env_state):
    """Trace an IO policy decision."""
    from .policy_engine import BoundaryMode, PolicyDecision

    if mode == BoundaryMode.COLDROOM:
        if request.requires_filesystem:
            steps.append({
                "check": "COLDROOM: IO requires filesystem",
                "result": "deny — COLDROOM blocks filesystem",
            })
            trace.decision = PolicyDecision.DENY.value
            trace.verdict = TraceVerdict.IO_MODE_BLOCKED.name
        else:
            steps.append({
                "check": "COLDROOM: IO is keyboard/display only",
                "result": "allow",
            })
            trace.decision = PolicyDecision.ALLOW.value
            trace.verdict = TraceVerdict.TOOL_ALLOWED.name
        return

    if mode == BoundaryMode.AIRGAP:
        if request.requires_network or request.requires_usb:
            blocked = "network" if request.requires_network else "USB"
            steps.append({
                "check": f"AIRGAP: IO requires {blocked}",
                "result": f"deny — AIRGAP blocks {blocked}",
            })
            trace.decision = PolicyDecision.DENY.value
            trace.verdict = TraceVerdict.IO_MODE_BLOCKED.name
        else:
            steps.append({
                "check": "AIRGAP: IO requires filesystem only",
                "result": "allow",
            })
            trace.decision = PolicyDecision.ALLOW.value
            trace.verdict = TraceVerdict.TOOL_ALLOWED.name
        return

    # Lower modes: generally permissive
    steps.append({
        "check": f"{mode.name}: IO generally allowed",
        "result": "allow",
    })
    trace.decision = PolicyDecision.ALLOW.value
    trace.verdict = TraceVerdict.TOOL_ALLOWED.name


# ---------------------------------------------------------------------------
# Integration Health Registry
# ---------------------------------------------------------------------------

@dataclass
class IntegrationCheckin:
    """Record of an integration checking in with the daemon."""
    integration_name: str
    last_checkin: str
    checkin_count: int = 0
    last_request_type: str = ""
    last_decision: str = ""
    metadata: Dict = field(default_factory=dict)


class IntegrationHealthRegistry:
    """
    Tracks which external systems are checking in with the daemon.

    Operators need to know:
    - Which integrations are active (have checked in recently)
    - Which integrations have gone silent (no checkin within threshold)
    - What each integration is requesting

    Integrations register implicitly via check_in(), or an operator
    can pre-register expected integrations.
    """

    def __init__(self, silent_threshold_seconds: float = 300.0):
        """
        Args:
            silent_threshold_seconds: Seconds before an integration is
                considered "silent" (default 5 minutes).
        """
        self._threshold = silent_threshold_seconds
        self._integrations: Dict[str, IntegrationCheckin] = {}
        self._expected: set = set()  # Pre-registered expected integrations

    def expect(self, name: str) -> None:
        """Pre-register an expected integration."""
        self._expected.add(name)
        if name not in self._integrations:
            self._integrations[name] = IntegrationCheckin(
                integration_name=name,
                last_checkin="never",
            )

    def check_in(
        self,
        name: str,
        request_type: str = "",
        decision: str = "",
        metadata: Optional[Dict] = None,
    ) -> None:
        """
        Record a check-in from an integration.

        Called when an external system makes a policy request.
        """
        now = datetime.utcnow().isoformat() + "Z"

        if name in self._integrations:
            entry = self._integrations[name]
            entry.last_checkin = now
            entry.checkin_count += 1
            entry.last_request_type = request_type
            entry.last_decision = decision
            if metadata:
                entry.metadata.update(metadata)
        else:
            self._integrations[name] = IntegrationCheckin(
                integration_name=name,
                last_checkin=now,
                checkin_count=1,
                last_request_type=request_type,
                last_decision=decision,
                metadata=metadata or {},
            )

    def get_active(self) -> List[IntegrationCheckin]:
        """Get integrations that have checked in within the threshold."""
        cutoff = datetime.utcnow() - timedelta(seconds=self._threshold)
        active = []
        for entry in self._integrations.values():
            if entry.last_checkin == "never":
                continue
            try:
                last = datetime.fromisoformat(entry.last_checkin.rstrip("Z"))
                if last >= cutoff:
                    active.append(entry)
            except (ValueError, TypeError):
                pass
        return active

    def get_silent(self) -> List[IntegrationCheckin]:
        """
        Get integrations that have gone silent.

        Returns integrations that either:
        - Were expected but never checked in
        - Have not checked in within the threshold
        """
        cutoff = datetime.utcnow() - timedelta(seconds=self._threshold)
        silent = []
        for entry in self._integrations.values():
            if entry.last_checkin == "never":
                silent.append(entry)
                continue
            try:
                last = datetime.fromisoformat(entry.last_checkin.rstrip("Z"))
                if last < cutoff:
                    silent.append(entry)
            except (ValueError, TypeError):
                silent.append(entry)
        return silent

    def get_status(self) -> Dict[str, Any]:
        """Get integration health status overview."""
        active = self.get_active()
        silent = self.get_silent()

        return {
            "total_integrations": len(self._integrations),
            "active_count": len(active),
            "silent_count": len(silent),
            "expected_count": len(self._expected),
            "active": [
                {
                    "name": i.integration_name,
                    "last_checkin": i.last_checkin,
                    "checkin_count": i.checkin_count,
                    "last_request": i.last_request_type,
                    "last_decision": i.last_decision,
                }
                for i in active
            ],
            "silent": [
                {
                    "name": i.integration_name,
                    "last_checkin": i.last_checkin,
                    "checkin_count": i.checkin_count,
                }
                for i in silent
            ],
            "threshold_seconds": self._threshold,
        }


# ---------------------------------------------------------------------------
# Operator Console — unified operator view
# ---------------------------------------------------------------------------

class OperatorConsole:
    """
    Unified operator observability interface.

    Pulls together all the daemon's monitoring infrastructure into
    the five things operators need to know and the four things
    operators need to do (per ROADMAP §6).
    """

    def __init__(self, daemon: Any):
        """
        Args:
            daemon: BoundaryDaemon instance
        """
        self._daemon = daemon
        self._integration_registry = IntegrationHealthRegistry()
        self._decision_log: List[DecisionTrace] = []
        self._max_decision_log = 10000
        self._chain_last_verified: Optional[str] = None
        self._chain_last_valid: Optional[bool] = None

    @property
    def integration_registry(self) -> IntegrationHealthRegistry:
        """Access the integration health registry."""
        return self._integration_registry

    # -- What operators need to KNOW -----------------------------------------

    def get_operator_snapshot(self) -> Dict[str, Any]:
        """
        Get the complete operator snapshot — everything an operator needs
        to know at a glance.

        Returns a dictionary with five sections matching ROADMAP §6.
        """
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "mode": self._get_mode_with_rationale(),
            "recent_decisions": self._get_recent_decisions(),
            "tripwire_status": self._get_tripwire_status(),
            "log_health": self._get_log_health(),
            "integration_health": self._integration_registry.get_status(),
        }

    def _get_mode_with_rationale(self) -> Dict[str, Any]:
        """Current boundary mode with rationale for why it's there."""
        state = self._daemon.policy_engine.get_current_state()
        mode = state.mode

        # Build rationale
        rationale_parts = []

        # Who set it
        rationale_parts.append(
            f"Set by {state.operator.value} at {state.last_transition}"
        )

        # Is it frozen?
        if hasattr(self._daemon, '_mode_frozen_reason') and self._daemon._mode_frozen_reason:
            rationale_parts.append(
                f"Mode transitions FROZEN: {self._daemon._mode_frozen_reason}"
            )

        # Is environment compatible?
        env = self._daemon.state_monitor.get_current_state()
        if env:
            compat, reason = self._daemon.policy_engine.check_mode_environment_compatibility(env)
            if not compat:
                rationale_parts.append(f"Environment incompatible: {reason}")

        # Lockdown info
        lockdown_info = self._daemon.lockdown_manager.get_lockdown_info()
        if lockdown_info.get('lockdown_active'):
            rationale_parts.append(
                f"LOCKDOWN active: {lockdown_info.get('lockdown_reason', 'unknown')}"
            )

        # Enforcement status
        enforcement = []
        if hasattr(self._daemon, 'network_enforcer') and self._daemon.network_enforcer:
            enforcement.append(f"network={'active' if self._daemon.network_enforcer.is_available else 'unavailable'}")
        if hasattr(self._daemon, 'sandbox_bridge_enabled'):
            enforcement.append(f"sandbox_bridge={'active' if self._daemon.sandbox_bridge_enabled else 'inactive'}")

        return {
            "current_mode": mode.name,
            "mode_value": int(mode),
            "operator": state.operator.value,
            "last_transition": state.last_transition,
            "rationale": " | ".join(rationale_parts),
            "environment_compatible": env is None or self._daemon.policy_engine.check_mode_environment_compatibility(env)[0],
            "enforcement": enforcement,
            "mode_frozen": bool(
                hasattr(self._daemon, '_mode_frozen_reason')
                and self._daemon._mode_frozen_reason
            ),
        }

    def _get_recent_decisions(self, limit: int = 20) -> Dict[str, Any]:
        """Recent policy decisions and their outcomes."""
        recent = self._decision_log[-limit:]

        # Summary stats
        total = len(self._decision_log)
        by_decision = {}
        by_type = {}
        for d in self._decision_log:
            by_decision[d.decision] = by_decision.get(d.decision, 0) + 1
            by_type[d.request_type] = by_type.get(d.request_type, 0) + 1

        return {
            "total_logged": total,
            "by_decision": by_decision,
            "by_request_type": by_type,
            "recent": [
                {
                    "timestamp": d.timestamp,
                    "request_type": d.request_type,
                    "decision": d.decision,
                    "verdict": d.verdict,
                    "mode": d.mode,
                    "memory_class": d.memory_class,
                    "tool_name": d.tool_name,
                }
                for d in reversed(recent)
            ],
        }

    def _get_tripwire_status(self) -> Dict[str, Any]:
        """Tripwire status — armed, fired, and cleared."""
        ts = self._daemon.tripwire_system

        # Violation types and their current state
        from .tripwires import ViolationType as TripViolationType

        all_wires = [v for v in TripViolationType]
        violations = list(ts._violations)

        fired_types = set()
        for v in violations:
            fired_types.add(v.violation_type)

        armed = [w for w in all_wires if w not in fired_types]

        return {
            "enabled": ts._enabled,
            "locked": ts._locked,
            "total_violations": len(violations),
            "armed_count": len(armed),
            "fired_count": len(fired_types),
            "armed": [w.value for w in armed],
            "fired": [w.value for w in fired_types],
            "recent_violations": [
                {
                    "id": v.violation_id,
                    "timestamp": v.timestamp,
                    "type": v.violation_type.value,
                    "details": v.details,
                    "auto_lockdown": v.auto_lockdown,
                }
                for v in list(violations)[-10:]  # Last 10
            ],
        }

    def _get_log_health(self) -> Dict[str, Any]:
        """Event log health — chain integrity and verification status."""
        el = self._daemon.event_logger

        health = {
            "event_count": el.get_event_count(),
            "signed_logging": self._daemon.signed_logging,
            "chain_last_verified": self._chain_last_verified,
            "chain_valid": self._chain_last_valid,
        }

        # Add redundant logging info
        if hasattr(self._daemon, 'redundant_logging'):
            health["redundant_logging"] = self._daemon.redundant_logging

        return health

    def verify_log_chain(self) -> Tuple[bool, str]:
        """
        Verify the event log hash chain integrity.

        Returns (is_valid, message) and updates the last-verified timestamp.
        """
        try:
            is_valid, error = self._daemon.event_logger.verify_chain()
            self._chain_last_verified = datetime.utcnow().isoformat() + "Z"
            self._chain_last_valid = is_valid

            if is_valid:
                return True, f"Chain valid ({self._daemon.event_logger.get_event_count()} events)"
            else:
                return False, f"Chain BROKEN: {error}"
        except Exception as e:
            self._chain_last_verified = datetime.utcnow().isoformat() + "Z"
            self._chain_last_valid = False
            return False, f"Verification error: {e}"

    # -- What operators need to DO -------------------------------------------

    def trace_decision(
        self,
        request: Any,
        env_state: Any,
        agent: Optional[str] = None,
    ) -> DecisionTrace:
        """
        Trace a policy decision — understand WHY a decision was made.

        This evaluates the request and returns a complete reasoning trace.
        The trace is also recorded in the decision log.
        """
        trace = trace_policy_decision(
            self._daemon.policy_engine, request, env_state, agent
        )

        # Record in decision log
        self._decision_log.append(trace)
        if len(self._decision_log) > self._max_decision_log:
            self._decision_log = self._decision_log[-self._max_decision_log:]

        return trace

    def record_decision(self, trace: DecisionTrace) -> None:
        """Record a pre-computed decision trace in the log."""
        self._decision_log.append(trace)
        if len(self._decision_log) > self._max_decision_log:
            self._decision_log = self._decision_log[-self._max_decision_log:]

    def query_decisions(
        self,
        request_type: Optional[str] = None,
        decision: Optional[str] = None,
        limit: int = 100,
    ) -> List[DecisionTrace]:
        """
        Query the decision log with filters.

        Args:
            request_type: Filter by request type (recall, tool, model, io)
            decision: Filter by decision (allow, deny, require_ceremony)
            limit: Maximum results
        """
        results = self._decision_log

        if request_type:
            results = [d for d in results if d.request_type == request_type]

        if decision:
            results = [d for d in results if d.decision == decision]

        return list(reversed(results[-limit:]))

    def export_evidence_bundle(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        output_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Export an evidence bundle for compliance or incident response.

        The bundle contains:
        - Daemon status snapshot
        - Event log entries for the time range
        - Decision traces for the time range
        - Tripwire violation details
        - Integration health status
        - Log chain verification result
        - Enforcement status (sandbox bridge, etc.)

        Args:
            start_time: ISO format start time (default: last 24 hours)
            end_time: ISO format end time (default: now)
            output_dir: Directory to write bundle (default: return dict only)

        Returns:
            Bundle as a dictionary (also written to disk if output_dir given)
        """
        now = datetime.utcnow()
        if not end_time:
            end_time = now.isoformat() + "Z"
        if not start_time:
            start_time = (now - timedelta(hours=24)).isoformat() + "Z"

        # Verify chain first
        chain_valid, chain_msg = self.verify_log_chain()

        # Build bundle
        bundle = {
            "bundle_metadata": {
                "generated_at": now.isoformat() + "Z",
                "time_range": {
                    "start": start_time,
                    "end": end_time,
                },
                "generator": "boundary-daemon/operator-observability",
                "version": "1.0",
            },
            "daemon_status": self._daemon.get_status(),
            "operator_snapshot": self.get_operator_snapshot(),
            "log_chain_verification": {
                "valid": chain_valid,
                "message": chain_msg,
                "verified_at": self._chain_last_verified,
            },
            "events": self._get_events_in_range(start_time, end_time),
            "decision_traces": [
                d.to_dict()
                for d in self._decision_log
                if self._in_range(d.timestamp, start_time, end_time)
            ],
            "tripwire_violations": self._get_tripwire_status(),
            "integration_health": self._integration_registry.get_status(),
        }

        # Add sandbox bridge status if available
        if hasattr(self._daemon, 'sandbox_bridge') and self._daemon.sandbox_bridge:
            bundle["sandbox_enforcement"] = self._daemon.sandbox_bridge.get_stats()

        # Add telemetry violations if available
        if hasattr(self._daemon, 'sandbox_telemetry') and self._daemon.sandbox_telemetry:
            bundle["sandbox_violations"] = self._daemon.sandbox_telemetry.get_stats()

        # Compute bundle hash for integrity
        bundle_json = json.dumps(bundle, sort_keys=True, default=str)
        bundle["bundle_hash"] = hashlib.sha256(bundle_json.encode()).hexdigest()

        # Write to disk if requested
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            bundle_file = os.path.join(
                output_dir,
                f"evidence_bundle_{now.strftime('%Y%m%d_%H%M%S')}.json",
            )
            with open(bundle_file, 'w') as f:
                json.dump(bundle, f, indent=2, default=str)
            bundle["bundle_file"] = bundle_file
            logger.info(f"Evidence bundle written to {bundle_file}")

        return bundle

    def _get_events_in_range(
        self, start_time: str, end_time: str
    ) -> List[Dict]:
        """Get events from the event logger within a time range."""
        try:
            events = self._daemon.event_logger.get_recent_events(
                limit=10000
            )
            result = []
            for event in events:
                if self._in_range(event.timestamp, start_time, end_time):
                    result.append(event.to_dict())
            return result
        except Exception as e:
            logger.error(f"Error fetching events: {e}")
            return [{"error": str(e)}]

    def _in_range(self, ts: str, start: str, end: str) -> bool:
        """Check if a timestamp falls within a range."""
        try:
            t = ts.rstrip("Z")
            s = start.rstrip("Z")
            e = end.rstrip("Z")
            return s <= t <= e
        except (TypeError, ValueError):
            return True  # Include if we can't parse

    # -- Convenience methods -------------------------------------------------

    def get_decision_stats(self) -> Dict[str, Any]:
        """Get policy decision statistics."""
        if not self._decision_log:
            return {"total": 0, "by_decision": {}, "by_type": {}, "by_verdict": {}}

        by_decision: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        by_verdict: Dict[str, int] = {}

        for d in self._decision_log:
            by_decision[d.decision] = by_decision.get(d.decision, 0) + 1
            by_type[d.request_type] = by_type.get(d.request_type, 0) + 1
            by_verdict[d.verdict] = by_verdict.get(d.verdict, 0) + 1

        return {
            "total": len(self._decision_log),
            "by_decision": by_decision,
            "by_type": by_type,
            "by_verdict": by_verdict,
        }
