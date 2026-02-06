"""
Sandbox Telemetry — kernel-level violations fed into the hash chain.

This module monitors sandboxed processes for violations detected at
the kernel level and feeds them back into the event logger's immutable
hash chain. This closes the loop between OS-level enforcement and the
daemon's audit trail.

Violations detected:
- Seccomp kills (process killed by syscall filter)
- OOM kills (process killed by memory limit)
- Cgroup limit hits (CPU/IO throttling, PID limit reached)
- Firewall blocks (iptables/nftables drops from sandbox rules)

Each violation is logged as a hash-chained event with full context:
sandbox ID, profile, boundary mode, resource usage at time of violation.

Usage:
    from daemon.sandbox.telemetry import SandboxTelemetryCollector

    telemetry = SandboxTelemetryCollector(event_logger=event_logger)
    telemetry.start()

    # Telemetry now monitors sandboxes and logs violations
    telemetry.report_seccomp_kill(sandbox_id, syscall_nr, ...)
    telemetry.report_oom_kill(sandbox_id, memory_usage, ...)

    telemetry.stop()
"""

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class ViolationType(Enum):
    """Types of kernel-level sandbox violations."""
    SECCOMP_KILL = auto()        # Process killed by seccomp filter
    SECCOMP_EPERM = auto()       # Syscall denied by seccomp (EPERM)
    OOM_KILL = auto()            # Process killed by memory limit
    MEMORY_HIGH = auto()         # Memory high watermark exceeded
    CPU_THROTTLED = auto()       # CPU limit throttling
    PID_LIMIT = auto()           # PID limit reached
    IO_THROTTLED = auto()        # IO bandwidth limit hit
    FIREWALL_BLOCK = auto()      # Network traffic blocked by sandbox firewall
    RESOURCE_EXHAUSTION = auto() # General resource limit reached
    NAMESPACE_ESCAPE = auto()    # Attempted namespace escape detected


@dataclass
class SandboxViolation:
    """A kernel-level violation detected in a sandbox."""
    violation_id: str
    timestamp: str
    violation_type: ViolationType
    sandbox_id: str
    details: str
    severity: str = "high"  # low, medium, high, critical

    # Context at time of violation
    boundary_mode: int = 0
    profile_name: str = ""
    resource_usage: Optional[Dict] = None
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for logging."""
        return {
            "violation_id": self.violation_id,
            "timestamp": self.timestamp,
            "violation_type": self.violation_type.name,
            "sandbox_id": self.sandbox_id,
            "details": self.details,
            "severity": self.severity,
            "boundary_mode": self.boundary_mode,
            "profile_name": self.profile_name,
            "resource_usage": self.resource_usage,
            "metadata": self.metadata,
        }


class SandboxTelemetryCollector:
    """
    Collects sandbox telemetry and feeds violations into the event logger.

    Monitors:
    1. Cgroup memory.events for OOM kills and high watermark hits
    2. Cgroup pids.events for PID limit violations
    3. Cgroup cpu.stat for throttling
    4. Kernel logs for seccomp violations (audit subsystem)
    5. Sandbox firewall log entries

    All violations are logged as hash-chained events, creating an
    immutable audit trail of kernel-level enforcement actions.
    """

    def __init__(
        self,
        event_logger: Any = None,  # EventLogger
        poll_interval: float = 2.0,
        violation_callback: Optional[Callable[[SandboxViolation], None]] = None,
    ):
        self._event_logger = event_logger
        self._poll_interval = poll_interval
        self._violation_callback = violation_callback

        # Tracked sandboxes: sandbox_id -> tracking state
        self._tracked: Dict[str, _SandboxTrackingState] = {}
        self._lock = threading.Lock()

        # Monitoring thread
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Violation history
        self._violations: List[SandboxViolation] = []
        self._max_violations = 10000
        self._violation_count = 0
        self._next_violation_id = 0

    # -- Lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Start the telemetry collection loop."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return

        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="sandbox-telemetry",
        )
        self._monitor_thread.start()
        logger.info("Sandbox telemetry collector started")

    def stop(self) -> None:
        """Stop the telemetry collection loop."""
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None
        logger.info("Sandbox telemetry collector stopped")

    # -- Sandbox tracking ----------------------------------------------------

    def track_sandbox(
        self,
        sandbox_id: str,
        cgroup_path: Optional[Path] = None,
        profile_name: str = "",
        boundary_mode: int = 0,
    ) -> None:
        """Start tracking a sandbox for telemetry."""
        with self._lock:
            self._tracked[sandbox_id] = _SandboxTrackingState(
                sandbox_id=sandbox_id,
                cgroup_path=cgroup_path,
                profile_name=profile_name,
                boundary_mode=boundary_mode,
            )
        logger.debug(f"Tracking sandbox {sandbox_id} for telemetry")

    def untrack_sandbox(self, sandbox_id: str) -> None:
        """Stop tracking a sandbox."""
        with self._lock:
            self._tracked.pop(sandbox_id, None)

    # -- Violation reporting (called by sandbox or external monitors) --------

    def report_seccomp_kill(
        self,
        sandbox_id: str,
        syscall_nr: int = 0,
        syscall_name: str = "",
        pid: int = 0,
    ) -> SandboxViolation:
        """Report a seccomp kill event."""
        return self._record_violation(
            violation_type=ViolationType.SECCOMP_KILL,
            sandbox_id=sandbox_id,
            details=(
                f"Process killed by seccomp filter: "
                f"syscall={syscall_name or syscall_nr} pid={pid}"
            ),
            severity="high",
            metadata={
                "syscall_nr": syscall_nr,
                "syscall_name": syscall_name,
                "pid": pid,
            },
        )

    def report_seccomp_deny(
        self,
        sandbox_id: str,
        syscall_nr: int = 0,
        syscall_name: str = "",
        pid: int = 0,
    ) -> SandboxViolation:
        """Report a seccomp EPERM (denied but not killed)."""
        return self._record_violation(
            violation_type=ViolationType.SECCOMP_EPERM,
            sandbox_id=sandbox_id,
            details=(
                f"Syscall denied by seccomp: "
                f"syscall={syscall_name or syscall_nr} pid={pid}"
            ),
            severity="medium",
            metadata={
                "syscall_nr": syscall_nr,
                "syscall_name": syscall_name,
                "pid": pid,
            },
        )

    def report_oom_kill(
        self,
        sandbox_id: str,
        memory_bytes: int = 0,
        limit_bytes: int = 0,
        pid: int = 0,
    ) -> SandboxViolation:
        """Report an OOM kill in a sandbox."""
        return self._record_violation(
            violation_type=ViolationType.OOM_KILL,
            sandbox_id=sandbox_id,
            details=(
                f"Process OOM killed: "
                f"usage={memory_bytes} limit={limit_bytes} pid={pid}"
            ),
            severity="high",
            metadata={
                "memory_bytes": memory_bytes,
                "limit_bytes": limit_bytes,
                "pid": pid,
            },
        )

    def report_resource_limit(
        self,
        sandbox_id: str,
        resource_type: str,
        current_value: int = 0,
        limit_value: int = 0,
    ) -> SandboxViolation:
        """Report a resource limit hit (PID, CPU throttle, IO throttle)."""
        type_map = {
            "pids": ViolationType.PID_LIMIT,
            "cpu": ViolationType.CPU_THROTTLED,
            "io": ViolationType.IO_THROTTLED,
            "memory_high": ViolationType.MEMORY_HIGH,
        }
        vtype = type_map.get(resource_type, ViolationType.RESOURCE_EXHAUSTION)

        return self._record_violation(
            violation_type=vtype,
            sandbox_id=sandbox_id,
            details=(
                f"Resource limit hit: {resource_type} "
                f"current={current_value} limit={limit_value}"
            ),
            severity="medium",
            metadata={
                "resource_type": resource_type,
                "current_value": current_value,
                "limit_value": limit_value,
            },
        )

    def report_firewall_block(
        self,
        sandbox_id: str,
        destination: str = "",
        port: int = 0,
        protocol: str = "tcp",
    ) -> SandboxViolation:
        """Report a firewall block from sandbox rules."""
        return self._record_violation(
            violation_type=ViolationType.FIREWALL_BLOCK,
            sandbox_id=sandbox_id,
            details=(
                f"Network traffic blocked: "
                f"dst={destination}:{port}/{protocol}"
            ),
            severity="medium",
            metadata={
                "destination": destination,
                "port": port,
                "protocol": protocol,
            },
        )

    # -- Monitoring loop (polls cgroup stats) --------------------------------

    def _monitor_loop(self) -> None:
        """Background monitoring loop that checks cgroup events."""
        while not self._stop_event.is_set():
            try:
                self._poll_cgroup_events()
            except Exception as e:
                logger.error(f"Telemetry poll error: {e}")

            self._stop_event.wait(timeout=self._poll_interval)

    def _poll_cgroup_events(self) -> None:
        """Check cgroup event files for violations."""
        with self._lock:
            tracked = dict(self._tracked)

        for sandbox_id, state in tracked.items():
            if not state.cgroup_path or not state.cgroup_path.exists():
                continue

            self._check_memory_events(sandbox_id, state)
            self._check_pids_events(sandbox_id, state)
            self._check_cpu_throttle(sandbox_id, state)

    def _check_memory_events(
        self, sandbox_id: str, state: '_SandboxTrackingState'
    ) -> None:
        """Check memory.events for OOM kills and high watermark hits."""
        events_file = state.cgroup_path / "memory.events"
        if not events_file.exists():
            return

        try:
            content = events_file.read_text()
            for line in content.strip().split("\n"):
                if not line:
                    continue
                parts = line.split()
                if len(parts) != 2:
                    continue
                key, value = parts[0], int(parts[1])

                if key == "oom_kill" and value > state.last_oom_kills:
                    new_kills = value - state.last_oom_kills
                    state.last_oom_kills = value
                    for _ in range(new_kills):
                        self.report_oom_kill(sandbox_id)

                elif key == "high" and value > state.last_memory_high:
                    new_high = value - state.last_memory_high
                    state.last_memory_high = value
                    if new_high > 0:
                        self.report_resource_limit(
                            sandbox_id, "memory_high",
                            current_value=value,
                        )

        except Exception as e:
            logger.debug(f"Error reading memory events for {sandbox_id}: {e}")

    def _check_pids_events(
        self, sandbox_id: str, state: '_SandboxTrackingState'
    ) -> None:
        """Check pids.events for PID limit hits."""
        events_file = state.cgroup_path / "pids.events"
        if not events_file.exists():
            return

        try:
            content = events_file.read_text()
            for line in content.strip().split("\n"):
                if not line:
                    continue
                parts = line.split()
                if len(parts) != 2:
                    continue
                key, value = parts[0], int(parts[1])

                if key == "max" and value > state.last_pids_max_events:
                    new_events = value - state.last_pids_max_events
                    state.last_pids_max_events = value
                    if new_events > 0:
                        self.report_resource_limit(
                            sandbox_id, "pids",
                            current_value=value,
                        )

        except Exception as e:
            logger.debug(f"Error reading pids events for {sandbox_id}: {e}")

    def _check_cpu_throttle(
        self, sandbox_id: str, state: '_SandboxTrackingState'
    ) -> None:
        """Check cpu.stat for throttling events."""
        stat_file = state.cgroup_path / "cpu.stat"
        if not stat_file.exists():
            return

        try:
            content = stat_file.read_text()
            for line in content.strip().split("\n"):
                if not line:
                    continue
                parts = line.split()
                if len(parts) != 2:
                    continue
                key, value = parts[0], int(parts[1])

                if key == "nr_throttled" and value > state.last_cpu_throttled:
                    new_throttled = value - state.last_cpu_throttled
                    state.last_cpu_throttled = value
                    # Only report significant throttling (not one-off spikes)
                    if new_throttled >= 10:
                        self.report_resource_limit(
                            sandbox_id, "cpu",
                            current_value=new_throttled,
                        )

        except Exception as e:
            logger.debug(f"Error reading cpu stat for {sandbox_id}: {e}")

    # -- Internal helpers ----------------------------------------------------

    def _record_violation(
        self,
        violation_type: ViolationType,
        sandbox_id: str,
        details: str,
        severity: str,
        metadata: Dict,
    ) -> SandboxViolation:
        """Record a violation and log it to the hash chain."""
        self._next_violation_id += 1
        violation_id = f"sv-{self._next_violation_id:06d}"

        # Get tracking context if available
        with self._lock:
            state = self._tracked.get(sandbox_id)

        violation = SandboxViolation(
            violation_id=violation_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            violation_type=violation_type,
            sandbox_id=sandbox_id,
            details=details,
            severity=severity,
            boundary_mode=state.boundary_mode if state else 0,
            profile_name=state.profile_name if state else "",
            resource_usage=None,
            metadata=metadata,
        )

        # Record in local history
        self._violations.append(violation)
        if len(self._violations) > self._max_violations:
            self._violations = self._violations[-self._max_violations:]
        self._violation_count += 1

        # Feed into hash-chained event logger
        self._log_to_hash_chain(violation)

        # Invoke callback if registered
        if self._violation_callback:
            try:
                self._violation_callback(violation)
            except Exception as e:
                logger.error(f"Violation callback error: {e}")

        logger.warning(
            f"Sandbox violation [{violation_id}]: "
            f"{violation_type.name} in {sandbox_id}: {details}"
        )

        return violation

    def _log_to_hash_chain(self, violation: SandboxViolation) -> None:
        """Log a violation to the immutable hash-chained event logger."""
        if not self._event_logger:
            return

        try:
            from ..event_logger import EventType

            # Use SANDBOX_VIOLATION type if available, fall back to VIOLATION
            if hasattr(EventType, "SANDBOX_VIOLATION"):
                etype = EventType.SANDBOX_VIOLATION
            else:
                etype = EventType.VIOLATION

            self._event_logger.log_event(
                etype,
                f"Sandbox kernel violation: {violation.details}",
                metadata={
                    "violation_id": violation.violation_id,
                    "violation_type": violation.violation_type.name,
                    "sandbox_id": violation.sandbox_id,
                    "severity": violation.severity,
                    "boundary_mode": violation.boundary_mode,
                    "profile_name": violation.profile_name,
                    "sandbox_telemetry": True,
                    **violation.metadata,
                },
            )
        except Exception as e:
            logger.error(f"Failed to log violation to hash chain: {e}")

    # -- Query methods -------------------------------------------------------

    def get_violations(
        self,
        sandbox_id: Optional[str] = None,
        violation_type: Optional[ViolationType] = None,
        limit: int = 100,
    ) -> List[SandboxViolation]:
        """
        Get recorded violations, optionally filtered.

        Returns newest first.
        """
        violations = self._violations

        if sandbox_id:
            violations = [v for v in violations if v.sandbox_id == sandbox_id]

        if violation_type:
            violations = [
                v for v in violations if v.violation_type == violation_type
            ]

        return list(reversed(violations[-limit:]))

    def get_stats(self) -> Dict[str, Any]:
        """Get telemetry statistics."""
        by_type: Dict[str, int] = {}
        by_sandbox: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}

        for v in self._violations:
            by_type[v.violation_type.name] = (
                by_type.get(v.violation_type.name, 0) + 1
            )
            by_sandbox[v.sandbox_id] = by_sandbox.get(v.sandbox_id, 0) + 1
            by_severity[v.severity] = by_severity.get(v.severity, 0) + 1

        return {
            "total_violations": self._violation_count,
            "tracked_sandboxes": len(self._tracked),
            "by_type": by_type,
            "by_sandbox": by_sandbox,
            "by_severity": by_severity,
            "monitoring_active": (
                self._monitor_thread is not None
                and self._monitor_thread.is_alive()
            ),
        }


@dataclass
class _SandboxTrackingState:
    """Internal state for tracking a sandbox's cgroup events."""
    sandbox_id: str
    cgroup_path: Optional[Path] = None
    profile_name: str = ""
    boundary_mode: int = 0

    # Watermarks to detect new events (cgroup counters are cumulative)
    last_oom_kills: int = 0
    last_memory_high: int = 0
    last_pids_max_events: int = 0
    last_cpu_throttled: int = 0
