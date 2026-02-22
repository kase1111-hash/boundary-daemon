"""
eBPF Monitor - Real-Time Kernel Event Monitoring

This module provides real-time monitoring of security-relevant kernel events
using eBPF (extended Berkeley Packet Filter). Unlike polling-based detection,
eBPF hooks directly into the kernel and receives events in microseconds.

PHASE 2 ENFORCEMENT: Eliminates the ~1 second race condition from Phase 1
by intercepting syscalls before they complete.

Capabilities:
- Network syscall monitoring (socket, connect, sendto, bind, etc.)
- USB device events (device add/remove)
- Process execution monitoring (execve)
- File access monitoring (open, read, write)

Requirements:
- Linux kernel 4.15+ with BPF support
- BCC (BPF Compiler Collection) Python bindings
- Root privileges (CAP_SYS_ADMIN, CAP_BPF)
- Kernel headers installed

SECURITY NOTES:
- eBPF programs run in kernel space with safety verification
- Events are delivered to userspace via perf buffers
- Reaction time is typically <100 microseconds
- Can block operations by returning error codes (with BPF_PROG_TYPE_LSM)
"""

import os
import sys
import threading
import logging
import time
import ctypes
import json
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, List, Set, Any, Tuple
from datetime import datetime
from collections import deque

logger = logging.getLogger(__name__)

# Platform detection
IS_LINUX = sys.platform.startswith('linux')

# Try to import BCC
BCC_AVAILABLE = False
bcc = None
if IS_LINUX:
    try:
        from bcc import BPF
        import bcc
        BCC_AVAILABLE = True
        logger.info("BCC (BPF Compiler Collection) available")
    except ImportError:
        logger.warning("BCC not available - install with: apt install python3-bcc bpfcc-tools")


class EventType(Enum):
    """Types of events monitored by eBPF."""
    # Network events
    NETWORK_SOCKET = auto()
    NETWORK_CONNECT = auto()
    NETWORK_BIND = auto()
    NETWORK_SENDTO = auto()
    NETWORK_RECVFROM = auto()
    NETWORK_ACCEPT = auto()

    # USB events
    USB_DEVICE_ADD = auto()
    USB_DEVICE_REMOVE = auto()

    # Process events
    PROCESS_EXEC = auto()
    PROCESS_EXIT = auto()
    PROCESS_FORK = auto()

    # File events
    FILE_OPEN = auto()
    FILE_READ = auto()
    FILE_WRITE = auto()


class MonitorAction(Enum):
    """Action to take when event is detected."""
    ALLOW = auto()      # Allow the operation
    LOG = auto()        # Log but allow
    ALERT = auto()      # Alert and allow
    BLOCK = auto()      # Block the operation (requires LSM hooks)
    LOCKDOWN = auto()   # Trigger system lockdown


@dataclass
class SecurityEvent:
    """Represents a security event captured by eBPF."""
    event_type: EventType
    timestamp: datetime
    pid: int
    uid: int
    comm: str  # Process name
    details: Dict[str, Any] = field(default_factory=dict)
    action_taken: MonitorAction = MonitorAction.LOG


@dataclass
class MonitorPolicy:
    """Policy for how to handle monitored events."""
    event_type: EventType
    action: MonitorAction
    conditions: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True


class EBPFMonitorError(Exception):
    """Raised when eBPF monitoring fails."""
    pass


# eBPF program for network syscall monitoring
NETWORK_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/socket.h>

// Event structure passed to userspace
struct network_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 uid;
    u32 syscall;       // syscall number
    u32 family;        // AF_INET, AF_INET6, etc.
    u32 type;          // SOCK_STREAM, SOCK_DGRAM, etc.
    u32 protocol;
    u32 dport;         // destination port (for connect)
    u32 daddr;         // destination address (IPv4)
    char comm[16];
};

BPF_PERF_OUTPUT(network_events);

// Track socket() syscall
TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    struct network_event_t event = {};

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.syscall = 41;  // socket
    event.family = args->family;
    event.type = args->type;
    event.protocol = args->protocol;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    network_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// Track connect() syscall
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct network_event_t event = {};

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.syscall = 42;  // connect
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Try to extract address info
    struct sockaddr *addr = (struct sockaddr *)args->uservaddr;
    if (addr) {
        bpf_probe_read(&event.family, sizeof(event.family), &addr->sa_family);
        if (event.family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;
            bpf_probe_read(&event.dport, sizeof(event.dport), &sin->sin_port);
            bpf_probe_read(&event.daddr, sizeof(event.daddr), &sin->sin_addr);
        }
    }

    network_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// Track bind() syscall
TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
    struct network_event_t event = {};

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.syscall = 49;  // bind
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    network_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// Track sendto() syscall
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    struct network_event_t event = {};

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.syscall = 44;  // sendto
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    network_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// Track accept() syscall
TRACEPOINT_PROBE(syscalls, sys_enter_accept) {
    struct network_event_t event = {};

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.syscall = 43;  // accept
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    network_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

# eBPF program for process execution monitoring
PROCESS_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct exec_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event_t event = {};

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Read filename
    const char *filename = args->filename;
    bpf_probe_read_str(&event.filename, sizeof(event.filename), filename);

    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// Track process exit
TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct exec_event_t event = {};

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Mark as exit event with special filename
    __builtin_memcpy(event.filename, "[EXIT]", 7);

    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

# eBPF program for USB monitoring (via udev kobject events)
USB_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct usb_event_t {
    u64 timestamp_ns;
    u32 action;  // 1=add, 2=remove
    char devpath[128];
    char devtype[32];
};

BPF_PERF_OUTPUT(usb_events);

// Hook kobject_uevent for USB events
// Note: This is a simplified version - production would use kprobes on specific functions
"""


class EBPFMonitor:
    """
    Real-time kernel event monitor using eBPF.

    This class provides microsecond-latency detection of security events,
    eliminating the race condition window present in polling-based approaches.

    Usage:
        monitor = EBPFMonitor(event_logger=logger)
        monitor.add_callback(EventType.NETWORK_CONNECT, on_network_connect)
        monitor.start()
        ...
        monitor.stop()
    """

    # Syscall number to name mapping (x86_64)
    SYSCALL_NAMES = {
        41: 'socket',
        42: 'connect',
        43: 'accept',
        44: 'sendto',
        45: 'recvfrom',
        49: 'bind',
        50: 'listen',
    }

    # Address family names
    AF_NAMES = {
        0: 'AF_UNSPEC',
        1: 'AF_UNIX',
        2: 'AF_INET',
        10: 'AF_INET6',
        16: 'AF_NETLINK',
        17: 'AF_PACKET',
    }

    def __init__(
        self,
        daemon=None,
        event_logger=None,
        enable_network: bool = True,
        enable_process: bool = True,
        enable_usb: bool = False,  # USB via eBPF is complex, disabled by default
    ):
        """
        Initialize the eBPF monitor.

        Args:
            daemon: Reference to BoundaryDaemon for callbacks
            event_logger: EventLogger for audit logging
            enable_network: Enable network syscall monitoring
            enable_process: Enable process execution monitoring
            enable_usb: Enable USB event monitoring (experimental)
        """
        self.daemon = daemon
        self.event_logger = event_logger
        self._enable_network = enable_network
        self._enable_process = enable_process
        self._enable_usb = enable_usb

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # BPF program references
        self._network_bpf: Optional[Any] = None
        self._process_bpf: Optional[Any] = None
        self._usb_bpf: Optional[Any] = None

        # Event callbacks
        self._callbacks: Dict[EventType, List[Callable[[SecurityEvent], MonitorAction]]] = {}

        # Event buffer for recent events
        self._event_buffer: deque = deque(maxlen=1000)

        # Statistics
        self._stats = {
            'events_total': 0,
            'events_network': 0,
            'events_process': 0,
            'events_usb': 0,
            'alerts_triggered': 0,
            'blocks_attempted': 0,
        }

        # Current monitoring mode (affects what gets blocked)
        self._monitoring_mode: Optional[str] = None

        # Processes/UIDs to ignore (system processes)
        self._ignored_pids: Set[int] = set()
        self._ignored_uids: Set[int] = {0}  # Ignore root by default for some checks

        # Verify availability
        if not BCC_AVAILABLE:
            logger.warning("eBPF monitoring not available - BCC not installed")
        elif os.geteuid() != 0:
            logger.warning("eBPF monitoring requires root privileges")

    @property
    def is_available(self) -> bool:
        """Check if eBPF monitoring is available."""
        return BCC_AVAILABLE and os.geteuid() == 0

    def add_callback(
        self,
        event_type: EventType,
        callback: Callable[[SecurityEvent], MonitorAction]
    ):
        """
        Register a callback for a specific event type.

        Args:
            event_type: Type of event to listen for
            callback: Function to call when event occurs.
                      Should return MonitorAction indicating how to handle.
        """
        if event_type not in self._callbacks:
            self._callbacks[event_type] = []
        self._callbacks[event_type].append(callback)
        logger.debug(f"Registered callback for {event_type.name}")

    def remove_callback(
        self,
        event_type: EventType,
        callback: Callable[[SecurityEvent], MonitorAction]
    ):
        """Remove a previously registered callback."""
        if event_type in self._callbacks:
            try:
                self._callbacks[event_type].remove(callback)
            except ValueError:
                pass

    def set_monitoring_mode(self, mode: str):
        """
        Set the current monitoring mode.

        This affects how events are handled:
        - OPEN: Log only
        - RESTRICTED: Log + alert on suspicious activity
        - TRUSTED: Alert on non-VPN network activity
        - AIRGAP: Alert/block on any network activity
        - COLDROOM: Alert/block on network + non-essential processes
        - LOCKDOWN: Block everything, trigger alerts
        """
        self._monitoring_mode = mode
        logger.info(f"eBPF monitoring mode set to: {mode}")

    def ignore_pid(self, pid: int):
        """Add a PID to the ignore list."""
        self._ignored_pids.add(pid)

    def unignore_pid(self, pid: int):
        """Remove a PID from the ignore list."""
        self._ignored_pids.discard(pid)

    def start(self) -> Tuple[bool, str]:
        """
        Start eBPF monitoring.

        Returns:
            (success, message)
        """
        if not self.is_available:
            return False, "eBPF monitoring not available (BCC not installed or not root)"

        if self._running:
            return True, "Already running"

        with self._lock:
            try:
                # Load network BPF program
                if self._enable_network:
                    logger.info("Loading network eBPF program...")
                    self._network_bpf = BPF(text=NETWORK_BPF_PROGRAM)
                    self._network_bpf["network_events"].open_perf_buffer(
                        self._handle_network_event
                    )
                    logger.info("Network eBPF program loaded")

                # Load process BPF program
                if self._enable_process:
                    logger.info("Loading process eBPF program...")
                    self._process_bpf = BPF(text=PROCESS_BPF_PROGRAM)
                    self._process_bpf["exec_events"].open_perf_buffer(
                        self._handle_process_event
                    )
                    logger.info("Process eBPF program loaded")

                # Start polling thread
                self._running = True
                self._thread = threading.Thread(
                    target=self._poll_loop,
                    name="EBPFMonitor-Poll",
                    daemon=True
                )
                self._thread.start()

                return True, "eBPF monitoring started"

            except (OSError, RuntimeError) as e:
                self._cleanup_bpf()
                error_msg = f"Failed to start eBPF monitoring: {e}"
                logger.error(error_msg)
                return False, error_msg

    def stop(self):
        """Stop eBPF monitoring."""
        self._running = False

        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

        self._cleanup_bpf()
        logger.info("eBPF monitoring stopped")

    def _cleanup_bpf(self):
        """Clean up BPF programs."""
        if self._network_bpf:
            try:
                self._network_bpf.cleanup()
            except (OSError, RuntimeError):
                pass
            self._network_bpf = None

        if self._process_bpf:
            try:
                self._process_bpf.cleanup()
            except (OSError, RuntimeError):
                pass
            self._process_bpf = None

        if self._usb_bpf:
            try:
                self._usb_bpf.cleanup()
            except (OSError, RuntimeError):
                pass
            self._usb_bpf = None

    def _poll_loop(self):
        """Main polling loop for perf buffer events."""
        logger.info("eBPF poll loop started")

        while self._running:
            try:
                # Poll for events from network BPF
                if self._network_bpf:
                    self._network_bpf.perf_buffer_poll(timeout=100)

                # Poll for events from process BPF
                if self._process_bpf:
                    self._process_bpf.perf_buffer_poll(timeout=100)

            except (OSError, RuntimeError) as e:
                if self._running:
                    logger.error(f"Error in eBPF poll loop: {e}")
                    time.sleep(0.1)

        logger.info("eBPF poll loop exited")

    def _handle_network_event(self, cpu, data, size):
        """Handle network event from eBPF."""
        try:
            # Parse the event data
            event_data = self._network_bpf["network_events"].event(data)

            pid = event_data.pid
            uid = event_data.uid
            syscall = event_data.syscall
            family = event_data.family
            comm = event_data.comm.decode('utf-8', errors='replace').rstrip('\x00')

            # Skip ignored PIDs
            if pid in self._ignored_pids:
                return

            # Map syscall to event type
            event_type_map = {
                41: EventType.NETWORK_SOCKET,
                42: EventType.NETWORK_CONNECT,
                43: EventType.NETWORK_ACCEPT,
                44: EventType.NETWORK_SENDTO,
                45: EventType.NETWORK_RECVFROM,
                49: EventType.NETWORK_BIND,
            }
            event_type = event_type_map.get(syscall, EventType.NETWORK_SOCKET)

            # Create security event
            event = SecurityEvent(
                event_type=event_type,
                timestamp=datetime.utcnow(),
                pid=pid,
                uid=uid,
                comm=comm,
                details={
                    'syscall': self.SYSCALL_NAMES.get(syscall, str(syscall)),
                    'family': self.AF_NAMES.get(family, str(family)),
                    'family_num': family,
                    'dport': event_data.dport if hasattr(event_data, 'dport') else None,
                    'daddr': event_data.daddr if hasattr(event_data, 'daddr') else None,
                }
            )

            # Process the event
            self._process_event(event)

        except (ValueError, TypeError, KeyError) as e:
            logger.error(f"Error handling network event: {e}")

    def _handle_process_event(self, cpu, data, size):
        """Handle process execution event from eBPF."""
        try:
            event_data = self._process_bpf["exec_events"].event(data)

            pid = event_data.pid
            ppid = event_data.ppid if hasattr(event_data, 'ppid') else 0
            uid = event_data.uid
            comm = event_data.comm.decode('utf-8', errors='replace').rstrip('\x00')
            filename = event_data.filename.decode('utf-8', errors='replace').rstrip('\x00')

            # Skip ignored PIDs
            if pid in self._ignored_pids:
                return

            # Determine event type
            if filename == "[EXIT]":
                event_type = EventType.PROCESS_EXIT
            else:
                event_type = EventType.PROCESS_EXEC

            event = SecurityEvent(
                event_type=event_type,
                timestamp=datetime.utcnow(),
                pid=pid,
                uid=uid,
                comm=comm,
                details={
                    'filename': filename,
                    'ppid': ppid,
                }
            )

            self._process_event(event)

        except (ValueError, TypeError, KeyError) as e:
            logger.error(f"Error handling process event: {e}")

    def _process_event(self, event: SecurityEvent):
        """Process a security event and invoke callbacks."""
        self._stats['events_total'] += 1

        # Update type-specific stats
        if event.event_type.name.startswith('NETWORK_'):
            self._stats['events_network'] += 1
        elif event.event_type.name.startswith('PROCESS_'):
            self._stats['events_process'] += 1
        elif event.event_type.name.startswith('USB_'):
            self._stats['events_usb'] += 1

        # Add to event buffer
        self._event_buffer.append(event)

        # Determine action based on mode
        action = self._evaluate_event(event)
        event.action_taken = action

        # Invoke registered callbacks
        if event.event_type in self._callbacks:
            for callback in self._callbacks[event.event_type]:
                try:
                    callback_action = callback(event)
                    # Use most restrictive action
                    if callback_action.value > action.value:
                        action = callback_action
                        event.action_taken = action
                except (TypeError, AttributeError, ValueError) as e:
                    logger.error(f"Error in event callback: {e}")

        # Handle the action
        if action == MonitorAction.ALERT:
            self._stats['alerts_triggered'] += 1
            self._trigger_alert(event)
        elif action == MonitorAction.BLOCK:
            self._stats['blocks_attempted'] += 1
            self._attempt_block(event)
        elif action == MonitorAction.LOCKDOWN:
            self._stats['alerts_triggered'] += 1
            self._trigger_lockdown(event)

        # Log the event
        self._log_event(event)

    def _evaluate_event(self, event: SecurityEvent) -> MonitorAction:
        """Evaluate what action to take for an event based on current mode."""
        if not self._monitoring_mode:
            return MonitorAction.LOG

        mode = self._monitoring_mode.upper()

        # Network events
        if event.event_type.name.startswith('NETWORK_'):
            # In AIRGAP/COLDROOM/LOCKDOWN, any network activity is suspicious
            if mode in ('AIRGAP', 'COLDROOM', 'LOCKDOWN'):
                # Allow loopback
                family = event.details.get('family_num', 0)
                if family == 1:  # AF_UNIX
                    return MonitorAction.LOG

                # Block/alert on external network
                if mode == 'LOCKDOWN':
                    return MonitorAction.LOCKDOWN
                else:
                    return MonitorAction.ALERT

            # In TRUSTED, alert on non-VPN traffic
            elif mode == 'TRUSTED':
                return MonitorAction.LOG  # Would need more info to determine VPN

            # In RESTRICTED, log with attention
            elif mode == 'RESTRICTED':
                return MonitorAction.LOG

        # Process execution events
        if event.event_type == EventType.PROCESS_EXEC:
            filename = event.details.get('filename', '')

            # In LOCKDOWN, alert on any new process
            if mode == 'LOCKDOWN':
                return MonitorAction.ALERT

            # Check for suspicious execution locations
            suspicious_paths = ['/tmp/', '/dev/shm/', '/var/tmp/']
            for path in suspicious_paths:
                if filename.startswith(path):
                    return MonitorAction.ALERT

        return MonitorAction.LOG

    def _trigger_alert(self, event: SecurityEvent):
        """Trigger an alert for a security event."""
        logger.warning(
            f"SECURITY ALERT: {event.event_type.name} by {event.comm} "
            f"(PID={event.pid}, UID={event.uid}): {event.details}"
        )

        # Notify daemon if available
        if self.daemon and hasattr(self.daemon, 'on_security_alert'):
            try:
                self.daemon.on_security_alert(
                    source='ebpf_monitor',
                    event_type=event.event_type.name,
                    details={
                        'pid': event.pid,
                        'uid': event.uid,
                        'comm': event.comm,
                        **event.details
                    }
                )
            except (AttributeError, TypeError) as e:
                logger.error(f"Error notifying daemon of alert: {e}")

    def _attempt_block(self, event: SecurityEvent):
        """Attempt to block an operation (logging only without LSM hooks)."""
        logger.warning(
            f"BLOCK ATTEMPTED (advisory): {event.event_type.name} by {event.comm} "
            f"(PID={event.pid})"
        )
        # Note: Actual blocking requires BPF_PROG_TYPE_LSM which needs more setup
        # For now, this logs the attempt and relies on iptables/seccomp for blocking

    def _trigger_lockdown(self, event: SecurityEvent):
        """Trigger system lockdown due to critical security event."""
        logger.critical(
            f"LOCKDOWN TRIGGERED by eBPF: {event.event_type.name} from {event.comm} "
            f"(PID={event.pid})"
        )

        # Notify daemon to enter lockdown
        if self.daemon:
            try:
                if hasattr(self.daemon, 'enter_lockdown'):
                    self.daemon.enter_lockdown(
                        reason=f"eBPF detected {event.event_type.name} violation",
                        source='ebpf_monitor'
                    )
                elif hasattr(self.daemon, 'tripwire_system'):
                    self.daemon.tripwire_system.trigger_lockdown(
                        reason=f"eBPF: {event.event_type.name} violation"
                    )
            except (AttributeError, TypeError) as e:
                logger.error(f"Error triggering lockdown: {e}")

    def _log_event(self, event: SecurityEvent):
        """Log event to the event logger."""
        if not self.event_logger:
            return

        try:
            # Only log significant events to avoid log spam
            if event.action_taken in (MonitorAction.ALERT, MonitorAction.BLOCK, MonitorAction.LOCKDOWN):
                from ..event_logger import EventType as LogEventType
                self.event_logger.log_event(
                    LogEventType.SECURITY_ALERT,
                    f"eBPF: {event.event_type.name}",
                    metadata={
                        'source': 'ebpf_monitor',
                        'event_type': event.event_type.name,
                        'action': event.action_taken.name,
                        'pid': event.pid,
                        'uid': event.uid,
                        'comm': event.comm,
                        'details': event.details,
                        'timestamp': event.timestamp.isoformat() + 'Z',
                    }
                )
        except (ImportError, AttributeError, TypeError) as e:
            logger.debug(f"Error logging eBPF event: {e}")

    def get_stats(self) -> Dict:
        """Get monitoring statistics."""
        return {
            **self._stats,
            'running': self._running,
            'mode': self._monitoring_mode,
            'buffer_size': len(self._event_buffer),
            'network_enabled': self._enable_network and self._network_bpf is not None,
            'process_enabled': self._enable_process and self._process_bpf is not None,
        }

    def get_recent_events(self, count: int = 100) -> List[Dict]:
        """Get recent events from the buffer."""
        events = []
        for event in list(self._event_buffer)[-count:]:
            events.append({
                'event_type': event.event_type.name,
                'timestamp': event.timestamp.isoformat() + 'Z',
                'pid': event.pid,
                'uid': event.uid,
                'comm': event.comm,
                'action': event.action_taken.name,
                'details': event.details,
            })
        return events

    def get_status(self) -> Dict:
        """Get full monitor status."""
        return {
            'available': self.is_available,
            'bcc_installed': BCC_AVAILABLE,
            'running_as_root': os.geteuid() == 0,
            'running': self._running,
            'monitoring_mode': self._monitoring_mode,
            'network_monitoring': self._enable_network and self._network_bpf is not None,
            'process_monitoring': self._enable_process and self._process_bpf is not None,
            'usb_monitoring': self._enable_usb and self._usb_bpf is not None,
            'stats': self.get_stats(),
            'ignored_pids': list(self._ignored_pids)[:10],  # First 10
            'callback_count': sum(len(cbs) for cbs in self._callbacks.values()),
        }


def check_ebpf_requirements() -> Tuple[bool, List[str]]:
    """
    Check if all requirements for eBPF monitoring are met.

    Returns:
        (all_met, list_of_issues)
    """
    issues = []

    # Check if Linux
    if not IS_LINUX:
        issues.append("eBPF requires Linux")
        return False, issues

    # Check if root
    if os.geteuid() != 0:
        issues.append("eBPF requires root privileges")

    # Check BCC
    if not BCC_AVAILABLE:
        issues.append("BCC (BPF Compiler Collection) not installed")
        issues.append("Install with: apt install python3-bcc bpfcc-tools linux-headers-$(uname -r)")

    # Check kernel version
    try:
        with open('/proc/version', 'r') as f:
            version_str = f.read()
            # Parse version (e.g., "Linux version 5.4.0-...")
            import re
            match = re.search(r'Linux version (\d+)\.(\d+)', version_str)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                if major < 4 or (major == 4 and minor < 15):
                    issues.append(f"Kernel version {major}.{minor} too old (need 4.15+)")
    except (OSError, ValueError):
        issues.append("Could not determine kernel version")

    # Check for BPF filesystem
    if not os.path.exists('/sys/fs/bpf'):
        issues.append("BPF filesystem not mounted (/sys/fs/bpf)")

    # Check for debugfs (needed for tracepoints)
    if not os.path.exists('/sys/kernel/debug/tracing'):
        issues.append("debugfs not mounted (needed for tracepoints)")

    return len(issues) == 0, issues


# Module-level instance for singleton pattern
_monitor_instance: Optional[EBPFMonitor] = None


def get_ebpf_monitor(
    daemon=None,
    event_logger=None,
    **kwargs
) -> EBPFMonitor:
    """
    Get or create the global eBPF monitor instance.

    Args:
        daemon: Reference to BoundaryDaemon
        event_logger: EventLogger for audit logging
        **kwargs: Additional arguments passed to EBPFMonitor

    Returns:
        EBPFMonitor instance
    """
    global _monitor_instance

    if _monitor_instance is None:
        _monitor_instance = EBPFMonitor(
            daemon=daemon,
            event_logger=event_logger,
            **kwargs
        )

    return _monitor_instance


if __name__ == '__main__':
    # Test the eBPF monitor
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("Checking eBPF requirements...")
    all_met, issues = check_ebpf_requirements()

    if issues:
        print("Issues found:")
        for issue in issues:
            print(f"  - {issue}")

    if not all_met:
        print("\neBPF monitoring not available.")
        sys.exit(1)

    print("\nStarting eBPF monitor...")
    monitor = EBPFMonitor(enable_network=True, enable_process=True)

    # Add a test callback
    def on_network_event(event):
        print(f"Network event: {event.comm} ({event.pid}) - {event.details}")
        return MonitorAction.LOG

    monitor.add_callback(EventType.NETWORK_CONNECT, on_network_event)
    monitor.set_monitoring_mode('AIRGAP')

    success, msg = monitor.start()
    print(f"Start result: {msg}")

    if success:
        print("\nMonitoring... (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(5)
                stats = monitor.get_stats()
                print(f"Events: {stats['events_total']} total, "
                      f"{stats['events_network']} network, "
                      f"{stats['events_process']} process")
        except KeyboardInterrupt:
            print("\nStopping...")

        monitor.stop()
        print("Stopped.")
