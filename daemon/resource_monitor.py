"""
Resource Monitor - System Resource Tracking and Leak Detection
Monitors file descriptors, threads, disk space, CPU, and network connections.

Features:
- File descriptor monitoring with leak detection
- Thread count tracking
- Disk space monitoring for log directories
- CPU usage tracking
- Network connection monitoring
- Configurable alert thresholds
- Integration with OpenTelemetry metrics
"""

import os
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable, Any, Set
from datetime import datetime
from enum import Enum
from collections import deque
from pathlib import Path

logger = logging.getLogger(__name__)

# Try importing psutil
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None


class ResourceAlertLevel(Enum):
    """Resource alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class ResourceType(Enum):
    """Types of monitored resources"""
    FILE_DESCRIPTORS = "file_descriptors"
    THREADS = "threads"
    DISK_SPACE = "disk_space"
    CPU = "cpu"
    CONNECTIONS = "connections"


@dataclass
class ResourceSnapshot:
    """Point-in-time resource measurement"""
    timestamp: float

    # File descriptors
    fd_count: int
    fd_limit: int  # ulimit -n

    # Threads
    thread_count: int

    # CPU
    cpu_percent: float

    # Disk (for monitored paths)
    disk_usage: Dict[str, Dict]  # path -> {total, used, free, percent}

    # Network connections
    connection_count: int
    connections_by_status: Dict[str, int]

    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'timestamp_iso': datetime.fromtimestamp(self.timestamp).isoformat(),
            'file_descriptors': {
                'count': self.fd_count,
                'limit': self.fd_limit,
                'percent_used': round((self.fd_count / self.fd_limit) * 100, 1) if self.fd_limit > 0 else 0,
            },
            'threads': {
                'count': self.thread_count,
            },
            'cpu': {
                'percent': self.cpu_percent,
            },
            'disk': self.disk_usage,
            'connections': {
                'count': self.connection_count,
                'by_status': self.connections_by_status,
            },
        }


@dataclass
class ResourceAlert:
    """Resource-related alert"""
    timestamp: float
    level: ResourceAlertLevel
    resource_type: ResourceType
    alert_type: str
    message: str
    current_value: float
    threshold: float
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'timestamp_iso': datetime.fromtimestamp(self.timestamp).isoformat(),
            'level': self.level.value,
            'resource_type': self.resource_type.value,
            'alert_type': self.alert_type,
            'message': self.message,
            'current_value': self.current_value,
            'threshold': self.threshold,
            'metadata': self.metadata,
        }


@dataclass
class ResourceMonitorConfig:
    """Configuration for resource monitoring"""
    # Sampling configuration
    sample_interval: float = 10.0     # Seconds between samples
    history_size: int = 360           # Keep 1 hour at 10s intervals

    # File descriptor thresholds
    fd_warning_percent: float = 70.0   # % of ulimit
    fd_critical_percent: float = 90.0
    fd_growth_warning: int = 100       # FDs gained in growth window
    fd_growth_window_samples: int = 30 # 5 min at 10s

    # Thread thresholds
    thread_warning: int = 100
    thread_critical: int = 200
    thread_growth_warning: int = 20    # Threads gained in growth window

    # CPU thresholds
    cpu_warning_percent: float = 80.0
    cpu_critical_percent: float = 95.0
    cpu_sustained_samples: int = 6     # 1 min at 10s - must be high for this long
    cpu_spike_threshold: float = 50.0  # Sudden jump in CPU percent
    cpu_alert_cooldown: int = 30       # Samples between repeated alerts (5 min)

    # Disk thresholds
    disk_warning_percent: float = 80.0
    disk_critical_percent: float = 95.0
    disk_paths: List[str] = field(default_factory=list)  # Paths to monitor

    # Connection thresholds
    connection_warning: int = 500
    connection_critical: int = 1000

    def to_dict(self) -> Dict:
        return {
            'sample_interval': self.sample_interval,
            'history_size': self.history_size,
            'fd_warning_percent': self.fd_warning_percent,
            'fd_critical_percent': self.fd_critical_percent,
            'fd_growth_warning': self.fd_growth_warning,
            'thread_warning': self.thread_warning,
            'thread_critical': self.thread_critical,
            'cpu_warning_percent': self.cpu_warning_percent,
            'cpu_critical_percent': self.cpu_critical_percent,
            'cpu_sustained_samples': self.cpu_sustained_samples,
            'cpu_spike_threshold': self.cpu_spike_threshold,
            'cpu_alert_cooldown': self.cpu_alert_cooldown,
            'disk_warning_percent': self.disk_warning_percent,
            'disk_critical_percent': self.disk_critical_percent,
            'disk_paths': self.disk_paths,
            'connection_warning': self.connection_warning,
            'connection_critical': self.connection_critical,
        }


class ResourceMonitor:
    """
    Monitors system resources and detects potential leaks.

    Provides:
    - File descriptor monitoring with leak detection
    - Thread count tracking
    - Disk space monitoring
    - CPU usage tracking
    - Network connection monitoring
    - Configurable alert thresholds
    """

    def __init__(
        self,
        daemon=None,
        config: Optional[ResourceMonitorConfig] = None,
        on_alert: Optional[Callable[[ResourceAlert], None]] = None,
    ):
        """
        Initialize ResourceMonitor.

        Args:
            daemon: Reference to BoundaryDaemon instance
            config: ResourceMonitorConfig instance
            on_alert: Callback for resource alerts
        """
        self.daemon = daemon
        self.config = config or ResourceMonitorConfig()
        self._on_alert = on_alert

        # State
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # History storage
        self._history: deque = deque(maxlen=self.config.history_size)
        self._alerts: List[ResourceAlert] = []
        self._alert_history_size = 100

        # Current state
        self._current_snapshot: Optional[ResourceSnapshot] = None

        # Baseline values for leak detection
        self._baseline_fd_count: Optional[int] = None
        self._baseline_thread_count: Optional[int] = None

        # Enhanced CPU sustained high tracking
        self._cpu_warning_samples: int = 0       # Consecutive samples at warning+
        self._cpu_critical_samples: int = 0      # Consecutive samples at critical
        self._cpu_peak_during_sustained: float = 0.0  # Peak CPU during current sustained period
        self._cpu_sustained_start: Optional[float] = None  # When sustained period started
        self._last_cpu_alert_sample: int = 0     # Sample count at last alert (for cooldown)
        self._sample_count: int = 0              # Total samples taken
        self._previous_cpu_percent: float = 0.0  # For spike detection
        self._cpu_was_sustained: bool = False    # Track if we need to send recovery alert

        # Process handle
        self._process: Optional[Any] = None
        if PSUTIL_AVAILABLE:
            self._process = psutil.Process(os.getpid())

        # Telemetry integration
        self._telemetry_manager = None

        # Default disk paths to monitor
        if not self.config.disk_paths:
            self.config.disk_paths = [
                '/var/log',
                '/tmp',
                str(Path.home()),
            ]

    @property
    def is_available(self) -> bool:
        """Check if resource monitoring is available"""
        return PSUTIL_AVAILABLE

    def set_telemetry_manager(self, telemetry_manager):
        """Set telemetry manager for metrics export"""
        self._telemetry_manager = telemetry_manager

    def start(self):
        """Start resource monitoring"""
        if self._running:
            return

        if not self.is_available:
            logger.warning("Resource monitoring not available (psutil not installed)")
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info(f"Resource monitor started (interval: {self.config.sample_interval}s)")

    def stop(self):
        """Stop resource monitoring"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("Resource monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                snapshot = self._take_snapshot()

                with self._lock:
                    self._current_snapshot = snapshot
                    self._history.append(snapshot)
                    self._sample_count += 1

                    # Set baselines on first sample
                    if self._baseline_fd_count is None:
                        self._baseline_fd_count = snapshot.fd_count
                    if self._baseline_thread_count is None:
                        self._baseline_thread_count = snapshot.thread_count

                # Check all thresholds
                self._check_fd_thresholds(snapshot)
                self._check_thread_thresholds(snapshot)
                self._check_cpu_thresholds(snapshot)
                self._check_disk_thresholds(snapshot)
                self._check_connection_thresholds(snapshot)

                # Detect leaks
                self._detect_fd_leak()
                self._detect_thread_leak()

                # Export metrics
                self._export_metrics(snapshot)

                time.sleep(self.config.sample_interval)

            except Exception as e:
                logger.error(f"Error in resource monitor loop: {e}")
                time.sleep(self.config.sample_interval)

    def _take_snapshot(self) -> ResourceSnapshot:
        """Take a resource snapshot"""
        # File descriptors
        try:
            fd_count = self._process.num_fds()
        except (AttributeError, psutil.Error):
            # num_fds() not available on Windows
            fd_count = len(self._process.open_files()) + len(self._process.connections())

        # Get FD limit
        try:
            import resource
            fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        except (ImportError, Exception):
            fd_limit = 1024  # Default assumption

        # Threads
        thread_count = self._process.num_threads()

        # CPU (interval=None returns since last call)
        cpu_percent = self._process.cpu_percent(interval=None)

        # Disk usage for monitored paths
        disk_usage = {}
        for path in self.config.disk_paths:
            try:
                if os.path.exists(path):
                    usage = psutil.disk_usage(path)
                    disk_usage[path] = {
                        'total_gb': round(usage.total / (1024**3), 2),
                        'used_gb': round(usage.used / (1024**3), 2),
                        'free_gb': round(usage.free / (1024**3), 2),
                        'percent': usage.percent,
                    }
            except (PermissionError, OSError):
                pass

        # Network connections
        try:
            connections = self._process.connections()
            connection_count = len(connections)
            connections_by_status = {}
            for conn in connections:
                status = conn.status if hasattr(conn, 'status') else 'unknown'
                connections_by_status[status] = connections_by_status.get(status, 0) + 1
        except (psutil.AccessDenied, psutil.Error):
            connection_count = 0
            connections_by_status = {}

        return ResourceSnapshot(
            timestamp=time.time(),
            fd_count=fd_count,
            fd_limit=fd_limit,
            thread_count=thread_count,
            cpu_percent=cpu_percent,
            disk_usage=disk_usage,
            connection_count=connection_count,
            connections_by_status=connections_by_status,
        )

    def _check_fd_thresholds(self, snapshot: ResourceSnapshot):
        """Check file descriptor thresholds"""
        if snapshot.fd_limit <= 0:
            return

        fd_percent = (snapshot.fd_count / snapshot.fd_limit) * 100

        if fd_percent >= self.config.fd_critical_percent:
            self._raise_alert(
                ResourceAlertLevel.CRITICAL,
                ResourceType.FILE_DESCRIPTORS,
                "fd_critical",
                f"File descriptors critical: {snapshot.fd_count}/{snapshot.fd_limit} "
                f"({fd_percent:.1f}% >= {self.config.fd_critical_percent}%)",
                fd_percent,
                self.config.fd_critical_percent,
                metadata={'fd_count': snapshot.fd_count, 'fd_limit': snapshot.fd_limit},
            )
        elif fd_percent >= self.config.fd_warning_percent:
            self._raise_alert(
                ResourceAlertLevel.WARNING,
                ResourceType.FILE_DESCRIPTORS,
                "fd_warning",
                f"File descriptors warning: {snapshot.fd_count}/{snapshot.fd_limit} "
                f"({fd_percent:.1f}% >= {self.config.fd_warning_percent}%)",
                fd_percent,
                self.config.fd_warning_percent,
                metadata={'fd_count': snapshot.fd_count, 'fd_limit': snapshot.fd_limit},
            )

    def _check_thread_thresholds(self, snapshot: ResourceSnapshot):
        """Check thread count thresholds"""
        if snapshot.thread_count >= self.config.thread_critical:
            self._raise_alert(
                ResourceAlertLevel.CRITICAL,
                ResourceType.THREADS,
                "thread_critical",
                f"Thread count critical: {snapshot.thread_count} >= {self.config.thread_critical}",
                snapshot.thread_count,
                self.config.thread_critical,
            )
        elif snapshot.thread_count >= self.config.thread_warning:
            self._raise_alert(
                ResourceAlertLevel.WARNING,
                ResourceType.THREADS,
                "thread_warning",
                f"Thread count warning: {snapshot.thread_count} >= {self.config.thread_warning}",
                snapshot.thread_count,
                self.config.thread_warning,
            )

    def _check_cpu_thresholds(self, snapshot: ResourceSnapshot):
        """
        Enhanced CPU usage monitoring with:
        - Sustained high detection (warning and critical tracked separately)
        - Spike detection for sudden CPU jumps
        - Alert cooldown to prevent log spam
        - Recovery alerts when CPU normalizes
        - Peak tracking during sustained periods
        """
        cpu = snapshot.cpu_percent
        now = time.time()

        # Check for CPU spike (sudden jump)
        cpu_delta = cpu - self._previous_cpu_percent
        if cpu_delta >= self.config.cpu_spike_threshold and self._sample_count > 1:
            self._raise_alert(
                ResourceAlertLevel.WARNING,
                ResourceType.CPU,
                "cpu_spike",
                f"CPU spike detected: {self._previous_cpu_percent:.1f}% -> {cpu:.1f}% "
                f"(+{cpu_delta:.1f}%)",
                cpu,
                self.config.cpu_spike_threshold,
                metadata={
                    'previous': self._previous_cpu_percent,
                    'delta': cpu_delta,
                },
            )
        self._previous_cpu_percent = cpu

        # Track sustained high CPU
        is_warning = cpu >= self.config.cpu_warning_percent
        is_critical = cpu >= self.config.cpu_critical_percent

        if is_warning:
            # Start or continue sustained period
            if self._cpu_warning_samples == 0:
                self._cpu_sustained_start = now
                self._cpu_peak_during_sustained = cpu
            else:
                self._cpu_peak_during_sustained = max(self._cpu_peak_during_sustained, cpu)

            self._cpu_warning_samples += 1
            if is_critical:
                self._cpu_critical_samples += 1

            # Check if we should alert (sustained threshold met and cooldown expired)
            samples_since_alert = self._sample_count - self._last_cpu_alert_sample
            cooldown_expired = samples_since_alert >= self.config.cpu_alert_cooldown

            if self._cpu_warning_samples >= self.config.cpu_sustained_samples:
                sustained_duration = now - self._cpu_sustained_start if self._cpu_sustained_start else 0

                # Determine alert level based on critical samples
                if self._cpu_critical_samples >= self.config.cpu_sustained_samples:
                    if cooldown_expired or not self._cpu_was_sustained:
                        self._raise_alert(
                            ResourceAlertLevel.CRITICAL,
                            ResourceType.CPU,
                            "cpu_sustained_critical",
                            f"CPU sustained critical: {cpu:.1f}% (peak: {self._cpu_peak_during_sustained:.1f}%) "
                            f"for {sustained_duration:.0f}s",
                            cpu,
                            self.config.cpu_critical_percent,
                            metadata={
                                'sustained_samples': self._cpu_critical_samples,
                                'peak_percent': self._cpu_peak_during_sustained,
                                'duration_seconds': sustained_duration,
                            },
                        )
                        self._last_cpu_alert_sample = self._sample_count
                        self._cpu_was_sustained = True
                else:
                    if cooldown_expired or not self._cpu_was_sustained:
                        self._raise_alert(
                            ResourceAlertLevel.WARNING,
                            ResourceType.CPU,
                            "cpu_sustained_warning",
                            f"CPU sustained warning: {cpu:.1f}% (peak: {self._cpu_peak_during_sustained:.1f}%) "
                            f"for {sustained_duration:.0f}s",
                            cpu,
                            self.config.cpu_warning_percent,
                            metadata={
                                'sustained_samples': self._cpu_warning_samples,
                                'peak_percent': self._cpu_peak_during_sustained,
                                'duration_seconds': sustained_duration,
                            },
                        )
                        self._last_cpu_alert_sample = self._sample_count
                        self._cpu_was_sustained = True
        else:
            # CPU returned to normal
            if self._cpu_was_sustained and self._cpu_sustained_start:
                # Send recovery alert
                sustained_duration = now - self._cpu_sustained_start
                self._raise_alert(
                    ResourceAlertLevel.INFO,
                    ResourceType.CPU,
                    "cpu_recovered",
                    f"CPU recovered: {cpu:.1f}% (was sustained high for {sustained_duration:.0f}s, "
                    f"peak: {self._cpu_peak_during_sustained:.1f}%)",
                    cpu,
                    self.config.cpu_warning_percent,
                    metadata={
                        'peak_percent': self._cpu_peak_during_sustained,
                        'duration_seconds': sustained_duration,
                    },
                )

            # Reset sustained tracking
            self._cpu_warning_samples = 0
            self._cpu_critical_samples = 0
            self._cpu_peak_during_sustained = 0.0
            self._cpu_sustained_start = None
            self._cpu_was_sustained = False

    def _check_disk_thresholds(self, snapshot: ResourceSnapshot):
        """Check disk space thresholds"""
        for path, usage in snapshot.disk_usage.items():
            percent = usage['percent']

            if percent >= self.config.disk_critical_percent:
                self._raise_alert(
                    ResourceAlertLevel.CRITICAL,
                    ResourceType.DISK_SPACE,
                    "disk_critical",
                    f"Disk space critical: {path} at {percent:.1f}% "
                    f"(free: {usage['free_gb']:.1f} GB)",
                    percent,
                    self.config.disk_critical_percent,
                    metadata={'path': path, 'free_gb': usage['free_gb']},
                )
            elif percent >= self.config.disk_warning_percent:
                self._raise_alert(
                    ResourceAlertLevel.WARNING,
                    ResourceType.DISK_SPACE,
                    "disk_warning",
                    f"Disk space warning: {path} at {percent:.1f}% "
                    f"(free: {usage['free_gb']:.1f} GB)",
                    percent,
                    self.config.disk_warning_percent,
                    metadata={'path': path, 'free_gb': usage['free_gb']},
                )

    def _check_connection_thresholds(self, snapshot: ResourceSnapshot):
        """Check network connection thresholds"""
        if snapshot.connection_count >= self.config.connection_critical:
            self._raise_alert(
                ResourceAlertLevel.CRITICAL,
                ResourceType.CONNECTIONS,
                "connection_critical",
                f"Connection count critical: {snapshot.connection_count} >= "
                f"{self.config.connection_critical}",
                snapshot.connection_count,
                self.config.connection_critical,
                metadata={'by_status': snapshot.connections_by_status},
            )
        elif snapshot.connection_count >= self.config.connection_warning:
            self._raise_alert(
                ResourceAlertLevel.WARNING,
                ResourceType.CONNECTIONS,
                "connection_warning",
                f"Connection count warning: {snapshot.connection_count} >= "
                f"{self.config.connection_warning}",
                snapshot.connection_count,
                self.config.connection_warning,
                metadata={'by_status': snapshot.connections_by_status},
            )

    def _detect_fd_leak(self):
        """Detect file descriptor leaks through growth analysis"""
        with self._lock:
            if len(self._history) < self.config.fd_growth_window_samples:
                return
            samples = list(self._history)[-self.config.fd_growth_window_samples:]

        # Calculate FD growth over window
        start_fd = samples[0].fd_count
        end_fd = samples[-1].fd_count
        growth = end_fd - start_fd

        if growth >= self.config.fd_growth_warning:
            self._raise_alert(
                ResourceAlertLevel.WARNING,
                ResourceType.FILE_DESCRIPTORS,
                "fd_leak_possible",
                f"Possible FD leak: grew by {growth} in "
                f"{len(samples) * self.config.sample_interval:.0f}s",
                growth,
                self.config.fd_growth_warning,
                metadata={'start_fd': start_fd, 'end_fd': end_fd},
            )

    def _detect_thread_leak(self):
        """Detect thread leaks through growth analysis"""
        with self._lock:
            if len(self._history) < self.config.fd_growth_window_samples:
                return
            samples = list(self._history)[-self.config.fd_growth_window_samples:]

        # Calculate thread growth over window
        start_threads = samples[0].thread_count
        end_threads = samples[-1].thread_count
        growth = end_threads - start_threads

        if growth >= self.config.thread_growth_warning:
            self._raise_alert(
                ResourceAlertLevel.WARNING,
                ResourceType.THREADS,
                "thread_leak_possible",
                f"Possible thread leak: grew by {growth} in "
                f"{len(samples) * self.config.sample_interval:.0f}s",
                growth,
                self.config.thread_growth_warning,
                metadata={'start_threads': start_threads, 'end_threads': end_threads},
            )

    def _raise_alert(
        self,
        level: ResourceAlertLevel,
        resource_type: ResourceType,
        alert_type: str,
        message: str,
        current_value: float,
        threshold: float,
        metadata: Optional[Dict] = None,
    ):
        """Raise a resource alert"""
        alert = ResourceAlert(
            timestamp=time.time(),
            level=level,
            resource_type=resource_type,
            alert_type=alert_type,
            message=message,
            current_value=current_value,
            threshold=threshold,
            metadata=metadata or {},
        )

        # Store in history
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > self._alert_history_size:
                self._alerts = self._alerts[-self._alert_history_size:]

        # Log the alert
        log_level = {
            ResourceAlertLevel.INFO: logging.INFO,
            ResourceAlertLevel.WARNING: logging.WARNING,
            ResourceAlertLevel.CRITICAL: logging.ERROR,
        }.get(level, logging.WARNING)

        logger.log(log_level, f"Resource alert [{level.value}]: {message}")

        # Notify callback
        if self._on_alert:
            try:
                self._on_alert(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")

        # Log to daemon event logger if available
        if self.daemon and hasattr(self.daemon, 'event_logger'):
            try:
                from .event_logger import EventType
                self.daemon.event_logger.log_event(
                    EventType.ALERT if level == ResourceAlertLevel.CRITICAL else EventType.INFO,
                    message,
                    metadata={
                        'alert_type': alert_type,
                        'resource_type': resource_type.value,
                        'level': level.value,
                        'current_value': current_value,
                        'threshold': threshold,
                        **(metadata or {}),
                    }
                )
            except Exception:
                pass

    def _export_metrics(self, snapshot: ResourceSnapshot):
        """Export metrics to telemetry system"""
        if not self._telemetry_manager:
            return

        try:
            # File descriptors
            self._telemetry_manager.set_gauge("resource.fd_count", snapshot.fd_count)
            self._telemetry_manager.set_gauge("resource.fd_limit", snapshot.fd_limit)
            if snapshot.fd_limit > 0:
                fd_percent = int((snapshot.fd_count / snapshot.fd_limit) * 100)
                self._telemetry_manager.set_gauge("resource.fd_percent", fd_percent)

            # Threads
            self._telemetry_manager.set_gauge("resource.thread_count", snapshot.thread_count)

            # CPU
            self._telemetry_manager.set_gauge("resource.cpu_percent", int(snapshot.cpu_percent))

            # Connections
            self._telemetry_manager.set_gauge("resource.connection_count", snapshot.connection_count)

            # Disk (primary path only to avoid metric explosion)
            if snapshot.disk_usage:
                primary_path = list(snapshot.disk_usage.keys())[0]
                usage = snapshot.disk_usage[primary_path]
                self._telemetry_manager.set_gauge("resource.disk_percent", int(usage['percent']))
                self._telemetry_manager.set_gauge("resource.disk_free_gb", int(usage['free_gb']))

        except Exception as e:
            logger.debug(f"Failed to export resource metrics: {e}")

    def get_current_snapshot(self) -> Optional[ResourceSnapshot]:
        """Get the most recent resource snapshot"""
        with self._lock:
            return self._current_snapshot

    def get_history(self, limit: Optional[int] = None) -> List[ResourceSnapshot]:
        """Get resource history"""
        with self._lock:
            if limit:
                return list(self._history)[-limit:]
            return list(self._history)

    def get_alerts(self, limit: Optional[int] = None,
                   resource_type: Optional[ResourceType] = None) -> List[ResourceAlert]:
        """Get recent alerts, optionally filtered by resource type"""
        with self._lock:
            alerts = self._alerts
            if resource_type:
                alerts = [a for a in alerts if a.resource_type == resource_type]
            if limit:
                return alerts[-limit:]
            return list(alerts)

    def get_summary_stats(self) -> Dict:
        """Get summary statistics"""
        with self._lock:
            current = self._current_snapshot
            history_len = len(self._history)
            alert_count = len(self._alerts)

        stats = {
            'available': self.is_available,
            'running': self._running,
            'samples_collected': history_len,
            'alerts_total': alert_count,
            'config': self.config.to_dict(),
        }

        if current:
            stats['current'] = current.to_dict()

        # Add baselines
        if self._baseline_fd_count is not None:
            stats['baseline_fd_count'] = self._baseline_fd_count
            if current:
                stats['fd_growth'] = current.fd_count - self._baseline_fd_count

        if self._baseline_thread_count is not None:
            stats['baseline_thread_count'] = self._baseline_thread_count
            if current:
                stats['thread_growth'] = current.thread_count - self._baseline_thread_count

        # Add CPU sustained tracking info
        stats['cpu_monitoring'] = {
            'warning_samples': self._cpu_warning_samples,
            'critical_samples': self._cpu_critical_samples,
            'is_sustained_high': self._cpu_was_sustained,
            'sustained_threshold': self.config.cpu_sustained_samples,
        }
        if self._cpu_sustained_start:
            stats['cpu_monitoring']['sustained_duration'] = time.time() - self._cpu_sustained_start
            stats['cpu_monitoring']['peak_during_sustained'] = self._cpu_peak_during_sustained

        return stats

    def get_cpu_stats(self) -> Dict:
        """
        Get detailed CPU statistics.

        Returns:
            Dictionary with CPU monitoring state and history
        """
        with self._lock:
            history = list(self._history)

        # Calculate CPU statistics from history
        if not history:
            return {'available': False, 'message': 'No samples collected yet'}

        cpu_values = [s.cpu_percent for s in history]
        recent_cpu = cpu_values[-min(6, len(cpu_values)):]  # Last minute (6 samples at 10s)

        stats = {
            'current': cpu_values[-1] if cpu_values else 0,
            'average_1min': sum(recent_cpu) / len(recent_cpu) if recent_cpu else 0,
            'average_all': sum(cpu_values) / len(cpu_values) if cpu_values else 0,
            'min': min(cpu_values) if cpu_values else 0,
            'max': max(cpu_values) if cpu_values else 0,
            'samples': len(cpu_values),
            'sustained_high': {
                'is_active': self._cpu_was_sustained,
                'warning_samples': self._cpu_warning_samples,
                'critical_samples': self._cpu_critical_samples,
                'threshold': self.config.cpu_sustained_samples,
            },
        }

        if self._cpu_sustained_start:
            stats['sustained_high']['duration_seconds'] = time.time() - self._cpu_sustained_start
            stats['sustained_high']['peak'] = self._cpu_peak_during_sustained

        return stats

    def get_open_files(self) -> List[Dict]:
        """Get list of open files for debugging FD leaks"""
        if not self._process:
            return []

        try:
            files = []
            for f in self._process.open_files():
                files.append({
                    'path': f.path,
                    'fd': f.fd,
                    'mode': f.mode if hasattr(f, 'mode') else 'unknown',
                })
            return files
        except (psutil.AccessDenied, psutil.Error) as e:
            logger.debug(f"Failed to get open files: {e}")
            return []

    def get_connections_detail(self) -> List[Dict]:
        """Get detailed connection info for debugging connection leaks"""
        if not self._process:
            return []

        try:
            conns = []
            for c in self._process.connections():
                conn_info = {
                    'fd': c.fd,
                    'family': str(c.family),
                    'type': str(c.type),
                    'status': c.status if hasattr(c, 'status') else 'unknown',
                }
                if c.laddr:
                    conn_info['local'] = f"{c.laddr.ip}:{c.laddr.port}"
                if c.raddr:
                    conn_info['remote'] = f"{c.raddr.ip}:{c.raddr.port}"
                conns.append(conn_info)
            return conns
        except (psutil.AccessDenied, psutil.Error) as e:
            logger.debug(f"Failed to get connections: {e}")
            return []

    def get_threads_detail(self) -> List[Dict]:
        """Get thread info for debugging thread leaks"""
        if not self._process:
            return []

        try:
            threads = []
            for t in self._process.threads():
                threads.append({
                    'id': t.id,
                    'user_time': round(t.user_time, 3),
                    'system_time': round(t.system_time, 3),
                })
            return threads
        except (psutil.AccessDenied, psutil.Error) as e:
            logger.debug(f"Failed to get threads: {e}")
            return []

    def reset_baselines(self):
        """Reset baselines to current values"""
        snapshot = self._take_snapshot()
        with self._lock:
            self._baseline_fd_count = snapshot.fd_count
            self._baseline_thread_count = snapshot.thread_count
        logger.info(f"Resource baselines reset: FD={snapshot.fd_count}, "
                   f"Threads={snapshot.thread_count}")


# Convenience function
def create_resource_monitor(
    daemon=None,
    sample_interval: float = 10.0,
    disk_paths: Optional[List[str]] = None,
) -> ResourceMonitor:
    """
    Create a configured resource monitor.

    Args:
        daemon: BoundaryDaemon instance
        sample_interval: Seconds between samples
        disk_paths: Paths to monitor for disk space

    Returns:
        Configured ResourceMonitor instance
    """
    config = ResourceMonitorConfig(
        sample_interval=sample_interval,
        disk_paths=disk_paths or [],
    )

    return ResourceMonitor(daemon=daemon, config=config)


if __name__ == '__main__':
    # Test the resource monitor
    import sys

    print("Testing Resource Monitor...")
    print(f"psutil available: {PSUTIL_AVAILABLE}")

    if not PSUTIL_AVAILABLE:
        print("Cannot run test without psutil")
        sys.exit(1)

    # Create monitor with short intervals for testing
    config = ResourceMonitorConfig(
        sample_interval=2.0,
        history_size=30,
        fd_warning_percent=50.0,  # Low threshold for testing
        thread_warning=10,        # Low threshold for testing
    )

    def on_alert(alert: ResourceAlert):
        print(f"\n[ALERT] {alert.level.value} ({alert.resource_type.value}): {alert.message}")

    monitor = ResourceMonitor(config=config, on_alert=on_alert)
    monitor.start()

    try:
        print("\nMonitoring resources. Press Ctrl+C to stop...")
        print("Creating some resources to test monitoring...\n")

        # Test by opening some files
        test_files = []
        for i in range(15):
            snapshot = monitor.get_current_snapshot()
            if snapshot:
                print(f"[{i:2d}] FD: {snapshot.fd_count}/{snapshot.fd_limit}, "
                      f"Threads: {snapshot.thread_count}, "
                      f"CPU: {snapshot.cpu_percent:.1f}%, "
                      f"Conns: {snapshot.connection_count}")

            # Open a file to test FD monitoring
            try:
                f = open('/dev/null', 'r')
                test_files.append(f)
            except Exception:
                pass

            time.sleep(2)

        # Print summary
        print("\n=== Summary ===")
        stats = monitor.get_summary_stats()
        for key, value in stats.items():
            if key not in ('config', 'current'):
                print(f"{key}: {value}")

        # Print current snapshot details
        if stats.get('current'):
            print("\n=== Current Snapshot ===")
            for key, value in stats['current'].items():
                print(f"{key}: {value}")

        # Get alerts
        print("\n=== Alerts ===")
        alerts = monitor.get_alerts()
        if alerts:
            for alert in alerts[-5:]:
                print(f"[{alert.level.value}] {alert.resource_type.value}: {alert.message}")
        else:
            print("No alerts recorded")

        # Cleanup test files
        for f in test_files:
            f.close()

    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        monitor.stop()
        print("Resource monitor test complete.")
