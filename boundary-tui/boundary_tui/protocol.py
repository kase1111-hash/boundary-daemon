"""
Daemon Protocol Interface

Defines the abstract interface that any daemon implementation must follow
to communicate with the TUI dashboard.

Usage:
    from boundary_tui.protocol import DaemonProtocol

    class MyDaemon(DaemonProtocol):
        def get_status(self):
            return {'mode': 'ACTIVE', 'online': True, ...}
        # ... implement other methods
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any


@dataclass
class StatusResponse:
    """Response from get_status()."""
    mode: str = "UNKNOWN"
    online: bool = False
    network_state: str = "unknown"
    hardware_trust: str = "unknown"
    lockdown_active: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EventRecord:
    """A single event record."""
    timestamp: str
    event_type: str
    details: str
    severity: str = "INFO"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def time_short(self) -> str:
        """Get short time format (HH:MM:SS)."""
        try:
            dt = datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
            return dt.strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            return self.timestamp[:8] if self.timestamp else "??:??:??"


@dataclass
class AlertRecord:
    """A single alert record."""
    alert_id: str
    timestamp: str
    severity: str
    message: str
    status: str = "NEW"  # NEW, ACKNOWLEDGED, RESOLVED
    source: str = ""


@dataclass
class SandboxRecord:
    """A single sandbox status record."""
    sandbox_id: str
    profile: str
    status: str
    memory_used: int = 0
    memory_limit: int = 0
    cpu_percent: float = 0.0
    uptime: float = 0.0


class DaemonProtocol(ABC):
    """
    Abstract interface for daemon communication.

    Implement this class to connect the TUI to any monitoring backend.
    All methods should be non-blocking or have reasonable timeouts.
    """

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """
        Get current daemon/system status.

        Returns:
            Dict with keys:
                - mode: str - Current operational mode (e.g., "TRUSTED", "LOCKDOWN")
                - online: bool - Whether the system is online
                - network_state: str - Network connectivity state
                - hardware_trust: str - Hardware trust level
                - lockdown_active: bool - Whether lockdown is active
                - (optional) Additional status fields
        """
        pass

    @abstractmethod
    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent events.

        Args:
            limit: Maximum number of events to return

        Returns:
            List of event dicts with keys:
                - timestamp: str - ISO format timestamp
                - event_type: str - Type of event
                - details: str - Event description
                - severity: str - INFO, WARNING, ERROR, CRITICAL
                - (optional) metadata: dict - Additional event data
        """
        pass

    @abstractmethod
    def get_alerts(self) -> List[Dict[str, Any]]:
        """
        Get active alerts.

        Returns:
            List of alert dicts with keys:
                - alert_id: str - Unique alert identifier
                - timestamp: str - ISO format timestamp
                - severity: str - Alert severity level
                - message: str - Alert message
                - status: str - NEW, ACKNOWLEDGED, RESOLVED
                - (optional) source: str - Alert source
        """
        pass

    def get_sandboxes(self) -> List[Dict[str, Any]]:
        """
        Get sandbox status (optional).

        Returns:
            List of sandbox dicts with keys:
                - sandbox_id: str - Sandbox identifier
                - profile: str - Sandbox profile name
                - status: str - Running, stopped, etc.
                - memory_used: int - Memory usage in bytes
                - memory_limit: int - Memory limit in bytes
                - cpu_percent: float - CPU usage percentage
                - uptime: float - Uptime in seconds
        """
        return []

    def get_siem_status(self) -> Dict[str, Any]:
        """
        Get SIEM integration status (optional).

        Returns:
            Dict with SIEM shipping/ingestion status
        """
        return {}

    def get_ingestion_status(self) -> Dict[str, Any]:
        """
        Get data ingestion status (optional).

        Returns:
            Dict with ingestion client status
        """
        return {}

    def is_connected(self) -> bool:
        """
        Check if connection to backend is active.

        Returns:
            True if connected, False otherwise
        """
        return True

    def is_demo_mode(self) -> bool:
        """
        Check if running in demo/offline mode.

        Returns:
            True if in demo mode, False if connected to real backend
        """
        return False

    # Command methods (optional - for interactive features)

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert. Returns True on success."""
        return False

    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert. Returns True on success."""
        return False

    def request_mode_change(self, new_mode: str) -> Dict[str, Any]:
        """Request a mode change. Returns result dict."""
        return {'success': False, 'error': 'Not implemented'}

    def export_events(self, start: str, end: str, format: str = 'json') -> Dict[str, Any]:
        """Export events in date range. Returns result with path or data."""
        return {'success': False, 'error': 'Not implemented'}


class DemoProtocol(DaemonProtocol):
    """
    Demo implementation that returns simulated data.

    Used when no real daemon is available.
    """

    def __init__(self):
        self._event_counter = 0

    def get_status(self) -> Dict[str, Any]:
        return {
            'mode': 'DEMO',
            'online': True,
            'network_state': 'simulated',
            'hardware_trust': 'simulated',
            'lockdown_active': False,
            'demo_mode': True,
        }

    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Generate some demo events."""
        import random
        events = []
        event_types = [
            ('SYSTEM_START', 'INFO', 'Daemon started'),
            ('MODE_CHANGE', 'INFO', 'Mode changed to DEMO'),
            ('NETWORK_CHECK', 'INFO', 'Network connectivity verified'),
            ('POLICY_EVAL', 'INFO', 'Policy evaluation completed'),
            ('HEALTH_CHECK', 'INFO', 'Health check passed'),
        ]

        for i in range(min(limit, 10)):
            evt_type, severity, details = random.choice(event_types)
            events.append({
                'timestamp': datetime.now().isoformat(),
                'event_type': evt_type,
                'details': f"{details} (demo event {self._event_counter})",
                'severity': severity,
            })
            self._event_counter += 1

        return events

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Return empty alerts in demo mode."""
        return []

    def is_demo_mode(self) -> bool:
        return True
