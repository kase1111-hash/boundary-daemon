"""
TUI Data Models - Data classes for dashboard display.

Extracted from dashboard.py for maintainability.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict


class PanelType(Enum):
    """Types of dashboard panels."""
    STATUS = "status"
    EVENTS = "events"
    ALERTS = "alerts"
    SANDBOXES = "sandboxes"
    SIEM = "siem"
    RESOURCES = "resources"


@dataclass
class DashboardEvent:
    """Event for display in dashboard."""
    timestamp: str
    event_type: str
    details: str
    severity: str = "INFO"
    metadata: Dict = field(default_factory=dict)

    @property
    def time_short(self) -> str:
        """Get short time format (HH:MM:SS)."""
        try:
            dt = datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
            return dt.strftime("%H:%M:%S")
        except ValueError:
            return self.timestamp[:8]


@dataclass
class DashboardAlert:
    """Alert for display in dashboard."""
    alert_id: str
    timestamp: str
    severity: str
    message: str
    status: str = "NEW"  # NEW, ACKNOWLEDGED, RESOLVED
    source: str = ""

    @property
    def time_str(self) -> str:
        """Get short time format (HH:MM:SS), matching DashboardEvent.time_short."""
        try:
            dt = datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
            return dt.strftime("%H:%M:%S")
        except ValueError:
            return self.timestamp[:8]

    @property
    def acknowledged(self) -> bool:
        """True once the alert has been acknowledged or resolved."""
        return self.status in ("ACKNOWLEDGED", "RESOLVED")


@dataclass
class SandboxStatus:
    """Sandbox status for display."""
    sandbox_id: str
    profile: str
    status: str
    memory_used: int = 0
    memory_limit: int = 0
    cpu_percent: float = 0.0
    uptime: float = 0.0

    @property
    def id(self) -> str:
        """Alias for sandbox_id (used by the dashboard's chat/CLI commands)."""
        return self.sandbox_id

    @property
    def name(self) -> str:
        """Display name: the profile the sandbox runs under."""
        return self.profile

    @property
    def uptime_str(self) -> str:
        """Uptime formatted as Hh Mm Ss."""
        total = int(self.uptime)
        hours, rem = divmod(total, 3600)
        minutes, seconds = divmod(rem, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        if minutes:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"
