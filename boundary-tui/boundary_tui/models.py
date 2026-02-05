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
