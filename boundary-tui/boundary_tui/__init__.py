"""
Boundary TUI - Cyberpunk Terminal Dashboard

A standalone terminal user interface featuring animated cityscapes,
weather effects, and real-time system monitoring.

Basic Usage:
    from boundary_tui import Dashboard, run_dashboard
    run_dashboard()

With Custom Daemon:
    from boundary_tui import Dashboard, DaemonProtocol

    class MyDaemon(DaemonProtocol):
        def get_status(self):
            return {'mode': 'ACTIVE', 'online': True, ...}
        # ... implement other methods

    dashboard = Dashboard(daemon=MyDaemon())
    dashboard.run()
"""

__version__ = "1.0.0"

# Core classes
from .dashboard import Dashboard, run_dashboard, main
from .protocol import DaemonProtocol, DemoProtocol
from .client import DashboardClient

# Data models
from .models import (
    PanelType,
    DashboardEvent,
    DashboardAlert,
    SandboxStatus,
)

# Visual components
from .colors import Colors
from .weather import WeatherMode, MatrixRain
from .backdrop import TunnelBackdrop
from .creatures import LightningBolt, AlleyRat, LurkingShadow
from .scene import AlleyScene

__all__ = [
    # Version
    "__version__",
    # Core
    "Dashboard",
    "run_dashboard",
    "main",
    "DaemonProtocol",
    "DemoProtocol",
    "DashboardClient",
    # Models
    "PanelType",
    "DashboardEvent",
    "DashboardAlert",
    "SandboxStatus",
    # Visual
    "Colors",
    "WeatherMode",
    "MatrixRain",
    "TunnelBackdrop",
    "LightningBolt",
    "AlleyRat",
    "LurkingShadow",
    "AlleyScene",
]
