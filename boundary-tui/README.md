# Boundary TUI

**Cyberpunk Terminal Dashboard for Security Monitoring**

A standalone terminal user interface (TUI) featuring animated cityscapes, weather effects, and real-time system monitoring. Originally part of the Boundary Daemon project, now available as a reusable package.

## Features

- **Animated Cyberpunk Cityscape** - Buildings, neon signs, and atmospheric effects
- **Weather System** - Matrix rain, snow, sandstorms, and calm modes
- **Real-time Monitoring** - Status panels, event streams, alert management
- **Cross-platform** - Linux, Windows, macOS support
- **High Performance** - 10ms refresh rate with frame caching
- **Extensible** - Protocol-based daemon communication

## Installation

```bash
# Basic installation
pip install boundary-tui

# With audio effects (TTS car sounds)
pip install boundary-tui[audio]

# With AI chat features
pip install boundary-tui[ai]

# Full installation
pip install boundary-tui[full]
```

## Quick Start

### Standalone Demo Mode

```python
from boundary_tui import Dashboard, run_dashboard

# Run in demo mode (no daemon required)
run_dashboard()
```

### With Custom Daemon

```python
from boundary_tui import Dashboard, DaemonProtocol

class MyDaemon(DaemonProtocol):
    def get_status(self):
        return {
            'mode': 'TRUSTED',
            'online': True,
            'network_state': 'connected',
        }

    def get_events(self):
        return [...]

    def get_alerts(self):
        return [...]

dashboard = Dashboard(daemon=MyDaemon())
dashboard.run()
```

### Command Line

```bash
# Run dashboard
boundary-tui

# With custom refresh rate
boundary-tui --refresh 0.5

# Connect to specific socket
boundary-tui --socket /var/run/boundary-daemon/daemon.sock

# Matrix mode (secret!)
boundary-tui --matrix
```

## Architecture

```
boundary_tui/
├── models.py      # Data classes (PanelType, DashboardEvent, etc.)
├── colors.py      # Curses color definitions
├── weather.py     # Weather effects (Matrix rain, snow, sand)
├── backdrop.py    # 3D tunnel backdrop animation
├── creatures.py   # Animated creatures (rats, shadows, lightning)
├── scene.py       # Main alley scene rendering (~7000 lines)
├── client.py      # Daemon communication client
├── protocol.py    # Abstract daemon protocol interface
└── dashboard.py   # Main Dashboard class
```

## Daemon Protocol

To integrate with your own monitoring system, implement the `DaemonProtocol`:

```python
from boundary_tui.protocol import DaemonProtocol

class MyMonitor(DaemonProtocol):
    def get_status(self) -> dict:
        """Return current system status."""
        return {
            'mode': 'ACTIVE',           # Current mode string
            'online': True,              # System online status
            'network_state': 'connected', # Network status
            'hardware_trust': 'high',    # Trust level
            'lockdown_active': False,    # Lockdown flag
        }

    def get_events(self, limit: int = 100) -> list:
        """Return recent events."""
        return [
            {
                'timestamp': '2024-01-01T12:00:00Z',
                'event_type': 'STATUS_CHANGE',
                'details': 'Mode changed to ACTIVE',
                'severity': 'INFO',
            },
            # ...
        ]

    def get_alerts(self) -> list:
        """Return active alerts."""
        return [
            {
                'alert_id': 'alert-001',
                'timestamp': '2024-01-01T12:00:00Z',
                'severity': 'WARNING',
                'message': 'High CPU usage detected',
                'status': 'NEW',
            },
            # ...
        ]

    def get_sandboxes(self) -> list:
        """Return sandbox status (optional)."""
        return []

    def get_siem_status(self) -> dict:
        """Return SIEM integration status (optional)."""
        return {}
```

## Weather Modes

The TUI supports multiple weather effects:

| Mode | Description | Trigger |
|------|-------------|---------|
| Matrix | Classic green digital rain | Default |
| Rain | Blue rain with puddles | Press 'w' |
| Snow | White snowflakes with accumulation | Press 'w' |
| Sand | Brown/yellow sandstorm | Press 'w' |
| Calm | Clear sky, wind effects only | Press 'w' |

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `q` | Quit |
| `r` | Refresh data |
| `w` | Cycle weather modes |
| `m` | Mode change ceremony |
| `a` | Acknowledge alert |
| `e` | Export events |
| `/` | Search events |
| `?` | Help |
| `Tab` | Switch panels |

## Requirements

- Python 3.9+
- curses library (built-in on Linux/macOS, `windows-curses` on Windows)

## License

MIT License - See LICENSE file for details.

## Credits

Extracted from the [Boundary Daemon](https://github.com/kase1111-hash/boundary-daemon) project.
