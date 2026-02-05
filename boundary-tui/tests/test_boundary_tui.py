"""
Tests for boundary-tui package.
"""

import pytest
import sys


class TestImports:
    """Test that all modules can be imported."""

    def test_import_package(self):
        """Package should be importable."""
        import boundary_tui
        assert boundary_tui.__version__ == "1.0.0"

    def test_import_dashboard(self):
        """Dashboard class should be importable."""
        from boundary_tui import Dashboard
        assert Dashboard is not None

    def test_import_protocol(self):
        """Protocol classes should be importable."""
        from boundary_tui import DaemonProtocol, DemoProtocol
        assert DaemonProtocol is not None
        assert DemoProtocol is not None

    def test_import_client(self):
        """Client should be importable."""
        from boundary_tui import DashboardClient
        assert DashboardClient is not None

    def test_import_models(self):
        """Models should be importable."""
        from boundary_tui import (
            PanelType,
            DashboardEvent,
            DashboardAlert,
            SandboxStatus,
        )
        assert PanelType is not None
        assert DashboardEvent is not None
        assert DashboardAlert is not None
        assert SandboxStatus is not None

    def test_import_visual_components(self):
        """Visual components should be importable."""
        from boundary_tui import (
            Colors,
            WeatherMode,
            MatrixRain,
            TunnelBackdrop,
            LightningBolt,
            AlleyRat,
            LurkingShadow,
            AlleyScene,
        )
        assert Colors is not None
        assert WeatherMode is not None
        assert MatrixRain is not None


class TestProtocol:
    """Test the DaemonProtocol interface."""

    def test_demo_protocol_status(self):
        """DemoProtocol should return valid status."""
        from boundary_tui import DemoProtocol

        demo = DemoProtocol()
        status = demo.get_status()

        assert isinstance(status, dict)
        assert 'mode' in status
        assert 'online' in status
        assert status['mode'] == 'DEMO'

    def test_demo_protocol_events(self):
        """DemoProtocol should return events."""
        from boundary_tui import DemoProtocol

        demo = DemoProtocol()
        events = demo.get_events(limit=5)

        assert isinstance(events, list)
        assert len(events) <= 5

    def test_demo_protocol_is_demo_mode(self):
        """DemoProtocol should indicate demo mode."""
        from boundary_tui import DemoProtocol

        demo = DemoProtocol()
        assert demo.is_demo_mode() is True


class TestModels:
    """Test data model classes."""

    def test_dashboard_event(self):
        """DashboardEvent should work correctly."""
        from boundary_tui import DashboardEvent

        event = DashboardEvent(
            timestamp="2024-01-01T12:30:45Z",
            event_type="TEST",
            details="Test event",
            severity="INFO"
        )

        assert event.timestamp == "2024-01-01T12:30:45Z"
        assert event.event_type == "TEST"
        assert event.time_short == "12:30:45"

    def test_dashboard_alert(self):
        """DashboardAlert should work correctly."""
        from boundary_tui import DashboardAlert

        alert = DashboardAlert(
            alert_id="alert-001",
            timestamp="2024-01-01T12:30:45Z",
            severity="WARNING",
            message="Test alert"
        )

        assert alert.alert_id == "alert-001"
        assert alert.status == "NEW"

    def test_panel_type_enum(self):
        """PanelType enum should have expected values."""
        from boundary_tui import PanelType

        assert PanelType.STATUS.value == "status"
        assert PanelType.EVENTS.value == "events"
        assert PanelType.ALERTS.value == "alerts"


class TestWeather:
    """Test weather system."""

    def test_weather_mode_enum(self):
        """WeatherMode enum should have expected values."""
        from boundary_tui import WeatherMode

        assert WeatherMode.MATRIX.value == "matrix"
        assert WeatherMode.RAIN.value == "rain"
        assert WeatherMode.SNOW.value == "snow"
        assert WeatherMode.SAND.value == "sand"
        assert WeatherMode.CALM.value == "calm"

    def test_weather_mode_display_name(self):
        """WeatherMode should have display names."""
        from boundary_tui import WeatherMode

        assert WeatherMode.MATRIX.display_name == "Matrix"
        assert WeatherMode.RAIN.display_name == "Rain"


@pytest.mark.skipif(sys.platform == 'win32', reason="curses not available on Windows without windows-curses")
class TestColors:
    """Test color system (requires curses)."""

    def test_color_constants(self):
        """Color constants should be defined."""
        from boundary_tui import Colors

        assert Colors.NORMAL == 0
        assert Colors.STATUS_OK == 1
        assert Colors.STATUS_WARN == 2
        assert Colors.STATUS_ERROR == 3
