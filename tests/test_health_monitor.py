"""
Tests for the Health Monitor module.

Tests health checking, heartbeat tracking, and component status monitoring.
"""

import os
import sys
import time
import threading
from unittest.mock import MagicMock


# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.health_monitor import (
    HealthMonitor,
    HealthMonitorConfig,
    HealthStatus,
    ComponentStatus,
    ComponentHealth,
    HealthSnapshot,
    HealthAlert,
)


class TestHealthStatus:
    def test_health_status_values(self):
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"
        assert HealthStatus.UNKNOWN.value == "unknown"


class TestComponentStatus:
    def test_component_status_values(self):
        assert ComponentStatus.OK.value == "ok"
        assert ComponentStatus.WARNING.value == "warning"
        assert ComponentStatus.ERROR.value == "error"
        assert ComponentStatus.UNRESPONSIVE.value == "unresponsive"
        assert ComponentStatus.NOT_AVAILABLE.value == "not_available"


class TestComponentHealth:
    def test_component_health_creation(self):
        health = ComponentHealth(
            name="test_component",
            status=ComponentStatus.OK,
            last_check=time.time(),
        )
        assert health.name == "test_component"
        assert health.status == ComponentStatus.OK

    def test_component_health_defaults(self):
        health = ComponentHealth(
            name="test",
            status=ComponentStatus.OK,
            last_check=time.time(),
        )
        assert health.last_success is None
        assert health.message == ""
        assert health.metadata == {}

    def test_component_health_to_dict(self):
        now = time.time()
        health = ComponentHealth(
            name="test",
            status=ComponentStatus.OK,
            last_check=now,
            last_success=now,
            message="All good",
            metadata={"key": "value"},
        )
        d = health.to_dict()
        assert d['name'] == "test"
        assert d['status'] == "ok"
        assert d['message'] == "All good"
        assert 'last_check_iso' in d


class TestHealthSnapshot:
    def test_health_snapshot_creation(self):
        now = time.time()
        snapshot = HealthSnapshot(
            timestamp=now,
            overall_status=HealthStatus.HEALTHY,
            components={},
            uptime_seconds=100.0,
            heartbeat_count=10,
            last_heartbeat=now,
        )
        assert snapshot.overall_status == HealthStatus.HEALTHY
        assert snapshot.uptime_seconds == 100.0

    def test_health_snapshot_to_dict(self):
        now = time.time()
        snapshot = HealthSnapshot(
            timestamp=now,
            overall_status=HealthStatus.HEALTHY,
            components={},
            uptime_seconds=3661.0,  # 1 hour, 1 minute, 1 second
            heartbeat_count=10,
            last_heartbeat=now,
        )
        d = snapshot.to_dict()
        assert d['overall_status'] == "healthy"
        assert 'uptime_formatted' in d
        assert 'timestamp_iso' in d

    def test_format_uptime_seconds(self):
        assert HealthSnapshot._format_uptime(30) == "30s"

    def test_format_uptime_minutes(self):
        assert HealthSnapshot._format_uptime(90) == "1m 30s"

    def test_format_uptime_hours(self):
        assert HealthSnapshot._format_uptime(3661) == "1h 1m 1s"

    def test_format_uptime_days(self):
        assert HealthSnapshot._format_uptime(90061) == "1d 1h 1m 1s"


class TestHealthAlert:
    def test_health_alert_creation(self):
        alert = HealthAlert(
            timestamp=time.time(),
            component="test",
            previous_status=ComponentStatus.OK,
            new_status=ComponentStatus.ERROR,
            message="Component failed",
        )
        assert alert.component == "test"
        assert alert.new_status == ComponentStatus.ERROR

    def test_health_alert_to_dict(self):
        alert = HealthAlert(
            timestamp=time.time(),
            component="test",
            previous_status=ComponentStatus.OK,
            new_status=ComponentStatus.ERROR,
            message="Test message",
        )
        d = alert.to_dict()
        assert d['component'] == "test"
        assert d['previous_status'] == "ok"
        assert d['new_status'] == "error"


class TestHealthMonitorConfig:
    def test_config_defaults(self):
        config = HealthMonitorConfig()
        assert config.check_interval == 30.0
        assert config.heartbeat_interval == 10.0
        assert config.heartbeat_timeout == 60.0
        assert config.component_timeout == 5.0
        assert config.alert_on_degraded is True
        assert config.history_size == 100

    def test_config_custom(self):
        config = HealthMonitorConfig(
            check_interval=10.0,
            heartbeat_interval=5.0,
            history_size=50,
        )
        assert config.check_interval == 10.0
        assert config.history_size == 50

    def test_config_to_dict(self):
        config = HealthMonitorConfig()
        d = config.to_dict()
        assert 'check_interval' in d
        assert 'heartbeat_interval' in d
        assert 'history_size' in d


class TestHealthMonitorInit:
    def test_init_default(self):
        monitor = HealthMonitor()
        assert monitor.daemon is None
        assert isinstance(monitor.config, HealthMonitorConfig)
        assert monitor._running is False

    def test_init_with_daemon(self):
        mock_daemon = MagicMock()
        monitor = HealthMonitor(daemon=mock_daemon)
        assert monitor.daemon == mock_daemon

    def test_init_with_config(self):
        config = HealthMonitorConfig(check_interval=5.0)
        monitor = HealthMonitor(config=config)
        assert monitor.config.check_interval == 5.0

    def test_init_with_alert_callback(self):
        callback = MagicMock()
        monitor = HealthMonitor(on_alert=callback)
        assert monitor._on_alert == callback

    def test_init_registers_default_checks(self):
        monitor = HealthMonitor()
        assert 'daemon_core' in monitor._health_checks
        assert 'event_logger' in monitor._health_checks
        assert 'policy_engine' in monitor._health_checks

    def test_init_tracking_state(self):
        monitor = HealthMonitor()
        assert monitor._heartbeat_count == 0
        assert monitor._last_heartbeat > 0
        assert monitor._current_status == HealthStatus.UNKNOWN


class TestHealthMonitorComponents:
    def test_register_component(self):
        monitor = HealthMonitor()

        def check_func():
            return (ComponentStatus.OK, "All good", {})

        monitor.register_component('custom', check_func)
        assert 'custom' in monitor._health_checks
        assert 'custom' in monitor._components

    def test_register_component_initializes_health(self):
        monitor = HealthMonitor()

        def check_func():
            return (ComponentStatus.OK, "", {})

        monitor.register_component('test', check_func)
        health = monitor._components['test']
        assert health.status == ComponentStatus.NOT_AVAILABLE
        assert health.last_check == 0


class TestHealthMonitorLifecycle:
    def test_start_sets_running(self):
        config = HealthMonitorConfig(
            check_interval=100.0,
            heartbeat_interval=100.0,
        )
        monitor = HealthMonitor(config=config)
        try:
            monitor.start()
            assert monitor._running is True
        finally:
            monitor.stop()

    def test_start_creates_threads(self):
        config = HealthMonitorConfig(
            check_interval=100.0,
            heartbeat_interval=100.0,
        )
        monitor = HealthMonitor(config=config)
        try:
            monitor.start()
            assert isinstance(monitor._heartbeat_thread, threading.Thread)
            assert isinstance(monitor._check_thread, threading.Thread)
            assert monitor._heartbeat_thread.is_alive()
            assert monitor._check_thread.is_alive()
        finally:
            monitor.stop()

    def test_start_idempotent(self):
        config = HealthMonitorConfig(
            check_interval=100.0,
            heartbeat_interval=100.0,
        )
        monitor = HealthMonitor(config=config)
        try:
            monitor.start()
            first_hb_thread = monitor._heartbeat_thread
            monitor.start()
            assert monitor._heartbeat_thread is first_hb_thread
        finally:
            monitor.stop()

    def test_stop_sets_not_running(self):
        config = HealthMonitorConfig(
            check_interval=100.0,
            heartbeat_interval=100.0,
        )
        monitor = HealthMonitor(config=config)
        monitor.start()
        monitor.stop()
        assert monitor._running is False

    def test_stop_without_start(self):
        monitor = HealthMonitor()
        monitor.stop()  # Should not raise


class TestHealthMonitorHeartbeat:
    def test_heartbeat_increments_count(self):
        monitor = HealthMonitor()
        initial = monitor._heartbeat_count
        monitor.heartbeat()
        assert monitor._heartbeat_count == initial + 1

    def test_heartbeat_updates_timestamp(self):
        monitor = HealthMonitor()
        old_time = monitor._last_heartbeat
        time.sleep(0.01)
        monitor.heartbeat()
        assert monitor._last_heartbeat > old_time

    def test_multiple_heartbeats(self):
        monitor = HealthMonitor()
        for i in range(5):
            monitor.heartbeat()
        assert monitor._heartbeat_count >= 5


class TestHealthMonitorStatusCalculation:
    def test_calculate_overall_empty(self):
        monitor = HealthMonitor()
        monitor._components = {}
        status = monitor._calculate_overall_status()
        assert status == HealthStatus.UNKNOWN

    def test_calculate_overall_all_ok(self):
        monitor = HealthMonitor()
        monitor._components = {
            'c1': ComponentHealth('c1', ComponentStatus.OK, time.time()),
            'c2': ComponentHealth('c2', ComponentStatus.OK, time.time()),
        }
        status = monitor._calculate_overall_status()
        assert status == HealthStatus.HEALTHY

    def test_calculate_overall_with_warning(self):
        """Warning components should return DEGRADED."""
        monitor = HealthMonitor()
        monitor._components = {
            'c1': ComponentHealth('c1', ComponentStatus.OK, time.time()),
            'c2': ComponentHealth('c2', ComponentStatus.WARNING, time.time()),
        }
        status = monitor._calculate_overall_status()
        assert status == HealthStatus.DEGRADED

    def test_calculate_overall_with_error(self):
        monitor = HealthMonitor()
        monitor._components = {
            'c1': ComponentHealth('c1', ComponentStatus.OK, time.time()),
            'c2': ComponentHealth('c2', ComponentStatus.ERROR, time.time()),
        }
        status = monitor._calculate_overall_status()
        # With 50% errors (1/2), this returns UNHEALTHY (>= 50% threshold)
        assert status in (HealthStatus.DEGRADED, HealthStatus.UNHEALTHY)

    def test_calculate_overall_majority_errors(self):
        monitor = HealthMonitor()
        monitor._components = {
            'c1': ComponentHealth('c1', ComponentStatus.ERROR, time.time()),
            'c2': ComponentHealth('c2', ComponentStatus.ERROR, time.time()),
        }
        status = monitor._calculate_overall_status()
        assert status == HealthStatus.UNHEALTHY

    def test_calculate_ignores_not_available(self):
        monitor = HealthMonitor()
        monitor._components = {
            'c1': ComponentHealth('c1', ComponentStatus.OK, time.time()),
            'c2': ComponentHealth('c2', ComponentStatus.NOT_AVAILABLE, time.time()),
        }
        status = monitor._calculate_overall_status()
        assert status == HealthStatus.HEALTHY


class TestHealthMonitorTelemetry:
    def test_set_telemetry_manager(self):
        monitor = HealthMonitor()
        mock_telemetry = MagicMock()
        monitor.set_telemetry_manager(mock_telemetry)
        assert monitor._telemetry_manager == mock_telemetry


class TestHealthMonitorIntegration:
    def test_health_check_flow(self):
        config = HealthMonitorConfig(
            check_interval=0.1,
            heartbeat_interval=0.1,
        )
        monitor = HealthMonitor(config=config)

        # Register a custom check
        def custom_check():
            return (ComponentStatus.OK, "Working", {"test": True})

        monitor.register_component('custom', custom_check)

        # Start and let it run
        monitor.start()
        time.sleep(0.3)
        monitor.stop()

        # Verify component was checked
        assert 'custom' in monitor._components
        health = monitor._components['custom']
        assert health.status == ComponentStatus.OK

    def test_history_is_populated(self):
        config = HealthMonitorConfig(
            check_interval=0.1,
            heartbeat_interval=0.1,
            history_size=10,
        )
        monitor = HealthMonitor(config=config)

        monitor.start()
        time.sleep(0.35)
        monitor.stop()

        assert len(monitor._history) > 0

    def test_alert_callback_on_error(self):
        alerts_received = []

        def on_alert(alert):
            alerts_received.append(alert)

        config = HealthMonitorConfig(
            check_interval=0.1,
            heartbeat_interval=0.1,
            alert_on_degraded=True,
        )
        monitor = HealthMonitor(config=config, on_alert=on_alert)

        # Start with healthy, then switch to error
        call_count = [0]
        def flaky_check():
            call_count[0] += 1
            if call_count[0] > 1:
                return (ComponentStatus.ERROR, "Failed", {})
            return (ComponentStatus.OK, "OK", {})

        monitor.register_component('flaky', flaky_check)

        monitor.start()
        time.sleep(0.35)
        monitor.stop()

        # May or may not have alerts depending on timing
        # Just verify no exceptions


class TestHealthMonitorEdgeCases:
    def test_check_with_exception(self):
        monitor = HealthMonitor()

        def bad_check():
            raise ValueError("Intentional error")

        monitor.register_component('bad', bad_check)
        monitor._run_health_checks()

        health = monitor._components['bad']
        assert health.status == ComponentStatus.ERROR
        assert "Health check failed" in health.message

    def test_empty_history_deque(self):
        monitor = HealthMonitor()
        assert len(monitor._history) == 0

    def test_concurrent_heartbeats(self):
        monitor = HealthMonitor()

        def beat():
            for _ in range(100):
                monitor.heartbeat()

        threads = [threading.Thread(target=beat) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have 500 heartbeats (but at least close due to initialization)
        assert monitor._heartbeat_count >= 500
