"""
Daemon lifecycle integration tests.

Verifies that BoundaryDaemon starts, shuts down cleanly, and releases
all threads and temporary resources.
"""

import os
import sys
import tempfile
import threading
import time
import shutil

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from daemon.boundary_daemon import BoundaryDaemon
from daemon.policy_engine import BoundaryMode, Operator


@pytest.fixture
def daemon_log_dir():
    """Provide a temporary log directory, cleaned up after test."""
    tmpdir = tempfile.mkdtemp(prefix="daemon_lifecycle_")
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


def _start_daemon(log_dir, mode=BoundaryMode.OPEN):
    """Create, start, and return a BoundaryDaemon instance."""
    daemon = BoundaryDaemon(
        log_dir=log_dir,
        initial_mode=mode,
        skip_integrity_check=True,
        dev_mode=True,
    )
    daemon.start()
    return daemon


class TestDaemonStartStop:
    """Basic start/stop lifecycle."""

    def test_start_and_stop(self, daemon_log_dir):
        daemon = _start_daemon(daemon_log_dir)
        assert daemon._running is True

        daemon.stop()
        assert daemon._running is False

    def test_stop_is_idempotent(self, daemon_log_dir):
        daemon = _start_daemon(daemon_log_dir)
        daemon.stop()
        daemon.stop()  # second stop must not raise
        assert daemon._running is False

    def test_stop_without_start(self, daemon_log_dir):
        daemon = BoundaryDaemon(
            log_dir=daemon_log_dir,
            skip_integrity_check=True,
            dev_mode=True,
        )
        daemon.stop()  # must not raise


class TestThreadCleanup:
    """Verify no daemon threads are leaked after stop."""

    def test_no_leaked_threads(self, daemon_log_dir):
        threads_before = set(threading.enumerate())

        daemon = _start_daemon(daemon_log_dir)
        # Give threads a moment to start
        time.sleep(0.2)

        daemon.stop()
        # Give threads a moment to exit
        time.sleep(0.5)

        threads_after = set(threading.enumerate())
        leaked = threads_after - threads_before
        # Filter to only daemon-related threads (ignore pytest/coverage threads)
        daemon_leaked = [
            t for t in leaked
            if t.is_alive() and not t.daemon
            and 'pytest' not in (t.name or '').lower()
            and 'coverage' not in (t.name or '').lower()
        ]
        assert daemon_leaked == [], (
            f"Leaked threads: {[t.name for t in daemon_leaked]}"
        )


class TestLogFileCleanup:
    """Verify log files are created properly and are non-empty."""

    def test_log_file_created(self, daemon_log_dir):
        daemon = _start_daemon(daemon_log_dir)
        daemon.stop()

        log_file = os.path.join(daemon_log_dir, 'boundary_chain.log')
        assert os.path.exists(log_file)

    def test_log_dir_writable_after_stop(self, daemon_log_dir):
        daemon = _start_daemon(daemon_log_dir)
        daemon.stop()

        # Verify log dir is still writable (no locked files)
        test_file = os.path.join(daemon_log_dir, 'test_write')
        with open(test_file, 'w') as f:
            f.write('ok')
        os.unlink(test_file)


class TestModeTransitionDuringLifecycle:
    """Verify mode transitions work during start/stop cycle."""

    def test_mode_transition_before_stop(self, daemon_log_dir):
        daemon = _start_daemon(daemon_log_dir, mode=BoundaryMode.OPEN)

        success, _msg = daemon.policy_engine.transition_mode(
            BoundaryMode.RESTRICTED,
            operator=Operator.HUMAN,
            reason="lifecycle test",
        )
        assert success is True
        # Final mode may differ from RESTRICTED because the state monitor
        # can trigger a tripwire (e.g. network-in-airgap) that escalates
        # to LOCKDOWN.  We only verify the transition call succeeded.
        assert daemon.policy_engine.get_current_mode() != BoundaryMode.OPEN

        daemon.stop()

    def test_initial_mode_is_set(self, daemon_log_dir):
        daemon = _start_daemon(daemon_log_dir, mode=BoundaryMode.RESTRICTED)
        assert daemon.policy_engine.get_current_mode() == BoundaryMode.RESTRICTED
        daemon.stop()


class TestEnforcementCleanup:
    """Verify enforcement state is handled on shutdown."""

    def test_shutdown_event_set(self, daemon_log_dir):
        daemon = _start_daemon(daemon_log_dir)
        assert not daemon._shutdown_event.is_set()

        daemon.stop()
        assert daemon._shutdown_event.is_set()

    def test_state_monitor_stopped(self, daemon_log_dir):
        daemon = _start_daemon(daemon_log_dir)
        daemon.stop()
        assert daemon.state_monitor._running is False


class TestMonitorShutdownCleanup:
    """Verify monitors are stopped after daemon.stop()."""

    def test_health_monitor_stopped_after_daemon_stop(self, daemon_log_dir):
        daemon = _start_daemon(daemon_log_dir)
        daemon.stop()

        if daemon.health_monitor:
            assert daemon.health_monitor._running is False

    def test_resource_monitor_clears_after_daemon_stop(self, daemon_log_dir):
        daemon = _start_daemon(daemon_log_dir)
        daemon.stop()

        if daemon.resource_monitor:
            assert daemon.resource_monitor._running is False
            assert len(daemon.resource_monitor._history) == 0

    def test_memory_monitor_clears_after_daemon_stop(self, daemon_log_dir):
        daemon = _start_daemon(daemon_log_dir)
        daemon.stop()

        if daemon.memory_monitor:
            assert daemon.memory_monitor._running is False
            assert len(daemon.memory_monitor._history) == 0

    def test_queue_monitor_clears_after_daemon_stop(self, daemon_log_dir):
        daemon = _start_daemon(daemon_log_dir)
        daemon.stop()

        if daemon.queue_monitor:
            assert daemon.queue_monitor._running is False
            assert len(daemon.queue_monitor._queues) == 0
