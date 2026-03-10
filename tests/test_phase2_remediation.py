"""
Tests for Phase 2 remediation — Findings #3, #4, #6.

Covers:
- Finding #3: Health endpoint defaults to 127.0.0.1
- Finding #4: Prometheus metrics defaults to 127.0.0.1
- Finding #6: Cluster secret rotation with dual-key grace period
"""

import inspect
import time

import pytest

from daemon.api.health import HealthCheckServer
from daemon.telemetry.prometheus_metrics import MetricsExporter
from daemon.distributed.coordinators import (
    FileCoordinator,
    compute_entry_hmac,
    generate_cluster_secret,
)


# ---------------------------------------------------------------------------
# Finding #3: Health endpoint default binding
# ---------------------------------------------------------------------------

class TestHealthEndpointBinding:
    """Health check server must default to 127.0.0.1."""

    def test_default_host_is_localhost(self):
        sig = inspect.signature(HealthCheckServer.start)
        assert sig.parameters['host'].default == '127.0.0.1'


# ---------------------------------------------------------------------------
# Finding #4: Prometheus metrics default binding
# ---------------------------------------------------------------------------

class TestMetricsEndpointBinding:
    """Prometheus metrics exporter must default to 127.0.0.1."""

    def test_default_host_is_localhost(self):
        sig = inspect.signature(MetricsExporter.__init__)
        assert sig.parameters['host'].default == '127.0.0.1'


# ---------------------------------------------------------------------------
# Finding #6: Cluster secret rotation
# ---------------------------------------------------------------------------

class TestClusterSecretRotation:
    """FileCoordinator.rotate_secret with dual-key grace period."""

    def setup_method(self, tmp_path_factory=None):
        import tempfile
        self.tmp_dir = tempfile.mkdtemp(prefix="boundary-test-rotation-")
        self.old_secret = generate_cluster_secret()
        self.coord = FileCoordinator(
            data_dir=self.tmp_dir, cluster_secret=self.old_secret
        )

    def test_rotate_installs_new_secret(self):
        new_secret = generate_cluster_secret()
        assert self.coord.rotate_secret(new_secret) is True
        assert self.coord._cluster_secret == new_secret

    def test_writes_use_new_secret_immediately(self):
        new_secret = generate_cluster_secret()
        self.coord.rotate_secret(new_secret)
        self.coord.put("/test/key", "value")

        # The stored HMAC should match the NEW secret
        entry = self.coord._state["/test/key"]
        expected = compute_entry_hmac("/test/key", "value", new_secret)
        assert entry["hmac"] == expected

    def test_old_secret_entries_accepted_during_grace(self):
        # Write with old secret
        self.coord.put("/test/old", "data")

        # Rotate
        new_secret = generate_cluster_secret()
        self.coord.rotate_secret(new_secret, grace_period_seconds=300)

        # Old entry should still be readable
        assert self.coord.get("/test/old") == "data"

    def test_old_secret_rejected_after_grace(self):
        # Write with old secret
        self.coord.put("/test/old", "data")

        # Rotate with 0-second grace period (immediately expires)
        new_secret = generate_cluster_secret()
        self.coord.rotate_secret(new_secret, grace_period_seconds=0)

        # Force deadline to be in the past
        self.coord._rotation_deadline = time.time() - 1

        # Old entry should be rejected
        assert self.coord.get("/test/old") is None

    def test_reject_short_secret(self):
        assert self.coord.rotate_secret("tooshort") is False
        # Original secret should be unchanged
        assert self.coord._cluster_secret == self.old_secret

    def test_first_time_installation(self):
        """rotate_secret on a coordinator with no secret acts as install."""
        coord = FileCoordinator(data_dir=self.tmp_dir)
        new_secret = generate_cluster_secret()
        assert coord.rotate_secret(new_secret) is True
        assert coord._cluster_secret == new_secret

    def test_check_secret_age_warns_when_stale(self, caplog):
        import logging
        # Set installed_at to 60 days ago
        self.coord._secret_installed_at = time.time() - (60 * 86400)
        with caplog.at_level(logging.WARNING):
            age = self.coord.check_secret_age()
        assert age >= 59
        assert "Rotate" in caplog.text

    def test_check_secret_age_no_warning_when_fresh(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING):
            age = self.coord.check_secret_age()
        assert age == 0
        assert "Rotate" not in caplog.text

    def test_check_secret_age_returns_none_without_secret(self):
        coord = FileCoordinator(data_dir=self.tmp_dir)
        assert coord.check_secret_age() is None
