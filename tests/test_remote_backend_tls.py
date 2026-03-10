"""
Tests for RemoteBackend TLS support — Phase 1 remediation.

Covers Finding #2: Remote event logger must support TLS.
"""

import logging
import ssl
from unittest.mock import MagicMock, patch

import pytest

from daemon.redundant_event_logger import (
    BackendConfig,
    LogBackendType,
    LogBackendStatus,
    RemoteBackend,
)


class TestRemoteBackendTLS:
    """RemoteBackend should default to TLS and warn when plaintext."""

    def test_tcp_tls_enabled_by_default(self):
        config = BackendConfig(
            backend_type=LogBackendType.REMOTE,
            path="tcp://logserver.example.com:5514",
        )
        assert config.tls_enabled is True

    def test_tcp_creates_ssl_context(self):
        config = BackendConfig(
            backend_type=LogBackendType.REMOTE,
            path="tcp://logserver.example.com:5514",
            tls_enabled=True,
        )
        with patch.object(RemoteBackend, '_build_ssl_context', return_value=MagicMock(spec=ssl.SSLContext)) as mock_build:
            backend = RemoteBackend(config)
            mock_build.assert_called_once_with(config)
            assert backend._ssl_context is not None

    def test_tcp_plaintext_logs_warning(self, caplog):
        config = BackendConfig(
            backend_type=LogBackendType.REMOTE,
            path="tcp://logserver.example.com:5514",
            tls_enabled=False,
        )
        with caplog.at_level(logging.WARNING):
            backend = RemoteBackend(config)
        assert "plaintext" in caplog.text.lower()
        assert backend._ssl_context is None

    def test_udp_tls_logs_warning(self, caplog):
        config = BackendConfig(
            backend_type=LogBackendType.REMOTE,
            path="udp://logserver.example.com:5514",
            tls_enabled=True,
        )
        with caplog.at_level(logging.WARNING):
            backend = RemoteBackend(config)
        assert "udp" in caplog.text.lower() or "UDP" in caplog.text
        assert backend._ssl_context is None

    def test_build_ssl_context_sets_minimum_tls_version(self):
        config = BackendConfig(
            backend_type=LogBackendType.REMOTE,
            path="tcp://logserver.example.com:5514",
            tls_enabled=True,
        )
        ctx = RemoteBackend._build_ssl_context(config)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2

    def test_build_ssl_context_with_ca_bundle(self, tmp_path):
        # Create a dummy CA file (won't be a real cert but tests the path)
        ca_file = tmp_path / "ca.pem"
        ca_file.write_text("dummy")
        config = BackendConfig(
            backend_type=LogBackendType.REMOTE,
            path="tcp://logserver.example.com:5514",
            tls_enabled=True,
            tls_ca_bundle=str(ca_file),
        )
        # load_verify_locations will fail with a bad cert, which is fine —
        # we just verify the code path calls it
        with pytest.raises(ssl.SSLError):
            RemoteBackend._build_ssl_context(config)

    def test_disabled_backend_no_tls_setup(self):
        config = BackendConfig(
            backend_type=LogBackendType.REMOTE,
            path=None,
            tls_enabled=True,
        )
        backend = RemoteBackend(config)
        assert backend.status == LogBackendStatus.DISABLED
        assert backend._ssl_context is None
