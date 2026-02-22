"""
Tests for the Append-Only Storage module.

Tests immutable audit log protection and integrity features.
"""

import os
import sys
import tempfile
from datetime import datetime
from unittest.mock import patch, MagicMock

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.storage.append_only import (
    AppendOnlyStorage,
    AppendOnlyConfig,
    AppendOnlyMode,
    SyslogFacility,
    SyslogSeverity,
    RemoteSyslogConfig,
    IntegrityCheckpoint,
)


# ===========================================================================
# Enum Tests
# ===========================================================================

class TestAppendOnlyMode:
    def test_append_only_mode_values(self):
        assert AppendOnlyMode.NONE.value == "none"
        assert AppendOnlyMode.CHATTR.value == "chattr"
        assert AppendOnlyMode.COPY_ON_WRITE.value == "cow"
        assert AppendOnlyMode.REMOTE_ONLY.value == "remote"
        assert AppendOnlyMode.FULL.value == "full"


class TestSyslogFacility:
    def test_syslog_facility_values(self):
        assert SyslogFacility.KERN.value == 0
        assert SyslogFacility.USER.value == 1
        assert SyslogFacility.DAEMON.value == 3
        assert SyslogFacility.AUTH.value == 4
        assert SyslogFacility.LOCAL0.value == 16
        assert SyslogFacility.LOCAL7.value == 23


class TestSyslogSeverity:
    def test_syslog_severity_values(self):
        assert SyslogSeverity.EMERGENCY.value == 0
        assert SyslogSeverity.ALERT.value == 1
        assert SyslogSeverity.CRITICAL.value == 2
        assert SyslogSeverity.ERROR.value == 3
        assert SyslogSeverity.WARNING.value == 4
        assert SyslogSeverity.NOTICE.value == 5
        assert SyslogSeverity.INFO.value == 6
        assert SyslogSeverity.DEBUG.value == 7


# ===========================================================================
# Dataclass Tests
# ===========================================================================

class TestRemoteSyslogConfig:
    def test_remote_syslog_config_creation(self):
        config = RemoteSyslogConfig(host="syslog.example.com")
        assert config.host == "syslog.example.com"
        assert config.port == 514
        assert config.protocol == "udp"

    def test_remote_syslog_config_defaults(self):
        config = RemoteSyslogConfig(host="test")
        assert config.facility == SyslogFacility.LOCAL0
        assert config.app_name == "boundary-daemon"
        assert config.use_tls is False
        assert config.tls_verify is True
        assert config.timeout == 5.0
        assert config.retry_count == 3

    def test_remote_syslog_config_custom(self):
        config = RemoteSyslogConfig(
            host="secure.example.com",
            port=6514,
            protocol="tls",
            use_tls=True,
            tls_ca_cert="/path/to/ca.crt",
        )
        assert config.port == 6514
        assert config.use_tls is True


class TestIntegrityCheckpoint:
    def test_integrity_checkpoint_creation(self):
        checkpoint = IntegrityCheckpoint(
            checkpoint_id="cp-001",
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_count=100,
            last_event_hash="abc123",
            checkpoint_hash="def456",
        )
        assert checkpoint.checkpoint_id == "cp-001"
        assert checkpoint.event_count == 100
        assert checkpoint.signature is None

    def test_integrity_checkpoint_with_signature(self):
        checkpoint = IntegrityCheckpoint(
            checkpoint_id="cp-002",
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_count=200,
            last_event_hash="hash1",
            checkpoint_hash="hash2",
            signature="sig123",
        )
        assert checkpoint.signature == "sig123"


class TestAppendOnlyConfig:
    def test_config_defaults(self):
        config = AppendOnlyConfig()
        assert config.mode == AppendOnlyMode.CHATTR
        assert config.log_path == "./logs/boundary_chain.log"
        assert config.checkpoint_interval == 3600
        assert config.auto_protect is True
        assert config.backup_count == 5

    def test_config_custom(self):
        config = AppendOnlyConfig(
            mode=AppendOnlyMode.NONE,
            log_path="/var/log/boundary.log",
            checkpoint_interval=1800,
        )
        assert config.mode == AppendOnlyMode.NONE
        assert config.log_path == "/var/log/boundary.log"

    def test_config_with_remote_syslog(self):
        remote = RemoteSyslogConfig(host="syslog.example.com")
        config = AppendOnlyConfig(remote_syslog=remote)
        assert config.remote_syslog is not None
        assert config.remote_syslog.host == "syslog.example.com"


# ===========================================================================
# AppendOnlyStorage Initialization Tests
# ===========================================================================

class TestAppendOnlyStorageInit:
    def test_init_default(self):
        storage = AppendOnlyStorage()
        assert isinstance(storage.config, AppendOnlyConfig)
        assert storage._initialized is False
        assert storage._protected is False

    def test_init_with_config(self):
        config = AppendOnlyConfig(mode=AppendOnlyMode.NONE)
        storage = AppendOnlyStorage(config=config)
        assert storage.config.mode == AppendOnlyMode.NONE

    def test_init_creates_lock(self):
        storage = AppendOnlyStorage()
        assert storage._lock is not None


# ===========================================================================
# AppendOnlyStorage Mode Tests
# ===========================================================================

class TestAppendOnlyStorageModes:
    def test_mode_none(self):
        config = AppendOnlyConfig(mode=AppendOnlyMode.NONE)
        storage = AppendOnlyStorage(config=config)
        assert storage.config.mode == AppendOnlyMode.NONE

    def test_mode_chattr(self):
        config = AppendOnlyConfig(mode=AppendOnlyMode.CHATTR)
        storage = AppendOnlyStorage(config=config)
        assert storage.config.mode == AppendOnlyMode.CHATTR

    def test_mode_full(self):
        config = AppendOnlyConfig(mode=AppendOnlyMode.FULL)
        storage = AppendOnlyStorage(config=config)
        assert storage.config.mode == AppendOnlyMode.FULL


# ===========================================================================
# Syslog Priority Calculation Tests
# ===========================================================================

class TestSyslogPriority:
    def test_facility_codes(self):
        # Priority = (facility * 8) + severity
        # LOCAL0 (16) + INFO (6) = 134
        priority = SyslogFacility.LOCAL0.value * 8 + SyslogSeverity.INFO.value
        assert priority == 134

    def test_priority_range(self):
        for facility in SyslogFacility:
            for severity in SyslogSeverity:
                priority = facility.value * 8 + severity.value
                assert 0 <= priority <= 191


# ===========================================================================
# Integration Tests
# ===========================================================================

class TestAppendOnlyStorageIntegration:
    def test_create_storage_with_temp_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = AppendOnlyConfig(
                mode=AppendOnlyMode.NONE,
                log_path=os.path.join(tmpdir, "test.log"),
                wal_path=os.path.join(tmpdir, "test_wal.log"),
                checkpoint_path=os.path.join(tmpdir, "checkpoints"),
            )
            storage = AppendOnlyStorage(config=config)
            assert storage is not None

    def test_multiple_storage_instances(self):
        config1 = AppendOnlyConfig(mode=AppendOnlyMode.NONE)
        config2 = AppendOnlyConfig(mode=AppendOnlyMode.CHATTR)

        storage1 = AppendOnlyStorage(config=config1)
        storage2 = AppendOnlyStorage(config=config2)

        assert storage1.config.mode != storage2.config.mode


# ===========================================================================
# Edge Cases
# ===========================================================================

class TestAppendOnlyStorageEdgeCases:
    def test_none_config(self):
        storage = AppendOnlyStorage(config=None)
        assert storage.config is not None

    def test_empty_checkpoint_path(self):
        config = AppendOnlyConfig()
        assert config.checkpoint_path is not None

    def test_config_path_types(self):
        config = AppendOnlyConfig()
        assert isinstance(config.log_path, str)
        assert isinstance(config.wal_path, str)
        assert isinstance(config.checkpoint_path, str)


# ===========================================================================
# Remote Syslog Configuration Tests
# ===========================================================================

class TestRemoteSyslogIntegration:
    def test_syslog_udp_config(self):
        config = RemoteSyslogConfig(
            host="127.0.0.1",
            port=514,
            protocol="udp",
        )
        assert config.protocol == "udp"
        assert config.use_tls is False

    def test_syslog_tcp_config(self):
        config = RemoteSyslogConfig(
            host="127.0.0.1",
            port=514,
            protocol="tcp",
        )
        assert config.protocol == "tcp"

    def test_syslog_tls_config(self):
        config = RemoteSyslogConfig(
            host="secure.example.com",
            port=6514,
            protocol="tls",
            use_tls=True,
            tls_ca_cert="/etc/ssl/certs/ca.crt",
            tls_verify=True,
        )
        assert config.use_tls is True
        assert config.tls_verify is True


# ===========================================================================
# Error-Path Tests
# ===========================================================================

class TestAppendOnlyErrorPaths:
    """Error-path tests for AppendOnlyStorage using pytest.raises."""

    def test_append_only_mode_invalid_value_raises(self):
        with pytest.raises(ValueError):
            AppendOnlyMode("invalid_mode")

    def test_syslog_facility_invalid_value_raises(self):
        with pytest.raises(ValueError):
            SyslogFacility(999)

    def test_syslog_severity_invalid_value_raises(self):
        with pytest.raises(ValueError):
            SyslogSeverity(999)

    def test_append_when_not_initialized_returns_false(self, tmp_path):
        """Appending to uninitialized storage should return (False, msg)."""
        config = AppendOnlyConfig(
            mode=AppendOnlyMode.NONE,
            log_path=str(tmp_path / "test.log"),
            wal_path=str(tmp_path / "wal.log"),
            checkpoint_path=str(tmp_path / "checkpoints"),
        )
        storage = AppendOnlyStorage(config)
        # NOT calling storage.initialize()

        success, msg = storage.append('{"test": true}', "abc123")
        assert success is False
        assert "not initialized" in msg.lower()

    def test_initialize_with_bad_path_returns_false(self):
        """Initializing with an impossible path should return (False, msg)."""
        config = AppendOnlyConfig(
            mode=AppendOnlyMode.NONE,
            log_path="/proc/nonexistent/impossible/test.log",
            wal_path="/proc/nonexistent/impossible/wal.log",
            checkpoint_path="/proc/nonexistent/impossible/checkpoints",
        )
        storage = AppendOnlyStorage(config)

        success, msg = storage.initialize()
        assert success is False
        assert "Failed" in msg

    def test_verify_checkpoint_no_checkpoints_returns_false(self, tmp_path):
        """verify_checkpoint with no checkpoints should return (False, msg)."""
        config = AppendOnlyConfig(
            mode=AppendOnlyMode.NONE,
            log_path=str(tmp_path / "test.log"),
            wal_path=str(tmp_path / "wal.log"),
            checkpoint_path=str(tmp_path / "checkpoints"),
        )
        storage = AppendOnlyStorage(config)
        storage.initialize()

        success, msg = storage.verify_checkpoint()
        assert success is False

    def test_integrity_checkpoint_missing_fields_raises(self):
        with pytest.raises(TypeError):
            IntegrityCheckpoint(checkpoint_id="test")

    def test_append_only_config_missing_fields_uses_defaults(self):
        config = AppendOnlyConfig()
        assert config.mode == AppendOnlyMode.CHATTR
        assert config.checkpoint_interval == 3600

    def test_remote_syslog_config_missing_host_raises(self):
        with pytest.raises(TypeError):
            RemoteSyslogConfig()

    def test_connect_remote_syslog_unreachable_host_returns_false(self, tmp_path):
        remote_config = RemoteSyslogConfig(
            host="192.0.2.255",  # TEST-NET-1, guaranteed unreachable
            port=65535,
            protocol="tcp",
            timeout=0.1,
        )
        config = AppendOnlyConfig(
            mode=AppendOnlyMode.REMOTE_ONLY,
            log_path=str(tmp_path / "test.log"),
            wal_path=str(tmp_path / "wal.log"),
            checkpoint_path=str(tmp_path / "checkpoints"),
            remote_syslog=remote_config,
        )
        storage = AppendOnlyStorage(config)
        result = storage._connect_remote_syslog()
        assert result is False

    def test_load_state_corrupted_json_does_not_raise(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text("this is not json\n")

        config = AppendOnlyConfig(
            mode=AppendOnlyMode.NONE,
            log_path=str(log_file),
            wal_path=str(tmp_path / "wal.log"),
            checkpoint_path=str(tmp_path / "checkpoints"),
        )
        storage = AppendOnlyStorage(config)
        # _load_state catches exceptions internally
        storage._load_state()
        # Should not raise -- error is caught and logged


# ===========================================================================
# PARAMETRIZED TESTS - Added for comprehensive coverage
# ===========================================================================

import pytest


class TestParametrizedAppendOnlyModeValues:
    """Parametrized: All AppendOnlyMode enum members."""

    MODE_VALUES = [
        (AppendOnlyMode.NONE, "none"),
        (AppendOnlyMode.CHATTR, "chattr"),
        (AppendOnlyMode.COPY_ON_WRITE, "cow"),
        (AppendOnlyMode.REMOTE_ONLY, "remote"),
        (AppendOnlyMode.FULL, "full"),
    ]

    @pytest.mark.parametrize("mode,expected_value", MODE_VALUES,
        ids=[m.name for m, _ in MODE_VALUES])
    def test_mode_value(self, mode, expected_value):
        """Each AppendOnlyMode should have its expected string value."""
        assert mode.value == expected_value


class TestParametrizedAppendOnlyStorageWithAllModes:
    """Parametrized: AppendOnlyStorage can be created with every mode."""

    @pytest.mark.parametrize("mode", list(AppendOnlyMode),
        ids=[m.name for m in AppendOnlyMode])
    def test_storage_creation_with_mode(self, mode):
        """Storage can be created with each AppendOnlyMode."""
        config = AppendOnlyConfig(mode=mode)
        storage = AppendOnlyStorage(config=config)
        assert storage.config.mode == mode


class TestParametrizedSyslogFacilityValues:
    """Parametrized: All SyslogFacility enum members have correct int values."""

    FACILITY_VALUES = [
        (SyslogFacility.KERN, 0),
        (SyslogFacility.USER, 1),
        (SyslogFacility.MAIL, 2),
        (SyslogFacility.DAEMON, 3),
        (SyslogFacility.AUTH, 4),
        (SyslogFacility.SYSLOG, 5),
        (SyslogFacility.LPR, 6),
        (SyslogFacility.NEWS, 7),
        (SyslogFacility.UUCP, 8),
        (SyslogFacility.CRON, 9),
        (SyslogFacility.AUTHPRIV, 10),
        (SyslogFacility.FTP, 11),
        (SyslogFacility.LOCAL0, 16),
        (SyslogFacility.LOCAL1, 17),
        (SyslogFacility.LOCAL2, 18),
        (SyslogFacility.LOCAL3, 19),
        (SyslogFacility.LOCAL4, 20),
        (SyslogFacility.LOCAL5, 21),
        (SyslogFacility.LOCAL6, 22),
        (SyslogFacility.LOCAL7, 23),
    ]

    @pytest.mark.parametrize("facility,expected_value", FACILITY_VALUES,
        ids=[f.name for f, _ in FACILITY_VALUES])
    def test_facility_value(self, facility, expected_value):
        """Each SyslogFacility should have its expected int value."""
        assert facility.value == expected_value


class TestParametrizedSyslogSeverityValues:
    """Parametrized: All SyslogSeverity enum members."""

    SEVERITY_VALUES = [
        (SyslogSeverity.EMERGENCY, 0),
        (SyslogSeverity.ALERT, 1),
        (SyslogSeverity.CRITICAL, 2),
        (SyslogSeverity.ERROR, 3),
        (SyslogSeverity.WARNING, 4),
        (SyslogSeverity.NOTICE, 5),
        (SyslogSeverity.INFO, 6),
        (SyslogSeverity.DEBUG, 7),
    ]

    @pytest.mark.parametrize("severity,expected_value", SEVERITY_VALUES,
        ids=[s.name for s, _ in SEVERITY_VALUES])
    def test_severity_value(self, severity, expected_value):
        """Each SyslogSeverity should have its expected int value."""
        assert severity.value == expected_value


class TestParametrizedSyslogPriorityCalculation:
    """Parametrized: Syslog priority = (facility * 8) + severity."""

    PRIORITY_CASES = [
        (SyslogFacility.KERN, SyslogSeverity.EMERGENCY, 0),
        (SyslogFacility.KERN, SyslogSeverity.DEBUG, 7),
        (SyslogFacility.USER, SyslogSeverity.INFO, 14),
        (SyslogFacility.LOCAL0, SyslogSeverity.INFO, 134),
        (SyslogFacility.LOCAL0, SyslogSeverity.EMERGENCY, 128),
        (SyslogFacility.LOCAL7, SyslogSeverity.DEBUG, 191),
        (SyslogFacility.AUTH, SyslogSeverity.ALERT, 33),
        (SyslogFacility.DAEMON, SyslogSeverity.ERROR, 27),
    ]

    @pytest.mark.parametrize("facility,severity,expected_priority", PRIORITY_CASES,
        ids=[f"{f.name}-{s.name}" for f, s, _ in PRIORITY_CASES])
    def test_priority_value(self, facility, severity, expected_priority):
        """Syslog priority should equal (facility * 8) + severity."""
        priority = facility.value * 8 + severity.value
        assert priority == expected_priority
        assert 0 <= priority <= 191


class TestParametrizedCheckpointIntervals:
    """Parametrized: Various checkpoint interval values."""

    @pytest.mark.parametrize("interval", [60, 300, 900, 1800, 3600, 7200, 86400],
        ids=[f"{i}s" for i in [60, 300, 900, 1800, 3600, 7200, 86400]])
    def test_checkpoint_interval_stored(self, interval):
        """AppendOnlyConfig should accept various checkpoint intervals."""
        config = AppendOnlyConfig(checkpoint_interval=interval)
        assert config.checkpoint_interval == interval


class TestParametrizedBackupCounts:
    """Parametrized: Various backup count values."""

    @pytest.mark.parametrize("count", [0, 1, 3, 5, 10, 50],
        ids=[f"backups-{c}" for c in [0, 1, 3, 5, 10, 50]])
    def test_backup_count_stored(self, count):
        """AppendOnlyConfig should accept various backup counts."""
        config = AppendOnlyConfig(backup_count=count)
        assert config.backup_count == count


class TestParametrizedRemoteSyslogProtocols:
    """Parametrized: Remote syslog protocol options."""

    @pytest.mark.parametrize("protocol,port", [
        ("udp", 514),
        ("tcp", 514),
        ("tls", 6514),
    ], ids=["udp", "tcp", "tls"])
    def test_protocol_config(self, protocol, port):
        """RemoteSyslogConfig should accept various protocol/port combinations."""
        config = RemoteSyslogConfig(host="syslog.test", port=port, protocol=protocol)
        assert config.protocol == protocol
        assert config.port == port
