"""
Tests for daemon/storage/log_hardening.py - Tamper-Proof Log Protection

Tests cover:
- LogHardener initialization and configuration
- Permission management
- Log sealing and unsealing
- Integrity verification
- HardeningStatus reporting
- Edge cases
"""

import json
import os
import stat
import tempfile
from pathlib import Path

import pytest

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.storage.log_hardening import (
    LogHardener, HardeningMode, ProtectionStatus,
    LogHardeningError
)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def temp_log_dir():
    tmpdir = tempfile.mkdtemp(prefix="boundary_log_test_")
    yield Path(tmpdir)
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def temp_log_file(temp_log_dir):
    return temp_log_dir / "test.log"


@pytest.fixture
def log_hardener(temp_log_file):
    return LogHardener(
        log_path=str(temp_log_file),
        mode=HardeningMode.BASIC,
        fail_on_degraded=False
    )


# ===========================================================================
# HardeningMode Tests
# ===========================================================================

class TestHardeningMode:
    @pytest.mark.unit
    def test_mode_values(self):
        assert HardeningMode.NONE.value == "none"
        assert HardeningMode.BASIC.value == "basic"
        assert HardeningMode.STANDARD.value == "standard"
        assert HardeningMode.STRICT.value == "strict"
        assert HardeningMode.PARANOID.value == "paranoid"


class TestProtectionStatus:
    @pytest.mark.unit
    def test_status_values(self):
        assert ProtectionStatus.UNPROTECTED.value == "unprotected"
        assert ProtectionStatus.PARTIAL.value == "partial"
        assert ProtectionStatus.PROTECTED.value == "protected"
        assert ProtectionStatus.SEALED.value == "sealed"
        assert ProtectionStatus.DEGRADED.value == "degraded"
        assert ProtectionStatus.FAILED.value == "failed"


# ===========================================================================
# LogHardener Initialization Tests
# ===========================================================================

class TestLogHardenerInitialization:
    @pytest.mark.unit
    def test_basic_initialization(self, temp_log_file):
        hardener = LogHardener(str(temp_log_file), mode=HardeningMode.BASIC)
        assert hardener.log_path == temp_log_file
        assert hardener.mode == HardeningMode.BASIC
        assert hardener.fail_on_degraded is False

    @pytest.mark.unit
    def test_strict_mode_initialization(self, temp_log_file):
        hardener = LogHardener(
            str(temp_log_file),
            mode=HardeningMode.STRICT,
            fail_on_degraded=True
        )
        assert hardener.mode == HardeningMode.STRICT
        assert hardener.fail_on_degraded is True

    @pytest.mark.unit
    def test_custom_sig_dir(self, temp_log_file, temp_log_dir):
        sig_dir = temp_log_dir / "custom_sigs"
        hardener = LogHardener(
            str(temp_log_file),
            mode=HardeningMode.PARANOID,
            sig_dir=str(sig_dir)
        )
        assert hardener.sig_dir == sig_dir

    @pytest.mark.unit
    def test_default_sig_dir(self, temp_log_file):
        hardener = LogHardener(str(temp_log_file), mode=HardeningMode.PARANOID)
        expected_sig_dir = temp_log_file.parent / LogHardener.SIG_SUBDIR
        assert hardener.sig_dir == expected_sig_dir


# ===========================================================================
# Permission Tests
# ===========================================================================

class TestPermissions:
    @pytest.mark.unit
    def test_permission_constants(self):
        assert LogHardener.PERM_ACTIVE == 0o600
        assert LogHardener.PERM_SEALED == 0o400
        assert LogHardener.PERM_DIR == 0o700

    @pytest.mark.unit
    def test_set_permissions(self, log_hardener, temp_log_file):
        temp_log_file.touch()
        ok, err = log_hardener._set_permissions(temp_log_file, 0o600)
        assert ok is True
        assert err == ""

        st = os.stat(temp_log_file)
        mode = stat.S_IMODE(st.st_mode)
        assert mode == 0o600

    @pytest.mark.unit
    def test_get_permissions(self, log_hardener, temp_log_file):
        temp_log_file.touch()
        os.chmod(temp_log_file, 0o644)

        perms = log_hardener._get_permissions(temp_log_file)
        assert perms == "644"


# ===========================================================================
# Hardening Tests
# ===========================================================================

class TestHardening:
    @pytest.mark.unit
    def test_harden_basic_mode(self, temp_log_file):
        hardener = LogHardener(str(temp_log_file), mode=HardeningMode.BASIC)
        status = hardener.harden()

        assert status.path == str(temp_log_file)
        assert temp_log_file.exists()
        assert status.permissions == "600"

    @pytest.mark.unit
    def test_harden_none_mode(self, temp_log_file):
        hardener = LogHardener(str(temp_log_file), mode=HardeningMode.NONE)
        status = hardener.harden()

        assert temp_log_file.exists()

    @pytest.mark.unit
    def test_harden_creates_directory(self, temp_log_dir):
        log_path = temp_log_dir / "subdir" / "test.log"
        hardener = LogHardener(str(log_path), mode=HardeningMode.BASIC)

        status = hardener.harden()
        assert log_path.parent.exists()

    @pytest.mark.unit
    def test_harden_sets_directory_permissions(self, temp_log_file):
        hardener = LogHardener(str(temp_log_file), mode=HardeningMode.BASIC)
        hardener.harden()

        st = os.stat(temp_log_file.parent)
        mode = stat.S_IMODE(st.st_mode)
        assert mode == LogHardener.PERM_DIR

    @pytest.mark.unit
    def test_harden_with_callback(self, temp_log_file):
        callbacks_received = []

        def callback(path, status):
            callbacks_received.append((path, status))

        hardener = LogHardener(
            str(temp_log_file),
            mode=HardeningMode.BASIC,
            on_protection_change=callback
        )
        hardener.harden()

        assert len(callbacks_received) == 1
        assert callbacks_received[0][0] == str(temp_log_file)

    @pytest.mark.unit
    def test_harden_paranoid_creates_sig_dir(self, temp_log_file):
        hardener = LogHardener(str(temp_log_file), mode=HardeningMode.PARANOID)
        status = hardener.harden()

        assert hardener.sig_dir.exists()
        assert status.signature_separated is True


# ===========================================================================
# Sealing Tests
# ===========================================================================

class TestSealing:
    @pytest.mark.unit
    def test_seal_nonexistent_file_returns_errors(self, temp_log_file):
        hardener = LogHardener(
            str(temp_log_file),
            mode=HardeningMode.BASIC,
            fail_on_degraded=False
        )

        status = hardener.seal()
        assert len(status.errors) > 0
        assert any("does not exist" in err for err in status.errors)

    @pytest.mark.unit
    def test_seal_nonexistent_file_raises(self, temp_log_file):
        """Test sealing a non-existent file raises when fail_on_degraded=True."""
        hardener = LogHardener(
            str(temp_log_file),
            mode=HardeningMode.BASIC,
            fail_on_degraded=True
        )

        with pytest.raises(LogHardeningError):
            hardener.seal()

    @pytest.mark.unit
    def test_seal_existing_file(self, log_hardener, temp_log_file):
        log_hardener.harden()

        with open(temp_log_file, 'w') as f:
            f.write("test log line\n")

        status = log_hardener.seal()
        assert status.permissions == "400"

    @pytest.mark.unit
    def test_seal_creates_checkpoint(self, log_hardener, temp_log_file):
        log_hardener.harden()

        with open(temp_log_file, 'w') as f:
            f.write("test content\n")

        log_hardener.seal()

        checkpoint_path = temp_log_file.with_suffix('.sealed')
        assert checkpoint_path.exists()

        with open(checkpoint_path, 'r') as f:
            checkpoint = json.load(f)

        assert 'sealed_at' in checkpoint
        assert 'log_hash' in checkpoint
        assert 'log_size' in checkpoint


# ===========================================================================
# Integrity Verification Tests
# ===========================================================================

class TestIntegrityVerification:
    @pytest.mark.unit
    def test_verify_nonexistent_file(self, log_hardener):
        is_valid, issues = log_hardener.verify_integrity()
        assert is_valid is False
        assert any("does not exist" in issue for issue in issues)

    @pytest.mark.unit
    def test_verify_basic_file(self, log_hardener, temp_log_file):
        log_hardener.harden()

        is_valid, issues = log_hardener.verify_integrity()
        assert is_valid is True
        assert len(issues) == 0

    @pytest.mark.unit
    def test_verify_wrong_permissions(self, log_hardener, temp_log_file):
        log_hardener.harden()
        os.chmod(temp_log_file, 0o777)

        is_valid, issues = log_hardener.verify_integrity()
        assert is_valid is False
        assert any("permission" in issue.lower() for issue in issues)


# ===========================================================================
# Status Tests
# ===========================================================================

class TestStatus:
    @pytest.mark.unit
    def test_get_status_after_harden(self, log_hardener, temp_log_file):
        log_hardener.harden()
        status = log_hardener.get_status()

        assert status.path == str(temp_log_file)
        assert status.permissions == "600"
        assert status.last_verified is not None

    @pytest.mark.unit
    def test_status_to_dict(self, log_hardener, temp_log_file):
        log_hardener.harden()
        status = log_hardener.get_status()
        d = status.to_dict()

        assert 'path' in d
        assert 'status' in d
        assert 'permissions' in d
        assert 'is_append_only' in d
        assert 'is_immutable' in d


# ===========================================================================
# Edge Cases
# ===========================================================================

class TestEdgeCases:
    @pytest.mark.unit
    def test_harden_idempotent(self, log_hardener, temp_log_file):
        status1 = log_hardener.harden()
        status2 = log_hardener.harden()
        status3 = log_hardener.harden()

        assert status1.permissions == status2.permissions == status3.permissions

    @pytest.mark.unit
    def test_get_signature_path_basic(self, log_hardener, temp_log_file):
        sig_path = log_hardener.get_signature_path()
        expected = temp_log_file.with_suffix('.log.sig')
        assert sig_path == expected

    @pytest.mark.unit
    def test_get_signature_path_paranoid(self, temp_log_file):
        hardener = LogHardener(str(temp_log_file), mode=HardeningMode.PARANOID)
        hardener.harden()

        sig_path = hardener.get_signature_path()
        assert hardener.sig_dir.name in str(sig_path.parent)


# ===========================================================================
# PARAMETRIZED TESTS - Added for comprehensive coverage
# ===========================================================================


class TestParametrizedHardeningModeValues:
    """Parametrized: All HardeningMode enum members."""

    MODE_VALUES = [
        (HardeningMode.NONE, "none"),
        (HardeningMode.BASIC, "basic"),
        (HardeningMode.STANDARD, "standard"),
        (HardeningMode.STRICT, "strict"),
        (HardeningMode.PARANOID, "paranoid"),
    ]

    @pytest.mark.parametrize("mode,expected_value", MODE_VALUES,
        ids=[m.name for m, _ in MODE_VALUES])
    def test_mode_value(self, mode, expected_value):
        """Each HardeningMode should have its expected string value."""
        assert mode.value == expected_value


class TestParametrizedProtectionStatusValues:
    """Parametrized: All ProtectionStatus enum members."""

    STATUS_VALUES = [
        (ProtectionStatus.UNPROTECTED, "unprotected"),
        (ProtectionStatus.PARTIAL, "partial"),
        (ProtectionStatus.PROTECTED, "protected"),
        (ProtectionStatus.SEALED, "sealed"),
        (ProtectionStatus.DEGRADED, "degraded"),
        (ProtectionStatus.FAILED, "failed"),
    ]

    @pytest.mark.parametrize("status,expected_value", STATUS_VALUES,
        ids=[s.name for s, _ in STATUS_VALUES])
    def test_status_value(self, status, expected_value):
        """Each ProtectionStatus should have its expected string value."""
        assert status.value == expected_value


class TestParametrizedHardenWithAllModes:
    """Parametrized: LogHardener can harden in every mode."""

    @pytest.mark.unit
    @pytest.mark.parametrize("mode", list(HardeningMode),
        ids=[m.name for m in HardeningMode])
    def test_harden_mode(self, mode, temp_log_dir):
        """harden() should succeed in every HardeningMode."""
        log_file = temp_log_dir / f"test_{mode.name}.log"
        hardener = LogHardener(str(log_file), mode=mode)
        status = hardener.harden()
        assert log_file.exists()
        assert status is not None


class TestParametrizedPermissionConstants:
    """Parametrized: Permission constants are correct octal values."""

    PERM_CASES = [
        ("PERM_ACTIVE", 0o600),
        ("PERM_SEALED", 0o400),
        ("PERM_DIR", 0o700),
    ]

    @pytest.mark.unit
    @pytest.mark.parametrize("attr,expected", PERM_CASES,
        ids=[a for a, _ in PERM_CASES])
    def test_permission_constant(self, attr, expected):
        """Permission constants should have correct octal values."""
        assert getattr(LogHardener, attr) == expected


class TestParametrizedSetPermissions:
    """Parametrized: Setting various file permission modes."""

    @pytest.mark.unit
    @pytest.mark.parametrize("perm", [0o400, 0o600, 0o644, 0o700, 0o755],
        ids=["400", "600", "644", "700", "755"])
    def test_set_permission_mode(self, perm, temp_log_dir):
        """_set_permissions should apply various modes correctly."""
        log_file = temp_log_dir / "perm_test.log"
        log_file.touch()
        hardener = LogHardener(str(log_file), mode=HardeningMode.BASIC)
        ok, err = hardener._set_permissions(log_file, perm)
        assert ok is True
        st = os.stat(log_file)
        actual_mode = stat.S_IMODE(st.st_mode)
        assert actual_mode == perm


class TestParametrizedHardenIdempotent:
    """Parametrized: Hardening is idempotent in every mode."""

    @pytest.mark.unit
    @pytest.mark.parametrize("mode", [
        HardeningMode.NONE, HardeningMode.BASIC, HardeningMode.STANDARD,
    ], ids=["NONE", "BASIC", "STANDARD"])
    def test_harden_idempotent_per_mode(self, mode, temp_log_dir):
        """Hardening the same file multiple times should be idempotent."""
        log_file = temp_log_dir / f"idem_{mode.name}.log"
        hardener = LogHardener(str(log_file), mode=mode)
        s1 = hardener.harden()
        s2 = hardener.harden()
        s3 = hardener.harden()
        assert s1.permissions == s2.permissions == s3.permissions


class TestParametrizedVerifyIntegrityWithPermChanges:
    """Parametrized: Integrity verification detects various wrong permissions."""

    @pytest.mark.unit
    @pytest.mark.parametrize("bad_perm", [0o644, 0o666, 0o755, 0o777],
        ids=["644", "666", "755", "777"])
    def test_wrong_permission_detected(self, bad_perm, temp_log_dir):
        """verify_integrity should detect wrong permissions."""
        log_file = temp_log_dir / "verify_test.log"
        hardener = LogHardener(str(log_file), mode=HardeningMode.BASIC)
        hardener.harden()
        os.chmod(log_file, bad_perm)
        is_valid, issues = hardener.verify_integrity()
        assert is_valid is False
        assert any("permission" in issue.lower() for issue in issues)


# ===========================================================================
# Error-Path Tests
# ===========================================================================

class TestLogHardeningErrorPaths:
    """Error-path tests for LogHardener using pytest.raises."""

    def test_seal_nonexistent_file_strict_raises(self, tmp_path):
        """Sealing a nonexistent file with fail_on_degraded raises LogHardeningError."""
        hardener = LogHardener(
            str(tmp_path / "missing.log"),
            mode=HardeningMode.STRICT,
            fail_on_degraded=True,
        )
        with pytest.raises(LogHardeningError, match="Cannot seal"):
            hardener.seal()

    def test_seal_nonexistent_file_message_content(self, tmp_path):
        """LogHardeningError should mention 'log file does not exist'."""
        hardener = LogHardener(
            str(tmp_path / "missing.log"),
            mode=HardeningMode.STRICT,
            fail_on_degraded=True,
        )
        with pytest.raises(LogHardeningError, match="log file does not exist"):
            hardener.seal()

    def test_harden_strict_no_chattr_raises(self, tmp_path):
        """STRICT mode with unavailable chattr raises LogHardeningError."""
        log_file = tmp_path / "test.log"
        log_file.touch()
        hardener = LogHardener(
            str(log_file),
            mode=HardeningMode.STRICT,
            fail_on_degraded=True,
        )
        hardener._has_chattr = False
        hardener._is_root = False
        with pytest.raises(LogHardeningError, match="Log hardening failed"):
            hardener.harden()

    def test_harden_paranoid_no_chattr_raises(self, tmp_path):
        """PARANOID mode with unavailable chattr raises LogHardeningError."""
        log_file = tmp_path / "test.log"
        log_file.touch()
        hardener = LogHardener(
            str(log_file),
            mode=HardeningMode.PARANOID,
            fail_on_degraded=True,
        )
        hardener._has_chattr = False
        hardener._is_root = False
        with pytest.raises(LogHardeningError):
            hardener.harden()

    def test_harden_strict_chattr_not_root_raises(self, tmp_path):
        """STRICT mode without root privileges raises LogHardeningError."""
        log_file = tmp_path / "test.log"
        log_file.touch()
        hardener = LogHardener(
            str(log_file),
            mode=HardeningMode.STRICT,
            fail_on_degraded=True,
        )
        hardener._has_chattr = True
        hardener._is_root = False
        with pytest.raises(LogHardeningError, match="Log hardening failed"):
            hardener.harden()

    def test_run_chattr_not_available_returns_false(self, tmp_path):
        """_run_chattr returns (False, msg) when chattr is not available."""
        log_file = tmp_path / "test.log"
        log_file.touch()
        hardener = LogHardener(str(log_file), mode=HardeningMode.STANDARD)
        hardener._has_chattr = False
        ok, msg = hardener._run_chattr('+a', log_file)
        assert ok is False
        assert "not available" in msg

    def test_run_chattr_not_root_returns_false(self, tmp_path):
        """_run_chattr returns (False, msg) when not root."""
        log_file = tmp_path / "test.log"
        log_file.touch()
        hardener = LogHardener(str(log_file), mode=HardeningMode.STANDARD)
        hardener._has_chattr = True
        hardener._is_root = False
        ok, msg = hardener._run_chattr('+a', log_file)
        assert ok is False
        assert "root" in msg

    def test_run_chattr_subprocess_timeout_returns_false(self, tmp_path):
        """_run_chattr returns (False, msg) on subprocess timeout."""
        from unittest.mock import patch
        import subprocess
        log_file = tmp_path / "test.log"
        log_file.touch()
        hardener = LogHardener(str(log_file), mode=HardeningMode.STANDARD)
        hardener._has_chattr = True
        hardener._is_root = True
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd='chattr', timeout=5)):
            ok, msg = hardener._run_chattr('+a', log_file)
            assert ok is False
            assert "timed out" in msg

    def test_run_chattr_oserror_returns_false(self, tmp_path):
        """_run_chattr returns (False, msg) on OSError."""
        from unittest.mock import patch
        log_file = tmp_path / "test.log"
        log_file.touch()
        hardener = LogHardener(str(log_file), mode=HardeningMode.STANDARD)
        hardener._has_chattr = True
        hardener._is_root = True
        with patch('subprocess.run', side_effect=OSError("Permission denied")):
            ok, msg = hardener._run_chattr('+a', log_file)
            assert ok is False
            assert "Permission denied" in msg

    def test_set_permissions_oserror_returns_false(self, tmp_path):
        """_set_permissions returns (False, msg) on OSError."""
        from unittest.mock import patch
        log_file = tmp_path / "test.log"
        log_file.touch()
        hardener = LogHardener(str(log_file), mode=HardeningMode.STANDARD)
        with patch('os.chmod', side_effect=OSError("Operation not permitted")):
            ok, msg = hardener._set_permissions(log_file, 0o600)
            assert ok is False
            assert "Operation not permitted" in msg
