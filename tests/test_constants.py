"""
Tests for the Constants module.

Tests centralized configuration values and constants.
"""

import os
import sys


# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.constants import (
    Timeouts,
    BufferSizes,
    Permissions,
)


# ===========================================================================
# Timeout Constants Tests
# ===========================================================================

class TestTimeouts:
    def test_subprocess_timeouts_positive(self):
        assert Timeouts.SUBPROCESS_SHORT > 0
        assert Timeouts.SUBPROCESS_DEFAULT > 0
        assert Timeouts.SUBPROCESS_MEDIUM > 0
        assert Timeouts.SUBPROCESS_LONG > 0
        assert Timeouts.SUBPROCESS_EXTENDED > 0

    def test_subprocess_timeouts_ordered(self):
        assert Timeouts.SUBPROCESS_SHORT < Timeouts.SUBPROCESS_DEFAULT
        assert Timeouts.SUBPROCESS_DEFAULT < Timeouts.SUBPROCESS_MEDIUM
        assert Timeouts.SUBPROCESS_MEDIUM < Timeouts.SUBPROCESS_LONG
        assert Timeouts.SUBPROCESS_LONG < Timeouts.SUBPROCESS_EXTENDED

    def test_network_timeouts_positive(self):
        assert Timeouts.SOCKET_CONNECT > 0
        assert Timeouts.SOCKET_READ > 0
        assert Timeouts.DNS_QUERY > 0
        assert Timeouts.HTTP_REQUEST > 0

    def test_thread_join_timeouts_positive(self):
        assert Timeouts.THREAD_JOIN_SHORT > 0
        assert Timeouts.THREAD_JOIN_DEFAULT > 0
        assert Timeouts.THREAD_JOIN_LONG > 0

    def test_monitoring_intervals_positive(self):
        assert Timeouts.HEALTH_CHECK_INTERVAL > 0
        assert Timeouts.STATE_POLL_INTERVAL > 0
        assert Timeouts.ENFORCEMENT_INTERVAL > 0
        assert Timeouts.INTEGRITY_CHECK_INTERVAL > 0

    def test_challenge_timeouts(self):
        assert Timeouts.CHALLENGE_MAX_AGE > 0
        assert Timeouts.CEREMONY_COOLDOWN > 0

    def test_sleep_intervals(self):
        assert Timeouts.SLEEP_SHORT > 0
        assert Timeouts.SLEEP_DEFAULT > 0
        assert Timeouts.SLEEP_LONG > 0
        assert Timeouts.SLEEP_SHORT < Timeouts.SLEEP_DEFAULT < Timeouts.SLEEP_LONG

    def test_timeouts_are_class_attributes(self):
        # Verify we can access values
        assert hasattr(Timeouts, 'SUBPROCESS_DEFAULT')
        assert hasattr(Timeouts, 'SOCKET_CONNECT')


# ===========================================================================
# Buffer Size Constants Tests
# ===========================================================================

class TestBufferSizes:
    def test_socket_buffers_positive(self):
        assert BufferSizes.SOCKET_RECV > 0
        assert BufferSizes.SOCKET_SEND > 0

    def test_file_chunk_sizes_positive(self):
        assert BufferSizes.FILE_CHUNK > 0
        assert BufferSizes.FILE_CHUNK_SMALL > 0
        assert BufferSizes.FILE_CHUNK_LARGE > 0

    def test_file_chunk_sizes_ordered(self):
        assert BufferSizes.FILE_CHUNK_SMALL < BufferSizes.FILE_CHUNK
        assert BufferSizes.FILE_CHUNK < BufferSizes.FILE_CHUNK_LARGE

    def test_message_limits_positive(self):
        assert BufferSizes.MESSAGE_MAX_LENGTH > 0
        assert BufferSizes.LOG_LINE_MAX > 0

    def test_event_buffer_sizes_ordered(self):
        assert BufferSizes.EVENT_BUFFER_SMALL < BufferSizes.EVENT_BUFFER_DEFAULT
        assert BufferSizes.EVENT_BUFFER_DEFAULT < BufferSizes.EVENT_BUFFER_LARGE

    def test_max_file_sizes_ordered(self):
        assert BufferSizes.MAX_FILE_SIZE_SMALL < BufferSizes.MAX_FILE_SIZE_MEDIUM
        assert BufferSizes.MAX_FILE_SIZE_MEDIUM < BufferSizes.MAX_FILE_SIZE_LARGE

    def test_buffers_are_class_attributes(self):
        assert hasattr(BufferSizes, 'SOCKET_RECV')
        assert hasattr(BufferSizes, 'FILE_CHUNK')


# ===========================================================================
# Permission Constants Tests
# ===========================================================================

class TestPermissions:
    def test_owner_permissions(self):
        assert Permissions.OWNER_READ_ONLY == 0o400
        assert Permissions.OWNER_READ_WRITE == 0o600
        assert Permissions.OWNER_READ_WRITE_EXEC == 0o700

    def test_secure_permissions(self):
        assert Permissions.SECURE_FILE == 0o600
        assert Permissions.SECURE_DIR == 0o700

    def test_standard_permissions(self):
        assert Permissions.STANDARD_FILE == 0o644
        assert Permissions.STANDARD_DIR == 0o755

    def test_special_permissions(self):
        assert Permissions.NO_ACCESS == 0o000
        assert Permissions.READ_ONLY_ALL == 0o444

    def test_suid_sgid_bits(self):
        assert Permissions.SUID_BIT == 0o4000
        assert Permissions.SGID_BIT == 0o2000
        assert Permissions.STICKY_BIT == 0o1000

    def test_permissions_are_integers(self):
        for perm in Permissions:
            assert isinstance(perm.value, int)

    def test_secure_more_restrictive_than_standard(self):
        # SECURE_FILE (0o600) should not allow group/other access
        # STANDARD_FILE (0o644) allows read by group/other
        assert Permissions.SECURE_FILE < Permissions.STANDARD_FILE

    def test_permission_octal_format(self):
        for perm in Permissions:
            # All bits should be in valid range (0-7 for each octal digit)
            # This validates they're proper permission values
            assert 0 <= perm.value <= 0o7777


# ===========================================================================
# Integration Tests
# ===========================================================================

class TestConstantsIntegration:
    def test_timeout_reasonable_for_security(self):
        """Timeouts should be reasonable for security operations."""
        # Challenge should expire quickly to prevent replay attacks
        assert Timeouts.CHALLENGE_MAX_AGE <= 60

        # Socket operations shouldn't hang forever
        assert Timeouts.SOCKET_CONNECT <= 30
        assert Timeouts.SOCKET_READ <= 60

    def test_buffer_sizes_reasonable(self):
        # File chunks should be reasonable
        assert BufferSizes.FILE_CHUNK >= 1024
        assert BufferSizes.FILE_CHUNK_LARGE >= BufferSizes.FILE_CHUNK

    def test_all_constants_accessible(self):
        # These should not raise
        _ = Timeouts.SUBPROCESS_DEFAULT
        _ = BufferSizes.SOCKET_RECV
        _ = Permissions.SECURE_FILE
