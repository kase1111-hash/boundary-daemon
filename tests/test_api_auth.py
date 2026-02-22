"""
Tests for the API Authentication module.

Tests token-based authentication, capabilities, and rate limiting.
"""

import os
import sys
import time
from datetime import datetime, timedelta

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.auth.api_auth import (
    APICapability,
    APIToken,
    CAPABILITY_SETS,
    COMMAND_CAPABILITIES,
    COMMAND_RATE_LIMITS,
    CommandRateLimitEntry,
    TokenManager,
)


# ===========================================================================
# APICapability Enum Tests
# ===========================================================================

class TestAPICapability:
    def test_read_only_capabilities(self):
        assert isinstance(APICapability.STATUS, APICapability)
        assert isinstance(APICapability.READ_EVENTS, APICapability)
        assert isinstance(APICapability.VERIFY_LOG, APICapability)
        assert isinstance(APICapability.CHECK_RECALL, APICapability)
        assert isinstance(APICapability.CHECK_TOOL, APICapability)
        assert isinstance(APICapability.CHECK_MESSAGE, APICapability)

    def test_write_capabilities(self):
        assert isinstance(APICapability.SET_MODE, APICapability)

    def test_admin_capabilities(self):
        assert isinstance(APICapability.MANAGE_TOKENS, APICapability)
        assert isinstance(APICapability.ADMIN, APICapability)

    def test_all_capabilities_unique(self):
        values = [c.value for c in APICapability]
        assert len(values) == len(set(values))


# ===========================================================================
# Capability Sets Tests
# ===========================================================================

class TestCapabilitySets:
    def test_readonly_set_exists(self):
        assert 'readonly' in CAPABILITY_SETS
        readonly = CAPABILITY_SETS['readonly']
        assert APICapability.STATUS in readonly
        assert APICapability.READ_EVENTS in readonly

    def test_readonly_no_write(self):
        readonly = CAPABILITY_SETS['readonly']
        assert APICapability.SET_MODE not in readonly
        assert APICapability.MANAGE_TOKENS not in readonly
        assert APICapability.ADMIN not in readonly

    def test_operator_set_exists(self):
        assert 'operator' in CAPABILITY_SETS
        operator = CAPABILITY_SETS['operator']
        assert APICapability.SET_MODE in operator

    def test_operator_includes_readonly(self):
        readonly = CAPABILITY_SETS['readonly']
        operator = CAPABILITY_SETS['operator']
        for cap in readonly:
            assert cap in operator

    def test_admin_set_exists(self):
        assert 'admin' in CAPABILITY_SETS
        admin = CAPABILITY_SETS['admin']
        assert APICapability.ADMIN in admin


# ===========================================================================
# Command Capabilities Tests
# ===========================================================================

class TestCommandCapabilities:
    def test_status_command(self):
        assert COMMAND_CAPABILITIES['status'] == APICapability.STATUS

    def test_get_events_command(self):
        assert COMMAND_CAPABILITIES['get_events'] == APICapability.READ_EVENTS

    def test_set_mode_command(self):
        assert COMMAND_CAPABILITIES['set_mode'] == APICapability.SET_MODE

    def test_token_management_commands(self):
        assert COMMAND_CAPABILITIES['create_token'] == APICapability.MANAGE_TOKENS
        assert COMMAND_CAPABILITIES['revoke_token'] == APICapability.MANAGE_TOKENS
        assert COMMAND_CAPABILITIES['list_tokens'] == APICapability.MANAGE_TOKENS

    def test_all_commands_have_capability(self):
        for cmd, cap in COMMAND_CAPABILITIES.items():
            assert isinstance(cap, APICapability)


# ===========================================================================
# Command Rate Limits Tests
# ===========================================================================

class TestCommandRateLimits:
    def test_rate_limit_format(self):
        """Rate limits should be (max_requests, window_seconds) tuples."""
        for cmd, limit in COMMAND_RATE_LIMITS.items():
            assert isinstance(limit, tuple)
            assert len(limit) == 2
            assert isinstance(limit[0], int)
            assert isinstance(limit[1], int)

    def test_rate_limits_positive(self):
        for cmd, (max_req, window) in COMMAND_RATE_LIMITS.items():
            assert max_req > 0
            assert window > 0

    def test_read_commands_higher_limits(self):
        status_limit = COMMAND_RATE_LIMITS['status'][0]
        set_mode_limit = COMMAND_RATE_LIMITS['set_mode'][0]
        assert status_limit > set_mode_limit

    def test_token_commands_strict_limits(self):
        create_limit = COMMAND_RATE_LIMITS['create_token'][0]
        assert create_limit <= 10  # Very limited


# ===========================================================================
# CommandRateLimitEntry Tests
# ===========================================================================

class TestCommandRateLimitEntry:
    def test_entry_creation(self):
        entry = CommandRateLimitEntry()
        assert entry.request_times == []
        assert entry.blocked_until is None

    def test_entry_with_times(self):
        now = time.monotonic()
        entry = CommandRateLimitEntry(request_times=[now])
        assert len(entry.request_times) == 1

    def test_entry_with_block(self):
        block_time = time.monotonic() + 60
        entry = CommandRateLimitEntry(blocked_until=block_time)
        assert entry.blocked_until == block_time


# ===========================================================================
# APIToken Tests
# ===========================================================================

class TestAPIToken:
    def test_token_creation(self):
        token = APIToken(
            token_id="abc12345",
            token_hash="hash_value",
            name="test_token",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
        )
        assert token.token_id == "abc12345"
        assert token.name == "test_token"

    def test_token_defaults(self):
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
        )
        assert token.expires_at is None
        assert token.last_used is None
        assert token.created_by == "system"
        assert token.revoked is False
        assert token.use_count == 0
        assert token.metadata == {}

    def test_token_with_expiry(self):
        expiry = datetime.now() + timedelta(hours=24)
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
            expires_at=expiry,
        )
        assert token.expires_at == expiry

    def test_token_is_valid_active(self):
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
        )
        valid, message = token.is_valid()
        assert valid is True

    def test_token_is_valid_revoked(self):
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
            revoked=True,
        )
        valid, message = token.is_valid()
        assert valid is False
        assert "revoked" in message.lower()

    def test_token_is_valid_expired(self):
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now() - timedelta(hours=48),
            expires_at=datetime.now() - timedelta(hours=24),
        )
        valid, message = token.is_valid()
        assert valid is False
        assert "expired" in message.lower()

    def test_token_with_capabilities(self):
        caps = {APICapability.STATUS, APICapability.READ_EVENTS}
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities=caps,
            created_at=datetime.now(),
        )
        assert APICapability.STATUS in token.capabilities
        assert APICapability.READ_EVENTS in token.capabilities
        assert APICapability.SET_MODE not in token.capabilities


# ===========================================================================
# Integration Tests
# ===========================================================================

class TestAPIAuthIntegration:
    def test_readonly_token_workflow(self):
        readonly_caps = CAPABILITY_SETS['readonly']
        token = APIToken(
            token_id="readonly",
            token_hash="hash",
            name="Readonly Token",
            capabilities=readonly_caps,
            created_at=datetime.now(),
        )

        # Should be valid
        valid, _ = token.is_valid()
        assert valid is True

        # Should have readonly caps
        assert APICapability.STATUS in token.capabilities
        assert APICapability.SET_MODE not in token.capabilities

    def test_operator_token_workflow(self):
        operator_caps = CAPABILITY_SETS['operator']
        token = APIToken(
            token_id="operator",
            token_hash="hash",
            name="Operator Token",
            capabilities=operator_caps,
            created_at=datetime.now(),
        )

        # Should have SET_MODE
        assert APICapability.SET_MODE in token.capabilities

    def test_admin_token_workflow(self):
        admin_caps = CAPABILITY_SETS['admin']
        token = APIToken(
            token_id="admin",
            token_hash="hash",
            name="Admin Token",
            capabilities=admin_caps,
            created_at=datetime.now(),
        )

        # Should have ADMIN
        assert APICapability.ADMIN in token.capabilities


# ===========================================================================
# Edge Cases
# ===========================================================================

class TestAPIAuthEdgeCases:
    def test_empty_capabilities(self):
        """Token with empty capabilities should be valid but useless."""
        token = APIToken(
            token_id="empty",
            token_hash="hash",
            name="Empty Token",
            capabilities=set(),
            created_at=datetime.now(),
        )
        valid, _ = token.is_valid()
        assert valid is True
        assert len(token.capabilities) == 0

    def test_token_with_metadata(self):
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
            metadata={'client': 'test', 'version': '1.0'},
        )
        assert token.metadata['client'] == 'test'
        assert token.metadata['version'] == '1.0'

    def test_token_use_count(self):
        token = APIToken(
            token_id="test",
            token_hash="hash",
            name="test",
            capabilities={APICapability.STATUS},
            created_at=datetime.now(),
            use_count=42,
        )
        assert token.use_count == 42


# ===========================================================================
# Error-Path Tests
# ===========================================================================

class TestTokenManagerErrorPaths:
    """Error-path tests for TokenManager using pytest.raises."""

    def test_create_token_unknown_capability_raises_value_error(self, tmp_path):
        """Creating a token with an unknown capability should raise ValueError."""
        tm = TokenManager(token_file=str(tmp_path / "tokens.json"))
        with pytest.raises(ValueError, match="Unknown capability"):
            tm.create_token(
                name="bad-token",
                capabilities={"totally_fake_capability"},
                created_by="test",
            )

    def test_create_token_multiple_unknown_capabilities_raises(self, tmp_path):
        """Creating a token with multiple unknown capabilities raises ValueError."""
        tm = TokenManager(token_file=str(tmp_path / "tokens.json"))
        with pytest.raises(ValueError, match="Unknown capability"):
            tm.create_token(
                name="bad-token",
                capabilities={"nonexistent_a", "nonexistent_b"},
                created_by="test",
            )

    def test_from_dict_missing_token_id_raises_key_error(self):
        """APIToken.from_dict with missing token_id should raise KeyError."""
        bad_data = {
            'token_hash': 'abc',
            'name': 'test',
            'capabilities': ['STATUS'],
            'created_at': '2024-01-01T00:00:00',
        }
        with pytest.raises(KeyError):
            APIToken.from_dict(bad_data)

    def test_from_dict_missing_token_hash_raises_key_error(self):
        """APIToken.from_dict with missing token_hash should raise KeyError."""
        bad_data = {
            'token_id': 'abc',
            'name': 'test',
            'capabilities': ['STATUS'],
            'created_at': '2024-01-01T00:00:00',
        }
        with pytest.raises(KeyError):
            APIToken.from_dict(bad_data)

    def test_from_dict_missing_name_raises_key_error(self):
        """APIToken.from_dict with missing name should raise KeyError."""
        bad_data = {
            'token_id': 'abc',
            'token_hash': 'def',
            'capabilities': ['STATUS'],
            'created_at': '2024-01-01T00:00:00',
        }
        with pytest.raises(KeyError):
            APIToken.from_dict(bad_data)

    def test_from_dict_invalid_capability_raises_key_error(self):
        """APIToken.from_dict with an invalid capability name raises KeyError."""
        bad_data = {
            'token_id': 'abc',
            'token_hash': 'def',
            'name': 'test',
            'capabilities': ['NONEXISTENT_CAP'],
            'created_at': '2024-01-01T00:00:00',
        }
        with pytest.raises(KeyError):
            APIToken.from_dict(bad_data)

    def test_from_dict_invalid_created_at_raises_value_error(self):
        """APIToken.from_dict with malformed created_at raises ValueError."""
        bad_data = {
            'token_id': 'abc',
            'token_hash': 'def',
            'name': 'test',
            'capabilities': ['STATUS'],
            'created_at': 'not-a-date',
        }
        with pytest.raises(ValueError):
            APIToken.from_dict(bad_data)

    def test_from_dict_invalid_expires_at_raises_value_error(self):
        """APIToken.from_dict with malformed expires_at raises ValueError."""
        bad_data = {
            'token_id': 'abc',
            'token_hash': 'def',
            'name': 'test',
            'capabilities': ['STATUS'],
            'created_at': '2024-01-01T00:00:00',
            'expires_at': 'garbage-date',
        }
        with pytest.raises(ValueError):
            APIToken.from_dict(bad_data)

    def test_from_dict_missing_capabilities_raises_key_error(self):
        """APIToken.from_dict with missing capabilities raises KeyError."""
        bad_data = {
            'token_id': 'abc',
            'token_hash': 'def',
            'name': 'test',
            'created_at': '2024-01-01T00:00:00',
        }
        with pytest.raises(KeyError):
            APIToken.from_dict(bad_data)

    def test_from_dict_missing_created_at_raises_key_error(self):
        """APIToken.from_dict with missing created_at raises KeyError."""
        bad_data = {
            'token_id': 'abc',
            'token_hash': 'def',
            'name': 'test',
            'capabilities': ['STATUS'],
        }
        with pytest.raises(KeyError):
            APIToken.from_dict(bad_data)

    def test_from_dict_empty_dict_raises_key_error(self):
        """APIToken.from_dict with empty dict raises KeyError."""
        with pytest.raises(KeyError):
            APIToken.from_dict({})

    def test_create_token_mixed_valid_invalid_capabilities_raises(self, tmp_path):
        """Mixed valid and invalid capabilities should raise ValueError."""
        tm = TokenManager(token_file=str(tmp_path / "tokens.json"))
        with pytest.raises(ValueError, match="Unknown capability"):
            tm.create_token(
                name="mixed-token",
                capabilities={"readonly", "bogus_capability"},
                created_by="test",
            )
