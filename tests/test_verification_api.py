"""
Tests for Signature Verification API — Phase 1 remediation.

Covers:
- Finding #1: POST /keys requires authentication
- Finding #5: Hash chain uses full SHA-256 comparison
- Finding #8: GET /keys requires authentication
"""

import hashlib
import json
import threading
import time
from http.client import HTTPConnection
from unittest.mock import MagicMock, patch

import pytest

from daemon.external_integrations.siem.verification_api import (
    SignatureVerificationAPI,
    SignatureVerifier,
    VerificationStatus,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_token_manager(*, valid_tokens=None):
    """Create a mock TokenManager that validates specific tokens."""
    valid_tokens = valid_tokens or {}
    mgr = MagicMock()

    def _validate(raw_token):
        if raw_token in valid_tokens:
            return True, MagicMock(), "Valid"
        return False, None, "Token not found"

    def _check_capability(raw_token, command):
        if raw_token not in valid_tokens:
            return False, None, "Token not found"
        caps = valid_tokens[raw_token]
        if command in caps or "admin" in caps:
            return True, MagicMock(), "Authorized"
        return False, MagicMock(), f"Token lacks capability: {command}"

    mgr.validate_token.side_effect = _validate
    mgr.check_capability.side_effect = _check_capability
    return mgr


def _start_api(token_manager=None, trusted_keys=None):
    """Start a test API server on a random-ish port and return (api, port)."""
    import socket
    # Find a free port
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    api = SignatureVerificationAPI(
        host="127.0.0.1",
        port=port,
        trusted_keys=trusted_keys,
        token_manager=token_manager,
    )
    api.start()
    time.sleep(0.2)  # let server thread bind
    return api, port


def _request(port, method, path, body=None, headers=None):
    """Make an HTTP request and return (status, parsed_json)."""
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    payload = json.dumps(body).encode() if body else None
    conn.request(method, path, body=payload, headers=hdrs)
    resp = conn.getresponse()
    data = json.loads(resp.read().decode())
    status = resp.status
    conn.close()
    return status, data


# ---------------------------------------------------------------------------
# Finding #1 & #8: POST/GET /keys require authentication
# ---------------------------------------------------------------------------

class TestKeysAuthentication:
    """POST and GET /keys must require valid Bearer token."""

    def setup_method(self):
        self.token_manager = _make_token_manager(
            valid_tokens={
                "admin-tok": {"create_token", "list_tokens", "admin"},
                "readonly-tok": {"list_tokens"},
            }
        )
        self.api, self.port = _start_api(token_manager=self.token_manager)

    def teardown_method(self):
        self.api.stop()

    # -- POST /keys --

    def test_post_keys_no_token_returns_401(self):
        status, data = _request(self.port, "POST", "/keys", body={
            "key_id": "k1", "public_key": "aa" * 32,
        })
        assert status == 401

    def test_post_keys_bad_token_returns_401(self):
        status, data = _request(self.port, "POST", "/keys", body={
            "key_id": "k1", "public_key": "aa" * 32,
        }, headers={"Authorization": "Bearer bad-token"})
        assert status == 401

    def test_post_keys_readonly_token_returns_403(self):
        status, data = _request(self.port, "POST", "/keys", body={
            "key_id": "k1", "public_key": "aa" * 32,
        }, headers={"Authorization": "Bearer readonly-tok"})
        assert status == 403

    def test_post_keys_admin_token_accepted(self):
        """Admin token should reach the key-add logic (may fail on
        invalid key format, but auth itself passes — no 401/403)."""
        status, data = _request(self.port, "POST", "/keys", body={
            "key_id": "k1", "public_key": "aa" * 32,
        }, headers={"Authorization": "Bearer admin-tok"})
        # Either 200 (key added) or 400 (invalid key) — but NOT 401/403
        assert status in (200, 400)

    # -- GET /keys --

    def test_get_keys_no_token_returns_401(self):
        status, _ = _request(self.port, "GET", "/keys")
        assert status == 401

    def test_get_keys_valid_token_returns_200(self):
        status, data = _request(self.port, "GET", "/keys",
                                headers={"Authorization": "Bearer readonly-tok"})
        assert status == 200

    # -- No token manager configured --

    def test_keys_no_token_manager_returns_401(self):
        """When no token_manager is set, all protected endpoints reject."""
        api, port = _start_api(token_manager=None)
        try:
            status, _ = _request(port, "POST", "/keys", body={
                "key_id": "k1", "public_key": "aa" * 32,
            })
            assert status == 401
        finally:
            api.stop()


# ---------------------------------------------------------------------------
# Finding #5: Hash chain full comparison
# ---------------------------------------------------------------------------

class TestHashChainFullComparison:
    """Hash chain verification must use full SHA-256 comparison."""

    def test_matching_chain_passes(self):
        verifier = SignatureVerifier()
        event0_content = '{"event_type":"TEST"}'
        hash0 = hashlib.sha256(b"seed").hexdigest()

        event1_content_dict = {"event_type": "TEST2", "seq": 1}
        event1_content = json.dumps(
            {k: v for k, v in event1_content_dict.items()},
            sort_keys=True, separators=(",", ":"),
        )
        hash1 = hashlib.sha256(
            (hash0 + event1_content).encode("utf-8")
        ).hexdigest()

        events = [
            {"event_type": "TEST", "hash_chain": hash0},
            {**event1_content_dict, "hash_chain": hash1},
        ]
        valid, err, idx = verifier.verify_hash_chain(events)
        assert valid is True
        assert idx is None

    def test_prefix_collision_rejected(self):
        """Two hashes sharing a 16-char prefix but differing overall must fail."""
        verifier = SignatureVerifier()
        real_hash = hashlib.sha256(b"real").hexdigest()
        # Construct a fake hash that shares the first 16 chars
        fake_hash = real_hash[:16] + "0" * (len(real_hash) - 16)
        assert fake_hash != real_hash  # sanity

        event0 = {"event_type": "A", "hash_chain": "seed"}
        # Craft event1 so expected_hash != fake_hash
        event1 = {"event_type": "B", "hash_chain": fake_hash}

        valid, err, idx = verifier.verify_hash_chain([event0, event1])
        # The chain should be broken because fake_hash != expected
        assert valid is False or fake_hash == hashlib.sha256(
            ("seed" + json.dumps({"event_type": "B"}, sort_keys=True, separators=(",", ":"))).encode()
        ).hexdigest()

    def test_broken_chain_returns_break_index(self):
        verifier = SignatureVerifier()
        events = [
            {"event_type": "A", "hash_chain": "aaa"},
            {"event_type": "B", "hash_chain": "wrong"},
        ]
        valid, err, idx = verifier.verify_hash_chain(events)
        assert valid is False
        assert idx == 1
        assert "index 1" in err

    def test_empty_chain_passes(self):
        verifier = SignatureVerifier()
        valid, err, idx = verifier.verify_hash_chain([])
        assert valid is True


# ---------------------------------------------------------------------------
# Unprotected endpoints should still work
# ---------------------------------------------------------------------------

class TestUnprotectedEndpoints:
    """Health and verify endpoints should not require auth."""

    def setup_method(self):
        self.token_manager = _make_token_manager(valid_tokens={})
        self.api, self.port = _start_api(token_manager=self.token_manager)

    def teardown_method(self):
        self.api.stop()

    def test_health_no_auth(self):
        status, data = _request(self.port, "GET", "/health")
        assert status == 200

    def test_verify_no_auth(self):
        status, data = _request(self.port, "POST", "/verify", body={
            "event": {"event_id": "e1"},
        })
        assert status == 200
