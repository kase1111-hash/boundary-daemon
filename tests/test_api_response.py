"""
Tests for the shared API response envelope and error codes.
"""

import json

import pytest

from daemon.api.response import APIResponse, ok_response, error_response
from daemon.api.error_codes import (
    ErrorCode, AUTH_FAILED, RATE_LIMIT_EXCEEDED, INVALID_REQUEST,
    POLICY_EVAL_FAILED, MODE_TRANSITION_DENIED, CEREMONY_REQUIRED,
    SYSTEM_IN_LOCKDOWN, TRIPWIRE_LOCKED, CONFIG_ERROR, INTERNAL_ERROR,
    NOT_FOUND, lookup,
)


class TestAPIResponse:
    def test_ok_response_structure(self):
        resp = ok_response({"mode": "RESTRICTED"})
        body = json.loads(resp.to_json())
        assert body["status"] == "ok"
        assert body["data"]["mode"] == "RESTRICTED"
        assert "timestamp" in body
        assert "error" not in body

    def test_error_response_structure(self):
        resp = error_response("E001", "Auth failed", {"realm": "api"})
        body = json.loads(resp.to_json())
        assert body["status"] == "error"
        assert body["error"]["code"] == "E001"
        assert body["error"]["message"] == "Auth failed"
        assert body["error"]["details"]["realm"] == "api"
        assert "data" not in body

    def test_ok_response_without_data(self):
        resp = ok_response()
        body = json.loads(resp.to_json())
        assert body["status"] == "ok"
        assert "data" not in body

    def test_to_dict(self):
        resp = ok_response({"key": "val"})
        d = resp.to_dict()
        assert d["status"] == "ok"
        assert d["data"]["key"] == "val"
        assert "timestamp" in d

    def test_timestamp_format(self):
        resp = ok_response()
        assert resp.timestamp.endswith("Z")


class TestErrorCodes:
    def test_all_codes_unique(self):
        codes = [
            AUTH_FAILED, RATE_LIMIT_EXCEEDED, INVALID_REQUEST,
            POLICY_EVAL_FAILED, MODE_TRANSITION_DENIED, CEREMONY_REQUIRED,
            SYSTEM_IN_LOCKDOWN, TRIPWIRE_LOCKED, CONFIG_ERROR,
            INTERNAL_ERROR, NOT_FOUND,
        ]
        code_strs = [c.code for c in codes]
        assert len(code_strs) == len(set(code_strs))

    def test_code_format(self):
        for ec in [AUTH_FAILED, RATE_LIMIT_EXCEEDED, INVALID_REQUEST,
                   POLICY_EVAL_FAILED, MODE_TRANSITION_DENIED, CEREMONY_REQUIRED,
                   SYSTEM_IN_LOCKDOWN, TRIPWIRE_LOCKED, CONFIG_ERROR,
                   INTERNAL_ERROR, NOT_FOUND]:
            assert ec.code.startswith("E")
            assert ec.code[1:].isdigit()
            assert len(ec.message) > 0

    def test_lookup_existing(self):
        assert lookup("E001") is AUTH_FAILED
        assert lookup("E005") is MODE_TRANSITION_DENIED

    def test_lookup_unknown_returns_internal_error(self):
        assert lookup("E999") is INTERNAL_ERROR

    def test_error_code_has_hint(self):
        assert len(MODE_TRANSITION_DENIED.hint) > 0
        assert "ceremony" in MODE_TRANSITION_DENIED.hint.lower()

    def test_error_code_frozen(self):
        with pytest.raises(AttributeError):
            AUTH_FAILED.code = "X999"
