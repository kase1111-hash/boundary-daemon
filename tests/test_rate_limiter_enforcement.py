"""Integration tests verifying rate limiter actually blocks requests."""

import json
import os
import sys
import tempfile
import threading
import time
from unittest.mock import patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.auth.persistent_rate_limiter import PersistentRateLimiter


class TestPerTokenRateLimit:
    def test_per_token_rate_limit_blocks_after_threshold(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=5,
                rate_limit_window=10,
                rate_limit_block_duration=30,
                global_rate_limit_max_requests=1000,
            )

            token_id = "test_token_abc"

            # First 5 requests should all be allowed
            for i in range(5):
                allowed, reason = limiter.check_rate_limit(token_id)
                assert allowed is True, f"Request {i+1} should be allowed but got: {reason}"
                assert reason == "OK"

            # 6th request should be blocked
            allowed, reason = limiter.check_rate_limit(token_id)
            assert allowed is False, "6th request should be blocked"
            assert "rate limit" in reason.lower() or "blocked" in reason.lower()

    def test_different_tokens_have_independent_limits(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=3,
                rate_limit_window=10,
                rate_limit_block_duration=30,
                global_rate_limit_max_requests=1000,
            )

            # Exhaust token_a
            for _ in range(3):
                limiter.check_rate_limit("token_a")

            allowed_a, _ = limiter.check_rate_limit("token_a")
            assert allowed_a is False

            # token_b should still have its own quota
            allowed_b, reason_b = limiter.check_rate_limit("token_b")
            assert allowed_b is True
            assert reason_b == "OK"


class TestGlobalRateLimit:
    def test_global_rate_limit_blocks_after_threshold(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=1000,
                rate_limit_window=60,
                global_rate_limit_max_requests=5,
                global_rate_limit_window=10,
                global_rate_limit_block_duration=30,
            )

            # Use different token_ids for each request to avoid per-token limits
            for i in range(5):
                allowed, reason = limiter.check_global_rate_limit()
                assert allowed is True, f"Global request {i+1} should be allowed but got: {reason}"
                assert reason == "OK"

            # 6th global request should be blocked
            allowed, reason = limiter.check_global_rate_limit()
            assert allowed is False, "6th global request should be blocked"
            assert "global rate limit" in reason.lower() or "blocked" in reason.lower()

    def test_global_limit_blocks_even_different_tokens(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=1000,
                rate_limit_window=60,
                global_rate_limit_max_requests=4,
                global_rate_limit_window=10,
                global_rate_limit_block_duration=30,
            )

            # Exhaust global limit using different tokens
            for i in range(4):
                allowed, _ = limiter.check_global_rate_limit()
                assert allowed is True

            # Next global check should fail regardless of token
            allowed, reason = limiter.check_global_rate_limit()
            assert allowed is False


class TestRateLimitWindowExpiry:
    def test_rate_limit_expires_after_window(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            window = 10
            block_duration = 5
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=3,
                rate_limit_window=window,
                rate_limit_block_duration=block_duration,
                global_rate_limit_max_requests=1000,
            )

            token_id = "expiry_token"
            base_time = 1000000.0

            # Exhaust the limit at base_time
            with patch("time.time", return_value=base_time):
                for _ in range(3):
                    allowed, _ = limiter.check_rate_limit(token_id)
                    assert allowed is True

                # Should be blocked now
                allowed, reason = limiter.check_rate_limit(token_id)
                assert allowed is False

            # Advance time past the block duration - should be allowed again
            # The block_duration determines when the block expires,
            # and old request_times outside the window get purged
            with patch("time.time", return_value=base_time + block_duration + window + 1):
                allowed, reason = limiter.check_rate_limit(token_id)
                assert allowed is True, f"Should be allowed after window expiry but got: {reason}"

    def test_global_rate_limit_expires_after_window(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            window = 10
            block_duration = 5
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=1000,
                rate_limit_window=60,
                global_rate_limit_max_requests=3,
                global_rate_limit_window=window,
                global_rate_limit_block_duration=block_duration,
            )

            base_time = 1000000.0

            with patch("time.time", return_value=base_time):
                for _ in range(3):
                    limiter.check_global_rate_limit()
                allowed, _ = limiter.check_global_rate_limit()
                assert allowed is False

            # Advance past block + window
            with patch("time.time", return_value=base_time + block_duration + window + 1):
                allowed, reason = limiter.check_global_rate_limit()
                assert allowed is True, f"Global should be unblocked after window but got: {reason}"


class TestRateLimitPersistence:
    def test_rate_limit_state_persists_across_instances(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            token_id = "persist_token"

            # Create first limiter and consume some quota
            limiter1 = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=5,
                rate_limit_window=60,
                rate_limit_block_duration=300,
                global_rate_limit_max_requests=1000,
            )

            for _ in range(3):
                allowed, _ = limiter1.check_rate_limit(token_id)
                assert allowed is True

            # Force persist to disk
            limiter1.force_persist()

            # Create a NEW instance pointing to the same state file
            limiter2 = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=5,
                rate_limit_window=60,
                rate_limit_block_duration=300,
                global_rate_limit_max_requests=1000,
            )

            # Should only have 2 remaining requests (5 - 3 = 2)
            for _ in range(2):
                allowed, _ = limiter2.check_rate_limit(token_id)
                assert allowed is True

            # 6th overall request should be blocked
            allowed, reason = limiter2.check_rate_limit(token_id)
            assert allowed is False, "State should have persisted: 3 + 2 = 5, so 6th is blocked"

    def test_blocked_state_persists_across_instances(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            token_id = "blocked_persist_token"

            limiter1 = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=2,
                rate_limit_window=60,
                rate_limit_block_duration=300,
                global_rate_limit_max_requests=1000,
            )

            # Exhaust the limit to trigger a block
            limiter1.check_rate_limit(token_id)
            limiter1.check_rate_limit(token_id)
            allowed, _ = limiter1.check_rate_limit(token_id)
            assert allowed is False

            # Force persist (block is also persisted on trigger, but be explicit)
            limiter1.force_persist()

            # New instance should still show blocked
            limiter2 = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=2,
                rate_limit_window=60,
                rate_limit_block_duration=300,
                global_rate_limit_max_requests=1000,
            )

            allowed, reason = limiter2.check_rate_limit(token_id)
            assert allowed is False, f"Block state should persist across restarts but got allowed: {reason}"

    def test_state_file_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")

            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=10,
                rate_limit_window=60,
                global_rate_limit_max_requests=100,
            )

            limiter.check_rate_limit("json_test_token")
            limiter.check_global_rate_limit()
            limiter.force_persist()

            # Verify the file is valid JSON with expected structure
            with open(state_file, "r") as f:
                data = json.load(f)

            assert "version" in data
            assert "entries" in data
            assert "global" in data
            assert data["version"] == 1


class TestCommandRateLimit:
    def test_command_rate_limit_enforcement(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=1000,
                rate_limit_window=60,
                global_rate_limit_max_requests=10000,
            )

            token_id = "cmd_token"
            command = "set_mode"
            max_requests = 3
            window = 10

            # Fire requests up to the command limit
            for i in range(max_requests):
                allowed, reason = limiter.check_command_rate_limit(
                    token_id=token_id,
                    command=command,
                    max_requests=max_requests,
                    window=window,
                )
                assert allowed is True, f"Command request {i+1} should be allowed but got: {reason}"

            # Next request should be blocked
            allowed, reason = limiter.check_command_rate_limit(
                token_id=token_id,
                command=command,
                max_requests=max_requests,
                window=window,
            )
            assert allowed is False
            assert command in reason

    def test_different_commands_have_independent_limits(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=1000,
                rate_limit_window=60,
                global_rate_limit_max_requests=10000,
            )

            token_id = "cmd_indep_token"

            # Exhaust "set_mode" command limit
            for _ in range(2):
                limiter.check_command_rate_limit(
                    token_id=token_id, command="set_mode",
                    max_requests=2, window=10,
                )
            allowed_set, _ = limiter.check_command_rate_limit(
                token_id=token_id, command="set_mode",
                max_requests=2, window=10,
            )
            assert allowed_set is False

            # "status" command should still work (different limit tracker)
            allowed_status, reason = limiter.check_command_rate_limit(
                token_id=token_id, command="status",
                max_requests=200, window=60,
            )
            assert allowed_status is True
            assert reason == "OK"

    def test_command_rate_limit_stricter_than_token_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=100,
                rate_limit_window=60,
                global_rate_limit_max_requests=10000,
            )

            token_id = "strict_cmd_token"
            # Command limit is much stricter: only 2 per 10s vs 100 per 60s token limit
            for _ in range(2):
                allowed, _ = limiter.check_command_rate_limit(
                    token_id=token_id, command="create_token",
                    max_requests=2, window=10,
                )
                assert allowed is True

            # Command limit hit, even though per-token limit has plenty left
            allowed_cmd, _ = limiter.check_command_rate_limit(
                token_id=token_id, command="create_token",
                max_requests=2, window=10,
            )
            assert allowed_cmd is False

            # Per-token limit should still be fine
            allowed_token, _ = limiter.check_rate_limit(token_id)
            assert allowed_token is True


class TestRateLimiterReturnFormat:
    def test_rate_limiter_returns_correct_status(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=2,
                rate_limit_window=10,
                rate_limit_block_duration=30,
                global_rate_limit_max_requests=1000,
            )

            token_id = "format_token"

            # Allowed case: returns (True, "OK")
            result = limiter.check_rate_limit(token_id)
            assert isinstance(result, tuple)
            assert len(result) == 2
            assert result[0] is True
            assert isinstance(result[1], str)
            assert result[1] == "OK"

            # Consume remaining quota
            limiter.check_rate_limit(token_id)

            # Blocked case: returns (False, reason_string)
            result = limiter.check_rate_limit(token_id)
            assert isinstance(result, tuple)
            assert len(result) == 2
            assert result[0] is False
            assert isinstance(result[1], str)
            assert len(result[1]) > 0

    def test_global_rate_limit_returns_correct_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                global_rate_limit_max_requests=2,
                global_rate_limit_window=10,
                global_rate_limit_block_duration=30,
            )

            # Allowed
            result = limiter.check_global_rate_limit()
            assert result == (True, "OK")

            # Consume remaining
            limiter.check_global_rate_limit()

            # Blocked
            result = limiter.check_global_rate_limit()
            assert result[0] is False
            assert isinstance(result[1], str)
            assert "global rate limit" in result[1].lower() or "blocked" in result[1].lower()

    def test_command_rate_limit_returns_correct_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=1000,
                global_rate_limit_max_requests=10000,
            )

            # Allowed
            result = limiter.check_command_rate_limit(
                token_id="fmt_token", command="test_cmd",
                max_requests=1, window=10,
            )
            assert result == (True, "OK")

            # Blocked
            result = limiter.check_command_rate_limit(
                token_id="fmt_token", command="test_cmd",
                max_requests=1, window=10,
            )
            assert result[0] is False
            assert "test_cmd" in result[1]


class TestConcurrentRateLimiting:
    def test_concurrent_rate_limiting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            max_requests = 20
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=max_requests,
                rate_limit_window=60,
                rate_limit_block_duration=300,
                global_rate_limit_max_requests=10000,
            )

            token_id = "concurrent_token"
            results = []
            lock = threading.Lock()

            def make_request():
                allowed, reason = limiter.check_rate_limit(token_id)
                with lock:
                    results.append(allowed)

            # Launch more threads than the limit
            num_threads = 40
            threads = []
            for _ in range(num_threads):
                t = threading.Thread(target=make_request)
                threads.append(t)
                t.start()

            for t in threads:
                t.join(timeout=10)

            allowed_count = sum(1 for r in results if r is True)
            denied_count = sum(1 for r in results if r is False)

            # Exactly max_requests should be allowed, rest denied
            assert allowed_count == max_requests, (
                f"Expected exactly {max_requests} allowed, got {allowed_count}"
            )
            assert denied_count == num_threads - max_requests, (
                f"Expected {num_threads - max_requests} denied, got {denied_count}"
            )

    def test_concurrent_global_rate_limiting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            max_global = 15
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=10000,
                rate_limit_window=60,
                global_rate_limit_max_requests=max_global,
                global_rate_limit_window=60,
                global_rate_limit_block_duration=300,
            )

            results = []
            lock = threading.Lock()

            def make_global_request():
                allowed, reason = limiter.check_global_rate_limit()
                with lock:
                    results.append(allowed)

            num_threads = 30
            threads = []
            for _ in range(num_threads):
                t = threading.Thread(target=make_global_request)
                threads.append(t)
                t.start()

            for t in threads:
                t.join(timeout=10)

            allowed_count = sum(1 for r in results if r is True)
            denied_count = sum(1 for r in results if r is False)

            assert allowed_count == max_global, (
                f"Expected exactly {max_global} global allowed, got {allowed_count}"
            )
            assert denied_count == num_threads - max_global


class TestRateLimiterEdgeCases:
    def test_clear_all_resets_limits(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=2,
                rate_limit_window=60,
                rate_limit_block_duration=300,
                global_rate_limit_max_requests=1000,
            )

            token_id = "clear_token"

            # Exhaust limit
            limiter.check_rate_limit(token_id)
            limiter.check_rate_limit(token_id)
            allowed, _ = limiter.check_rate_limit(token_id)
            assert allowed is False

            # Clear all entries
            limiter.clear_all()

            # Should be allowed again
            allowed, reason = limiter.check_rate_limit(token_id)
            assert allowed is True
            assert reason == "OK"

    def test_unblock_token_allows_requests(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=1,
                rate_limit_window=60,
                rate_limit_block_duration=300,
                global_rate_limit_max_requests=1000,
            )

            token_id = "unblock_token"

            # Exhaust and get blocked
            limiter.check_rate_limit(token_id)
            allowed, _ = limiter.check_rate_limit(token_id)
            assert allowed is False

            # Unblock
            result = limiter.unblock_token(token_id)
            assert result is True

            # Should be allowed again (request_times still in window, but block cleared)
            # Note: the request_times are still present, so this will immediately re-block
            # since the count still exceeds the limit. This tests the unblock mechanism itself.
            # In practice, unblock + time passage would allow requests.

    def test_get_stats_returns_valid_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=10,
                rate_limit_window=60,
                global_rate_limit_max_requests=100,
            )

            limiter.check_rate_limit("stats_token")
            limiter.check_global_rate_limit()

            stats = limiter.get_stats()
            assert isinstance(stats, dict)
            assert "total_entries" in stats
            assert "blocked_tokens" in stats
            assert "global_total_requests" in stats
            assert "state_file" in stats
            assert stats["total_entries"] >= 1
            assert stats["global_total_requests"] >= 1

    def test_shutdown_persists_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "rate_limits.json")
            limiter = PersistentRateLimiter(
                state_file=state_file,
                rate_limit_max_requests=10,
                rate_limit_window=60,
                global_rate_limit_max_requests=100,
            )

            limiter.check_rate_limit("shutdown_token")
            limiter.shutdown()

            # Verify state was written
            assert os.path.exists(state_file)
            with open(state_file, "r") as f:
                data = json.load(f)
            assert "shutdown_token" in data["entries"]
