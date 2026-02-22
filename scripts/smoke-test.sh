#!/usr/bin/env bash
# Boundary Daemon Deployment Smoke Test
#
# Verifies that the daemon starts, produces event logs, and shuts down
# cleanly.  If the API server is available it also checks the health
# endpoint.
#
# Usage:
#   bash scripts/smoke-test.sh
#
# Exit codes:
#   0  All checks passed
#   1  One or more checks failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

LOG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/boundary-smoke-XXXXXX")
SOCK_PATH="${LOG_DIR}/api/boundary.sock"
EVENT_LOG="$LOG_DIR/boundary_chain.log"
DAEMON_PID=""
PASSED=0
FAILED=0

cleanup() {
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$LOG_DIR"
}
trap cleanup EXIT

pass() {
    echo "  [PASS] $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo "  [FAIL] $1"
    FAILED=$((FAILED + 1))
}

echo "========================================"
echo "  Boundary Daemon Smoke Test"
echo "========================================"
echo "  Log dir:  $LOG_DIR"
echo ""

# ------------------------------------------------------------------
# 1. Start daemon in the background
# ------------------------------------------------------------------
echo "Step 1: Start daemon"
cd "$PROJECT_DIR"
BOUNDARY_API_BIND="$SOCK_PATH" \
    python run_daemon.py --log-dir "$LOG_DIR" --mode open --skip-integrity-check --dev-mode \
    >"$LOG_DIR/stdout.log" 2>&1 &
DAEMON_PID=$!

# Wait for the event log to appear (proves daemon initialised)
waited=0
while [ ! -f "$EVENT_LOG" ] && [ $waited -lt 30 ]; do
    sleep 1
    waited=$((waited + 1))
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        fail "Daemon exited before event log was created"
        echo "  stdout/stderr:"
        head -40 "$LOG_DIR/stdout.log" 2>/dev/null || true
        exit 1
    fi
done

if kill -0 "$DAEMON_PID" 2>/dev/null; then
    pass "Daemon started (PID $DAEMON_PID, waited ${waited}s)"
else
    fail "Daemon is not running"
    exit 1
fi

# ------------------------------------------------------------------
# 2. Health check via API (optional — API server may not be available)
# ------------------------------------------------------------------
echo "Step 2: Health check"
if [ -S "$SOCK_PATH" ]; then
    HEALTH=$(curl -s --unix-socket "$SOCK_PATH" http://localhost/status 2>/dev/null || echo "CURL_FAILED")
    if echo "$HEALTH" | python -c "import sys,json; d=json.load(sys.stdin); assert d.get('running')" 2>/dev/null; then
        pass "Health endpoint responded with running=true"
    elif echo "$HEALTH" | grep -qi "unauthorized\|auth\|token"; then
        pass "Health endpoint reachable (auth required — expected)"
    elif [ "$HEALTH" = "CURL_FAILED" ]; then
        fail "Could not connect to API socket"
    else
        pass "Health endpoint reachable (response: ${HEALTH:0:80})"
    fi
else
    pass "API socket not available (optional — skipping health check)"
fi

# ------------------------------------------------------------------
# 3. Verify events are logged
# ------------------------------------------------------------------
echo "Step 3: Verify event log"
if [ -f "$EVENT_LOG" ] && [ -s "$EVENT_LOG" ]; then
    LINES=$(wc -l < "$EVENT_LOG")
    pass "Event log exists with $LINES entries"
else
    fail "Event log missing or empty at $EVENT_LOG"
fi

# ------------------------------------------------------------------
# 4. Verify daemon stdout shows startup messages
# ------------------------------------------------------------------
echo "Step 4: Verify startup output"
if grep -q "Boundary Daemon" "$LOG_DIR/stdout.log" 2>/dev/null; then
    pass "Startup banner present"
else
    fail "Startup banner not found in stdout"
fi

# ------------------------------------------------------------------
# 5. Clean shutdown via SIGTERM
# ------------------------------------------------------------------
echo "Step 5: Clean shutdown"
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null
EXIT_CODE=$?
DAEMON_PID=""  # prevent cleanup from trying again

if [ "$EXIT_CODE" -eq 0 ] || [ "$EXIT_CODE" -eq 143 ]; then
    pass "Daemon exited cleanly (code $EXIT_CODE)"
else
    fail "Daemon exited with unexpected code $EXIT_CODE"
fi

# ------------------------------------------------------------------
# 6. Verify no orphan socket remains
# ------------------------------------------------------------------
echo "Step 6: Verify no leftover socket"
if [ ! -S "$SOCK_PATH" ]; then
    pass "API socket cleaned up (or never created)"
else
    fail "API socket still exists after shutdown"
fi

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo ""
echo "========================================"
echo "  Results: $PASSED passed, $FAILED failed"
echo "========================================"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
