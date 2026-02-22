# Implementation Plan: Fix 32 Audit Findings

## Organization

32 findings organized into **6 phases**, grouped by file proximity and dependency order.
Each fix includes the exact change and a test strategy.

---

## Phase 1: API Authentication & Authorization (Findings #1, #2, #3, #14, #17)

These are the highest-impact items — unauthenticated access to privileged operations.

### 1A. Pass token to `_handle_create_tui_token` and validate (Finding #1)
**File:** `api/boundary_api.py:399-400, 534-587`
**Problem:** `create_tui_token` handler receives no `token` parameter. Although the dispatch
gate catches `token is None` for WRITE_COMMANDS, the handler itself never validates who's calling.
**Fix:** Pass `token` to handler. Inside handler, require either a valid token OR that no
tokens exist yet (bootstrap scenario):
```python
elif command == 'create_tui_token':
    return self._handle_create_tui_token(params, token)
```
In `_handle_create_tui_token(self, params, requesting_token)`:
- If tokens already exist and `requesting_token is None`, return auth error
- If no tokens exist at all (bootstrap), allow creation (first-run flow)

**Test:** Call `create_tui_token` without auth when tokens exist → assert failure.

### 1B. Add capability checks to `list_tokens` and `rate_limit_status` (Finding #2)
**File:** `api/boundary_api.py:616-673`
**Problem:** Any authenticated user can enumerate all tokens and rate limit status.
**Fix:** At top of `_handle_list_tokens`, check token has MANAGE_TOKENS capability:
```python
def _handle_list_tokens(self, params, token):
    if not token or not token.has_capability(APICapability.MANAGE_TOKENS):
        return {'success': False, 'error': 'Insufficient permissions'}
```
Same for `_handle_rate_limit_status` when `include_all=True`.
Pass `token` from dispatch for both commands.

**Test:** Call `list_tokens` with read-only token → assert permission denied.

### 1C. Fix socket permissions TOCTOU (Finding #14)
**File:** `api/boundary_api.py:209-213`
**Problem:** `bind()` then `chmod()` leaves a window where socket has default permissions.
**Fix:** Set umask before bind, restore after:
```python
old_umask = os.umask(0o177)  # Only owner rw
try:
    self._socket.bind(self.socket_path)
finally:
    os.umask(old_umask)
self._socket.listen(5)
```

**Test:** Verify socket file permissions are 0o600 immediately after bind (no chmod needed).

### 1D. Add JSON request size/depth validation (Finding #17)
**File:** `api/boundary_api.py:261-273`
**Problem:** No size limits on incoming JSON. Large/deeply nested payloads can DoS.
**Fix:** Check `len(data)` before parsing. Reject > 64KB. After parsing, validate
`command` is a string and `params` is a dict:
```python
data = conn.recv(65536)
if not data:
    return
if len(data) > 65536:
    conn.sendall(json.dumps({'error': 'Request too large'}).encode())
    return
```

**Test:** Send 128KB JSON payload → assert rejection.

### 1E. Validate numeric env vars with try/except and bounds (Finding #16)
**File:** `daemon/boundary_daemon.py:991`
**Problem:** `int(os.environ.get('BOUNDARY_SIEM_PORT', '514'))` crashes on malformed input.
**Fix:** Wrap all numeric env var parsing in try/except with bounds:
```python
try:
    siem_port = int(os.environ.get('BOUNDARY_SIEM_PORT', '514'))
    if not (1 <= siem_port <= 65535):
        raise ValueError(f"Port out of range: {siem_port}")
except (ValueError, TypeError) as e:
    logger.error(f"Invalid BOUNDARY_SIEM_PORT: {e}, using default 514")
    siem_port = 514
```
Apply same pattern to all float/int env var conversions (~lines 1055-1061).

**Test:** Set `BOUNDARY_SIEM_PORT=abc` → assert daemon starts with default.

---

## Phase 2: Signal Handler & Ceremony Safety (Findings #3, #4, #15)

### 2A. Make signal handler async-safe (Finding #3)
**File:** `daemon/boundary_daemon.py:2553-2557`
**Problem:** Signal handler calls `self.stop()` (logging, file I/O, thread joins) and `sys.exit(0)`.
**Fix:** Set a flag and let the main loop handle shutdown:
```python
def _signal_handler(self, signum, frame):
    self._shutdown_event.set()
```
In the main `run()` loop, check `self._shutdown_event.is_set()` and call `self.stop()` there.
Remove `sys.exit(0)` entirely — the run loop will exit naturally.

**Test:** Send SIGTERM to daemon → assert clean shutdown without deadlock.

### 2B. Remove interactive `input()` from ceremony override (Finding #4)
**File:** `daemon/boundary_daemon.py:3351`
**Problem:** `input("> ")` in a daemon context can be piped/automated.
**Fix:** Replace with a time-limited, token-based confirmation:
```python
else:
    # No biometric available - require explicit ceremony token
    logger.warning("Override ceremony requires biometric auth or ceremony token. "
                  "Interactive input not supported in daemon mode.")
    return (False, "Override ceremony requires biometric authentication or ceremony token. "
                   "Interactive mode not available.")
```

**Test:** Call `perform_override_ceremony` without biometric → assert failure (not hanging).

### 2C. Fail-closed on insecure config/secret file permissions (Finding #15)
**File:** `daemon/boundary_daemon.py:3172-3173, 1607-1608`
**Problem:** World-readable config and secret files only generate warnings, not failures.
**Fix:** In `load_config_secure`, raise on group/world-readable:
```python
if st.st_mode & 0o077:
    raise RuntimeError(f"SECURITY: Config file {config_path} has overly permissive "
                      f"mode {oct(st.st_mode)}. Fix with: chmod 600 {config_path}")
```
In `_read_secret_file`, return None (don't use the secret) if permissions are wrong:
```python
if st.st_mode & 0o077:
    logger.error(f"SECURITY: Refusing to use secret file {file_path} with mode {oct(st.st_mode)}")
    return None  # Do not use insecure secret
```

**Test:** Create config with 0o644 → assert load raises RuntimeError.

---

## Phase 3: Tripwire & Lockdown Integrity (Findings #11, #12, #22)

### 3A. Connect LockdownManager to TripwireSystem auth (Finding #11)
**File:** `daemon/tripwires.py:780-796`
**Problem:** `release_lockdown()` uses `hasattr(self, '_auth_token_hash')` which always fails
since `_auth_token_hash` belongs to `TripwireSystem`, not `LockdownManager`.
**Fix:** Pass a token verifier callable when constructing LockdownManager:
```python
class LockdownManager:
    def __init__(self, ..., token_verifier=None):
        ...
        self._token_verifier = token_verifier
```
In `release_lockdown`:
```python
if self._token_verifier:
    if not self._token_verifier(auth_token):
        logger.warning(f"Unauthorized lockdown release attempt by {operator}: invalid token")
        return False
elif auth_token:
    # No verifier configured - reject any release attempt
    logger.warning("No token verifier configured - lockdown release denied")
    return False
```
In `TripwireSystem.__init__`, pass `self._verify_token` to LockdownManager.

**Test:** Call `release_lockdown` with wrong token → assert returns False.

### 3B. Fix asymmetric `_failed_attempts` reset (Finding #12)
**File:** `daemon/tripwires.py:586`
**Problem:** `clear_violations` resets `_failed_attempts = 0` on success, allowing attackers
to reset the lockout counter by alternating between clear and disable attempts.
**Fix:** Remove the reset. Never reset `_failed_attempts`:
```python
# Remove this line:
# self._failed_attempts = 0
```
The failed attempts counter should be monotonic until manual system reset.

**Test:** Make 2 failed disable attempts, then successful clear_violations, then 1 more failed
disable → assert system locks (counter wasn't reset).

### 3C. Move callback invocation outside `self._lock` (Finding #22)
**File:** `daemon/tripwires.py:460-480`
**Problem:** Callbacks fire while holding `threading.Lock()`. If any callback calls methods
that acquire `self._lock`, instant deadlock.
**Fix:** Collect violation and callbacks under lock, then invoke outside:
```python
with self._lock:
    ...
    self._violations.append(violation)
    with self._callback_lock:
        callbacks = list(self._callbacks.values())
# Invoke callbacks OUTSIDE self._lock
for callback in callbacks:
    try:
        callback(violation)
    except Exception as e:
        logger.error(f"Error in tripwire callback: {e}")
return violation
```

**Test:** Register callback that calls `get_violations()` → must not deadlock.

---

## Phase 4: State Monitor, Event Logger, Crypto (Findings #5, #6, #7, #10, #19)

### 4A. Fix 6 remaining unprotected state monitor setters (Finding #10)
**File:** `daemon/state_monitor.py:309-381`
**Problem:** `set_monitor_arp_security`, `set_monitor_wifi_security`, `set_monitor_threat_intel`,
`set_monitor_file_integrity`, `set_monitor_traffic_anomaly`, `set_monitor_process_security`
all mutate config without holding `_state_lock`.
**Fix:** Add `with self._state_lock:` to each:
```python
def set_monitor_arp_security(self, enabled: bool):
    with self._state_lock:
        self.monitoring_config.monitor_arp_security = enabled
```
Repeat for all 6 methods.

**Test:** Existing tests pass; add concurrent setter/reader test.

### 4B. Use random nonce in genesis hash (Finding #5)
**File:** `daemon/event_logger.py:120`
**Problem:** Genesis hash `"0" * 64` is identical across all instances and predictable.
**Fix:** Generate instance-specific genesis hash:
```python
import secrets
self._instance_nonce = secrets.token_hex(16)
self._last_hash = hashlib.sha256(
    f"genesis:{self._instance_nonce}".encode()
).hexdigest()
```
Store the nonce in the first log event's metadata so `verify_chain()` can recompute it.
When loading existing logs, read the nonce from the first event.

**Test:** Create two loggers → assert different genesis hashes. verify_chain still passes.

### 4C. Set secure permissions on signature file (Finding #6)
**File:** `daemon/signed_event_logger.py:160-163`
**Problem:** `.sig` file created with `open(..., 'a')` inherits umask permissions.
**Fix:** Use `os.open()` with explicit 0o600 mode like the log file:
```python
try:
    fd = os.open(self.signature_file_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, 'a') as f:
        f.write(json.dumps(signature_record) + '\n')
        f.flush()
        os.fsync(f.fileno())
```

**Test:** Create signed logger, check `.sig` file permissions are 0o600.

### 4D. Pin public key hash for key substitution detection (Finding #7)
**File:** `daemon/signed_event_logger.py:58-107`
**Problem:** If signing key file is overwritten, all signatures verify against the new key.
**Fix:** On first key creation, write a separate `.pubkey_hash` file containing
`sha256(public_key_bytes)`. On subsequent loads, verify the loaded key's public key hash
matches the pinned hash:
```python
pubkey_hash_path = self.signing_key_path + '.pubkey_hash'
current_hash = hashlib.sha256(bytes(signing_key.verify_key)).hexdigest()
if os.path.exists(pubkey_hash_path):
    with open(pubkey_hash_path, 'r') as f:
        pinned_hash = f.read().strip()
    if not hmac.compare_digest(current_hash, pinned_hash):
        raise RuntimeError("SECURITY: Signing key public key hash mismatch! "
                         "Possible key substitution attack.")
else:
    fd = os.open(pubkey_hash_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, 'w') as f:
        f.write(current_hash)
```

**Test:** Create logger, overwrite key file with new key, reload → assert RuntimeError.

### 4E. Pass `raw_score` to `_determine_action` (Finding #19)
**File:** `daemon/security/prompt_injection.py:639`
**Problem:** `_determine_action(total_score, ...)` uses capped score, not raw multi-vector score.
**Fix:** Pass `raw_score` instead:
```python
action = self._determine_action(raw_score, highest_severity, context)
```

**Test:** Inject 5 patterns with combined score 4.5 → assert action is BLOCK, not just WARN.

---

## Phase 5: Enforcement & Sandbox Hardening (Findings #8, #9, #13, #18, #20, #21, #25, #31, #32)

### 5A. Verify iptables chain jump return codes (Finding #8)
**File:** `daemon/enforcement/network_enforcer.py:496-510`
**Analysis:** `_run_iptables` at line 502/510 DOES raise `NetworkEnforcementError` on failure.
The `-C` (check) call at 497-500 is correctly checked. The jump insertion is already safe.
**Action:** DOWNGRADE — no code change needed. Add a comment clarifying the error path.

### 5B. Fix sysfs write verification to return False on exception (Finding #9)
**File:** `daemon/enforcement/usb_enforcer.py:651-652`
**Problem:** Verification exception returns `True` ("best-effort"), defeating the purpose.
**Fix:** Return `False` on verification exception:
```python
except Exception as e:
    logger.error(f"SECURITY: Sysfs write verification failed for {validated_path}: {e}")
    return False  # Fail-closed: unverifiable write is a security failure
```

**Test:** Mock verification read to raise → assert `_write_sysfs` returns False.

### 5C. Fix empty `tool_name` bypassing BLOCKED_TOOLS (Finding #13)
**File:** `daemon/policy_engine.py:360`
**Problem:** `if request.tool_name:` is falsy for `""`.
**Fix:** Check `tool_name is not None` instead, and strip before checking:
```python
if request.tool_name is not None:
    tool = request.tool_name.lower().strip()
    if tool and tool in self.BLOCKED_TOOLS:
        return PolicyDecision.DENY
    if tool and tool in self.RESTRICTED_TOOLS and mode < BoundaryMode.RESTRICTED:
        return PolicyDecision.REQUIRE_CEREMONY
```

**Test:** Pass `tool_name=""` with `requires_network=True` → assert evaluated normally.
Pass `tool_name="raw_shell"` → assert DENY.

### 5D. Validate manifest save_path against traversal (Finding #18)
**File:** `daemon/security/daemon_integrity.py:556-577`
**Problem:** `save_manifest(path=...)` accepts arbitrary paths without canonicalization.
**Fix:** Resolve and validate against allowed base directory:
```python
save_path = os.path.realpath(path or self.config.manifest_path)
allowed_base = os.path.realpath(os.path.dirname(self.config.manifest_path))
if not save_path.startswith(allowed_base + os.sep) and save_path != os.path.realpath(self.config.manifest_path):
    raise ValueError(f"SECURITY: Path traversal detected in manifest save: {path}")
```

**Test:** Call `save_manifest(path="../../etc/evil")` → assert ValueError.

### 5E. Fix BPF jump offset calculation (Finding #20)
**File:** `daemon/sandbox/seccomp_filter.py:442-451`
**Problem:** `num_syscall_rules` is calculated but never used. Jump offsets are hardcoded.
**Fix:** The current hardcoded offsets (2, 0, 1) are correct for the fixed 4-instruction arch
check sequence (x86_64 check → i386 check → kill → kill → load syscall). The offsets are
relative to the current instruction, not to syscall rules. Remove the unused variable:
```python
# Remove: num_syscall_rules = len(self._rules) * 2 + 1
```
Add a comment explaining the jump targets:
```python
# BPF jumps: jt=2 skips i386 check + 2 kill stmts to reach syscall load
# jf=0 falls through to i386 check
```

**Test:** Build BPF with 0, 1, 10, 100 rules → verify program validates correctly.

### 5F. Add `rt_sigreturn` to LOCKDOWN seccomp profile (Finding #31)
**File:** `daemon/sandbox/seccomp_filter.py:718-725`
**Problem:** LOCKDOWN profile only allows `exit`/`exit_group`. Processes need signal-related
syscalls to exit cleanly.
**Fix:** Add minimum required syscalls:
```python
allowed_syscalls={'exit', 'exit_group', 'rt_sigreturn', 'rt_sigaction',
                  'rt_sigprocmask', 'set_tid_address', 'write'},
```
`write` is needed for writing to stderr before exit. `set_tid_address` is needed by glibc.

**Test:** Apply LOCKDOWN profile to subprocess → assert clean exit (no SIGSYS).

### 5G. Validate sandbox name (Finding #32)
**File:** `daemon/sandbox/sandbox_manager.py:842`
**Problem:** User-supplied `name` used in sandbox_id without validation.
**Fix:** Validate against safe pattern:
```python
import re
SANDBOX_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$')
if name:
    if not SANDBOX_NAME_PATTERN.match(name):
        raise ValueError(f"Invalid sandbox name: {name!r}")
sandbox_id = name or f"sandbox-{uuid.uuid4().hex[:8]}"
```

**Test:** Pass `name="../../etc"` → assert ValueError.

### 5H. Add seccomp argument filtering for dangerous syscalls (Finding #21)
**File:** `daemon/enforcement/process_enforcer.py:483-495`
**Problem:** Seccomp profiles block syscalls by number only, not by argument.
**Fix:** Add argument-based rules for key syscalls in the OCI profile format:
```python
# Add argument filtering for dangerous capabilities
profile["syscalls"].append({
    "names": ["mmap", "mprotect"],
    "action": "SCMP_ACT_ERRNO",
    "errnoRet": 1,
    "args": [
        {"index": 2, "value": 4, "op": "SCMP_CMP_MASKED_EQ", "valueTwo": 4}
    ]  # Block PROT_EXEC (bit 2) in prot argument (arg index 2)
})
```
This blocks `mmap(..., PROT_EXEC, ...)` and `mprotect(..., PROT_EXEC, ...)`.

**Test:** Verify generated profile contains argument filter for PROT_EXEC.

---

## Phase 6: Storage, Crypto, and Remaining (Findings #23, #24, #25, #26, #27, #28, #29, #30)

### 6A. Fix TOCTOU state sample to policy decision (Finding #23)
**File:** `daemon/state_monitor.py:448-472`
**Problem:** Environment state can change between sampling and callback invocation.
**Fix:** Pass a frozen snapshot to callbacks. The `EnvironmentState` dataclass should be
treated as immutable. Add a sequence number to detect stale state in policy evaluation:
```python
with self._state_lock:
    old_state = self._current_state
    self._current_state = new_state
    state_seq = self._state_seq  # Add counter in __init__
    self._state_seq += 1
```
No fundamental fix possible (TOCTOU is inherent in polling), but the snapshot approach
ensures callbacks see consistent state. Already mostly implemented — just add a comment
documenting the design constraint.

**Action:** Add `_state_seq` counter and document the inherent polling TOCTOU.

### 6B. Implement WAL recovery on startup (Finding #24)
**File:** `daemon/storage/append_only.py:208-240`
**Problem:** No code checks WAL for pending data on startup.
**Fix:** After `_load_state()`, check WAL:
```python
def _recover_wal(self):
    """Replay any pending WAL entries after crash recovery."""
    if not self._wal_path or not os.path.exists(self._wal_path):
        return
    with open(self._wal_path, 'r') as f:
        pending = f.read().strip()
    if pending:
        logger.warning(f"WAL recovery: found {len(pending.splitlines())} pending events")
        for line in pending.splitlines():
            if line.strip():
                with open(self.config.log_path, 'a') as f:
                    f.write(line + '\n')
                    f.flush()
                    os.fsync(f.fileno())
        # Clear WAL after successful recovery
        with open(self._wal_path, 'w') as f:
            f.truncate()
        logger.info("WAL recovery complete")
```
Call from `initialize()` after `_load_state()`.

**Test:** Write event to WAL only (simulate crash), reinitialize → assert event in main log.

### 6C. Fix syslog truncation to split messages (Finding #25)
**File:** `daemon/storage/append_only.py:462-475`
**Problem:** Events > 1024 bytes get truncated to invalid JSON.
**Fix:** Split large events into numbered chunks:
```python
max_payload = 900  # Leave room for syslog header
if len(event_json) > max_payload:
    chunks = [event_json[i:i+max_payload] for i in range(0, len(event_json), max_payload)]
    for idx, chunk in enumerate(chunks):
        chunk_msg = json.dumps({
            'chunk': idx + 1,
            'total': len(chunks),
            'event_id': json.loads(event_json).get('event_id', ''),
            'data': chunk
        })
        self._send_syslog_message(chunk_msg, config, priority, timestamp, hostname)
    return
```

**Test:** Send event > 1024 bytes → assert multiple syslog messages sent.

### 6D. Initialize `_pending_remote` in `__init__` and protect with lock (Finding #27)
**File:** `daemon/storage/append_only.py:485-505`
**Problem:** `_pending_remote` created lazily with `hasattr()`, accessed without lock.
**Fix:** Initialize in `__init__`:
```python
self._pending_remote: List[str] = []
```
All access to `_pending_remote` is already under `self._lock` (called from `append()` which
holds `_lock`), so just ensure initialization and remove `hasattr()` checks.

**Test:** Concurrent appends with failed remote → assert no list corruption.

### 6E. Require signatures for checkpoints when key is configured (Finding #26)
**File:** `daemon/storage/append_only.py:605-625`
**Problem:** Unsigned checkpoints accepted as valid even when signing is configured.
**Fix:** If signing key is configured, require signature:
```python
if not checkpoint.signature:
    if self._signing_key:
        return False, "Checkpoint missing required signature (signing key is configured)"
    return True, "Checkpoint valid (unsigned, no signing key configured)"
```

**Test:** Configure signing key, verify unsigned checkpoint → assert failure.

### 6F. Validate symlinks in file integrity baseline (Finding #25/FIM)
**File:** `daemon/security/file_integrity.py:264-268`
**Problem:** Symlinks can be swapped after baseline is created.
**Fix:** For critical paths, resolve symlinks and store the resolved target:
```python
if os.path.islink(path):
    real_target = os.path.realpath(path)
    stat_info = os.lstat(path)
    # Store both symlink and target info for comparison
    link_target = os.readlink(path)
else:
    stat_info = os.stat(path)
    link_target = None
```
In `_compare_files`, also check if symlink target changed:
```python
if baseline.link_target != current.link_target:
    changes.append(FileChange(alert=FileIntegrityAlert.SYMLINK_CHANGED, ...))
```

**Test:** Create baseline with symlink, change target → assert SYMLINK_CHANGED alert.

### 6G. Use `datetime.now(timezone.utc)` (Finding #29)
**File:** `daemon/auth/api_auth.py:169` and other locations
**Problem:** `datetime.utcnow()` deprecated in Python 3.12+.
**Fix:** Replace all `datetime.utcnow()` with `datetime.now(timezone.utc)`:
```python
from datetime import datetime, timezone
# ...
if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
```

**Test:** Existing tests pass. No behavior change.

### 6H. Log rate limit failures at WARNING level (Finding #30)
**File:** `daemon/auth/api_auth.py:391`
**Problem:** Rate limit event logging failures logged at DEBUG level only.
**Fix:** Change to WARNING:
```python
except (ImportError, AttributeError, IOError) as e:
    logger.warning(f"SECURITY: Rate limit event logging failed: {e}")
```

**Test:** Mock event_logger to raise → assert WARNING log emitted.

---

## Execution Order Summary

| Phase | Files Changed | Fix Count | Risk |
|-------|--------------|-----------|------|
| 1 | boundary_api.py, boundary_daemon.py | 5 | High (auth) |
| 2 | boundary_daemon.py | 3 | Medium (signal safety) |
| 3 | tripwires.py | 3 | High (lockdown bypass) |
| 4 | state_monitor.py, event_logger.py, signed_event_logger.py, prompt_injection.py | 5 | High (crypto) |
| 5 | network_enforcer.py, usb_enforcer.py, policy_engine.py, daemon_integrity.py, seccomp_filter.py, sandbox_manager.py, process_enforcer.py | 8 | Medium (enforcement) |
| 6 | append_only.py, file_integrity.py, api_auth.py | 8 | Low (storage/misc) |
| **Total** | **16 files** | **32 fixes** | |

## Test Updates Required

- `tests/test_api_auth.py` — Findings #1, #2, #29, #30
- `tests/test_event_logger.py` — Finding #5
- `tests/test_tripwires.py` — Findings #3B, #3C, #11, #12, #22
- `tests/test_policy_engine.py` — Finding #13
- `tests/test_state_monitor.py` — Finding #10
- `tests/test_attack_simulations.py` — Findings #1, #2
- `tests/integration/test_enforcement_integration.py` — Findings #9, #20, #21
- `tests/test_append_only.py` — Findings #24, #25, #26, #27
- `tests/test_sandbox_enforcement_bridge.py` — Findings #31, #32
