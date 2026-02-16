# Code Review: Bugs That Pass Tests But Don't Function

**Reviewer:** Claude Code
**Date:** 2026-02-16
**Scope:** Full daemon module review
**Methodology:** Static analysis of all core modules, cross-referencing test coverage gaps

---

## Executive Summary

This review identified **72 issues** across the daemon codebase where code passes existing tests but would fail or be exploitable in production. The issues cluster into several systemic patterns:

1. **Security enforcement theater** -- Code that writes config files / logs messages but never applies kernel-level controls
2. **Fail-open defaults** -- Exception handlers and missing-feature fallbacks that silently disable security
3. **No-op security features** -- Methods that set state variables nobody checks, or stub implementations returning empty results
4. **Race conditions** -- Shared mutable state accessed without consistent locking
5. **Authentication gaps** -- Public API endpoints that bypass the auth middleware entirely

The **15 most critical findings** are listed below, organized by severity.

---

## CRITICAL -- Security Invariant Violations

### 1. Seccomp Profiles Written to Disk But Never Applied to Processes

**File:** `daemon/enforcement/process_enforcer.py:496-533`

`_install_seccomp_profile()` writes a JSON file to `/etc/boundary-daemon/seccomp/` but never calls `prctl(PR_SET_SECCOMP)` or invokes `SeccompFilter.apply()`. No running process is ever constrained. The entire process enforcement subsystem -- RESTRICTED, AIRGAP, COLDROOM, and LOCKDOWN modes -- provides zero syscall filtering.

**Why tests pass:** Tests assert `enforce_mode()` returns `(True, ...)` and that the profile file exists on disk.

---

### 2. COLDROOM IO Policy Allows Network and USB Access

**File:** `daemon/policy_engine.py:391-409`

`_evaluate_io_policy()` in COLDROOM mode only checks `requires_filesystem`. A request with `requires_network=True, requires_filesystem=False` returns `ALLOW`. COLDROOM is documented as "No IO except keyboard/display."

```python
# COLDROOM: only checks filesystem, misses network/USB
if mode == BoundaryMode.COLDROOM:
    if request.requires_filesystem:
        return PolicyDecision.DENY
    return PolicyDecision.ALLOW  # Network/USB requests fall through here
```

**Why tests pass:** `test_filesystem_denied_in_coldroom` only sets `requires_filesystem=True`. No test sends `requires_network=True` with `requires_filesystem=False` in COLDROOM.

---

### 3. `_handle_violation` Logs "LOCKDOWN" But Never Transitions Mode

**File:** `daemon/boundary_daemon.py:1502-1507`

```python
def _handle_violation(self, violation: TripwireViolation):
    logger.critical("System entering LOCKDOWN mode")
    # ... only logging, no actual mode transition
```

Violations detected via `on_state_change` (the primary monitoring path) call `_handle_violation` directly, bypassing the tripwire callback that actually calls `transition_mode()`. State-monitoring violations are logged but never enforced.

**Why tests pass:** Tests assert the method was called and didn't raise. The tripwire callback path (which does work) is tested separately.

---

### 4. Enforcement Failure Does Not Trigger Lockdown (Fail-Open)

**File:** `daemon/boundary_daemon.py:1405-1449`

When network/USB/process enforcement raises an exception, the catch block logs "triggering lockdown" but never calls `transition_mode(BoundaryMode.LOCKDOWN)`. This pattern repeats for all three enforcement types.

**Why tests pass:** Tests that mock enforcers to raise exceptions verify the log event is created, not that the mode changed.

---

### 5. `_mode_frozen_reason` Is Set But Never Checked

**File:** `daemon/boundary_daemon.py:539, 1676, 1723, 1784`

After clock manipulation or network trust violations, `_mode_frozen_reason` is set to freeze mode transitions. But `request_mode_change()` at line 3157 never reads this field. An attacker who triggers clock manipulation can immediately request a mode change back to OPEN.

**Why tests pass:** Tests for clock handlers verify `_mode_frozen_reason` is set. Tests for mode changes don't check if it's frozen.

---

### 6. Authentication Bypass via PUBLIC_COMMANDS

**File:** `api/boundary_api.py:322-339`

`get_events`, `get_alerts`, `get_sandboxes`, and `create_tui_token` are in `PUBLIC_COMMANDS` and completely bypass the auth middleware. `create_tui_token` grants `operator` capabilities (including `SET_MODE`) to any unauthenticated local socket client.

**Why tests pass:** Tests exercise handlers directly or with valid tokens, not from the perspective of an unauthenticated caller.

---

### 7. Signature Verification Uses Attacker-Supplied Public Key

**File:** `daemon/signed_event_logger.py:210-219`

`verify_signatures()` reads the public key from each signature record rather than using the known-good `self.verify_key`. An attacker with file access can re-sign tampered events with their own keypair and embed their public key. Verification passes.

**Why tests pass:** The tamper test modifies the log file but not the signature file. No test forges both files together.

---

### 8. Last Event in Hash Chain Can Be Tampered Undetected

**File:** `daemon/event_logger.py:88-99, 268-274`

`compute_hash()` excludes the `hash_chain` field. The last event has no subsequent event whose `hash_chain` would fail verification. The test `test_invariant_verify_chain_catches_any_single_event_tamper` explicitly skips the last event with `if target < 4:`.

**Why tests pass:** The test literally avoids asserting on the case that fails.

---

### 9. AIRGAP/COLDROOM Allow Data Through ESTABLISHED Connections

**File:** `daemon/enforcement/network_enforcer.py:424-428`

AIRGAP mode adds `-m state --state ESTABLISHED,RELATED -j ACCEPT` before the DROP rules. Any TCP connection opened before mode transition continues to flow data indefinitely, completely bypassing the "block ALL network" guarantee.

**Why tests pass:** Tests verify iptables rules are generated correctly. No test has a live TCP connection.

---

### 10. iptables Rules Only on OUTPUT Chain -- No INPUT Enforcement

**File:** `daemon/enforcement/network_enforcer.py:491-497`

The BOUNDARY_CHAIN is only inserted into OUTPUT. Inbound connections are never blocked in any mode, including LOCKDOWN.

**Why tests pass:** Tests verify chain creation succeeds, not that all traffic directions are covered.

---

## HIGH -- Significant Functional Defects

### 11. USB Insertion Detection Is a No-Op Stub

**File:** `daemon/policy_engine.py:436-439`

```python
def _get_usb_changes(self, env_state) -> Tuple[set, set]:
    # This is a simplified version; real implementation would track baseline
    return (set(), set())  # Always empty
```

The COLDROOM USB tripwire calls this and checks `if added_usb:` -- which is always False.

---

### 12. `cleanup_expired` Never Persists Token Revocation

**File:** `daemon/auth/api_auth.py:922-939`

The `to_remove` list is never appended to, so `_save_tokens()` is never called and the method always returns 0. Expired tokens are revoked in memory but revert on restart.

```python
to_remove = []
for token_hash, token in self._tokens.items():
    if token.expires_at and now > token.expires_at:
        token.revoked = True  # In-memory only
        # to_remove is never appended to!
if to_remove:  # Always empty
    self._save_tokens()  # Never called
```

---

### 13. Namespace Isolation Fails Open

**File:** `daemon/sandbox/namespace.py:434-437`

When namespaces are unavailable, the sandboxed function runs with zero isolation. The caller cannot distinguish isolated from non-isolated execution.

```python
if not self.can_create_namespaces():
    return function()  # Runs completely unsandboxed
```

---

### 14. `EnvironmentState` Equality Always False (Timestamp in Comparison)

**File:** `daemon/state_monitor.py:451`

`EnvironmentState` is a dataclass with `eq=True`. The `timestamp` field changes every sample. `old_state != new_state` is always True, so state-change callbacks fire on every polling cycle regardless of actual changes.

---

### 15. Callbacks Execute Under `_state_lock` -- Deadlock on Re-entry

**File:** `daemon/policy_engine.py:203-223`

Transition callbacks run while holding the non-reentrant `threading.Lock()`. Any callback that calls `evaluate_policy()`, `get_current_mode()`, or `transition_mode()` will deadlock the entire policy engine.

---

## Additional Findings by Module

### boundary_daemon.py (15 issues)

| # | Line(s) | Issue | Severity |
|---|---------|-------|----------|
| 1 | 460-465 | Integrity check defaults to `WARN_ONLY`, production settings commented out | Critical |
| 2 | 733, 831 | `ceremony_manager` always None when passed to SandboxManager (init order) | High |
| 3 | 1502-1507 | `_handle_violation` logs but never triggers lockdown | Critical |
| 4 | 1405-1449 | Enforcement failure logs but doesn't lockdown (3 instances) | Critical |
| 5 | 539, 3157 | `_mode_frozen_reason` set but never checked | Critical |
| 6 | 1617-1646 | `request_cleanup_all` ignores individual cleanup failures | High |
| 7 | 1261-1283 | `_running` referenced before initialization in health check closure | Medium |
| 8 | 46-47 | `sys.path.insert(0, ...)` during import -- import hijacking risk | Medium |
| 9 | 434 | `skip_integrity_check` parameter with no authentication | High |
| 10 | 2470-2474 | Signal handler calls `sys.exit(0)` interrupting critical operations | Medium |
| 11 | 3082-3095 | Config fallback has no file permission or symlink check | High |
| 12 | 3110-3114 | Config save fallback uses default (world-readable) permissions | Medium |
| 13 | 995 | SIEM token read from env var (visible via `/proc/pid/environ`) | Medium |
| 14 | 3870 | No CLI path to strict integrity mode (`BLOCK_STARTUP` unreachable) | High |
| 15 | 3859-3865 | LOCKDOWN mode missing from CLI mode choices | Medium |

### policy_engine.py (10 issues)

| # | Line(s) | Issue | Severity |
|---|---------|-------|----------|
| 1 | 203-223 | Callbacks under `_state_lock` cause deadlock on re-entry | Critical |
| 2 | 144-164 | `_custom_policies` mutated without lock (race with evaluate) | Medium |
| 3 | 391-409 | `_evaluate_io_policy` allows network/USB in COLDROOM | Critical |
| 4 | 262-273 | `request_type` choice bypasses per-type restrictions | High |
| 5 | 377-381 | TRUSTED+offline allows external model access (impossible op) | Medium |
| 6 | 326-366 | `tool_name` never checked in base policy evaluation | High |
| 7 | 436-439 | `_get_usb_changes` is a no-op stub returning empty sets | Critical |
| 8 | 262-273 | `request_type` is case-sensitive with no normalization | Low |
| 9 | 144-164 | `load_custom_policies` validate-then-install is not atomic | Medium |
| 10 | 190-224 | Mode downgrades allowed without ceremony for non-LOCKDOWN | High |

### event_logger.py / signed_event_logger.py / append_only.py (12 issues)

| # | Line(s) | Issue | Severity |
|---|---------|-------|----------|
| 1 | event_logger:88-99 | Last event tampering undetectable (test skips this case) | Critical |
| 2 | event_logger:426-442 | `seal_log()` bypasses `log_event()`, breaks chain on double-seal | High |
| 3 | signed:110-129 | Race between log write and signature write under concurrency | Critical |
| 4 | signed:210-219 | Verification uses attacker-supplied public key | Critical |
| 5 | append_only:417-441 | WAL has no fsync; truncation can lose events | High |
| 6 | append_only:459-463 | Remote syslog silently truncates events to invalid JSON | Medium |
| 7 | append_only:476-479 | Failed remote sends never retried -- events permanently lost | Medium |
| 8 | event_logger:160 | Blank lines inflate `_event_count` | Medium |
| 9 | event_logger:296-298 | `get_recent_events(0)` returns all events (Python slice quirk) | Low |
| 10 | append_only:586-597 | Signature check skipped when signing key missing | High |
| 11 | event_logger:161-163 | Corrupted log silently forks hash chain on recovery | High |
| 12 | event_logger:199-213 | TOCTOU race on file creation permissions | Medium |

### tripwires.py / state_monitor.py (15 issues)

| # | Line(s) | Issue | Severity |
|---|---------|-------|----------|
| 1 | tripwires:291 | `_enabled` check outside lock (TOCTOU) | High |
| 2 | tripwires:478 | `trigger_violation` same TOCTOU pattern | High |
| 3 | tripwires:395 | Shell escape threshold `> 10` (off-by-one, not mode-sensitive) | Medium |
| 4 | state_monitor:738 | Docker/bridge interfaces cause permanent ONLINE state | Critical |
| 5 | tripwires:358-375 | USB removal in COLDROOM never detected | High |
| 6 | tripwires:131 | `_failed_attempts` increment not always under lock | Medium |
| 7 | tripwires:234-235 | Successful auth resets failed attempt counter (lockout bypass) | Medium |
| 8 | state_monitor:451 | `EnvironmentState` equality always False due to timestamp | Critical |
| 9 | state_monitor:1506 | `screen_unlocked` defaults to True (fail-open) | Medium |
| 10 | tripwires:411-423 | Hardware trust not checked in TRUSTED mode; MEDIUM accepted in COLDROOM | Medium |
| 11 | tripwires:305-327 | `check_violations` returns only first violation (masks others) | High |
| 12 | state_monitor:726-733 | `socket.setdefaulttimeout()` modifies process-global state | Medium |
| 13 | tripwires:742-760 | `LockdownManager.release_lockdown()` requires no authentication | Critical |
| 14 | tripwires:162,254,582 | Event logger exceptions silently swallowed (`except: pass`) | High |
| 15 | state_monitor:259-285 | Monitoring config setters have no thread safety | Medium |

### Security / Auth / API modules (15 issues)

| # | Line(s) | Issue | Severity |
|---|---------|-------|----------|
| 1 | boundary_api:322-339 | `PUBLIC_COMMANDS` bypasses all auth | Critical |
| 2 | boundary_api:523-576 | Unauthenticated `create_tui_token` grants operator access | Critical |
| 3 | boundary_api:378-470 | `_dispatch_command` has no independent auth check | Medium |
| 4 | prompt_injection:957-959 | `subscribe()` calls `.append()` on a dict -- crashes at runtime | High |
| 5 | prompt_injection:608-614 | Score capped at 1.0 defeats multi-detection severity | Medium |
| 6 | prompt_injection:774-785 | `"DAN"` pattern never matches lowered text | Medium |
| 7 | api_auth:595-621 | TOCTOU between token validation and command rate limiting | Medium |
| 8 | api_auth:448-487 | Bootstrap token never expires | High |
| 9 | boundary_api:284-288 | Error responses leak internal paths and system details | Medium |
| 10 | daemon_integrity:777-811 | `allow_missing_manifest` causes self-healing around tampering | High |
| 11 | api_auth:922-939 | `cleanup_expired` never persists revocation to disk | High |
| 12 | file_integrity:498-499 | Hash comparison not timing-safe | Low |
| 13 | api_auth:726 | Inconsistent lock discipline (double-locking with RLock) | Low |
| 14 | prompt_injection:990-999 | Singleton ignores re-configuration after first init | High |
| 15 | api_auth:489-510 | Bootstrap token file created with default perms then chmod'd | Medium |

### Enforcement modules (20 issues)

| # | Line(s) | Issue | Severity |
|---|---------|-------|----------|
| 1 | network_enforcer:385-408 | VPN interface names not sanitized -- nftables injection | Critical |
| 2 | network_enforcer:424-428 | AIRGAP allows ESTABLISHED connections through | Critical |
| 3 | network_enforcer:491-497 | Rules only on OUTPUT -- no INPUT enforcement | Critical |
| 4 | process_enforcer:496-533 | Seccomp profiles never applied to processes | Critical |
| 5 | process_enforcer:443-459 | LOCKDOWN has no actual process isolation | Critical |
| 6 | namespace:434-437 | Namespace isolation fails open | Critical |
| 7 | firewall_integration:89-527 | String join/split round-trip enables command injection | Critical |
| 8 | firewall_integration:293-401 | `allow_established` without conntrack bypasses all blocks | Critical |
| 9 | usb_enforcer:715-733 | LOCKDOWN preserves baseline USB devices | High |
| 10 | usb_enforcer:606-665 | Sysfs write failures silently ignored by callers | High |
| 11 | seccomp_filter:330-444 | 32-bit syscall bypass (missing i386 arch check) | High |
| 12 | process_enforcer:848-853 | Emergency lockdown permanently bricks network (no restore) | High |
| 13 | process_enforcer:1132-1143 | External watchdog lockdown silently fails | High |
| 14 | sandbox_manager:476-490 | Process starts before cgroup limits applied | Medium |
| 15 | sandbox_manager:361-364 | Firewall skipped when cgroups unavailable | Medium |
| 16 | sandbox_manager:613-667 | `tighten_profile()` accepts looser profiles | Medium |
| 17 | usb_enforcer:682-695 | Composite USB devices bypass runtime deauthorization | Medium |
| 18 | network_enforcer:499-508 | Flush/delete ordering creates enforcement gap | Medium |
| 19 | firewall_integration:645-659 | `allow_host()` flushes all existing rules | Medium |
| 20 | namespace:209-258 | All mount operations use `check=False` -- fail open | Medium |

---

## Systemic Patterns

### Pattern A: "Log and Forget" Security

Multiple critical code paths log that enforcement is happening without actually enforcing anything:
- `_handle_violation` logs "LOCKDOWN" but doesn't transition
- Enforcement failure handlers log "triggering lockdown" but don't
- `_mode_frozen_reason` is set but never read
- Seccomp profiles are written to files but never loaded into the kernel

### Pattern B: Fail-Open Exception Handling

Throughout the codebase, `except Exception: pass` or `except Exception as e: logger.warning(e)` patterns silently downgrade security to no security:
- Namespace isolation falls back to no isolation
- Event logger failures are swallowed (audit trail lost)
- Mount failures are ignored (sandbox shares host filesystem)
- Signing key absence causes signature checks to be skipped

### Pattern C: Tests That Codify Bugs

Several tests explicitly work around or avoid testing the broken behavior:
- `test_invariant_verify_chain_catches_any_single_event_tamper` skips the last event
- `test_get_recent_events_count_zero` avoids asserting on length
- `test_double_seal_adds_second_event` never calls `verify_chain()`
- `test_network_io_allowed_in_trusted` asserts ALLOW for the bypass case

### Pattern D: State Protected by Locks That Aren't Consistently Held

`_custom_policies`, `_enabled`, `_failed_attempts`, `monitoring_config`, and `EnvironmentState` are all read/written from multiple threads with inconsistent locking discipline.

---

## Recommendations

1. **Immediate:** Audit all `PUBLIC_COMMANDS` entries -- `create_tui_token` must require authentication
2. **Immediate:** Wire `SeccompFilter.apply()` into `ProcessEnforcer._install_seccomp_profile()`
3. **Immediate:** Add INPUT chain enforcement to `NetworkEnforcer`
4. **Immediate:** Fix `_evaluate_io_policy` COLDROOM to deny network and USB
5. **Immediate:** Make `_handle_violation` actually call `transition_mode(LOCKDOWN)`
6. **High priority:** Use `hmac.compare_digest()` or known-good key for signature verification
7. **High priority:** Exclude `timestamp` from `EnvironmentState.__eq__` or implement custom comparison
8. **High priority:** Add `_mode_frozen_reason` check to `request_mode_change()`
9. **High priority:** Fix `cleanup_expired` to actually append to `to_remove` and save
10. **High priority:** Sanitize VPN interface names before interpolating into nftables commands
