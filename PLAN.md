# Implementation Plan: Fix Bugs That Pass Tests But Don't Function

## Approach

72 issues organized into **10 phases**, ordered by severity and dependency. Each phase groups
related fixes that can be reasoned about together. Phases are ordered so that earlier phases
don't create conflicts with later ones.

Every fix includes a corresponding test fix or new test to ensure the bug stays dead.

---

## Phase 1: Policy Engine -- Core Decision Logic (5 fixes)

These are the rules the whole system evaluates against. Fix them first because every other
layer depends on correct policy decisions.

### 1A. Fix `_evaluate_io_policy` COLDROOM bypass
**File:** `daemon/policy_engine.py:396-400`
**Fix:** Add `requires_network` and `requires_usb` checks before the ALLOW fallthrough in COLDROOM.
```python
if mode == BoundaryMode.COLDROOM:
    if request.requires_filesystem or request.requires_network or request.requires_usb:
        return PolicyDecision.DENY
    return PolicyDecision.ALLOW
```
**Test:** Add `test_coldroom_denies_network_io` and `test_coldroom_denies_usb_io` that set
`requires_network=True, requires_filesystem=False` and assert DENY.

### 1B. Implement `_get_usb_changes` (replace no-op stub)
**File:** `daemon/policy_engine.py:436-439`
**Fix:** Track a `_baseline_usb_devices` set in the engine. On each call compare `env_state.usb_devices`
against baseline, return `(added, removed)`.
```python
def _get_usb_changes(self, env_state):
    if self._baseline_usb_devices is None:
        self._baseline_usb_devices = set(env_state.usb_devices)
        return (set(), set())
    added = env_state.usb_devices - self._baseline_usb_devices
    removed = self._baseline_usb_devices - env_state.usb_devices
    return (added, removed)
```
Initialize `self._baseline_usb_devices = None` in `__init__`.
**Test:** Add test that sets baseline, then changes `usb_devices`, asserts non-empty returned sets.

### 1C. Move callbacks outside `_state_lock` to prevent deadlock
**File:** `daemon/policy_engine.py:203-224`
**Fix:** Capture state under lock, release lock, then fire callbacks.
```python
def transition_mode(self, new_mode, operator, reason=""):
    with self._state_lock:
        old_mode = self._boundary_state.mode
        if old_mode == BoundaryMode.LOCKDOWN and operator != Operator.HUMAN:
            return (False, "Cannot exit LOCKDOWN mode without human intervention")
        self._boundary_state.mode = new_mode
        self._boundary_state.last_transition = datetime.utcnow().isoformat() + "Z"
        self._boundary_state.operator = operator
        with self._callback_lock:
            callbacks = list(self._transition_callbacks.values())
    # Callbacks run OUTSIDE _state_lock
    for callback in callbacks:
        try:
            callback(old_mode, new_mode, operator, reason)
        except Exception as e:
            logger.error(f"Error in transition callback: {e}")
    return (True, f"Transitioned from {old_mode.name} to {new_mode.name}")
```
**Test:** Add test that registers a callback which calls `get_current_mode()` -- must not deadlock.

### 1D. Guard mode downgrades without ceremony
**File:** `daemon/policy_engine.py:203-224`
**Fix:** Add a check: if `new_mode < old_mode` (downgrade) and `operator != Operator.HUMAN`,
deny unless it's a SYSTEM transition TO LOCKDOWN (auto-escalation is always OK).
```python
# Prevent mode downgrades without human operator
if new_mode < old_mode and new_mode != BoundaryMode.LOCKDOWN and operator != Operator.HUMAN:
    return (False, f"Cannot downgrade from {old_mode.name} to {new_mode.name} without human operator")
```
**Test:** Assert SYSTEM operator cannot transition AIRGAP -> OPEN. Assert HUMAN can.

### 1E. Protect `_custom_policies` with `_state_lock`
**File:** `daemon/policy_engine.py:144-164`
**Fix:** Acquire `_state_lock` in `load_custom_policies` and `clear_custom_policies`.
**Test:** Existing tests should still pass; add a threading test that loads while evaluating.

---

## Phase 2: Boundary Daemon -- Enforcement Wiring (6 fixes)

The orchestrator has multiple code paths that log security actions but never execute them.

### 2A. Make `_handle_violation` actually trigger lockdown
**File:** `daemon/boundary_daemon.py:1502-1507`
**Fix:** Add actual lockdown transition after the logging.
```python
def _handle_violation(self, violation: TripwireViolation):
    logger.critical("*** SECURITY VIOLATION DETECTED ***")
    logger.critical(f"Type: {violation.violation_type.value}")
    logger.critical(f"Details: {violation.details}")
    logger.critical("System entering LOCKDOWN mode")
    self.policy_engine.transition_mode(
        BoundaryMode.LOCKDOWN,
        Operator.SYSTEM,
        f"Tripwire violation: {violation.violation_type.value}"
    )
```
**Test:** Assert that calling `_handle_violation` causes `policy_engine.get_current_mode()` to
return LOCKDOWN.

### 2B. Make enforcement failure handlers trigger lockdown
**File:** `daemon/boundary_daemon.py:1405-1413, 1423-1431, 1442-1449`
**Fix:** After the `log_event` call in each except block, add:
```python
self.policy_engine.transition_mode(
    BoundaryMode.LOCKDOWN,
    Operator.SYSTEM,
    f"Enforcement failure (fail-closed): {e}"
)
```
**Test:** Mock an enforcer to raise, assert mode transitions to LOCKDOWN.

### 2C. Enforce `_mode_frozen_reason` in `request_mode_change`
**File:** `daemon/boundary_daemon.py:3157-3169`
**Fix:** Check `_mode_frozen_reason` before delegating to `transition_mode`.
```python
def request_mode_change(self, new_mode, operator, reason=""):
    if self._mode_frozen_reason:
        return (False, f"Mode transitions frozen: {self._mode_frozen_reason}")
    return self.policy_engine.transition_mode(new_mode, operator, reason)
```
**Test:** Set `_mode_frozen_reason`, call `request_mode_change`, assert it fails.

### 2D. Fix `request_cleanup_all` to check and aggregate results
**File:** `daemon/boundary_daemon.py:1617-1646`
**Fix:** Track `any_failed = False`. Check each `success` return value. Return `(not any_failed, ...)`.
Only set `_cleanup_on_shutdown_requested` when all succeed.

### 2E. Enable production integrity defaults
**File:** `daemon/boundary_daemon.py:460-465`
**Fix:** Change defaults to `failure_action=IntegrityAction.BLOCK_STARTUP, allow_missing_manifest=False`.
Add a `--dev-mode` CLI flag that switches to `WARN_ONLY` + `allow_missing_manifest=True`.
Wire `--dev-mode` through to the `BoundaryDaemon.__init__`.
**Also:** Add `lockdown` to CLI `--mode` choices (line 3840, 3859-3865).

### 2F. Fix initialization order: `ceremony_manager` before `sandbox_manager`
**File:** `daemon/boundary_daemon.py:733, 831`
**Fix:** Move ceremony manager init (including biometric setup) to before sandbox manager init.
Or pass ceremony_manager lazily (via a getter lambda instead of the value).

---

## Phase 3: Event Logger / Signed Logger -- Audit Integrity (7 fixes)

The tamper-evident log is the last line of defense. These fixes ensure it actually detects tampering.

### 3A. Include `hash_chain` in `compute_hash` to protect last event
**File:** `daemon/event_logger.py:88-99`
**Fix:** Add `'hash_chain': self.hash_chain` to the `data` dict in `compute_hash()`.
This means each event's hash covers its chain link, making standalone tampering of the
last event detectable (the stored hash won't match recomputation).
**Test:** Fix `test_invariant_verify_chain_catches_any_single_event_tamper` to include the
last event (remove `if target < 4:` guard). Tamper any single event and assert detection.

### 3B. Fix `seal_log` to use `log_event` and update internal state
**File:** `daemon/event_logger.py:426-442`
**Fix:** Use `self.log_event(EventType.INFO, "Log sealed", metadata={...})` instead of
writing directly. This updates `_last_hash` and `_event_count` correctly.
**Test:** Fix `test_double_seal_adds_second_event` to call `verify_chain()` after double seal.

### 3C. Use known-good public key in `verify_signatures`
**File:** `daemon/signed_event_logger.py:210-219`
**Fix:** Use `self.verify_key` instead of `sig_record['public_key']`:
```python
self.verify_key.verify(
    event.to_json().encode(),
    bytes.fromhex(sig_record['signature'])
)
```
Also verify that `sig_record['public_key']` matches `self.verify_key` hex encoding;
raise a tamper alert if they differ.
**Test:** Add test that forges both log and sig file with a different key pair -- must fail.

### 3D. Atomically sign in `SignedEventLogger.log_event`
**File:** `daemon/signed_event_logger.py:110-129`
**Fix:** Hold a single lock across both the parent `log_event` and `_sign_event`:
```python
def log_event(self, event_type, details, metadata=None):
    with self._sig_lock:
        event = super().log_event(event_type, details, metadata)
        self._sign_event(event)
    return event
```
**Test:** Add a threading test logging 100 events from 10 threads, then verify signatures pass.

### 3E. Fix `_load_existing_log` to count non-blank lines
**File:** `daemon/event_logger.py:138-163`
**Fix:** Replace `self._event_count = len(lines)` with:
```python
self._event_count = sum(1 for l in lines if l.strip())
```
**Test:** Write a log with blank lines, reload, assert `get_event_count()` is correct.

### 3F. Fix `get_recent_events(0)` to return empty list
**File:** `daemon/event_logger.py:296-298`
**Fix:** Add early return: `if count <= 0: return []`
**Test:** Fix test to assert `len(events) == 0`.

### 3G. Fix file creation TOCTOU in `_append_to_log`
**File:** `daemon/event_logger.py:199-213`
**Fix:** Use `os.open()` with `O_CREAT | O_WRONLY | O_APPEND` and explicit mode `0o600`
(same pattern as `signed_event_logger.py:91-101`). Remove the separate `os.path.exists`
check and `os.chmod` call.

---

## Phase 4: Tripwires & State Monitor -- Detection Accuracy (8 fixes)

### 4A. Move `_enabled` check inside lock
**File:** `daemon/tripwires.py:291-294, 478-482`
**Fix:** Move `if not self._enabled: return None` to inside `with self._lock:` in both
`check_violations` and `trigger_violation`.

### 4B. Collect ALL violations, not just the first
**File:** `daemon/tripwires.py:305-327`
**Fix:** Collect violations into a list. Return the highest-severity one but log all.
```python
violations = []
for check in [self._check_network_in_airgap, self._check_usb_in_coldroom,
              self._check_external_model_violations, self._check_suspicious_processes,
              self._check_hardware_trust]:
    v = check(current_mode, env_state)
    if v:
        violations.append(v)
if violations:
    # Record all, return first (highest priority by check order)
    for v in violations:
        self._record_violation(v, current_mode, env_state)
    return self._violations[-1]  # Return most recently recorded
```
**Test:** Present multiple simultaneous violations, assert all are in `_violations` list.

### 4C. Require auth for `LockdownManager.release_lockdown`
**File:** `daemon/tripwires.py:742-760`
**Fix:** Add `auth_token` parameter, validate against a token store or require the tripwire
system's current auth token. Fail if token is invalid.
```python
def release_lockdown(self, operator: str, reason: str, auth_token: str) -> bool:
    with self._lock:
        if not self._in_lockdown:
            return False
        if not self._verify_auth_token(auth_token):
            logger.warning(f"Unauthorized lockdown release attempt by {operator}")
            return False
        ...
```
**Test:** Assert that calling `release_lockdown` with wrong/empty token returns False.

### 4D. Exclude `timestamp` from `EnvironmentState.__eq__`
**File:** `daemon/state_monitor.py` (EnvironmentState dataclass)
**Fix:** Add `eq=False` to the dataclass decorator and implement custom `__eq__` that compares
all fields except `timestamp`. Or use `field(compare=False)` on the timestamp field.
```python
timestamp: str = field(default="", compare=False)
```
**Test:** Create two states with different timestamps but same data, assert equal.

### 4E. Filter virtual interfaces from network state
**File:** `daemon/state_monitor.py:738`
**Fix:** Skip interfaces matching known virtual patterns (`docker`, `br-`, `virbr`, `veth`,
`lo`, `lxc`):
```python
VIRTUAL_IFACE_PREFIXES = ('docker', 'br-', 'virbr', 'veth', 'lo', 'lxc', 'flannel', 'cni')
physical_interfaces = [
    iface for iface in interfaces
    if not any(iface.startswith(p) for p in VIRTUAL_IFACE_PREFIXES)
]
state = NetworkState.ONLINE if (physical_interfaces or has_internet) else NetworkState.OFFLINE
```
**Test:** Mock interfaces including `docker0`, assert state is OFFLINE when no physical interfaces.

### 4F. Default `screen_unlocked` to False (fail-closed)
**File:** `daemon/state_monitor.py:1506`
**Fix:** Change `screen_unlocked = True` to `screen_unlocked = False`.

### 4G. Fix shell escape threshold and mode sensitivity
**File:** `daemon/tripwires.py:395-399`
**Fix:** Change `> 10` to `>= 3` for high-security modes (AIRGAP+), `>= 10` for lower modes.
Also check suspicious processes in all modes, not just TRUSTED+.

### 4H. Detect USB removal (not just insertion) in COLDROOM
**File:** `daemon/tripwires.py:358-375`
**Fix:** Also compute `removed = self._baseline_usb_devices - env_state.usb_devices` and
trigger a violation if `removed` is non-empty (potential exfiltration device removal).

---

## Phase 5: Authentication & API -- Access Control (6 fixes)

### 5A. Remove sensitive commands from PUBLIC_COMMANDS
**File:** `api/boundary_api.py:322-339`
**Fix:** Remove `get_events`, `get_alerts`, `get_sandboxes`, `create_tui_token` from
`PUBLIC_COMMANDS`. Only `status`, `ping`, `version` should be public.
```python
PUBLIC_COMMANDS = {'status', 'ping', 'version'}
```
Move `create_tui_token` to require at minimum `READ_STATUS` capability, or gate it behind
a one-time setup flow with filesystem-based bootstrap token.

### 5B. Fix `cleanup_expired` to persist revocation
**File:** `daemon/auth/api_auth.py:922-939`
**Fix:** Add `to_remove.append(token_hash)` inside the loop:
```python
for token_hash, token in self._tokens.items():
    if token.expires_at and now > token.expires_at:
        if not token.revoked:
            token.revoked = True
            token.metadata['auto_expired'] = True
            token.metadata['expired_at'] = now.isoformat()
            to_remove.append(token_hash)
```
**Test:** Call cleanup, restart (reload from disk), assert tokens are still revoked.

### 5C. Set bootstrap token expiration
**File:** `daemon/auth/api_auth.py:448-487`
**Fix:** Change `expires_in_days=None` to `expires_in_days=1` (24-hour bootstrap window).

### 5D. Fix bootstrap file TOCTOU
**File:** `daemon/auth/api_auth.py:489-510`
**Fix:** Use `os.open(path, O_CREAT|O_WRONLY|O_EXCL, 0o600)` + `os.fdopen` instead of
`open(path, 'w')` + `os.chmod`.

### 5E. Sanitize error responses
**File:** `api/boundary_api.py:284-288`
**Fix:** Replace `str(e)` with generic error messages. Log full error server-side only.
```python
except Exception as e:
    logger.error(f"Unhandled error: {e}", exc_info=True)
    error_response = {'error': 'Internal server error'}
```

### 5F. Fix prompt injection `subscribe()` method
**File:** `daemon/security/prompt_injection.py:957-959`
**Fix:** Use the dict interface matching `register_callback`:
```python
def subscribe(self, callback):
    callback_id = id(callback)
    self._callbacks[callback_id] = callback
    return callback_id
```
Also fix `_looks_like_injection` DAN pattern: lowercase it to `r'dan'`.

---

## Phase 6: Network Enforcement -- Firewall Rules (6 fixes)

### 6A. Add INPUT chain enforcement
**File:** `daemon/enforcement/network_enforcer.py:491-497`
**Fix:** Create a second chain `BOUNDARY_INPUT` and insert it into the INPUT chain.
Apply matching rules to both chains in all `_apply_*_mode` methods.
For LOCKDOWN: both chains get DROP-all. For AIRGAP: both chains deny external.

### 6B. Remove ESTABLISHED rule in AIRGAP/COLDROOM modes
**File:** `daemon/enforcement/network_enforcer.py:424-428`
**Fix:** In `_apply_airgap_mode`, do NOT add the ESTABLISHED/RELATED accept rule.
Only allow loopback. Existing connections must be terminated:
```python
# Force-close existing connections by not allowing ESTABLISHED
# Only loopback is permitted
self._run_iptables(['-A', self.BOUNDARY_CHAIN, '-o', 'lo', '-j', 'ACCEPT'])
self._run_iptables(['-A', self.BOUNDARY_CHAIN, '-j', 'DROP'])
```

### 6C. Sanitize VPN interface names
**File:** `daemon/enforcement/network_enforcer.py:385-408`
**Fix:** Validate interface names against `^[a-zA-Z0-9_-]+$` in `set_vpn_interfaces`.
Reject any name not matching.
```python
import re
IFACE_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{0,14}$')
def set_vpn_interfaces(self, interfaces):
    for iface in interfaces:
        if not self.IFACE_PATTERN.match(iface):
            raise ValueError(f"Invalid interface name: {iface!r}")
    self._vpn_interfaces = list(interfaces)
```

### 6D. Fix firewall_integration.py command injection
**File:** `daemon/enforcement/firewall_integration.py:89-131, 527`
**Fix:** Keep commands as lists throughout. Replace `" ".join(cmd)` with returning the list.
Replace `cmd.split()` with using the list directly in `subprocess.run`.

### 6E. Fix `allow_established` to use conntrack
**File:** `daemon/enforcement/firewall_integration.py:293-401`
**Fix:** Add `-m conntrack --ctstate ESTABLISHED,RELATED` to the generated iptables arguments
for the `allow_established` rule.

### 6F. Fix flush/setup ordering
**File:** `daemon/enforcement/network_enforcer.py:499-508`
**Fix:** Swap order: first remove jump from OUTPUT, then flush, then delete. This ensures
traffic never hits an empty chain.

---

## Phase 7: Process Enforcement & Sandbox -- Kernel Controls (7 fixes)

### 7A. Wire SeccompFilter.apply() into ProcessEnforcer
**File:** `daemon/enforcement/process_enforcer.py:496-533`
**Fix:** After writing the profile JSON, instantiate `SeccompFilter` from the profile and call
`apply()` to actually load the BPF filter via `prctl(PR_SET_SECCOMP)`.
```python
def _install_seccomp_profile(self, profile):
    if not self._has_root:
        raise RuntimeError("Seccomp enforcement requires root privileges")
    # Write profile for audit/persistence
    if self._profile_manager:
        success, msg = self._profile_manager.install_profile(profile, profile.get('name', 'boundary'))
    # Actually apply the filter to the process
    from ..sandbox.seccomp_filter import SeccompFilter
    seccomp = SeccompFilter()
    seccomp.load_profile(profile)
    seccomp.apply()
```
**Test:** Verify `SeccompFilter.apply()` is called (mock it for unit tests).

### 7B. Add i386 arch check to seccomp BPF
**File:** `daemon/sandbox/seccomp_filter.py:330-343, 436-444`
**Fix:** On x86_64, emit BPF instructions that also check for `AUDIT_ARCH_I386` and apply
the same blocked syscall list with i386 syscall numbers.
The filter should: check arch -> if x86_64, check x86_64 syscalls -> if i386, check i386 syscalls -> else KILL.

### 7C. Make namespace isolation fail-closed
**File:** `daemon/sandbox/namespace.py:434-437`
**Fix:** Raise `RuntimeError` instead of running without isolation:
```python
if not self.can_create_namespaces():
    raise RuntimeError("Namespace isolation unavailable - refusing to run without isolation")
```

### 7D. Check mount return codes
**File:** `daemon/sandbox/namespace.py:209-258`
**Fix:** Change `check=False` to `check=True` for all security-critical mount operations.
Wrap in try/except and raise `RuntimeError` on failure.

### 7E. Add cgroup before process start
**File:** `daemon/sandbox/sandbox_manager.py:476-490`
**Fix:** Create the cgroup first, then pass the cgroup path to `create_isolated_process` so
the process is born into the cgroup. If the namespace manager doesn't support this, use
`clone()` with `CLONE_INTO_CGROUP` or pre-create the cgroup and write the PID immediately
before exec (use a wrapper that adds itself to the cgroup before executing the command).

### 7F. Validate `tighten_profile` direction
**File:** `daemon/sandbox/sandbox_manager.py:613-667`
**Fix:** Add severity comparison. Each `SandboxProfile` should have a numeric strictness level.
Reject if `new_profile.strictness < self._profile.strictness`.

### 7G. Add emergency lockdown restoration path
**File:** `daemon/enforcement/process_enforcer.py:848-853`
**Fix:** Save current iptables policies before changing them. Provide a `_restore_network`
method. Call restore in `cleanup()`.

---

## Phase 8: USB Enforcement (3 fixes)

### 8A. Deauthorize ALL devices in LOCKDOWN (including baseline)
**File:** `daemon/enforcement/usb_enforcer.py:715-733`
**Fix:** Remove `if device.path in self._baseline_devices: continue`.
In LOCKDOWN, ALL USB devices should be deauthorized except hubs.

### 8B. Check sysfs write return values
**File:** `daemon/enforcement/usb_enforcer.py:606-665, 680-700`
**Fix:** Make `_deauthorize_device` / `_deauthorize_storage_devices` check the return value of
`_write_sysfs`. If it returns False, log error and raise or return failure.

### 8C. Check `bInterfaceClass` for composite devices
**File:** `daemon/enforcement/usb_enforcer.py:682-695`
**Fix:** In addition to checking `device.device_class`, also enumerate device interfaces and
check `bInterfaceClass`. If any interface is mass storage (0x08), deauthorize.

---

## Phase 9: Append-Only Storage (4 fixes)

### 9A. Add fsync to WAL writes
**File:** `daemon/storage/append_only.py:417-441`
**Fix:** Add `os.fsync(self._wal_fd.fileno())` after `flush()`.
Also fsync after WAL truncation.

### 9B. Fix remote syslog truncation
**File:** `daemon/storage/append_only.py:459-463`
**Fix:** If event exceeds max length, split into multiple syslog messages with sequence numbers,
or send the full event via TCP syslog (RFC 5424 supports long messages). At minimum, log a
warning when truncation occurs.

### 9C. Retry failed remote sends
**File:** `daemon/storage/append_only.py:476-479`
**Fix:** Add a retry queue. On failure, append the event to a `_pending_remote` list.
On next successful send, drain the queue.

### 9D. Require signing key for checkpoint verification
**File:** `daemon/storage/append_only.py:586-597`
**Fix:** If `checkpoint.signature` is present but `self._signing_key` is None, return
`(False, "Signing key unavailable - cannot verify signature")` instead of skipping.

---

## Phase 10: Remaining Medium/Low Fixes (5 fixes)

### 10A. Fix `socket.setdefaulttimeout` global mutation
**File:** `daemon/state_monitor.py:726-733`
**Fix:** Use a dedicated socket with per-socket timeout instead of global default:
```python
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
try:
    s.connect(('8.8.8.8', 53))
    has_internet = True
finally:
    s.close()
```

### 10B. Fix monitoring config thread safety
**File:** `daemon/state_monitor.py:259-285`
**Fix:** Add a `_config_lock` and acquire it in setters and in `_sample_environment`.

### 10C. Fix `request_type` normalization
**File:** `daemon/policy_engine.py:262-273`
**Fix:** Normalize with `.lower().strip()` at the top of `evaluate_policy`.

### 10D. Fix prompt injection singleton re-configuration
**File:** `daemon/security/prompt_injection.py:985-1000`
**Fix:** If instance exists and new params differ, update the instance's config:
```python
if _detector_instance is not None:
    if event_logger: _detector_instance._event_logger = event_logger
    if policy_engine: _detector_instance._policy_engine = policy_engine
    if sensitivity != "medium": _detector_instance._configure_sensitivity(sensitivity)
    return _detector_instance
```

### 10E. Fix daemon_integrity allow_missing_manifest self-healing
**File:** `daemon/security/daemon_integrity.py:777-811`
**Fix:** When `status == IntegrityStatus.SIGNATURE_INVALID`, do NOT regenerate manifest even
if `allow_missing_manifest` is True. Only allow regeneration for `MANIFEST_MISSING`.
A signature mismatch is evidence of tampering and should never self-heal.

---

## Test Updates Required

For each phase, update corresponding test files:
- `tests/test_policy_engine.py` -- Phases 1, 10C
- `tests/test_tripwires.py` -- Phase 4
- `tests/test_state_monitor.py` -- Phase 4
- `tests/test_event_logger.py` -- Phase 3
- `tests/test_api_auth.py` -- Phase 5
- `tests/test_attack_simulations.py` -- Phase 5A
- `tests/integration/test_enforcement_integration.py` -- Phases 6, 7, 8
- `tests/test_sandbox_enforcement_bridge.py` -- Phase 7

Key test fixes (tests that currently codify bugs):
1. `test_invariant_verify_chain_catches_any_single_event_tamper` -- remove `if target < 4:` guard
2. `test_get_recent_events_count_zero` -- assert `len(events) == 0`
3. `test_double_seal_adds_second_event` -- add `verify_chain()` assertion
4. `test_network_io_allowed_in_trusted` -- may need update if TRUSTED IO policy changes

---

## Execution Order Summary

| Phase | Files Changed | Issue Count | Risk |
|-------|--------------|-------------|------|
| 1 | policy_engine.py | 5 | Medium (core logic) |
| 2 | boundary_daemon.py | 6 | Medium (wiring) |
| 3 | event_logger.py, signed_event_logger.py | 7 | High (hash format change) |
| 4 | tripwires.py, state_monitor.py | 8 | Medium |
| 5 | boundary_api.py, api_auth.py, prompt_injection.py | 6 | Medium |
| 6 | network_enforcer.py, firewall_integration.py | 6 | High (firewall rules) |
| 7 | process_enforcer.py, seccomp_filter.py, namespace.py, sandbox_manager.py | 7 | High (kernel) |
| 8 | usb_enforcer.py | 3 | Medium |
| 9 | append_only.py | 4 | Low |
| 10 | state_monitor.py, policy_engine.py, prompt_injection.py, daemon_integrity.py | 5 | Low |
| **Total** | **18 files** | **57 fixes** | |

Note: The remaining ~15 low-severity issues (info leakage, timing-safe comparisons, env var
credentials) are tracked in REVIEW_FINDINGS.md but deferred from this plan to keep scope manageable.
