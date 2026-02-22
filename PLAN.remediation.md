# Vibe-Check Remediation Plan

**Based on:** VIBE_CHECK_REPORT.md (Vibe-Code Detection Audit v2.0)
**Goal:** Address all 5 high-severity, 6 medium-severity, and 19 remediation checklist items
**Target:** Reduce Vibe-Code Confidence from 51.9% to <35% (AI-Assisted range)

---

## Phase 1: Scope Honesty — Archive Stubs & Fix Feature Claims

**Addresses:** High-1 (eBPF stubs), High-2 (HSM stubs), High-4 (README claims), Med-3 (SIEM shippers), Med-5 (doc bloat), A6, B3

This is the single highest-impact phase. The project claims 150+ modules and 50+ "Complete" features, but many are stubs. Fixing the claims to match reality immediately improves credibility.

### 1.1 Archive non-functional modules

Move these to `archive/` (they have no active callers in core daemon code):

| Module | Reason | Safe? |
|--------|--------|-------|
| `daemon/crypto/hsm_provider.py` | 5 abstract stub methods, never called | Yes — only cross-ref is archived `blockchain/validator_protection.py` |
| `daemon/crypto/post_quantum.py` | Dilithium/Kyber "simulators", not real PQC | Yes — no active imports |
| `daemon/identity/` (entire directory) | Declared "ADVISORY only" in `__init__.py`, zero callers in daemon | Yes — only imported by `build.py` |

**Files to update after archiving:**
- `daemon/crypto/__init__.py` — remove HSM and PQC exports
- `daemon/boundary_daemon.py` — remove identity federation try/except import block
- `build.py` — remove hidden imports for archived modules (lines 468-469, 512-516)

### 1.2 Mark partial stubs clearly (do NOT archive — they have active callers)

These modules have real callers but contain stub code that should be marked honestly:

| Module | Callers | Action |
|--------|---------|--------|
| `daemon/ebpf/` | `enforcement/__init__.py`, `security_verification.py` | Keep. Mark `BaseObserver` as abstract interface. Add `bcc` to optional deps in docs. |
| `daemon/alerts/case_manager.py` | `cli/boundaryctl.py` (case subcommand) | Keep. Mark ServiceNow/Slack/PagerDuty as `NotImplementedError` with clear "not yet implemented" messaging instead of silent `pass`. |
| `daemon/external_integrations/siem/log_shipper.py` | `sandbox_events.py` | Keep FileShipper + HTTPShipper. Mark KafkaShipper/S3Shipper/GCSShipper as `NotImplementedError`. |
| `daemon/distributed/` | `boundary_daemon.py` (line 253) | Keep FileCoordinator. Remove EtcdCoordinator claims from docs. |

### 1.3 Audit README feature tables

For every feature row in `README.md`:
- If the feature has a **complete call chain with tests** → keep as "Complete"
- If the feature has code but **no tests or callers** → change to "Experimental"
- If the feature is an **interface/stub only** → change to "Planned"
- If the feature was **archived** → remove from table entirely

Expected reclassifications:
- HSM support: Complete → **Removed** (archived)
- Post-quantum crypto: Complete → **Removed** (archived)
- Identity Federation (OIDC/LDAP/PAM): Complete → **Removed** (archived)
- eBPF monitoring: Complete → **Experimental** (requires bcc, not in deps)
- SIEM Kafka/S3/GCS shipping: Complete → **Planned**
- Case management (ServiceNow/Slack/PagerDuty): Complete → **Planned**
- Distributed cluster (Etcd/Consul): Complete → **Planned** (only FileCoordinator works)

### 1.4 Consolidate documentation

Merge 35 markdown files down to these ~8 essential documents:

| Keep | Merge Into It |
|------|---------------|
| `README.md` | `KEYWORDS.md` (inline SEO terms), `INTEGRATION.md` (short, merge into README) |
| `ARCHITECTURE.md` | `SPEC.md` (merge specification into architecture), `ENFORCEMENT_MODEL.md` |
| `SECURITY.md` | `SECURITY_AUDIT.md`, `AGENTIC_SECURITY_AUDIT.md` (merge findings) |
| `USER_GUIDE.md` | `API_CONTRACTS.md`, `MONITORING_METRICS.md` |
| `CONTRIBUTING.md` | `docs/DEVELOPER_GUIDE.md` |
| `CHANGELOG.md` | (standalone, keep as-is) |
| `ROADMAP.md` | `PLAN.md`, `PLAN.implementation.md`, `docs/FEATURE_ROADMAP.md` |
| `VIBE_CHECK_REPORT.md` | `REVIEW_FINDINGS.md`, `AUDIT_REPORT.md`, `EVALUATION_REPORT.md`, `CONCEPT_EXECUTION_EVALUATION.md`, `SCOPE_REDUCTION.md` |

**Delete after merging:** `KEYWORDS.md`, `INTEGRATION.md`, `SPEC.md`, `ENFORCEMENT_MODEL.md`, `SECURITY_AUDIT.md`, `AGENTIC_SECURITY_AUDIT.md`, `API_CONTRACTS.md`, `MONITORING_METRICS.md`, `PLAN.md`, `PLAN.implementation.md`, `REVIEW_FINDINGS.md`, `AUDIT_REPORT.md`, `EVALUATION_REPORT.md`, `CONCEPT_EXECUTION_EVALUATION.md`, `SCOPE_REDUCTION.md`, `docs/FEATURE_ROADMAP.md`, `docs/SECURITY_COMPARISON.md`, `docs/SELF_KNOWLEDGE.md`, `docs/INDEX.md`, `docs/MODULE_MAP.md`

---

## Phase 2: Error Handling Hardening

**Addresses:** High-3 (210 bare except Exception), B1, Med-1 (error-path tests)

### 2.1 Triage bare `except Exception:` handlers by severity

**Tier 1 — Security-critical paths (fix first):**
These are in modules that handle authentication, policy decisions, or event logging.

| File | Count | Approach |
|------|-------|----------|
| `daemon/enforcement/process_enforcer.py` | 6 | Replace with `psutil.NoSuchProcess`, `psutil.AccessDenied`, `PermissionError`, `OSError` |
| `daemon/enforcement/firewall_integration.py` | 3 | Replace with `subprocess.CalledProcessError`, `FileNotFoundError`, `PermissionError` |
| `daemon/enforcement/security_verification.py` | 3 | Replace with typed enforcement exceptions |
| `daemon/auth/secure_token_storage.py` | ~2 | Replace with `cryptography.fernet.InvalidToken`, `OSError` |
| `daemon/config/secure_config.py` | ~2 | Replace with `yaml.YAMLError`, `json.JSONDecodeError`, `cryptography.*` |

**Tier 2 — Logging/monitoring paths (fix second):**

| File | Count | Approach |
|------|-------|----------|
| `daemon/redundant_event_logger.py` | 7 | Replace with `IOError`, `socket.error`, `syslog.error`. The 2 `except: pass` instances should log at DEBUG level minimum. |
| `daemon/compliance/evidence_bundle.py` | 1 | Replace with `OSError` |

**Tier 3 — Remaining enforcement modules (fix last):**
All other enforcement modules — replace `except Exception: return False` with specific exception types and log the failure.

### 2.2 Add exception chaining

Search for all `raise SomeError(...)` inside `except` blocks and add `from e`:

```python
# Before (7 existing chains — need ~50 more)
except ValueError:
    raise ConfigError("invalid value")

# After
except ValueError as e:
    raise ConfigError("invalid value") from e
```

Target files: all files in `daemon/enforcement/`, `daemon/auth/`, `daemon/config/`, `daemon/security/`.

### 2.3 Add domain-specific exceptions where missing

Create exception classes for modules that currently use bare `Exception`:

| Module | New Exception |
|--------|---------------|
| `daemon/redundant_event_logger.py` | `LogBackendError`, `LogShipmentError` |
| `daemon/enforcement/firewall_integration.py` | `FirewallConfigError` (may already exist — verify) |
| `daemon/compliance/` | `ComplianceError`, `EvidenceError` |

---

## Phase 3: Test Quality Improvement

**Addresses:** High-5 (error-path tests), Med-1, Med-4 (trivial assertions), A3

### 3.1 Add error-path tests for security-critical modules

Target: increase `pytest.raises` count from 6 to 60+.

| Module | Error Paths to Test |
|--------|-------------------|
| `daemon/policy_engine.py` | Invalid mode transitions, unknown request types, custom policy validation failures, concurrent modification |
| `daemon/tripwires.py` | Invalid auth tokens, locked system bypass attempts, callback exceptions, disabled-then-triggered |
| `daemon/event_logger.py` | Corrupt log file loading, permission errors on write, hash chain breaks, concurrent writes |
| `daemon/config/secure_config.py` | Invalid encryption key, corrupt config file, missing required sections |
| `daemon/auth/api_auth.py` | Expired tokens, rate limit exceeded, invalid capabilities, malformed requests |
| `daemon/sandbox/sandbox_manager.py` | Missing namespace support, cgroup creation failures, seccomp filter errors |
| `daemon/signed_event_logger.py` | Invalid signatures, key rotation failures, tampered events |

### 3.2 Replace trivial `is not None` assertions

Find and replace the 112 instances. Pattern:

```python
# Before (trivial)
assert result is not None

# After (behavioral)
assert result.mode == BoundaryMode.RESTRICTED
assert result.decision == PolicyDecision.DENY
assert len(result.violations) == 1
assert result.violations[0].type == ViolationType.NETWORK_IN_AIRGAP
```

Focus on test files with highest trivial assertion counts first:
- `tests/test_state_monitor.py`
- `tests/test_integrations.py`
- `tests/test_health_monitor.py`

### 3.3 Add parametrized tests for boundary conditions

Target: increase from 10 to 50+ parametrized tests.

| Test Area | Parametrize Over |
|-----------|-----------------|
| Policy evaluation | All 6 modes × 4 request types × 3 network states |
| Memory class mapping | All 6 memory classes × 6 modes |
| Tripwire detection | All 10 violation types × enabled/disabled/locked states |
| Rate limiting | Various request rates × token states × global limits |
| Input validation | Edge cases: empty strings, unicode, max-length, special chars |

### 3.4 Remove formulaic test docstrings

Replace 126 instances of `"""Tests for X."""` and `"""Test X."""` with no docstring (let the test name speak) or a WHY-focused docstring if the test is non-obvious.

---

## Phase 4: Security Infrastructure — TLS & HTTP Hardening

**Addresses:** High-5 (no TLS), C4, B6

### 4.1 Add TLS support to HTTP API server

Modify `daemon/api/health.py` and `daemon/external_integrations/siem/verification_api.py`:

```python
import ssl

def create_ssl_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
```

- Add `--tls-cert` and `--tls-key` CLI flags to daemon startup
- Support auto-generated self-signed certs for development
- Document cert management in USER_GUIDE.md

### 4.2 Add security headers to HTTP responses

In all `do_GET`/`do_POST` handlers, add:

```python
self.send_header('X-Content-Type-Options', 'nosniff')
self.send_header('X-Frame-Options', 'DENY')
self.send_header('Cache-Control', 'no-store')
self.send_header('Content-Security-Policy', "default-src 'none'")
```

If CORS is needed (browser-based management UI):
```python
self.send_header('Access-Control-Allow-Origin', '<configured-origin>')
self.send_header('Access-Control-Allow-Methods', 'GET, POST')
self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
```

### 4.3 Verify rate limiter enforcement

Write an integration test that:
1. Sends requests at the rate limit boundary
2. Confirms requests are actually rejected (HTTP 429) not just logged
3. Confirms the block expires after the configured window

### 4.4 Document API threat model

Add a "Threat Model" section to SECURITY.md covering:
- Who can reach the API (Unix socket vs TCP)
- Authentication requirements
- What an attacker with API access could do
- Rate limiting and lockout behavior

---

## Phase 5: Code Cleanup — Comments & Formatting

**Addresses:** Med-6 (575 section dividers), A2 (tutorial comments, missing TODOs)

### 5.1 Remove section divider comments

Remove all 575 instances of:
```python
# ====================================================================
# Section Name
# ====================================================================
```
and
```python
# --------------------------------------------------------------------
```

Replace with natural file structure (class/function grouping, module-level docstrings).

**Scope:** All `.py` files in `daemon/` and `tests/`.

### 5.2 Replace tutorial-style comments

Replace the 26 "Step N" comments with descriptive function extractions:

```python
# Before
# Step 1: Verify human presence
verify_human()
# Step 2: Cooldown delay
time.sleep(cooldown)
# Step 3: Final confirmation
confirm()

# After (self-documenting function names, no step comments needed)
_verify_human_presence(session)
_enforce_cooldown_delay(cooldown_seconds)
_request_final_confirmation(session)
```

Target files:
- `daemon/operator_observability.py:173-206`
- `daemon/integrations.py:721-732`
- `daemon/auth/enhanced_ceremony.py:199-261`
- `daemon/tui/dashboard.py:2007-2052`

### 5.3 Add genuine TODO/FIXME markers

Add honest technical debt markers for known limitations. Target: 20+ real TODOs across the codebase. Examples:

```python
# TODO: KafkaShipper requires kafka-python dependency - implement when needed
# FIXME: blocking I/O in async context - should use asyncio.to_thread()
# TODO: EtcdCoordinator not implemented - only FileCoordinator works
# HACK: health check server has no TLS - see Phase 4 remediation
# TODO: YARA rule management (add/remove/update) not implemented - only compile+scan
```

---

## Phase 6: API & Interface Improvements

**Addresses:** C1, C6, C7

### 6.1 Define shared response envelope

Create `daemon/api/response.py`:

```python
@dataclass
class APIResponse:
    status: str  # "ok" | "error"
    data: Optional[Dict] = None
    error: Optional[Dict] = None  # {"code": "E001", "message": "..."}
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)
```

Update all HTTP handlers (`health.py:do_GET`, `verification_api.py:do_GET/do_POST`, `prometheus_metrics.py:do_GET`) to use this envelope.

### 6.2 Add API versioning

Prefix all HTTP routes with `/v1/`:
- `/v1/health` (currently `/health`)
- `/v1/metrics` (currently `/metrics`)
- `/v1/verify` (currently `/verify`)

### 6.3 Define error codes

Create `daemon/api/error_codes.py`:

| Code | Meaning |
|------|---------|
| `E001` | Authentication failed |
| `E002` | Rate limit exceeded |
| `E003` | Invalid request format |
| `E004` | Policy evaluation failed |
| `E005` | Mode transition denied |
| `E006` | Ceremony required |
| `E007` | System in LOCKDOWN |
| `E008` | Tripwire locked |
| `E009` | Configuration error |
| `E010` | Internal error |

### 6.4 Improve CLI error messages

Update `boundaryctl`, `queryctl`, `sandboxctl` to show:
- Error code + human-readable message
- Suggested next action
- Example: `E005: Mode transition denied. LOCKDOWN exit requires human operator. Run: boundaryctl ceremony unlock`

### 6.5 Add OTel integration test

Write a test that:
1. Configures a mock OTel collector (in-memory span exporter)
2. Triggers a policy evaluation
3. Verifies spans are created with correct trace/span IDs
4. Verifies parent-child span relationships

---

## Phase 7: Async & Resource Lifecycle Fixes

**Addresses:** Med-2 (blocking I/O in async), B4, B7

### 7.1 Fix blocking I/O in async context

**File:** `daemon/watchdog/log_watchdog.py:404-406`

```python
# Before (blocking)
async def _check_file(self, path):
    with open(path, 'r') as f:
        content = f.read()
    line_num = sum(1 for _ in open(path))

# After (non-blocking)
async def _check_file(self, path):
    content = await asyncio.to_thread(self._read_file_sync, path)
    line_num = await asyncio.to_thread(self._count_lines_sync, path)

def _read_file_sync(self, path):
    with open(path, 'r') as f:
        return f.read()

def _count_lines_sync(self, path):
    with open(path, 'r') as f:
        return sum(1 for _ in f)
```

### 7.2 Audit shutdown paths for all monitoring threads

Verify each of these modules has a `stop()`/`shutdown()`/`cleanup()` method that:
1. Sets a stop flag
2. Joins the monitoring thread with a timeout
3. Releases OS-level resources

| Module | Has Shutdown? | Action |
|--------|--------------|--------|
| `daemon/state_monitor.py` (StateMonitor) | Verify | Check `stop()` method |
| `daemon/watchdog/log_watchdog.py` | Verify | Check thread join |
| `daemon/watchdog/hardened_watchdog.py` | Verify | Check thread join |
| `daemon/health_monitor.py` | Verify | Check thread join |
| `daemon/resource_monitor.py` | Verify | Check thread join |
| `daemon/memory_monitor.py` | Verify | Check thread join |
| `daemon/queue_monitor.py` | Verify | Check thread join |

### 7.3 Add daemon lifecycle integration test

Write a test that:
1. Starts `BoundaryDaemon` in a subprocess
2. Sends SIGTERM
3. Verifies clean shutdown (no leaked threads, no orphan files)
4. Checks that enforcement rules (iptables, cgroup dirs) are cleaned up

---

## Phase 8: Configuration & Deployment Realism

**Addresses:** B2

### 8.1 Add environment variable overrides

For critical operational settings, support env var configuration:

| Setting | Env Var | Default |
|---------|---------|---------|
| Log level | `BOUNDARY_LOG_LEVEL` | `INFO` |
| API bind address | `BOUNDARY_API_BIND` | `/var/run/boundary-daemon.sock` |
| Config file path | `BOUNDARY_CONFIG` | `/etc/boundary-daemon/boundary.conf` |
| Log file path | `BOUNDARY_LOG_PATH` | `/var/log/boundary-daemon/events.jsonl` |
| Initial mode | `BOUNDARY_INITIAL_MODE` | `open` |
| TLS cert path | `BOUNDARY_TLS_CERT` | (none — plaintext) |
| TLS key path | `BOUNDARY_TLS_KEY` | (none — plaintext) |

### 8.2 Document privilege requirements

Add a "Deployment Prerequisites" section to USER_GUIDE.md:

| Feature | Required Privilege | Fallback |
|---------|-------------------|----------|
| Network enforcement (iptables) | `CAP_NET_ADMIN` + root | Detection-only mode |
| USB enforcement (udev) | root | Detection-only mode |
| Process enforcement (cgroups) | root or cgroup delegation | Detection-only mode |
| Namespace isolation | `CAP_SYS_ADMIN` | No sandboxing |
| Seccomp filtering | `CAP_SYS_ADMIN` | No syscall filtering |
| Log hardening (chattr +a) | root | Standard file logging |
| Hardware watchdog | root + `/dev/watchdog` | Software watchdog only |

### 8.3 Add deployment smoke test

Create `scripts/smoke-test.sh` that:
1. Starts daemon with default config
2. Checks health endpoint responds
3. Runs a policy evaluation via `boundaryctl`
4. Triggers a mode transition
5. Verifies events are logged
6. Stops daemon cleanly

---

## Phase 9: Low Priority Improvements

**Addresses:** A7, C2, C3, remaining checklist items

### 9.1 Deepen YARA integration

Currently 3 call sites (compile, scan, error handling). Add:
- Rule file management (load from directory, hot-reload)
- Rule validation before compilation
- Scan result caching with TTL
- Rule metadata tracking (author, date, severity)

### 9.2 Add parametrized tests for remaining modules

Use `@pytest.mark.parametrize` for:
- Config encryption/decryption with various key types
- PII detection across different entity types
- Prompt injection detection across all 10 injection types
- Rate limiter with various time windows

### 9.3 Add env var overrides for operational settings

(Covered in 8.1 — ensure implementation)

### 9.4 Improve TUI operational utility

Add TUI panels for:
- Live event log viewer (tail -f style)
- Active policy rule display
- Recent violations summary
- Rate limiter status dashboard

### 9.5 Add lock ordering documentation

Create a `THREADING.md` or section in ARCHITECTURE.md documenting:
- All lock instances and their hierarchy
- Required acquisition order
- Known deadlock prevention patterns (e.g., "callbacks outside lock")

---

## Execution Order & Dependencies

```
Phase 1 (Scope Honesty)        ← Do FIRST. No code deps. Biggest impact on credibility.
    │
    ├── Phase 5 (Code Cleanup)  ← Can run in parallel. Pure cleanup.
    │
    ▼
Phase 2 (Error Handling)       ← Depends on Phase 1 (fewer files after archiving)
    │
    ▼
Phase 3 (Test Quality)         ← Depends on Phase 2 (test the new error handling)
    │
    ├── Phase 6 (API/Interface) ← Can start after Phase 1
    │
    ▼
Phase 4 (TLS/Security)        ← Depends on Phase 6 (shared response envelope)
    │
    ▼
Phase 7 (Async/Resources)     ← Independent, can start anytime after Phase 1
    │
    ▼
Phase 8 (Config/Deployment)   ← Depends on Phase 4 (TLS config) and Phase 7 (shutdown)
    │
    ▼
Phase 9 (Low Priority)        ← Last. Polish after core issues resolved.
```

## Estimated Impact on Vibe-Code Score

| Phase | Primary Score Impact | Estimated Improvement |
|-------|---------------------|----------------------|
| Phase 1 | A6 (1→3), B3 (1→2) | +8% weighted authenticity |
| Phase 2 | B1 (2→3) | +4% weighted authenticity |
| Phase 3 | A3 (2→3) | +3% weighted authenticity |
| Phase 4 | C4 (1→2), B6 (2→3) | +5% weighted authenticity |
| Phase 5 | A2 (2→3) | +1% weighted authenticity |
| Phase 6 | C1 (2→3), C6 (1→2), C7 (2→3) | +4% weighted authenticity |
| Phase 7 | B4 (2→3), B7 (2→3) | +4% weighted authenticity |
| Phase 8 | B2 (2→3) | +2% weighted authenticity |

**Projected final score:** ~48.1% + 31% = ~79% weighted authenticity → **~21% Vibe-Code Confidence** (AI-Assisted range)

---

*Completing Phases 1-4 alone would bring the project into the 35-40% confidence range (AI-Assisted). Phases 5-9 push it toward Human-Authored territory by addressing code quality, deployment realism, and interface maturity.*
