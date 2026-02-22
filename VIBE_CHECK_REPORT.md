# Vibe-Code Detection Audit v2.0
**Project:** boundary-daemon (Agent Smith)
**Date:** 2026-02-22
**Auditor:** Claude (automated analysis)

## Executive Summary

Boundary Daemon is **almost certainly AI-generated code** with extensive, iterative AI-driven development. Of 87 non-merge commits, 85 (97.7%) are attributed to "Claude" with only 2 from a human author ("Kase"). The codebase is massive (~112K lines of Python in `daemon/` alone, plus ~35 markdown documentation files), created in approximately 6 weeks (Jan 8 to Feb 19, 2026). The commit messages are overwhelmingly formulaic ("Add X", "Fix Y across N files"), and every branch name follows the `claude/` prefix pattern.

Despite the provenance, the core security modules (PolicyEngine, TripwireSystem, EventLogger, StateMonitor) show genuine engineering depth: thread-safe state management with proper locking, fail-closed policy evaluation, bounded data structures, hash-chained audit logs, and constant-time token comparison. These modules have substantial test coverage (96 policy engine tests, 98 tripwire tests, 83 state monitor tests, 62 event logger tests) with behavioral assertions, not just existence checks.

The peripheral modules, however, are substantially less mature. Many enforcement modules contain `pass`-only function stubs, eBPF/HSM providers are abstract shells, and the enormous feature surface claimed in the README (150+ modules) far exceeds what's deeply implemented. The ratio of documentation volume (35 markdown files) to project age (6 weeks) is extreme. The project's ambition significantly outpaces its execution depth, particularly in hardware integration, distributed coordination, and platform enforcement layers.

---

## Scoring Summary

| Domain | Weight | Score | Percentage | Rating |
|--------|--------|-------|------------|--------|
| A. Surface Provenance | 20% | 7/21 | 33.3% | Weak |
| B. Behavioral Integrity | 50% | 12/21 | 57.1% | Moderate |
| C. Interface Authenticity | 30% | 9/21 | 42.9% | Moderate-Weak |

**Weighted Authenticity:** (33.3% × 0.20) + (57.1% × 0.50) + (42.9% × 0.30) = 6.66% + 28.55% + 12.87% = **48.1%**

**Vibe-Code Confidence:** 100% - 48.1% = **51.9%**

**Classification: Substantially Vibe-Coded (36-60 range)**

---

## Domain A: Surface Provenance (20%)

### A1. Commit History Patterns — Score: 1 (Weak)

**Evidence:**
- 85/87 (97.7%) commits attributed to "Claude", 2 to "Kase"
- 68/87 (78%) commit messages match formulaic patterns ("Add X", "Fix Y", "Implement Z")
- 7 human-iteration markers found (mostly "wip", "cleanup")
- 0 reverts in entire history
- All feature branches use `claude/` prefix naming (e.g., `claude/security-audit-review-prr9Y`, `claude/repo-review-evaluation-YF2MA`)

**Assessment:** Near-total AI authorship. The commit history reads as a series of AI-generated PRs with minimal human course correction. Zero reverts and almost no frustration markers suggest single-pass generation rather than iterative human development.

**Remediation:**
- Adopt human-written commit messages that explain "why" not "what"
- Add iterative commits showing debugging, rollbacks, and refinement
- Use descriptive branch names without AI tool prefixes

### A2. Comment Archaeology — Score: 2 (Moderate)

**Evidence:**
- 26 tutorial-style comments ("Step 1:", "Here we define...") across `daemon/` — e.g., `daemon/operator_observability.py:173`, `daemon/integrations.py:721`, `daemon/auth/enhanced_ceremony.py:199`
- 575 section divider comments (`# ====`, `# ----`) — extremely high for any project
- Only 8 TODO/FIXME/HACK markers across 259 source files (0.03 per file — unrealistically clean)
- 66 WHY comments (`because`, `since`, `NOTE:`) — moderate presence
- Some genuine security-focused comments: "SECURITY: Must be called while holding self._lock" (`daemon/tripwires.py:136`), "SECURITY (Vuln #3)" (`daemon/boundary_daemon.py:44`)

**Assessment:** Mixed. The security-specific comments show domain awareness and explain rationale. However, the overwhelming use of section dividers (575!) and the near-absence of TODOs/FIXMEs is a strong AI signature — real projects accumulate technical debt markers. The tutorial-style "Step 1/2/3" comments in ceremony flows are a classic AI pattern.

**Remediation:**
- Remove section divider comments; use module structure instead
- Add genuine TODOs for known limitations
- Replace "Step N" comments with descriptive function names

### A3. Test Quality Signals — Score: 2 (Moderate)

**Evidence:**
- 986 test functions across 17 test files
- 112 trivial `is not None` assertions (11.4% of tests)
- Only 6 error-path tests (`pytest.raises`)
- 126 formulaic test docstrings (`"""Tests for X."""`)
- 10 parametrized/table-driven tests
- 1,564 total assert statements

**Sampled test quality:**
- `tests/test_policy_engine.py` (96 tests): Good behavioral coverage — tests mode transitions, lockdown enforcement, callback mechanics, fail-closed defaults. Verifies policy *decisions* not just object existence.
- `tests/test_tripwires.py` (98 tests): Tests auth token mechanics, failed attempt locking, violation detection. Includes security-relevant assertions (constant-time comparison, bounded deque).
- `tests/test_security_stack_e2e.py` (11 tests): Integration tests that verify prompt injection detection against real attack patterns and confirm benign inputs pass.
- `tests/test_attack_simulations.py` (75 tests): Dedicated attack simulation suite.

**Assessment:** Core module tests (policy engine, tripwires, event logger) have real behavioral depth. However, the ratio of error-path tests to happy-path tests is poor (6 vs 986), parametrization is minimal, and many tests assert existence rather than behavior. The e2e and attack simulation tests show genuine security testing intent.

**Remediation:**
- Add `pytest.raises` for all error paths in security-critical modules
- Replace `is not None` assertions with value/behavior checks
- Add parametrized tests for boundary conditions
- Remove formulaic docstrings; use descriptive test names

### A4. Import & Dependency Hygiene — Score: 3 (Strong)

**Evidence:**
- 6 declared dependencies (psutil, cffi, pynacl, cryptography, yara-python, PyYAML) — all with exact version pins
- 0 wildcard imports
- 354 lazy imports (try/except pattern) — extensively used for optional features
- All declared dependencies are imported and used in source code
- Standard library imports cover a wide range (60+ stdlib modules)

**Assessment:** Genuinely clean. Minimal dependency surface, exact version pins with security rationale ("Audit 3.3.1: Exact version pins to prevent supply chain attacks"), zero wildcard imports, and extensive lazy loading for optional modules. This is one of the strongest areas.

**Remediation:** None needed. Consider adding `pip-audit` to CI for vulnerability scanning.

### A5. Naming Consistency — Score: 1 (Weak)

**Evidence:**
- 400+ class names, all PascalCase, consistently suffixed (Error, Config, Manager, Monitor, etc.)
- Function names uniformly snake_case with systematic prefixes (`_evaluate_`, `_check_`, `_verify_`)
- 38 factory function patterns (`create_*`)
- 106 files with identical `logger = logging.getLogger(__name__)` pattern
- Zero deviations, abbreviations, or legacy naming artifacts

**Assessment:** The naming is *too* uniform. Across 112K lines and 400+ classes, there is zero naming inconsistency — no abbreviations, no legacy names, no mixed conventions. Human codebases developed over 6 weeks with multiple features always accumulate some naming drift. This perfect uniformity is a strong AI generation signature.

**Remediation:**
- This isn't functionally harmful, but the uniformity itself is a provenance signal
- No action needed for code quality

### A6. Documentation vs Reality — Score: 1 (Weak)

**Evidence:**
- 35 markdown documentation files for a 6-week-old project
- `README.md` claims "150+ modules", "v1.0.0-beta", "production-ready"
- Feature tables claim 50+ features all marked "Complete"
- `daemon/` contains ~112K lines of Python
- Many claimed "Complete" features are stubs (eBPF observers, HSM providers, OIDC validators)
- Project has dedicated ARCHITECTURE.md, SPEC.md, API_CONTRACTS.md, MONITORING_METRICS.md, SECURITY.md, USER_GUIDE.md, ENFORCEMENT_MODEL.md, CONTRIBUTING.md, CHANGELOG.md, ROADMAP.md, and more

**Assessment:** The documentation volume is wildly disproportionate to the project's age and actual implementation depth. 35 markdown files in 6 weeks is a classic AI-generation pattern — it's easier to generate documentation than working code. The README claims features as "Complete" that are provably stubs (see B3). The important callout box in the README honestly disclosing the cooperative enforcement model is a positive signal, but the overall claims far exceed reality.

**Remediation:**
- Audit all "Complete" feature claims against actual implementation
- Remove or mark stub features as "Planned" or "Prototype"
- Consolidate 35 markdown files to 5-6 essential ones
- Add honest status indicators (e.g., "Core: Production", "Peripheral: Experimental")

### A7. Dependency Utilization — Score: 2 (Moderate)

**Evidence:**
- **psutil**: 50 usages — deeply integrated for process monitoring, health checks, resource monitoring
- **pynacl**: 48 usages — Ed25519 signing for event logs, key management, verification
- **cryptography**: 9 usages — Fernet encryption for config, PBKDF2 key derivation
- **yara-python**: 3 usages — rule compilation and scanning (thin integration)
- **PyYAML**: 11 usages — config loading, Sigma rules, policy files

**Assessment:** psutil and pynacl are deeply integrated into core functionality. cryptography is used meaningfully for config encryption. yara-python integration is thin (compile + scan, no rule management). PyYAML usage is functional but basic.

**Remediation:**
- Deepen YARA integration with rule lifecycle management
- Consider whether yara-python justifies its dependency weight with only 3 call sites

---

## Domain B: Behavioral Integrity (50%)

### B1. Error Handling Authenticity — Score: 2 (Moderate)

**Evidence:**
- 210 bare `except Exception:` handlers
- ~15 silent `except: pass` or `except Exception: return False` patterns (e.g., `daemon/redundant_event_logger.py:209`, `daemon/enforcement/firewall_integration.py:230`)
- 19 custom exception classes with domain-specific hierarchies (TPMError → TPMSealingError → TPMUnsealingError at `daemon/hardware/tpm_manager.py:125-145`)
- 7 exception chaining instances (`raise X from e`)
- 438 typed exception handlers (catching specific error types)

**Assessment:** The codebase shows a split personality. Core modules catch specific exceptions (psutil.NoSuchProcess, nacl.exceptions.BadSignatureError, json.JSONDecodeError), and the TPM module has a proper exception hierarchy. However, the enforcement and redundant logger modules fall back to broad `except Exception: return False` patterns that silently swallow errors. 7 exception chaining instances in 112K lines is very low.

**Remediation:**
- Replace `except Exception: return False` with specific exception types and logging
- Add `raise ... from e` chains in all re-raise paths
- Audit `daemon/redundant_event_logger.py` — 7 bare excepts in one file

### B2. Configuration Actually Used — Score: 2 (Moderate)

**Evidence:**
- Only 2 environment variables read: `BOUNDARY_API_TOKEN`, `USER`
- Extensive config class system across 20+ files
- Configuration is primarily file-based (INI/YAML) through `SecureConfigStorage`
- `MonitoringConfig` has 13 boolean toggles — verified consumed by StateMonitor
- Many config classes in enforcement modules are defined but hard to trace to runtime usage

**Assessment:** The core configuration (boundary modes, monitoring toggles, log paths) is wired through and consumed. The peripheral enforcement configs (firewall rules, USB policies, cgroup limits) are defined but may never be exercised in a real deployment without root privileges. The minimal env var surface is either a design choice or a sign that operational deployment hasn't been considered.

**Remediation:**
- Add env var overrides for critical operational settings (log level, API bind address)
- Document which configs require root/capabilities to take effect
- Verify enforcement configs are consumed end-to-end

### B3. Call Chain Completeness — Score: 1 (Weak)

**Evidence:**
- **Dead modules:** `api/` has 0 external imports (only loaded dynamically by boundary_daemon.py)
- **NotImplementedError stubs:** `daemon/ebpf/probes.py:105,109,113` — base probe class methods
- **Pass-only functions (20+):**
  - `daemon/redundant_event_logger.py:119,124` — LogBackend.write_event/health_check
  - `daemon/crypto/hsm_provider.py:201,206,223,228,233` — HSMProvider interface (5 stubs)
  - `daemon/ebpf/ebpf_observer.py:140,145,150` — BaseObserver start/stop/get_events
  - `daemon/alerts/case_manager.py:248,253,258` — IntegrationClient interface (3 stubs)
  - `daemon/external_integrations/siem/log_shipper.py:97` — ShipperProtocol._ship_batch
- **Hardcoded return:** `daemon/operator_observability.py:993` — returns empty dict
- **Feature chains traced:**
  1. **PolicyEngine → evaluate_policy**: Complete chain. Entry → mode check → request dispatch → custom policy refinement → decision. Verified working with tests.
  2. **TripwireSystem → check_environment**: Complete chain. Environment scan → violation detection → callback fire → lockdown trigger. Verified with tests.
  3. **eBPF monitoring**: Dead end. `BaseObserver.start()` is `pass`. `ProcObserver` falls back to `/proc` polling. `eBPFObserverImpl` requires bcc module that isn't in dependencies.
  4. **HSM integration**: Dead end. `HSMProvider` is 5 stub methods. `SoftHSMProvider` implementation exists but `PKCS11Provider` is abstract.
  5. **SIEM log shipping**: Partial. `FileShipper` and `HTTPShipper` have implementations. `KafkaShipper`, `S3Shipper`, `GCSShipper` are stubs that inherit from protocol class.

**Assessment:** The "Core Four" (PolicyEngine, TripwireSystem, EventLogger, StateMonitor) have complete call chains. However, the majority of the claimed 150+ modules are shells, interfaces, or stubs. The eBPF, HSM, and most SIEM shipping backends don't connect to real implementations. The ratio of declared interfaces to working implementations is concerning.

**Remediation:**
- Mark all stub/interface-only modules clearly in docs
- Remove or archive modules with no working implementation (eBPF, HSM/PKCS11, Kafka/S3/GCS shippers)
- Focus development effort on completing a smaller set of features end-to-end
- Add integration tests that verify feature chains actually execute

### B4. Async Correctness — Score: 2 (Moderate)

**Evidence:**
- Only 5 async functions total (project is primarily synchronous)
- 2 blocking calls inside async functions: `daemon/watchdog/log_watchdog.py:404,406` — `open()` and file line counting inside async context
- 0 async locks (asyncio.Lock, asyncio.Semaphore)
- 6 global mutable state variables at module level (lazy-loaded optional modules)

**Assessment:** The project is predominantly synchronous with threading-based concurrency, which is appropriate for a system daemon. The few async functions have blocking I/O violations (file reads in async context). The global mutable state is used for lazy module loading and is acceptable.

**Remediation:**
- Fix `daemon/watchdog/log_watchdog.py:404-406`: use `aiofiles` or `asyncio.to_thread()` for file operations in async context
- If async scope expands, add proper async locking

### B5. State Management Coherence — Score: 3 (Strong)

**Evidence:**
- 6 global mutable state variables (all for lazy module loading, not shared state)
- 114 thread lock instances across the codebase
- 141 cache/size limit references (TTL, max_size, evict patterns)
- Core modules use consistent pattern: `self._lock = threading.Lock()` with `with self._lock:` guards
- PolicyEngine: `_state_lock` + `_callback_lock` with documented ordering to prevent deadlock (`policy_engine.py:230`: "Fire callbacks OUTSIDE _state_lock to prevent deadlock")
- TripwireSystem: bounded `deque(maxlen=1000)` for violations, `deque(maxlen=100)` for attempt history
- EventLogger: thread-safe hash chain updates under lock

**Assessment:** This is one of the strongest areas. The threading model is well-designed with proper lock hierarchies, bounded collections, and documented lock ordering. The "callbacks outside lock" pattern at `policy_engine.py:230` shows understanding of deadlock prevention. Cache/size limits are widespread.

**Remediation:** None critical. Consider adding lock timeout monitoring for production deployments.

### B6. Security Implementation Depth — Score: 2 (Moderate)

**Evidence:**
- **Real crypto:** PBKDF2 key derivation (`daemon/config/secure_config.py:311`), Ed25519 signing (pynacl), Fernet encryption (AES-128-CBC + HMAC-SHA256), constant-time comparison (`daemon/tripwires.py:130`: `hmac.compare_digest`)
- **Hardcoded secrets:** `daemon/identity/ldap_mapper.py:115,426` — placeholder strings `<LDAP_BIND_PASSWORD>` (not real secrets, but placeholder patterns)
- **SQL injection:** None found (no SQL usage)
- **Rate limiting:** 506 references — extensively implemented in `daemon/auth/persistent_rate_limiter.py`, `daemon/auth/api_auth.py`
- **Input validation:** 219 references across the codebase
- **No CORS/CSP headers** (HTTP API is minimal, BaseHTTPRequestHandler only)
- **Token auth:** SHA-256 hashed storage with constant-time comparison
- **Supply chain:** Pre-load hash verification before `exec_module()` (`daemon/boundary_daemon.py:61-156`)

**Assessment:** The core security primitives are genuine — real PBKDF2, Ed25519, constant-time comparison, and the supply chain hash verification is a sophisticated pattern. Rate limiting is deeply integrated. However, the HTTP API lacks standard web security headers (CORS, CSP), and many security monitoring modules (ARP, DNS, WiFi, threat intel) are detection-only with no enforcement bridge.

**Remediation:**
- Add CORS and CSP headers to HTTP API endpoints
- Verify rate limiter actually blocks rather than just logging
- Add TLS to the health check HTTP server
- Complete the enforcement bridge for detection modules that currently only alert

### B7. Resource Management — Score: 2 (Moderate)

**Evidence:**
- 798 context manager (`with`) usages — strong
- Only 2 file handles opened without context managers
- 503 cleanup/shutdown handler references
- Background thread lifecycle: `daemon/boundary_daemon.py` manages shutdown via signal handlers
- `daemon/tripwires.py:70`: `deque(maxlen=1000)` for bounded violation history
- `daemon/policy_engine.py:180-184`: explicit `cleanup()` method clears callbacks

**Assessment:** Good resource hygiene. Context managers are used consistently, file handles are properly managed, and bounded collections prevent memory growth. The cleanup patterns in core modules are explicit. The concern is with the many enforcement/monitoring modules — it's unclear if all of them have proper shutdown paths when the daemon exits.

**Remediation:**
- Audit all monitoring threads for graceful shutdown on SIGTERM
- Add integration test that starts/stops daemon and verifies no leaked resources
- Verify enforcement modules release OS-level resources (iptables rules, cgroup dirs)

---

## Domain C: Interface Authenticity (30%)

### C1. API Design Consistency — Score: 2 (Moderate)

**Evidence:**
- HTTP API uses raw `BaseHTTPRequestHandler` (not Flask/FastAPI)
- Routes defined in `daemon/api/health.py:374` (do_GET) and `daemon/external_integrations/siem/verification_api.py:402,414` (do_GET, do_POST)
- `daemon/telemetry/prometheus_metrics.py:381` (do_GET for /metrics)
- No shared response model — each handler constructs its own JSON dicts
- No OpenAPI/Swagger specification

**Assessment:** The API surface is minimal and hand-rolled. There's no shared response format, error model, or API specification. Each HTTP handler independently constructs responses. This is acceptable for an internal daemon API but doesn't match the "API contracts finalized" claim in the README.

**Remediation:**
- Define shared response envelope (status, data, error)
- Add API versioning (/v1/ prefix)
- Generate OpenAPI spec from actual endpoints

### C2. UI Implementation Depth — Score: 2 (Moderate)

**Evidence:**
- Full TUI dashboard (`daemon/tui/dashboard.py`) with curses-based rendering
- Animated cityscape visualization (`daemon/tui/scene.py` — 2400+ lines)
- Art editor (`daemon/tui/art_editor.py`)
- Weather effects, matrix rain, creature animations
- Extracted to standalone `boundary-tui` package

**Assessment:** The TUI is elaborate with genuine visual complexity (scene rendering, animations, weather effects). However, it's primarily a display — the interactive elements are limited to mode switching and basic navigation. The art editor and creature system are creative but peripheral to security functionality.

**Remediation:**
- Focus TUI development on operational utility (log viewing, policy testing, real-time alerts)
- Consider whether the animated cityscape serves operational needs

### C3. State Management (Frontend) — Score: 1 (Weak)

**Evidence:**
- TUI uses global state through `DashboardClient` class
- No formal state management pattern (no event bus, no reducer)
- Dashboard polls daemon for state updates

**Assessment:** The TUI state management is ad-hoc. For a terminal application this is acceptable, but it doesn't demonstrate sophisticated frontend engineering.

**Remediation:** Not critical for a TUI. Consider event-driven updates if latency matters.

### C4. Security Infrastructure — Score: 1 (Weak)

**Evidence:**
- No CORS headers on any HTTP endpoint
- No CSP headers
- No TLS on health check server
- Token auth exists in `daemon/auth/api_auth.py` with rate limiting
- No session management (stateless token auth)

**Assessment:** The HTTP API has token authentication and rate limiting, which is good. But it lacks standard web security infrastructure (TLS, CORS, CSP). For an internal daemon API this may be acceptable, but it contradicts the "production-ready" claim.

**Remediation:**
- Add TLS support (even self-signed) for API server
- Add CORS headers for any browser-based management interface
- Document the threat model for the API surface

### C5. WebSocket Implementation — Score: N/A

No WebSocket implementation found. TUI communicates via direct method calls, not network protocols.

### C6. Error UX — Score: 1 (Weak)

**Evidence:**
- CLI tools (`boundaryctl`, `queryctl`, `sandboxctl`) exist but error presentation is basic
- TUI shows raw state data without user-friendly error messages
- No error aggregation or user-facing error codes

**Assessment:** Error presentation to operators is minimal. The logging infrastructure is sophisticated (structured JSON, hash chains), but the user-facing error experience is underdeveloped.

**Remediation:**
- Add error codes for common failure modes
- Improve CLI error messages with actionable guidance
- Add TUI panels for error/alert summary

### C7. Logging & Observability — Score: 2 (Moderate)

**Evidence:**
- JSON structured logging available (`daemon/logging_config.py:90`)
- Trace/span IDs via OpenTelemetry (`daemon/telemetry/otel_setup.py:170-171`)
- Correlation IDs in SIEM integration (`daemon/security/siem_integration.py:123`)
- Health check HTTP server with component status (`daemon/api/health.py`)
- Prometheus metrics exporter (`daemon/telemetry/prometheus_metrics.py`)
- Decision trace logging (`daemon/operator_observability.py`)

**Assessment:** The observability stack is broad — structured logging, OTel traces, Prometheus metrics, health checks. Whether it's all wired together end-to-end is less clear (OTel integration requires external collectors). The health check server provides real data from psutil, which is genuine.

**Remediation:**
- Add integration test verifying OTel trace propagation
- Document required external infrastructure (Prometheus, Jaeger, etc.)
- Add log correlation between daemon components

---

## High Severity Findings

| # | Finding | Location | Impact | Remediation |
|---|---------|----------|--------|-------------|
| 1 | eBPF monitoring is entirely stubbed | `daemon/ebpf/probes.py:105-113`, `daemon/ebpf/ebpf_observer.py:140-150` | Claimed feature doesn't work; bcc not in deps | Remove from feature claims or implement with bcc dependency |
| 2 | HSM provider is 5 abstract stubs | `daemon/crypto/hsm_provider.py:201-233` | No hardware security module integration exists | Remove from feature claims or implement PKCS#11 |
| 3 | 210 bare `except Exception` handlers | Across `daemon/` (concentrated in enforcement/) | Silent error swallowing in security-critical paths | Replace with typed exceptions and logging |
| 4 | README claims 50+ features as "Complete" that are stubs | `README.md` feature tables | Misleading capability claims | Audit and reclassify stub features |
| 5 | No TLS on HTTP API server | `daemon/api/health.py`, `daemon/external_integrations/siem/verification_api.py` | Credentials and events transmitted in cleartext | Add TLS support |

## Medium Severity Findings

| # | Finding | Location | Impact | Remediation |
|---|---------|----------|--------|-------------|
| 1 | Only 6 error-path tests across 986 test functions | `tests/` directory | Error handling untested | Add `pytest.raises` for all security-critical error paths |
| 2 | Blocking I/O in async context | `daemon/watchdog/log_watchdog.py:404-406` | Event loop blocking | Use `aiofiles` or `asyncio.to_thread()` |
| 3 | SIEM shipping backends mostly stubbed | `daemon/external_integrations/siem/log_shipper.py` | Kafka, S3, GCS shippers non-functional | Implement or remove |
| 4 | 112 trivial `is not None` assertions | Across `tests/` | Tests verify existence not behavior | Replace with value/behavior assertions |
| 5 | 35 markdown documentation files in 6-week project | Root and `docs/` directory | Documentation overhead, many docs describe unimplemented features | Consolidate to essential docs |
| 6 | 575 section divider comments | Across `daemon/` | Code noise, strong AI signature | Remove decorative dividers |

---

## What's Genuine

- **PolicyEngine core logic** (`daemon/policy_engine.py`): Complete mode × request × environment evaluation matrix with fail-closed defaults, proper lock hierarchy, custom policy tighten-only invariant. 96 tests verify behavioral outcomes. *Evidence: policy_engine.py:87-306, policy_engine.py:230 deadlock prevention comment*

- **TripwireSystem security model** (`daemon/tripwires.py`): Token-authenticated critical operations, constant-time comparison (`tripwires.py:130`), bounded violation deque (`tripwires.py:70`), progressive lockout after failed attempts. *Evidence: tripwires.py:54-170, 98 tests*

- **EventLogger hash chain** (`daemon/event_logger.py`): Instance-specific genesis nonce (`event_logger.py:132-135`), fail-closed on corrupt log (`event_logger.py:177-184`), secure file permissions, fsync after writes. *Evidence: event_logger.py:111-184*

- **Supply chain verification** (`daemon/boundary_daemon.py:61-156`): Pre-load hash verification against manifest before `exec_module()`. This is a sophisticated pattern that addresses a real supply chain attack vector.

- **Thread-safe state management**: Consistent `threading.Lock()` patterns, documented lock ordering, bounded collections. 114 lock instances across codebase.

- **Dependency hygiene**: Exact version pins, zero wildcard imports, 354 lazy imports for optional features, minimal attack surface (6 deps).

- **Attack simulation tests** (`tests/test_attack_simulations.py`): 75 tests simulating real attack patterns against prompt injection, tool validation, and security stack.

---

## What's Vibe-Coded

- **eBPF monitoring suite** (`daemon/ebpf/`): Three files of abstract interfaces with `pass`/`NotImplementedError` bodies. `bcc` not even in dependencies. *Evidence: probes.py:105-113, ebpf_observer.py:140-150*

- **HSM/PKCS#11 integration** (`daemon/crypto/hsm_provider.py`): 5 stub methods in HSMProvider. SoftHSM has a partial implementation, PKCS11Provider is abstract. *Evidence: hsm_provider.py:201-233*

- **SIEM shipping backends** (`daemon/external_integrations/siem/log_shipper.py`): KafkaShipper, S3Shipper, GCSShipper inherit protocol class but have no implementation. *Evidence: log_shipper.py:97*

- **Case management integrations** (`daemon/alerts/case_manager.py`): ServiceNow, Slack, PagerDuty clients are 3 stub methods each. *Evidence: case_manager.py:248-258*

- **Distributed cluster coordination** (`daemon/distributed/`): EtcdCoordinator is largely theoretical, FileCoordinator has basic implementation.

- **Post-quantum cryptography** (`daemon/crypto/post_quantum.py`): Dilithium/Kyber "simulators" — not real PQC implementations.

- **Identity federation** (`daemon/identity/`): OIDC validator, LDAP mapper, PAM integration have structures but no real server interaction. Placeholder bind passwords. *Evidence: ldap_mapper.py:115*

- **README feature claims**: 50+ features marked "Complete" including items that are stubs, interfaces, or single-file prototypes.

- **35 documentation files**: ARCHITECTURE.md, SPEC.md, API_CONTRACTS.md, MONITORING_METRICS.md, SECURITY_COMPARISON.md, KEYWORDS.md (SEO?), etc. — volume far exceeds substance for a 6-week project.

- **575 section divider comments**: Decorative code formatting that adds noise without information.

---

## Remediation Checklist

### Critical (address before any "production-ready" claim)
- [ ] Audit all README feature claims — mark stubs as "Planned" or "Interface Only"
- [ ] Remove or archive non-functional modules (eBPF, HSM/PKCS11, PQC simulators, dead SIEM shippers)
- [ ] Replace 210 bare `except Exception:` handlers with typed exceptions
- [ ] Add TLS support to HTTP API server
- [ ] Add error-path tests (`pytest.raises`) for all security-critical modules

### High Priority
- [ ] Fix blocking I/O in async context (`daemon/watchdog/log_watchdog.py:404-406`)
- [ ] Add integration tests that trace feature call chains end-to-end
- [ ] Consolidate 35 markdown files to ~6 essential documents
- [ ] Replace 112 trivial `is not None` assertions with behavioral checks
- [ ] Add real deployment documentation (prerequisites, capabilities needed, threat model)

### Medium Priority
- [ ] Remove 575 decorative section divider comments
- [ ] Replace 26 tutorial-style "Step N" comments with descriptive function names
- [ ] Add genuine TODO/FIXME markers for known limitations
- [ ] Add API versioning and shared response envelope
- [ ] Document lock ordering and thread safety invariants

### Low Priority
- [ ] Deepen YARA engine integration (rule lifecycle, management)
- [ ] Add parametrized tests for boundary conditions
- [ ] Add env var overrides for operational settings
- [ ] Improve CLI/TUI error presentation with actionable messages

---

*This audit is remediation-focused. The core security modules (PolicyEngine, TripwireSystem, EventLogger, StateMonitor) demonstrate genuine engineering depth and are worth building upon. The primary issue is that the project's claimed scope far exceeds its actual implementation depth. Narrowing the feature surface to what's genuinely complete would produce an honest and impressive security daemon.*
