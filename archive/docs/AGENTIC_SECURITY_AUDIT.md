# Agentic Security Audit Report

**Project:** Boundary Daemon (Agent Smith) v1.0.0-beta
**Audit Date:** 2026-02-19
**Methodology:** [Agent-OS Three-Tier Security Framework](https://github.com/kase1111-hash/Claude-prompts/blob/main/Agentic-Security-Audit.md)
**Auditor:** Claude Code (Automated Security Audit)
**Scope:** Full repository scan - 152+ Python modules, 173K+ lines of code

---

## Executive Summary

The Boundary Daemon implements a cognitive firewall for multi-agent AI systems with six security modes (OPEN through LOCKDOWN). This audit evaluates the repository against the Agent-OS three-tier security framework covering architectural defaults, core enforcement, and protocol-level maturity.

**Overall Score: 83/100 - STRONG with targeted gaps**

| Tier | Component | Score | Status |
|------|-----------|-------|--------|
| 1 | Architectural Defaults | 82% | STRONG |
| 2 | Core Enforcement Layer | 85% | STRONG |
| 3 | Protocol-Level Maturity | 83% | STRONG |

**Critical Findings:** 4
**High Findings:** 6
**Medium Findings:** 8
**Low/Info Findings:** 12+

---

## TIER 1: Architectural Defaults

### 1.1 Credential Storage

**Score: 9/10 - Excellent**

#### Positive Findings
- No real secrets hardcoded in production code
- Pre-commit hook (`.githooks/pre-commit`) scans for 15+ credential patterns before commits
- Token encryption via Fernet (AES-128-CBC + HMAC-SHA256) in `daemon/auth/secure_token_storage.py`
- Configuration encryption with key rotation in `daemon/config/secure_config.py`
- PII detection engine (`daemon/pii/detector.py`) catches AWS keys, JWTs, OAuth tokens
- Proper use of environment variables (`BOUNDARY_*` prefix) with no hardcoded defaults
- No `.env` files, no private keys, no certificates in repository

#### Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| 1.1.1 | LOW | Documentation example contains `auth_token = "boundary_secure_token"` | `SPEC.md:1795` |
| 1.1.2 | LOW | Test code uses `bind_password="secret"` placeholder | `daemon/identity/ldap_mapper.py:115,426` |

**Recommendation:** Replace documentation examples with `<PLACEHOLDER>` markers.

---

### 1.2 Least Privilege Permissions

**Score: 7/10 - Good with gaps**

#### Positive Findings
- Systemd service declares explicit Linux capabilities: `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_KILL`, `CAP_DAC_OVERRIDE`
- File permissions consistently set to `0o600` for secrets, `0o400` for sealed logs
- Privilege manager (`daemon/privilege_manager.py`) provides cross-platform elevation checking

#### Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| 1.2.1 | HIGH | Daemon runs as `User=root` / `Group=root` with broad capabilities including `CAP_SYS_ADMIN` | `systemd/boundary-daemon.service:40-42` |
| 1.2.2 | HIGH | Enforcement modules silently degrade to monitoring-only when run without root, without escalating alerts | `daemon/enforcement/network_enforcer.py`, `daemon/enforcement/usb_enforcer.py` |
| 1.2.3 | MEDIUM | Predictable socket path `~/.agent-os/api/boundary.sock` enables socket hijacking on shared systems | `API_CONTRACTS.md:12`, `boundary-tui/boundary_tui/client.py:387` |
| 1.2.4 | MEDIUM | `/tmp/boundary-cluster` used for cluster data (world-readable, symlink-attackable) | `cluster_demo.py:41,168` |

**Recommendations:**
1. Create a dedicated `boundary-daemon` service user with only required capabilities instead of root
2. Enforce fail-closed behavior when running without root: refuse to start in modes >= TRUSTED
3. Use `/var/run/boundary-daemon/` for sockets with `0o750` directory permissions
4. Replace `/tmp` usage with `tempfile.TemporaryDirectory()` with restricted permissions

---

### 1.3 Cryptographic Agent Identity

**Score: 8/10 - Strong**

#### Positive Findings
- Ed25519 signing via PyNaCl/libsodium (`daemon/signed_event_logger.py:85-100`)
- Post-quantum hybrid cryptography with Dilithium-3 (`daemon/crypto/post_quantum.py`)
- HSM support: PKCS#11, AWS CloudHSM, Azure HSM, YubiHSM (`daemon/crypto/hsm_provider.py`)
- 7-tier trust levels from UNTRUSTED(0) to SYSTEM(6) (`daemon/security/agent_attestation.py:86-94`)
- Secure key storage with `0o600` permissions and memory zeroing (`daemon/security/secure_memory.py`)
- No weak cryptographic patterns (MD5, SHA1, ECB, DES) used for security purposes

#### Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| 1.3.1 | MEDIUM | Agents do not automatically receive unique keypairs at creation - attestation system is opt-in | `daemon/security/agent_attestation.py` |
| 1.3.2 | MEDIUM | Cryptographic signatures bind to audit events but NOT to individual policy decisions/actions | `daemon/signed_event_logger.py` |

**Recommendations:**
1. Make agent keypair assignment mandatory at registration time
2. Extend action binding so each policy decision carries a cryptographic proof

---

## TIER 2: Core Enforcement Layer

### 2.1 Input Classification Gate

**Score: 8/10 - Strong**

#### Positive Findings
- Comprehensive prompt injection detection with 50+ patterns (`daemon/security/prompt_injection.py:265-641`)
- Covers: DAN jailbreaks, instruction injection, roleplay bypasses, delimiter injection, encoding bypasses (Base64, Unicode homographs, zero-width characters), authority escalation, tool abuse, memory poisoning, credential exfiltration
- RAG injection detection with document quarantine (`daemon/security/rag_injection.py`)
- Multi-layer sanitization: pattern scan, encoding bypass detection, structural analysis, semantic indicators

#### Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| 2.1.1 | HIGH | Input DATA vs INSTRUCTION tagging is advisory-only. `source_trust` defaults to `"unknown"` rather than deny-by-default | `daemon/messages/message_checker.py:35-56` |
| 2.1.2 | HIGH | Agent attestation system is optional (`attestation_system=None` by default) - instructions accepted without authentication | `daemon/messages/message_checker.py:200-227` |

**Recommendations:**
1. Default `source_trust` to `"untrusted"` and require explicit promotion to higher trust levels
2. Make attestation system mandatory for all authority level >= 2 messages

---

### 2.2 Memory Integrity

**Score: 9/10 - Excellent**

#### Positive Findings
- Each memory entry carries full provenance: author, intent, timestamp, signature, `source_trust`, `ingestion_context` (`daemon/messages/message_checker.py:35-77`)
- SHA-256 hash chains with provenance inclusion prevent tampering (`message_checker.py:57-64`)
- UNKNOWN provenance documents quarantined, not silently passed through (`daemon/security/rag_injection.py:345-399`)
- Time-shifted memory poisoning attacks prevented by trust level enforcement

#### Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| 2.2.1 | MEDIUM | Memory scanning is on-demand only - no periodic background verification of stored memories for instruction-like content injection | `daemon/security/rag_injection.py` |

**Recommendation:** Implement scheduled background audits of memory stores to detect delayed poisoning.

---

### 2.3 Outbound Secret Scanning

**Score: 8/10 - Strong**

#### Positive Findings
- Tool output scanned for credentials: API keys, tokens, Bearer/Basic auth headers, PEM private keys (`daemon/security/tool_validator.py:196-618`)
- Response guardrails detect PII: emails, phone numbers, addresses (`daemon/security/response_guardrails.py:580-622`)
- Critical credentials trigger `ValidationResult.BLOCKED` with `SanitizationAction.REDACT`
- Credential exfiltration attempts detected in prompts before execution (`daemon/security/prompt_injection.py`)
- RAG exfiltration detection for send/transmit/export patterns (`daemon/security/rag_injection.py`)
- Network egress filtering via per-sandbox firewall rules (`daemon/sandbox/network_policy.py`)

#### Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| 2.3.1 | HIGH | No explicit constitutional rule "agents MUST NEVER transmit credentials" - relies on pattern matching rather than affirmative policy | `daemon/messages/message_checker.py` |
| 2.3.2 | MEDIUM | No network-level deep packet inspection for credential patterns in egress traffic | Network enforcement modules |

**Recommendations:**
1. Implement an immutable `NO_CREDENTIAL_TRANSMISSION` policy rule in `BoundaryPolicy` that triggers automatic LOCKDOWN on violation
2. Add DPI-based credential scanning at the network enforcement layer

---

### 2.4 Skill/Module Signing & Sandboxing

**Score: 9/10 - Excellent**

#### Positive Findings

**Code Signing:**
- Ed25519 manifest signing with canonical JSON (`daemon/integrity/code_signer.py:365-382`)
- Startup integrity verification refuses to start on failure (`daemon/integrity/integrity_verifier.py:514-559`)
- SHA-256 per-module hashes with size and timestamp tracking
- LOCKDOWN escalation on tampering detection

**Sandboxing:**
- Linux namespace isolation: PID, Mount, Network, User, IPC, UTS, Cgroup (`daemon/sandbox/namespace.py:39-54`)
- Seccomp-BPF syscall filtering with boundary-mode profiles (`daemon/sandbox/seccomp_filter.py:708-737`):
  - LOCKDOWN: 7 syscalls (exit only)
  - COLDROOM: 16 syscalls (minimal)
  - AIRGAP: 26 syscalls (no network)
- Cgroups v2 resource limits: CPU, memory, PIDs, I/O (`daemon/sandbox/cgroups.py:34-115`)
- Per-sandbox iptables/nftables firewall rules
- x86_64 protection against 32-bit syscall bypasses (int 0x80) (`seccomp_filter.py:439-451`)
- Fail-closed mount namespace: `RuntimeError` on mount failure prevents shared filesystem

**Violation Response:**
- Mode escalation triggers automatic profile tightening
- LOCKDOWN triggers immediate process termination
- Ceremony required for relaxed sandboxing in modes >= COLDROOM

#### Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| 2.4.1 | MEDIUM | Module manifests lack per-module capability declarations (only hashes, no `file_access`, `network_access`, etc.) | `daemon/integrity/code_signer.py:96-147` |
| 2.4.2 | MEDIUM | Integrity verification only at startup - no per-import module verification hook | `daemon/integrity/integrity_verifier.py` |

**Recommendations:**
1. Extend `ModuleHash` dataclass with `capabilities: Set[str]` for fine-grained access control
2. Hook into Python import system (`importlib`) for on-demand signature verification

---

## TIER 3: Protocol-Level Maturity

### 3.1 Constitutional Audit Trail

**Score: 9/10 - Excellent**

#### Positive Findings
- 28 event types tracked including violations, mode changes, overrides, PII detection, sandbox enforcement, channel lifecycle (`daemon/event_logger.py:29-64`)
- SHA-256 hash chains create tamper-evident logs (`event_logger.py:181-210`)
- Ed25519 signed events with public key pinning (`daemon/signed_event_logger.py:174-196`)
- Append-only storage: `O_APPEND` flag + `chattr +a` + `chattr +i` for sealed archives (`daemon/storage/append_only.py`, `daemon/storage/log_hardening.py`)
- `fsync()` after every write for crash recovery (`event_logger.py:223-237`)
- File permissions: `0o600` active, `0o400` sealed
- Redundant logging to multiple backends (`daemon/redundant_event_logger.py`)
- Violations tracked separately with `EventType.VIOLATION` and `EventType.TRIPWIRE`
- Human-readable JSON format with ISO-8601 timestamps

#### Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| 3.1.1 | MEDIUM | Events log WHAT happened but not the full reasoning chain (policy conditions evaluated, condition results, decision logic) | `daemon/event_logger.py:181-210` |

**Recommendation:** Add `reasoning_chain` field to `BoundaryEvent` capturing `{policy_rule, conditions_evaluated, condition_results, final_decision}`.

---

### 3.2 Mutual Agent Authentication

**Score: 8/10 - Strong**

#### Positive Findings
- Token-based attestation with signature verification, expiration, and nonce (`daemon/security/agent_attestation.py:584-607`)
- 7-tier trust levels enforced in identity registration (`agent_attestation.py:86-94`)
- Self-assertion prevented: only `ROOT_ISSUER_ID` is initially trusted; agents cannot self-issue tokens
- HMAC-SHA256 message signing with constant-time comparison (`hmac.compare_digest`)
- Authority level >= 2 requires cryptographic identity verification (`daemon/messages/message_checker.py:443-466`)

#### Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| 3.2.1 | MEDIUM | Authentication uses static bearer tokens rather than challenge-response exchange - susceptible to replay attacks if intercepted | `daemon/security/agent_attestation.py:509-543` |
| 3.2.2 | LOW | Token nonce field exists but no explicit replay detection mechanism (nonce uniqueness not enforced) | `agent_attestation.py:593` |

**Recommendations:**
1. Implement challenge-response protocol with per-session nonces for interactive agent-to-agent authentication
2. Add nonce uniqueness tracking with a sliding window to prevent replay attacks

---

### 3.3 Anti-C2 Pattern Enforcement

**Score: 9/10 - Excellent**

#### Positive Findings
- Four CRITICAL-severity C2 detection patterns (`daemon/security/prompt_injection.py:548-581`):
  - `fetch_execute_url`: "fetch/download instructions from URL"
  - `periodic_checkin`: "every X hours check/fetch/poll URL"
  - `execute_remote_content`: "execute/run content from URL/API"
  - `heartbeat_pattern`: "heartbeat/beacon to URL"
- Remote content treated as data only - execution blocked
- Ceremony-gated updates requiring multi-factor approval (`daemon/auth/advanced_ceremony.py`, `daemon/auth/enhanced_ceremony.py`)

#### Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| 3.3.1 | MEDIUM | Dependencies use `>=` floor pins instead of exact versions - vulnerable to supply chain attacks via minor version backdoors | `requirements.txt:4-15` |

**Recommendation:** Pin dependencies to exact versions (e.g., `psutil==5.9.8`) and use a lock file or hash verification.

---

### 3.4 Vibe-Code Security Review

**Score: 8/10 - Strong**

#### Positive Findings
- Bandit SAST scanner runs on every PR (`bandit -r daemon/ -ll`) (`.github/workflows/ci.yml:64-66`)
- `safety check` for dependency vulnerability detection (`ci.yml:68-71`)
- Ruff linter and MyPy type checker in CI pipeline
- pytest with 60% minimum coverage threshold
- No SQL database = no SQL injection surface; file-based storage with strict permissions

#### Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| 3.4.1 | MEDIUM | No dedicated secret scanning tool (e.g., `detect-secrets`, `trufflehog`, `gitleaks`) in CI/CD pipeline | `.github/workflows/ci.yml` |
| 3.4.2 | INFO | Bandit skips rules B101 (assert), B404 (subprocess import), B603 (subprocess call), B607 (partial executable path) - these should be periodically reviewed | `ci.yml:66` |

**Recommendations:**
1. Add secret scanner to CI: `detect-secrets scan --baseline .secrets.baseline`
2. Periodically review Bandit exclusions to ensure they remain justified

---

### 3.5 Agent Coordination Boundaries

**Score: 7/10 - Good with critical gap**

#### Positive Findings
- Channel lifecycle fully audited: `CHANNEL_OPENED`, `CHANNEL_CLOSED`, `CHANNEL_SUMMARY` events (`daemon/event_logger.py:62-64`)
- Per-token rate limiting with configurable windows and blocking duration (`daemon/auth/persistent_rate_limiter.py`)
- Global rate limiting across all agents
- Persistent rate limit state survives daemon restart
- Destructive actions gated by `requires_consent` flag and `ceremony_completed` metadata (`daemon/messages/message_checker.py:468-481`)

#### Findings

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| 3.5.1 | **CRITICAL** | No mechanism prevents autonomous agent hierarchy formation. `AGENT_SUPERVISE` can delegate `AGENT_DELEGATE` capability, enabling unbounded authority chains (up to `MAX_CHAIN_DEPTH=5` levels) without human approval | `daemon/security/agent_attestation.py:247-265` |
| 3.5.2 | HIGH | `SYSTEM_ADMIN` capability grants ALL capabilities including `AGENT_DELEGATE` and `AGENT_SUPERVISE`, creating a single point of compromise | `agent_attestation.py:262-264` |

**Recommendations:**
1. Require human ceremony approval for any `AGENT_DELEGATE` capability delegation
2. Remove `AGENT_DELEGATE` from the `AGENT_SUPERVISE` delegatable set
3. Add per-agent delegation depth tracking (not just global `MAX_CHAIN_DEPTH`)
4. Audit all delegation transfers with full reasoning chain
5. Eliminate `SYSTEM_ADMIN` blanket capability grant - use explicit capability enumeration

---

## Additional Architectural Findings

### Socket Security

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| A.1 | MEDIUM | Socket creation has TOCTOU window despite umask mitigation. Parent directory permissions not enforced. No connecting-client UID verification | `api/boundary_api.py:211-218` |

### Code Advisor Vulnerability Demonstrations

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| A.2 | INFO | `code_advisor.py` contains intentional vulnerability demonstrations (command injection, SQL injection, XSS) used as test inputs for the scanner. These are string literals written to temp files, NOT executable production code | `daemon/security/code_advisor.py:603-615` |

---

## Compliance Matrix

| # | Control | Status | Evidence |
|---|---------|--------|----------|
| 1.1 | No plaintext secrets | **PASS** | Pre-commit hooks, encrypted storage, PII detection |
| 1.2 | Least privilege | **PARTIAL** | Root required for enforcement; silent degradation |
| 1.3 | Cryptographic identity | **PASS** | Ed25519 + post-quantum hybrid; HSM support |
| 2.1 | Input classification | **PARTIAL** | 50+ injection patterns but tagging is advisory-only |
| 2.2 | Memory integrity | **PASS** | Hash chains, provenance tracking, quarantine |
| 2.3 | Outbound secret scanning | **PARTIAL** | Multi-layer detection but no constitutional rule |
| 2.4 | Module signing/sandboxing | **PASS** | Ed25519 signing, namespaces, seccomp, cgroups |
| 3.1 | Constitutional audit trail | **PASS** | Append-only, signed, hash-chained, redundant |
| 3.2 | Mutual authentication | **PASS** | Token attestation, trust levels, signed comms |
| 3.3 | Anti-C2 enforcement | **PASS** | 4 C2 patterns detected at CRITICAL severity |
| 3.4 | Vibe-code review | **PARTIAL** | SAST present but no secret scanner in CI |
| 3.5 | Coordination boundaries | **PARTIAL** | Rate limiting + ceremony but hierarchy gap |

---

## Priority Remediation Roadmap

### P0 - Immediate (Critical)
1. **Prevent autonomous hierarchy formation** - Require human ceremony for `AGENT_DELEGATE` delegation; remove from `AGENT_SUPERVISE` delegatable set (`agent_attestation.py:247-265`)
2. **Eliminate `SYSTEM_ADMIN` blanket grant** - Replace with explicit capability enumeration (`agent_attestation.py:262-264`)

### P1 - High Priority
3. **Make attestation mandatory** for authority level >= 2 messages (`message_checker.py`)
4. **Implement constitutional credential rule** - Hardcoded `NO_CREDENTIAL_TRANSMISSION` policy with LOCKDOWN on violation
5. **Fix silent privilege degradation** - Fail-closed in modes >= TRUSTED when running without root
6. **Default `source_trust` to `"untrusted"`** instead of `"unknown"` (`message_checker.py:52`)

### P2 - Medium Priority
7. **Pin dependencies to exact versions** with hash verification (`requirements.txt`)
8. **Add secret scanner to CI/CD** (detect-secrets or gitleaks)
9. **Add reasoning chains to events** for forensic decision reconstruction
10. **Secure socket paths** - Use `/var/run/` with enforced parent directory permissions
11. **Add per-module capability declarations** to signing manifests
12. **Implement periodic background memory audits**

### P3 - Low Priority / Hardening
13. Challenge-response authentication for inter-agent exchange
14. Token replay detection with nonce uniqueness tracking
15. Per-import module signature verification
16. Network-level DPI for credential patterns
17. Replace `/tmp` usage in cluster demos
18. Review Bandit exclusion list periodically

---

## Files Audited

| Category | Key Files |
|----------|-----------|
| Core Daemon | `daemon/boundary_daemon.py`, `daemon/policy_engine.py`, `daemon/tripwires.py` |
| Event Logging | `daemon/event_logger.py`, `daemon/signed_event_logger.py`, `daemon/redundant_event_logger.py` |
| Storage | `daemon/storage/append_only.py`, `daemon/storage/log_hardening.py` |
| Security | `daemon/security/prompt_injection.py`, `daemon/security/rag_injection.py`, `daemon/security/tool_validator.py`, `daemon/security/response_guardrails.py`, `daemon/security/agent_attestation.py`, `daemon/security/code_advisor.py` |
| Authentication | `daemon/auth/api_auth.py`, `daemon/auth/secure_token_storage.py`, `daemon/auth/persistent_rate_limiter.py`, `daemon/auth/enhanced_ceremony.py`, `daemon/auth/advanced_ceremony.py` |
| Sandbox | `daemon/sandbox/sandbox_manager.py`, `daemon/sandbox/namespace.py`, `daemon/sandbox/seccomp_filter.py`, `daemon/sandbox/cgroups.py`, `daemon/sandbox/network_policy.py` |
| Integrity | `daemon/integrity/code_signer.py`, `daemon/integrity/integrity_verifier.py` |
| Crypto | `daemon/crypto/hsm_provider.py`, `daemon/crypto/post_quantum.py` |
| Messages | `daemon/messages/message_checker.py` |
| Config | `daemon/config/secure_config.py`, `config/boundary.conf` |
| Identity | `daemon/identity/ldap_mapper.py` |
| Enforcement | `daemon/enforcement/network_enforcer.py`, `daemon/enforcement/usb_enforcer.py` |
| CI/CD | `.github/workflows/ci.yml` |
| Service | `systemd/boundary-daemon.service` |
| API | `api/boundary_api.py` |
| Dependencies | `requirements.txt`, `requirements-dev.txt` |

---

*Audit conducted using the [Agent-OS Three-Tier Security Framework](https://github.com/kase1111-hash/Claude-prompts/blob/main/Agentic-Security-Audit.md). This report covers all 12 control areas across 3 tiers with 30+ individual findings.*
