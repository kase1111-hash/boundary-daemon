# Agentic Security Audit v3.0 — Boundary Daemon

```
AUDIT METADATA
  Project:       boundary-daemon (Agent Smith)
  Date:          2026-03-10
  Auditor:       Claude Opus 4.6 (automated analysis)
  Commit:        fbf74b3ec073207fd4002769ef8039a7be35a5a2
  Strictness:    STANDARD
  Context:       PROTOTYPE

PROVENANCE ASSESSMENT
  Vibe-Code Confidence:   85%
  Human Review Evidence:  MINIMAL

LAYER VERDICTS
  L1 Provenance:       WARN
  L2 Credentials:      PASS
  L3 Agent Boundaries: PASS
  L4 Supply Chain:     WARN
  L5 Infrastructure:   FAIL
```

---

## L1: PROVENANCE & TRUST ORIGIN

### 1.1 Vibe-Code Detection

- [x] **No tests**: Tests exist (19,570 LOC across 25+ test files) — **CLEARED**
- [ ] **No security config**: Extensive security config present — **CLEARED**
- [x] **AI boilerplate**: Formulaic commit messages ("Phase N: Add X, Fix Y across N files"), uniform formatting, `SECURITY (Audit X.Y.Z):` comments that read like audit-response patterns
- [x] **Rapid commit history**: 142 commits over ~6 weeks (Jan 8 – Feb 22, 2026). 162,242 LOC of Python. 92/142 commits (65%) authored by "Claude", 44 by human, 6 by human alias
- [x] **Polished README, hollow codebase**: Extensive documentation (35+ markdown files, ARCHITECTURE.md, SECURITY.md, USER_GUIDE.md, ROADMAP.md). Many enforcement modules contain `pass`-only stubs (archived but still present)
- [x] **Bloated deps**: Only 6 production dependencies — **CLEARED** (lean)

**Severity:** WARN — The codebase is predominantly AI-generated (65% Claude-authored commits) with iterative AI-driven remediation phases. Core modules show genuine depth but peripheral modules are stubs. Previous vibe-check (v2.0, 2026-02-22) scored 51.9% vibe-code confidence.

### 1.2 Human Review Evidence

- [x] Security-focused commits exist (18-step security audit remediation, phased vibe-check remediation)
- [x] Security tooling in CI/CD: bandit, safety, detect-secrets, ruff, mypy
- [x] `.gitignore` excludes `.env`, credentials, key files, `*.pem`, `*.key`
- [ ] No threat model docs beyond SECURITY.md API threat model section
- [ ] No evidence of manual penetration testing

### 1.3 The "Tech Preview" Trap

- [ ] Production traffic: No — project is labeled "1.0.0b1" (beta)
- [ ] Real credentials: No real credentials found in codebase
- [x] Beta label used: `setup.py` declares `Development Status :: 4 - Beta`

**L1 Verdict: WARN** — Extensive AI generation with security-focused remediation iterations. Human review evidence is MINIMAL (merge approvals but no human-authored security commits). The iterative remediation phases themselves were AI-driven responses to AI-generated audit findings.

---

## L2: CREDENTIAL & SECRET HYGIENE

### 2.1 Secret Storage

- [x] No plaintext credentials in source — **PASS**
- [x] No API keys in client-side code — **PASS**
- [x] `.gitignore` blocks: `config/.token_salt`, `config/.config_salt`, `config/api_tokens.json`, `config/bootstrap_token.enc`, `config/*.enc`, `config/signing.key`, `*.pem`, `*.key`
- [x] Pre-commit hook scans for 20+ secret patterns (AWS keys, GCP creds, GitHub tokens, etc.)
- [x] CI pipeline runs `detect-secrets scan` — **PASS**
- [ ] No `.env` files committed — **PASS**

### 2.2 Credential Scoping & Lifecycle

- [x] Capability-based API token scoping (`APICapability` enum: readonly, operator, admin sets) — `daemon/auth/api_auth.py:56-71`
- [x] Token expiration support (configurable `expires_in_days`) — `daemon/auth/api_auth.py:572`
- [x] Bootstrap token expires after 24 hours — `daemon/auth/api_auth.py:467`
- [x] Per-token and per-command rate limiting with persistence — `daemon/auth/persistent_rate_limiter.py`

### 2.3 Machine Credential Exposure

- [x] Environment variable token loading DEPRECATED (Vuln #5 fix) — `daemon/auth/secure_token_storage.py:577-612`
- [x] File-based secrets with strict 0o600 permission checks — `daemon/boundary_daemon.py:1764-1800`
- [x] Token encryption via Fernet (AES-128-CBC + HMAC-SHA256) — `daemon/config/secure_config.py`
- [x] PBKDF2 key derivation with 480,000 iterations — `daemon/auth/secure_token_storage.py`
- [x] Memory zeroing for encryption keys — `daemon/config/secure_config.py:900-943`
- [x] Tokens truncated in logs (`token[:20]...`) — `daemon/auth/api_auth.py:1247`

**L2 Verdict: PASS** — Credential hygiene is strong. No real secrets in codebase. Encryption at rest with proper key derivation. Pre-commit and CI scanning. Token scoping and expiration implemented.

---

## L3: AGENT BOUNDARY ENFORCEMENT

### 3.1 Agent Permission Model

- [x] Default permissions: **DENY** — Seccomp default action is `DENY` (`daemon/sandbox/seccomp_filter.py:84,315`), RAG documents with UNKNOWN provenance are BLOCKED (`daemon/security/rag_injection.py:378-396`)
- [x] Privilege escalation mitigated:
  - Chain depth capped at 3 (`daemon/security/agent_attestation.py:244-245`)
  - `AGENT_DELEGATE` cannot be delegated without human ceremony approval (`agent_attestation.py:472-479`)
  - Child capabilities must be subset of parent (`agent_attestation.py:967`)
- [x] File system, network, and command execution boundaries defined per sandbox profile (`daemon/sandbox/sandbox_manager.py:87-232`)
- [x] Least-privilege enforcement via mode-specific capability filtering (`agent_attestation.py:386-388`)
- [x] Human-in-the-loop gates via ceremony system (`daemon/auth/advanced_ceremony.py:122-200`):
  - EMERGENCY_ACCESS: biometric + hardware token
  - LOCKDOWN_RELEASE: N-of-M (2 of 3) approval
  - DATA_EXPORT: business hours only, biometric required

### 3.2 Prompt Injection Defense

- [x] 8 injection attack types detected: jailbreak, instruction injection, context manipulation, prompt extraction, delimiter injection, encoding bypass, roleplay bypass, authority escalation — `daemon/security/prompt_injection.py:41-48`
- [x] Semantic analysis for DAN-style attacks, "ignore instructions" patterns
- [x] Base64/encoding detection, zero-width character detection
- [ ] Multi-modal injection (images, PDFs): Not addressed — N/A for daemon context (no multi-modal input processing)

### 3.3 Memory Poisoning

- [x] Document provenance tracking with trust levels (VERIFIED/TRUSTED/UNKNOWN/SUSPICIOUS/BLOCKED) — `daemon/security/rag_injection.py:46-52`
- [x] Unknown-source documents quarantined, not silently passed — `rag_injection.py:345-346`
- [x] Cross-document coordinated injection detection — `rag_injection.py:541-581`
- [x] Risk scoring with configurable thresholds — `rag_injection.py:349-371`

### 3.4 Agent-to-Agent Trust

- [x] Replay detection with 2-hour nonce window — `agent_attestation.py:304-308, 636-651`
- [x] Delegation depth limits and capability subsetting — `agent_attestation.py:451-485`
- [x] Mode-based capability restrictions at registration and token issuance

**L3 Verdict: PASS** — Comprehensive agent boundary enforcement with deny-by-default architecture, ceremony-gated critical operations, and multi-layer injection defenses.

---

## L4: SUPPLY CHAIN & DEPENDENCY TRUST

### 4.1 Plugin/Skill Supply Chain

- [ ] N/A — no plugin/skill marketplace

### 4.2 MCP Server Trust

- [ ] N/A — no MCP server integration

### 4.3 Dependency Audit

- [x] Production dependencies pinned to exact versions — `requirements.txt` (6 deps: psutil==5.9.8, cffi==1.17.1, pynacl==1.5.0, cryptography==44.0.0, yara-python==4.5.1, PyYAML==6.0.2)
- [ ] Dev dependencies use floating ranges (`>=`) — `requirements-dev.txt` (pytest>=7.0.0, etc.)
- [x] CI runs `safety check` for known vulnerabilities — `.github/workflows/ci.yml:74-75`
- [x] Minimal attack surface: only 6 production dependencies

```
[MEDIUM] — Dev dependency versions not pinned
Layer:     4
Location:  requirements-dev.txt:7-20
Evidence:  pytest>=7.0.0, pytest-cov>=4.0.0, mypy>=1.0.0, ruff>=0.1.0, hypothesis>=6.0.0
Risk:      Supply chain attack via compromised dev dependency update
Fix:       Pin dev dependencies to exact versions (e.g., pytest==8.3.4)
```

```
[MEDIUM] — GitHub Actions not pinned to commit SHAs
Layer:     4
Location:  .github/workflows/ci.yml:17,20,44; .github/workflows/publish.yml:11,14,30,75,94
Evidence:  actions/checkout@v4, actions/setup-python@v5, codecov/codecov-action@v4, pypa/gh-action-pypi-publish@release/v1
Risk:      Action hijacking via tag mutation or compromised action repository
Fix:       Pin to full commit SHAs (e.g., actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11)
```

**L4 Verdict: WARN** — Production deps properly pinned. Dev deps and CI actions use floating versions, creating supply chain risk.

---

## L5: INFRASTRUCTURE & RUNTIME

### 5.1 Database Security

- [ ] N/A — no external database; uses local file-based storage with append-only logs

### 5.2 BaaS Configuration

- [ ] N/A — no BaaS integration

### 5.3 Network & Hosting

```
[CRITICAL] — Unauthenticated POST /keys endpoint accepts arbitrary public keys
Layer:     5
Location:  daemon/external_integrations/siem/verification_api.py:496
Evidence:  TODO comment: "POST /keys should require authentication — currently unauthenticated"
Risk:      Attacker injects public keys to forge event signatures, bypassing audit log integrity
Fix:       Require API token authentication on POST /keys; validate key format and provenance
```

```
[CRITICAL] — Remote event logger transmits logs in plaintext (no TLS)
Layer:     5
Location:  daemon/redundant_event_logger.py:379
Evidence:  TODO comment: "RemoteBackend does not support TLS — all remote log traffic is sent in plaintext"
Risk:      Network eavesdropping on event logs containing security decisions, policy violations, PII
Fix:       Implement TLS for TCP backend and DTLS for UDP backend; reject plaintext connections in production
```

```
[HIGH] — Health check endpoint binds to 0.0.0.0 without authentication
Layer:     5
Location:  daemon/api/health.py:459-462
Evidence:  Default host="0.0.0.0", no auth on GET /health, /ready, /live
Risk:      Information disclosure: daemon status, uptime, memory/disk usage, component health exposed to network
Fix:       Default to 127.0.0.1 binding; add optional auth token for remote access; strip sensitive details from unauthenticated responses
```

```
[HIGH] — Prometheus metrics endpoint binds to 0.0.0.0 without authentication
Layer:     5
Location:  daemon/telemetry/prometheus_metrics.py
Evidence:  Default host="0.0.0.0" for metrics server
Risk:      Sensitive metrics (request counts, rate limits, memory usage) exposed to all network interfaces
Fix:       Default to 127.0.0.1; require auth token or restrict to Prometheus scraper IPs
```

```
[HIGH] — Hash chain verification uses 16-char prefix instead of full comparison
Layer:     5
Location:  daemon/external_integrations/siem/verification_api.py:247-250
Evidence:  FIXME comment: "hash chain verification uses partial match (16 chars) — should do full comparison"
Risk:      Reduced collision resistance; crafted hash collisions feasible with 64-bit prefix matching
Fix:       Use full SHA-256 comparison; remove partial-match fallback
```

```
[HIGH] — Cluster secret rotation not implemented
Layer:     5
Location:  daemon/distributed/cluster_manager.py:64
Evidence:  TODO comment: "cluster secret rotation not implemented — manual rotation only"
Risk:      Compromised cluster secrets persist indefinitely; no automated recovery
Fix:       Implement periodic key rotation with graceful dual-key transition period
```

```
[MEDIUM] — SIEM ingestion does not enforce HTTPS
Layer:     5
Location:  integrations/boundary-siem/src/boundary_ingestion.py:367-380
Evidence:  urllib.request.urlopen without scheme validation
Risk:      Events sent in plaintext if configured with http:// endpoint
Fix:       Validate URL scheme is https:// before transmission; reject http:// in production config
```

```
[MEDIUM] — GET /keys endpoint lists all trusted public keys without authentication
Layer:     5
Location:  daemon/external_integrations/siem/verification_api.py:431-436
Evidence:  do_GET returns all trusted keys without auth
Risk:      Information disclosure of trust anchors enables targeted attacks
Fix:       Require read authentication or remove public key listing endpoint
```

### 5.4 Deployment Pipeline

- [x] CI/CD runs linter (ruff), type checker (mypy), tests with coverage (60% minimum), bandit, safety, detect-secrets
- [ ] GitHub Actions use version tags, not pinned SHAs (see L4)
- [ ] No dev/staging/prod environment isolation documented
- [x] Docker image exists for integration tests (`tests/integration/Dockerfile`)

### 5.5 Regulatory Compliance

- [ ] No explicit GDPR/HIPAA/PCI-DSS compliance documentation
- [ ] PII detection engine exists (`daemon/pii/detector.py`) but no data processing agreements
- [ ] No EU Cyber Resilience Act assessment

**L5 Verdict: FAIL** — Two CRITICAL findings (unauthenticated key injection, plaintext remote logging) and four HIGH findings (exposed health/metrics endpoints, weak hash verification, no cluster key rotation).

---

## FINDING SUMMARY

| # | Severity | Title | Layer | Location |
|---|----------|-------|-------|----------|
| 1 | CRITICAL | Unauthenticated POST /keys accepts arbitrary public keys | L5 | verification_api.py:496 |
| 2 | CRITICAL | Remote event logger has no TLS — plaintext log transmission | L5 | redundant_event_logger.py:379 |
| 3 | HIGH | Health endpoint binds 0.0.0.0 without auth | L5 | health.py:459-462 |
| 4 | HIGH | Prometheus metrics binds 0.0.0.0 without auth | L5 | prometheus_metrics.py |
| 5 | HIGH | Hash chain verification uses 16-char prefix match | L5 | verification_api.py:247-250 |
| 6 | HIGH | No cluster secret rotation | L5 | cluster_manager.py:64 |
| 7 | MEDIUM | SIEM ingestion doesn't enforce HTTPS | L5 | boundary_ingestion.py:367-380 |
| 8 | MEDIUM | GET /keys exposes trust anchors without auth | L5 | verification_api.py:431-436 |
| 9 | MEDIUM | Dev dependencies use floating version ranges | L4 | requirements-dev.txt |
| 10 | MEDIUM | GitHub Actions not pinned to commit SHAs | L4 | ci.yml, publish.yml |

---

## POSITIVE FINDINGS

The following represent genuine security engineering depth:

1. **Deny-by-default architecture** — Seccomp filters, RAG document trust, and tool validation all default to DENY/BLOCK
2. **Capability-based access control** — Fine-grained 18-capability agent attestation with delegation depth limits (max 3)
3. **Human ceremony gates** — Critical operations (lockdown release, key rotation, data export) require biometric + hardware token + time-window constraints
4. **Credential encryption at rest** — Fernet (AES-128-CBC + HMAC) with PBKDF2-480K iterations and machine-derived keys
5. **Fail-closed sandbox enforcement** — Processes killed if cgroup enforcement fails; sandbox profiles can only be tightened, never loosened
6. **Comprehensive CI security tooling** — bandit, safety, detect-secrets, ruff, mypy in automated pipeline
7. **Pre-commit secret scanning** — 20+ patterns for credential types (AWS, GCP, GitHub, Stripe, etc.)
8. **Thread-safe core modules** — PolicyEngine, TripwireSystem, EventLogger use proper locking with documented lock ordering hierarchy
9. **Hash-chained audit logs** — Tamper-evident event logging with optional cryptographic signing
10. **Prompt injection defense** — 8-category detection with encoding bypass and zero-width character awareness

---

## RECOMMENDATIONS (Priority Order)

1. **STOP: Fix CRITICALs before any production use**
   - Add authentication to POST /keys endpoint
   - Implement TLS for RemoteBackend (TCP+TLS, UDP+DTLS)

2. **Fix within 24h:**
   - Change health/metrics default binding from `0.0.0.0` to `127.0.0.1`
   - Fix hash chain verification to use full SHA-256 comparison
   - Implement cluster secret rotation

3. **Fix within 1 week:**
   - Pin GitHub Actions to commit SHAs
   - Pin dev dependencies to exact versions
   - Add HTTPS enforcement to SIEM ingestion
   - Add auth to GET /keys endpoint

4. **When convenient:**
   - Add regulatory compliance documentation
   - Security-harden Docker image (distroless/alpine)
   - Add automated penetration testing to CI
   - Document dev/staging/prod environment isolation

---

*Audit conducted per [Agentic Security Audit v3.0](https://github.com/kase1111-hash/Claude-prompts/blob/main/vibe-check.md) framework, aligned with OWASP Top 10 for Agentic Applications (2026).*
