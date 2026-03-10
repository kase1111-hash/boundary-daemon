# Remediation Plan — Boundary Daemon Security Audit v3.0

**Source:** `SECURITY_AUDIT_V3.md` (2026-03-10)
**Tracking:** 10 findings across L4 (Supply Chain) and L5 (Infrastructure)

---

## Phase 1: CRITICAL — Block Production Use (Findings #1, #2)

### 1.1 Authenticate POST /keys endpoint
**Finding:** #1 — Unauthenticated POST /keys accepts arbitrary public keys
**File:** `daemon/external_integrations/siem/verification_api.py:496`
**Risk:** Attacker injects public keys to forge event signatures

**Changes:**
1. In the `do_POST` handler for `/keys`, extract and validate an API token from the `Authorization` header before processing
2. Reuse the existing `APIAuthManager` token validation from `daemon/auth/api_auth.py`
3. Require the `admin` capability set for key registration
4. Return 401 if no token, 403 if insufficient capabilities
5. Remove the TODO comment

**Tests:**
- Unit test: POST /keys without token → 401
- Unit test: POST /keys with read-only token → 403
- Unit test: POST /keys with admin token → 200 (existing behavior)

### 1.2 Add TLS to RemoteBackend
**Finding:** #2 — Remote event logger transmits logs in plaintext
**File:** `daemon/redundant_event_logger.py:379`
**Risk:** Network eavesdropping on security event logs

**Changes:**
1. Add `tls_enabled`, `tls_certfile`, `tls_keyfile`, and `tls_ca_bundle` parameters to `RemoteBackend.__init__`
2. For TCP transport: wrap the socket with `ssl.SSLContext` (TLSv1.2+ minimum, `PROTOCOL_TLS_CLIENT`)
3. For UDP transport: encrypt payloads with a pre-shared symmetric key (full DTLS is impractical in stdlib); document this limitation and recommend TCP+TLS for production
4. Default `tls_enabled=True` — require explicit `tls_enabled=False` to send plaintext, and log a WARNING when plaintext is used
5. Remove the TODO comment

**Tests:**
- Unit test: RemoteBackend refuses connection without TLS by default
- Unit test: TCP backend wraps socket with SSL context
- Unit test: Plaintext mode logs a warning

---

## Phase 2: HIGH — Fix Within 24h (Findings #3, #4, #5, #6)

### 2.1 Default health endpoint to localhost
**Finding:** #3 — Health endpoint binds to 0.0.0.0 without auth
**File:** `daemon/api/health.py:459-462`

**Changes:**
1. Change default `host` parameter from `"0.0.0.0"` to `"127.0.0.1"`
2. Remove the `# nosec B104` suppression comment (no longer needed)
3. Remove the TODO comment

### 2.2 Default Prometheus metrics to localhost
**Finding:** #4 — Prometheus metrics binds to 0.0.0.0 without auth
**File:** `daemon/telemetry/prometheus_metrics.py:422`

**Changes:**
1. Change default `host` parameter from `"0.0.0.0"` to `"127.0.0.1"`
2. Update any related `# nosec` comments

### 2.3 Full hash chain comparison
**Finding:** #5 — Hash chain verification uses 16-char prefix
**File:** `daemon/external_integrations/siem/verification_api.py:247-250`

**Changes:**
1. Replace `current_hash.startswith(expected_hash[:16])` with `hmac.compare_digest(current_hash, expected_hash)` for constant-time full comparison
2. Remove the partial-match fallback `pass` block
3. Remove the FIXME comment

**Tests:**
- Unit test: Matching full hashes → verification passes
- Unit test: Hashes that share 16-char prefix but differ → verification fails

### 2.4 Implement cluster secret rotation
**Finding:** #6 — No cluster secret rotation
**File:** `daemon/distributed/cluster_manager.py:64`

**Changes:**
1. Add a `rotate_secret(new_secret)` method to `ClusterManager`
2. During rotation, accept both old and new secrets for a configurable grace period (default: 300 seconds) to allow cluster-wide propagation
3. After the grace period, drop the old secret
4. Log rotation events to the audit log
5. Add a `secret_max_age_days` configuration (default: 30) with a warning logged when the secret exceeds this age
6. Remove the TODO comment

**Tests:**
- Unit test: `rotate_secret` installs new secret
- Unit test: During grace period, both old and new secrets are accepted
- Unit test: After grace period, old secret is rejected
- Unit test: Warning logged when secret exceeds max age

---

## Phase 3: MEDIUM — Fix Within 1 Week (Findings #7, #8, #9, #10)

### 3.1 Enforce HTTPS in SIEM ingestion
**Finding:** #7 — SIEM ingestion doesn't enforce HTTPS
**File:** `integrations/boundary-siem/src/boundary_ingestion.py:367-380`

**Changes:**
1. Before calling `urllib.request.urlopen`, validate that `self.http_endpoint` starts with `https://`
2. If `http://` is used, raise `ValueError("SIEM ingestion requires HTTPS. Use https:// endpoint.")`
3. Ensure `ssl` certificate verification is not disabled (no `context = ssl._create_unverified_context()`)

### 3.2 Authenticate GET /keys endpoint
**Finding:** #8 — GET /keys exposes trust anchors without auth
**File:** `daemon/external_integrations/siem/verification_api.py:431-436`

**Changes:**
1. In the `do_GET` handler for `/keys`, require a valid API token with at least `readonly` capability
2. Return 401 if no token provided

### 3.3 Pin dev dependencies
**Finding:** #9 — Dev dependencies use floating version ranges
**File:** `requirements-dev.txt`

**Changes:**
1. Replace `>=` ranges with exact pins:
   ```
   pytest==8.3.4
   pytest-cov==6.0.0
   pytest-timeout==2.3.1
   pytest-asyncio==0.24.0
   coverage==7.6.10
   mypy==1.14.1
   ruff==0.8.6
   hypothesis==6.122.3
   bandit==1.8.3
   safety==3.2.14
   detect-secrets==1.5.0
   ```
2. Verify all pinned versions are compatible by running the test suite

### 3.4 Pin GitHub Actions to commit SHAs
**Finding:** #10 — GitHub Actions not pinned to commit SHAs
**Files:** `.github/workflows/ci.yml`, `.github/workflows/publish.yml`

**Changes:**
1. Replace version tags with full commit SHAs. For each action, look up the commit SHA for the currently-used version tag:
   ```yaml
   # Example format (SHAs to be resolved at implementation time):
   - uses: actions/checkout@<sha>       # v4.x.x
   - uses: actions/setup-python@<sha>   # v5.x.x
   - uses: codecov/codecov-action@<sha> # v4.x.x
   - uses: actions/upload-artifact@<sha>   # v4.x.x
   - uses: actions/download-artifact@<sha> # v4.x.x
   - uses: pypa/gh-action-pypi-publish@<sha> # release/v1.x.x
   ```
2. Add a comment next to each SHA noting the human-readable version for maintainability

---

## Phase 4: Hardening — When Convenient

These are not findings from the audit but recommended improvements noted in the report:

1. Add regulatory compliance documentation (GDPR, HIPAA applicability assessment)
2. Harden Docker test image (switch from full base to alpine/distroless)
3. Add automated penetration testing to CI (e.g., OWASP ZAP for API endpoints)
4. Document dev/staging/prod environment isolation strategy

---

## Implementation Order

```
Phase 1 (CRITICAL)
  ├── 1.1  POST /keys auth          ← do first, highest risk
  └── 1.2  RemoteBackend TLS        ← most complex change

Phase 2 (HIGH)
  ├── 2.1  Health → 127.0.0.1       ← one-line fix
  ├── 2.2  Metrics → 127.0.0.1      ← one-line fix
  ├── 2.3  Full hash comparison      ← small fix
  └── 2.4  Cluster secret rotation   ← moderate complexity

Phase 3 (MEDIUM)
  ├── 3.1  SIEM HTTPS enforcement    ← small fix
  ├── 3.2  GET /keys auth            ← small fix (pairs with 1.1)
  ├── 3.3  Pin dev deps              ← version research needed
  └── 3.4  Pin GH Actions SHAs       ← SHA lookup needed
```

**Estimated total: 10 changes across 8 files, 4 new test files/sections.**
