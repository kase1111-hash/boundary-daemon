# Dependency Audit Report — Boundary Daemon

**Date:** 2026-03-12
**Auditor:** Automated dependency review
**Project:** boundary-daemon v1.0.0-beta1
**Python:** 3.9–3.13

---

## Summary

| Metric | Before | After |
|---|---|---|
| Direct dependencies (runtime) | 6 | 5 |
| Direct dependencies (dev) | 8 | 8 |
| Removed | — | 1 (cffi) |
| Consolidated | — | 0 |
| Replaced | — | 0 |

**One dependency removed** (`cffi`) — it was explicitly pinned in `requirements.txt` but is a transitive dependency of `pynacl`, automatically installed by pip. No code in the project imports `cffi` directly. All other runtime dependencies are actively used and justified.

---

## Dependency Inventory — Runtime (`requirements.txt`)

| Dependency | Version | Classification | Usage Intensity | Files | Action |
|---|---|---|---|---|---|
| **psutil** | 5.9.8 | ESSENTIAL | Pervasive | 12+ files, 26+ import sites | Keep |
| **cffi** | 1.17.1 | DEAD (transitive) | None (0 imports) | 0 Python files | **Removed** |
| **pynacl** | 1.5.0 | ESSENTIAL | Heavy | 14 files | Keep (upgrade recommended) |
| **cryptography** | 44.0.0 | ESSENTIAL | Heavy | 6 files | Keep (upgrade recommended) |
| **yara-python** | 4.5.1 | ESSENTIAL | Moderate | 1 core module + consumers | Keep |
| **PyYAML** | 6.0.2 | JUSTIFIED | Moderate | 6 files | Keep |

## Dependency Inventory — Dev (`requirements-dev.txt`)

| Dependency | Version | Classification | Action |
|---|---|---|---|
| **pytest** | 8.3.4 | ESSENTIAL | Keep |
| **pytest-cov** | 6.0.0 | JUSTIFIED | Keep |
| **pytest-timeout** | 2.3.1 | JUSTIFIED | Keep |
| **pytest-asyncio** | 0.24.0 | JUSTIFIED | Keep |
| **coverage** | 7.6.10 | JUSTIFIED | Keep |
| **mypy** | 1.14.1 | JUSTIFIED | Keep |
| **ruff** | 0.8.6 | JUSTIFIED | Keep |
| **hypothesis** | 6.122.3 | JUSTIFIED | Keep |

---

## Changes Made

### 1. Removed: `cffi==1.17.1`

- **Classification:** DEAD (transitive dependency)
- **Reason:** `cffi` is not imported in any Python source file. It is a build/runtime dependency of `pynacl` (which uses `cffi` internally via its C bindings to libsodium). Pip installs it automatically as a transitive dependency when `pynacl` is installed.
- **References in codebase:** Only found in build scripts (`build.py`, `build.sh`, `build.bat`) as PyInstaller `--hidden-import` directives, which is correct — PyInstaller needs the hint, but `requirements.txt` does not need to pin it.
- **File modified:** `requirements.txt` — removed `cffi==1.17.1`
- **Risk level:** NONE — `cffi` will still be installed as a transitive dependency of `pynacl`

---

## Detailed Analysis of Kept Dependencies

### psutil==5.9.8 — ESSENTIAL

**Purpose:** Cross-platform system and process monitoring.

**Usage:** Pervasive across the codebase (12+ files, 26+ import sites):
- `daemon/state_monitor.py` — network interfaces, disk partitions, process enumeration, logged-in users
- `daemon/memory_monitor.py` — process memory tracking
- `daemon/resource_monitor.py` — process FDs, open files, connections, disk usage
- `daemon/boundary_daemon.py` — RSS memory monitoring
- `daemon/enforcement/secure_process_termination.py` — process enumeration and termination
- `daemon/enforcement/process_enforcer.py` — process iteration
- `daemon/api/health.py` — system health metrics (CPU, memory, disk)
- `daemon/security/process_security.py` — process inspection
- `daemon/security/traffic_anomaly.py` — network I/O counters
- `daemon/security/wifi_security.py` — process scanning
- `daemon/tui/client.py` — daemon discovery via process/port scanning
- `boundary-antivirus/boundary_antivirus/scanner.py` — process management
- `boundary-tui/boundary_tui/client.py` — daemon discovery

**Why essential:** There is no stdlib alternative for cross-platform process enumeration, network connection listing, disk usage monitoring, or memory introspection. This functionality is core to a security daemon.

### pynacl==1.5.0 — ESSENTIAL

**Purpose:** Python binding to libsodium for Ed25519 signatures, key management, and secret-box encryption.

**Usage:** Heavy across 14 files:
- `daemon/signed_event_logger.py` — cryptographic event signing (core feature)
- `daemon/compliance/zk_proofs.py` — zero-knowledge proof signing
- `daemon/compliance/evidence_bundle.py` — evidence bundle signing
- `daemon/integrity/code_signer.py` — code signing and verification
- `daemon/integrity/integrity_verifier.py` — integrity verification
- `daemon/storage/forensic_audit.py` — forensic audit chain signing
- `daemon/detection/ioc_feeds.py` — IOC feed signature verification
- `daemon/external_integrations/siem/verification_api.py` — SIEM signature verification

**Why essential:** Ed25519 signatures are fundamental to the trust enforcement model. `pynacl` (libsodium) is the standard library for this. No stdlib alternative exists.

### cryptography==44.0.0 — ESSENTIAL

**Purpose:** Fernet symmetric encryption, PBKDF2 key derivation, AES-GCM, PEM key loading.

**Usage:** Heavy across 5 active files:
- `daemon/config/secure_config.py` — configuration encryption/decryption (Fernet + PBKDF2)
- `daemon/auth/secure_token_storage.py` — token encryption (Fernet + PBKDF2)
- `daemon/hardware/tpm_manager.py` — AES-GCM encryption for TPM sealed data
- `daemon/storage/append_only.py` — PEM key loading for append-only log signing
- `daemon/security/secure_memory.py` — memory encryption (Fernet)

**Why essential:** Handles real cryptographic complexity (symmetric encryption, key derivation, authenticated encryption). No stdlib alternative. Well-maintained, industry-standard library.

### yara-python==4.5.1 — ESSENTIAL

**Purpose:** YARA rule compilation and scanning for threat detection.

**Usage:** Concentrated in `daemon/detection/yara_engine.py`:
- Rule compilation (`yara.compile`)
- Pattern scanning against data
- Timeout-protected scanning
- Consumed by `daemon/detection/event_publisher.py` and exported via `daemon/detection/__init__.py`

**Why essential:** YARA is the industry standard for malware pattern matching. The detection engine is a core feature of the daemon. No alternative provides equivalent functionality.

### PyYAML==6.0.2 — JUSTIFIED

**Purpose:** YAML parsing and serialization for configuration, policies, and Sigma rules.

**Usage:** Moderate across 6 files:
- `daemon/detection/sigma_engine.py` — Sigma rule loading
- `daemon/policy/custom_policy_engine.py` — custom policy file loading
- `daemon/config/secure_config.py` — YAML config load/save
- `daemon/sandbox/profile_config.py` — sandbox profile configuration
- `daemon/boundary_daemon.py` — config loading
- `tests/test_parametrized_modules.py` — test config round-trip

**Security note:** All YAML operations use `yaml.safe_load()` — no unsafe `yaml.load()` calls found. This is the correct defensive pattern.

**Why justified:** YAML is the standard format for security policies and Sigma detection rules. While JSON could theoretically replace it, YAML is the expected format for these use cases and all imports are defensive (try/except with graceful fallback).

---

## Health Warnings

### CRITICAL: pynacl 1.5.0 — CVE-2025-69277 (Medium, CVSS 4.5)

- **Issue:** libsodium (bundled in pynacl wheels) before a specific commit mishandles `crypto_core_ed25519_is_valid_point` validation, potentially allowing invalid elliptic curve points.
- **Impact:** Local attack vector; some loss of confidentiality possible under specific conditions.
- **Fix:** Upgrade to **pynacl>=1.6.2** (released 2026-01-01, bundles libsodium 1.0.20-stable).
- **Note:** pynacl 1.6.x dropped Python 3.6/3.7 support, which is compatible with this project's >=3.9 requirement.

### HIGH PRIORITY: cryptography 44.0.0 — CVE-2024-12797 (Medium, CVSS 6.3)

- **Issue:** Bundled OpenSSL vulnerable to RFC7250 Raw Public Key authentication bypass (man-in-the-middle).
- **Impact:** Network attack vector, low complexity. Affects TLS connections when RPK is enabled.
- **Fix:** Upgrade to **cryptography>=44.0.1** (patch), ideally **>=46.0.5** (latest, released 2026-02-10).

### LOW: psutil 5.9.8 — Outdated (latest is 7.2.2)

- **Issue:** No known CVEs, but 5.9.8 is significantly behind the latest release (7.2.2, 2026-01-28).
- **Benefits of upgrading:** Performance improvements (`pidfd_open` on Linux, `kqueue` on macOS/BSD), memory leak fixes on macOS, better error handling.
- **Risk:** Major version jump (5.x → 7.x) may have breaking changes. Test thoroughly before upgrading.

### INFO: yara-python 4.5.1 — Current

- No known CVEs. Latest version on PyPI. Maintenance is noted as lower activity but version is current.

### INFO: PyYAML 6.0.2 — Current

- No direct CVEs in the library itself. All usage in this codebase correctly uses `safe_load()`.

---

## Kept With Reservations

| Dependency | Concern | Recommendation |
|---|---|---|
| **pynacl** 1.5.0 | CVE-2025-69277 in bundled libsodium | Upgrade to >=1.6.2 |
| **cryptography** 44.0.0 | CVE-2024-12797 in bundled OpenSSL | Upgrade to >=44.0.1 (patch) or >=46.0.5 (latest) |
| **psutil** 5.9.8 | Significantly outdated (latest 7.2.2) | Upgrade after testing for breaking changes |

---

## Dependency Graph Notes

- **Total direct runtime dependencies:** 5 (after removing cffi)
- **Transitive dependencies pulled in:**
  - `pynacl` → `cffi` → `pycparser` (cffi still installed, just not pinned explicitly)
  - `cryptography` → `cffi` → `pycparser`
  - Other deps are mostly self-contained or stdlib-only
- **Heaviest sub-tree:** `cryptography` (pulls in cffi + pycparser and bundles OpenSSL)
- **No circular or redundant dependency chains** detected
- **No overlapping functionality** between dependencies — each serves a distinct purpose

---

## Final Status

**LEANER** — One dead dependency (`cffi`) removed from explicit pinning. The remaining 5 runtime dependencies are all actively used, well-justified, and serve distinct non-overlapping purposes. The dependency set is minimal for a security daemon of this scope. Two dependencies have known CVEs requiring version upgrades.
