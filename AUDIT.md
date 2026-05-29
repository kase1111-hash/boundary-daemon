# Boundary Daemon — Audit Report

**Date:** 2026-05-29
**Scope:** Read-only audit, no code changes.
**Verdict:** *Real core buried under heavy AI-generated sprawl.*

> Method: five parallel area auditors (daemon core, CLI/build, docs, tests/API/integrations,
> archive/exotic modules) plus direct spot-checks and a partial test run. Findings below cite
> `file:line` where it matters.

---

## Bottom line

This is **not** a fake "print-success" project. There is a genuinely functional security
daemon at the center — real kernel-level enforcement, real crypto, dense passing tests. But it
is wrapped in **3–4× more code and docs than the idea warrants**: dead "archive" modules,
fictional features, duplicated subsystems, and ~10 overlapping self-referential audit
documents. The cleanup target is the sprawl, not the core. The over-the-top TUI is a deliberate
Easter egg and a **keep**.

By the numbers: ~176k LOC Python / 263 files · 47 markdown docs · 1,679 tests collected ·
963/964 core tests pass · 15 audit/review cycles in git history.

---

## What's genuinely REAL (keep)

- **Enforcement core** — actually shells out to the kernel, root-gated, fail-closed:
  - `daemon/enforcement/network_enforcer.py` → real `iptables`/`nft` rules per mode
  - `daemon/sandbox/seccomp_filter.py` → real BPF syscall filter via `prctl`
  - `daemon/sandbox/cgroups.py` → writes real cgroup v2 controllers
  - `daemon/enforcement/usb_enforcer.py` → real udev rules + sysfs de-authorization
  - `daemon/ebpf/ebpf_observer.py` → real BCC programs with a `/proc` fallback
  - `daemon/hardware/tpm_manager.py` → real tpm2-tools/swtpm
  - Wired into the daemon on mode-change (`boundary_daemon.py:1599`) and startup
    (`:2195`), gated by `privilege_manager`.
- **Crypto / integrity / detection** — real NaCl-signed hash-chained logs, YARA + Sigma
  matching, code signing.
- **CLI tooling** — `boundaryctl`, `authctl`, `verify_signatures`, `boundary-watchdog`,
  `cluster_ctl` are real and wired to a real Unix-socket API (`api/boundary_api.py`, 2,249 LOC).
- **Integrations** — SIEM (real CEF/LEEF/syslog/Splunk HEC sockets), Slack/PagerDuty/ServiceNow
  (real HTTP), with honest TODOs.
- **Tests & benchmarks** — dense and meaningful for policy/tripwire/event/gate logic;
  benchmarks use real `perf_counter_ns` + statistics, not fabricated numbers.
- **Graceful degradation** — the daemon imports and runs without yara/textual/bcc.

---

## THEATER, FICTION & DEAD CODE (the cut-list)

### Tier 1 — pure fiction / cosplay (safe to delete; nothing imports `archive/`)
- `archive/dreaming/dreaming.py` — emits `"...dreaming of order..."` ASCII flavor text dressed
  as a subsystem.
- `archive/audio/` — TTS/STT/`audio_engine` that return empty bytes; an onomatopoeia "library".
- `archive/wallpaper/lively.py` — shells out to set a Matrix desktop wallpaper (in a security
  daemon).
- `archive/blockchain/validator_protection.py` — "slashing prevention" for a daemon that isn't
  a validator.
- `archive/crypto/post_quantum.py` — self-labeled SIMULATOR (`verify` = `len(sig) > 100`,
  docstring "NO quantum resistance").
- `archive/crypto/hsm_provider.py` — `self._pkcs11_lib = True # Placeholder`; no real HSM.
- `archive/airgap/{qr_ceremony,sneakernet,data_diode}.py` — airgap-ritual cosplay.
- `archive/federation/threat_mesh.py` — real crypto plumbing posting to a server that doesn't
  exist.

  → `archive/` is **~13.6k lines of deliberately quarantined orphaned code that still ships**.
  Zero live imports. Whole-directory deletion candidate.

### Tier 2 — mislabeled / degrades to mock
- `daemon/auth/biometric_verifier.py` + `biometric_ctl` — real on fprintd hardware, but
  **silently falls back to `os.urandom()` fake fingerprints and `random.uniform(0.65, 0.95)`
  match scores** when libs are absent, while still printing success. False sense of security.
- `query_daemon.py` / `generate_report.py` — named like daemon clients; actually **Ollama
  front-ends** (`daemon=None`, never wired to a running daemon).
- `boundary_tui --connect` — admitted stub ("Socket connection not yet implemented"), silently
  falls back to embedded daemon.
- `daemon/enforcement/disk_encryption.py` — only *reads* LUKS/BitLocker status; never encrypts
  (mislabeled inside the enforcement dir).

### Tier 3 — duplication / over-engineering
- **Three event loggers**: `daemon/event_logger.py` (628) + `daemon/redundant_event_logger.py`
  (1,024) + `daemon/signed_event_logger.py` (413).
- **Two `mac_profiles.py`** (`enforcement/` 529 LOC vs `sandbox/` 953 LOC), overlapping
  AppArmor/SELinux generators.
- **Three TUI trees**: `tui/` (Textual), `daemon/tui/` (curses Matrix), `boundary-tui/`
  (separate package). *The Easter-egg TUI lives here — preserve it, but the triplication is
  real.*
- Three build systems (`build.py` 855 LOC / `build.sh` / `build.bat` 252 LOC) that drift — and
  **`build.py` still lists deleted `daemon.airgap.*` / `daemon.blockchain.*` as PyInstaller
  hidden-imports** (stale dead refs).

---

## Risks / real bugs

- ⚠️ **`daemon/integrity/integrity_verifier.py:572`** — `return True  # Allow startup without
  manifest (development mode)`: integrity verification **fails open** by default.
- **`SIEMConnector.send_event` returns `True` when disabled/filtered** — "queued" can be
  misread as "delivered."
- **Biometric mock returns plausible match scores instead of hard-failing** (see Tier 2).
- **`requirements.txt` drift** — pins `cryptography==44.0.0` but the test environment had
  41.0.7; `textual` not installed at all.
- **`test_bypass_vulnerability.py`** (root) has zero asserts — an honest *demonstration* that
  default-mode controls are advisory/log-only, but no regression protection. The headline
  "enforcement" is only real with root + the enforcement path active.
- **Enforcement layer is largely unverified by CI** — real OS-level tests are `@requires_root`
  and skip in non-root/CI; `test_security_stack_e2e.py` silently skips 9× on `ImportError`.

---

## Documentation bloat

Docs are ~3–4× oversized and dominated by accreted AI audit reports:

- **`SECURITY.md` (94 KB)** is ~5 audit reports concatenated — three separate "Executive
  Summary" sections. The actual security *policy* is ~10 KB.
- **~10 overlapping audit/eval/remediation docs** all repeating "this is AI-generated, core
  solid, edges stubbed": `VIBE_CHECK_REPORT.md`, `SECURITY_AUDIT_V3.md`, `REMEDIATION_PLAN.md`,
  `PLAN.remediation.md` + six more under `archive/docs/` (`AUDIT_REPORT`, `SECURITY_AUDIT`,
  `AGENTIC_SECURITY_AUDIT`, `EVALUATION_REPORT`, `REVIEW_FINDINGS`,
  `CONCEPT_EXECUTION_EVALUATION`). Plus `SELF_KNOWLEDGE.md` (audit-of-the-audit recursion).
- `archive/docs/SPEC.md` (2,737 lines) is the largest file and almost certainly stale.
- **Credit where due:** the README "Known Limitations" / "Non-Goals" tables are *honest* — they
  correctly disclaim PQC, HSM, and biometrics. The problem is volume and contradiction
  (elsewhere claiming "Compliance ✅ Complete", "150+ modules", "Blockchain Layer"), not
  wholesale fabrication.

---

## The TUI (intentional keep)

Confirmed intentional and functional, not theater — Textual app in `tui/app.py`, plus the
over-the-top curses Matrix dashboard (`daemon/tui/dashboard.py --matrix` with
MatrixRain/creatures/weather/lightning and the "Wake up, Neo" startup VBScripts). Listed here
only so any future cleanup explicitly **excludes** it.

---

## Test results

- 1,679 tests collected. Full suite did not finish in a 7-minute budget (too large).
- Core high-value files run green: **963 passed, 1 failed** in 45s.
- The single failure (`test_event_logger.py::...test_double_seal_adds_second_event`) is a
  test-environment artifact — running as root, a `chmod` on an already-sealed log throws
  `EPERM`. Not a real logic bug.

---

## Suggested cleanup (if you act on this later)

Highest-value, lowest-risk, in order:

1. **Delete `archive/` wholesale** (~13.6k LOC, zero live imports).
2. **Collapse the ~10 audit/remediation docs** into nothing (or one current report).
3. **Split `SECURITY.md`** down to the real ~10 KB policy.
4. **Fix the 2 genuine bugs**: integrity fail-open, biometric mock scores.
5. De-duplicate the three event loggers, the two `mac_profiles.py`, and the stale `build.py`
   hidden-imports.

That alone removes well over half the repo's bytes without touching the working core or the
TUI.
