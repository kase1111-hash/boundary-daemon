# Scope Reduction Analysis

**Analysis Date:** 2026-02-05
**Current State:** 171 Python modules, 122K+ lines of code

## Executive Summary

Analysis identified **5 orphaned modules** (not imported anywhere) totaling ~7,300 lines of code that can be archived. Additionally, the `daemon/integrity/` module partially duplicates `daemon/security/daemon_integrity.py`.

## Orphaned Modules (No Imports Found)

| Module | Files | Lines | Purpose | Recommendation |
|--------|-------|-------|---------|----------------|
| `daemon/intelligence/` | 2 | 931 | Mode advisor AI | Archive |
| `daemon/containment/` | 2 | 1,104 | Agent profiler | Archive |
| `daemon/blockchain/` | 3 | 1,351 | Blockchain audit trail | Archive |
| `daemon/federation/` | 2 | 1,233 | Threat mesh federation | Archive |
| `daemon/airgap/` | 4 | 2,241 | Airgap enforcement | Archive |
| **Total** | **13** | **~6,860** | | |

### Module Details

#### daemon/intelligence/ (931 lines)
- `mode_advisor.py` - AI-powered mode recommendations based on context
- `__init__.py` - Module exports
- **Status:** Feature was planned but never integrated
- **Decision:** Archive - Can be restored if mode recommendation feature is prioritized

#### daemon/containment/ (1,104 lines)
- `agent_profiler.py` - AI agent behavioral profiling and anomaly detection
- `__init__.py` - Module exports
- **Status:** Implements graduated response (WARN → THROTTLE → ISOLATE → SUSPEND → TERMINATE)
- **Decision:** Archive - Useful concept but not wired into main daemon

#### daemon/blockchain/ (1,351 lines)
- `audit_chain.py` - Blockchain-based audit trail
- `distributed_ledger.py` - P2P ledger sync
- `__init__.py` - Module exports
- **Status:** Experimental feature for immutable audit logs
- **Decision:** Archive - Current hash-chain logging provides similar guarantees

#### daemon/federation/ (1,233 lines)
- `threat_mesh.py` - Cross-instance threat intelligence sharing
- `__init__.py` - Module exports
- **Status:** Designed for multi-daemon deployments
- **Decision:** Archive - Can be restored when federation feature is needed

#### daemon/airgap/ (2,241 lines)
- `airgap_enforcer.py` - Network airgap enforcement
- `policy_manager.py` - Airgap policy management
- `device_control.py` - USB/peripheral control in airgap mode
- `__init__.py` - Module exports
- **Status:** Partially duplicates enforcement/ modules
- **Decision:** Archive - Functionality covered by enforcement/network_enforcer.py

## Duplicate Code Analysis

### daemon/integrity/ vs daemon/security/daemon_integrity.py

Both modules handle code integrity verification with overlapping concepts:

| Feature | daemon/integrity/ | daemon/security/daemon_integrity.py |
|---------|------------------|-------------------------------------|
| IntegrityStatus enum | ✓ (different values) | ✓ (different values) |
| Manifest signing | ✓ CodeSigner | ✓ DaemonIntegrityProtector |
| Verification | ✓ IntegrityVerifier | ✓ verify_integrity() |
| Runtime monitoring | ✓ IntegrityMonitor | ✓ Built-in |
| Used by | scripts/sign_release.py | boundary_daemon.py, build.bat |

**Recommendation:** Keep both for now - they serve different workflows:
- `daemon/integrity/` - Release signing workflow
- `daemon/security/daemon_integrity.py` - Runtime verification

Future consolidation would require careful refactoring of the release signing process.

## Large Module Analysis

### daemon/security/ (23 files, 23,407 lines)

The security directory is well-organized but large. Potential sub-package structure:

```
daemon/security/
├── core/          # daemon_integrity, file_integrity, clock_monitor
├── network/       # dns_security, arp_security, wifi_security, etc.
├── ai/            # prompt_injection, rag_injection, response_guardrails
├── endpoint/      # antivirus, process_security, hardening
└── integration/   # siem_integration, threat_intel
```

**Recommendation:** Consider reorganization in future phase - not urgent.

## Action Plan

### Phase 1: Archive Orphaned Modules (Immediate)

1. Move orphaned modules to `archive/` directory
2. Update `daemon/__init__.py` if needed
3. Document in this file

### Phase 2: Documentation (Short-term)

1. Add module purpose comments to remaining modules
2. Create architecture diagram showing module relationships
3. Update CONTRIBUTING.md with module organization guide

### Phase 3: Reorganization (Future)

1. Consider security/ sub-packages when module count grows
2. Evaluate integrity module consolidation
3. Review for additional dead code

## Impact Assessment

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Python files | 171 | 158 | -13 (-7.6%) |
| Lines of code | 122,089 | ~115,229 | -6,860 (-5.6%) |
| Directories | 35 | 30 | -5 (-14.3%) |

## Archived Modules Location

After archival, modules will be in:
```
archive/
├── intelligence/
├── containment/
├── blockchain/
├── federation/
└── airgap/
```

These can be restored by moving back to `daemon/` and updating imports.
