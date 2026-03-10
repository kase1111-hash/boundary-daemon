# Regulatory Compliance Assessment — Boundary Daemon

**Version:** 1.0.0-beta
**Date:** 2026-03-10
**Status:** Initial assessment — no certifications pursued yet

---

## Scope

Boundary Daemon is a **policy enforcement and audit-trail layer** for AI agent
workloads. It does not directly store end-user PII, process payment card data,
or serve as a healthcare records system. However, deployments that sit in
regulated environments inherit compliance obligations.

This document maps Boundary Daemon capabilities to common regulatory frameworks
so operators can assess applicability.

---

## GDPR (EU General Data Protection Regulation)

| Article | Relevance | Boundary Daemon Coverage |
|---------|-----------|--------------------------|
| Art. 5 — Data minimisation | LOW — Daemon logs agent actions, not end-user data | Event logs contain action metadata, not user PII. Operators must ensure agent payloads routed through the daemon do not embed PII unnecessarily. |
| Art. 25 — Data protection by design | MEDIUM | Policy engine enforces least-privilege boundaries; cryptographic audit trail provides integrity guarantees. |
| Art. 30 — Records of processing | MEDIUM | Immutable event log with hash-chain can serve as a processing record if agent actions constitute data processing. |
| Art. 32 — Security of processing | HIGH | TLS on remote backends, authenticated API endpoints, secret rotation — all address Art. 32 "appropriate technical measures". |
| Art. 33/34 — Breach notification | LOW | Daemon detects boundary violations and emits events; operators must build notification workflows on top. |
| Art. 35 — DPIA | If agents process personal data, a DPIA should evaluate the daemon's role. | Daemon is a control, not a data processor. Include it in the DPIA scope as a security measure. |

**Action items for GDPR-regulated deployments:**
1. Audit agent payloads to confirm no PII transits event logs unmasked.
2. Configure log retention policies (the daemon does not auto-purge).
3. Document the daemon in your Record of Processing Activities (Art. 30).

---

## HIPAA (US Health Insurance Portability and Accountability Act)

| Safeguard | Boundary Daemon Coverage |
|-----------|--------------------------|
| Administrative — Access controls (§164.312(a)) | API token auth with capability sets (admin / readonly). |
| Administrative — Audit controls (§164.312(b)) | Cryptographic hash-chain event log provides tamper-evident audit trail. |
| Technical — Integrity (§164.312(c)) | Hash-chain verification, HMAC-based comparison. |
| Technical — Transmission security (§164.312(e)) | TLS enforced on RemoteBackend (TCP), HTTPS enforced on SIEM ingestion. |
| Physical — N/A | Daemon is software-only; defer to infrastructure provider. |

**Action items for HIPAA-covered deployments:**
1. Ensure the daemon runs in a BAA-covered environment (cloud provider agreement).
2. Enable TLS on all remote backends — plaintext mode must never be used with ePHI.
3. Restrict API tokens: grant `admin` capability only to privileged operators.
4. Review PII detector module (`daemon/pii/detector.py`) for ePHI patterns.

---

## PCI-DSS v4.0

Boundary Daemon is unlikely to be in-scope for PCI-DSS unless agents process
cardholder data. If in-scope:

- **Req 3 (Protect stored data):** Event logs must not contain PANs. Validate
  agent payloads.
- **Req 8 (Identify and authenticate):** API auth with token-based access
  satisfies identity requirements.
- **Req 10 (Log and monitor):** Hash-chain event log meets integrity
  requirements for audit trails.
- **Req 11 (Test security):** Add penetration testing (see CI hardening).

---

## EU Cyber Resilience Act (CRA)

As a security-critical software component, the daemon should track CRA
requirements once the regulation is finalized:

- **Vulnerability handling:** SECURITY.md documents responsible disclosure.
- **SBOM:** Generate with `pip-audit` or `cyclonedx-py` for each release.
- **Security updates:** Pin dependencies and monitor with `safety check` in CI.

---

## Summary

| Framework | In-Scope? | Readiness |
|-----------|-----------|-----------|
| GDPR | Only if agents process EU personal data | Controls present; operator configuration needed |
| HIPAA | Only if agents handle ePHI | Technical safeguards in place; BAA and policy needed |
| PCI-DSS | Only if agents handle cardholder data | Unlikely; controls adequate if needed |
| EU CRA | Probable (security software) | SBOM generation recommended |

**No certifications are claimed.** This assessment identifies control mappings
to help operators evaluate compliance posture.
