# Boundary Daemon — Growth Roadmap

Post-scope-reduction priorities. What to deepen, not how.

---

## 1. Harden the Core Four

The policy engine, state monitor, tripwire system, and event logger are the product. Everything else is infrastructure or integration surface.

### Policy Engine
- Property-based testing for the mode x request decision matrix — every combination of boundary mode, request type, memory class, and environment state should have a deterministic, documented outcome
- Adversarial fuzzing of policy evaluation inputs — malformed requests, boundary values, rapid mode transitions
- Formal documentation of the decision matrix as a truth table that can be audited independently of the code

### Event Logger
- Hash chain verification under adversarial conditions — truncated logs, corrupted entries, replayed events, clock rollback during writes
- Recovery semantics — what happens when the daemon crashes mid-write, what state does the chain resume from
- Append-only guarantees tested against filesystem edge cases (full disk, permission changes, symlink attacks)

### Tripwire System
- Violation detection coverage for every boundary mode — enumerate every environment state that should trigger a tripwire in every mode and test each one
- Lockdown recovery path testing — the ceremony required to exit LOCKDOWN after a tripwire fires
- Race condition testing between state monitor updates and tripwire evaluation

### State Monitor
- Sensor accuracy validation — does the monitor correctly detect network state, USB changes, and process state across Linux kernel versions
- Polling reliability under load — what happens to 1Hz monitoring when the system is resource-constrained
- False positive/negative rates for each sensor type

---

## 2. Custom Policy Language

The current mode x request matrix is correct but rigid. Users who adopt this system will immediately need policies the matrix doesn't express.

### What the Language Needs to Express
- Conditional access based on combinations of environment signals (e.g., "allow SECRET recall only when offline AND no USB devices AND human presence confirmed")
- Time-based policies (e.g., "CROWN_JEWEL access only during business hours with ceremony")
- Per-agent policies (e.g., "agent X can use network tools, agent Y cannot regardless of mode")
- Escalation chains (e.g., "deny, then offer ceremony, then require multi-party approval")
- Policy composition — combining base policies with overrides without silent conflicts

### What the Language Should Not Become
- Not a general-purpose programming language
- Not Turing-complete — policies must terminate and be statically analyzable
- Not a replacement for the mode system — modes remain the coarse-grained control, policies are fine-grained refinements within a mode

---

## 3. Integration Adoption Path

The daemon's value scales with the number of systems that check in before acting. The current integration packages are a start, but several are empty stubs.

### Integration Completeness
- Memory Vault integration — the most critical path; recall gating is the flagship use case
- Agent-OS tool gating — the second most visible integration point
- synth-mind cognitive gates — validates the "cognitive firewall" positioning

### Integration Friction
- Time from "I want to integrate" to "first policy check working" — this needs to be measurable and minimized
- Error messages when the daemon is unreachable — what does fail-closed look like from the caller's perspective
- Socket discovery — the precedence order (env var, production path, user path, dev path) needs to be obvious and debuggable

### Integration Contracts
- Versioned API guarantees — what can callers depend on not changing between releases
- Response format stability — the shape of allow/deny/ceremony-required responses
- Latency expectations — how fast does a policy check return, and what's the timeout contract

---

## 4. Test Coverage on the Core

Current state: 603+ tests, 10.3% test-to-code ratio, 60% coverage target in CI.

### Where Coverage Matters Most
- Policy engine decision paths — every branch in evaluate_policy should have a test that exercises it
- Event logger integrity — chain verification, signature validation, crash recovery
- Tripwire violation detection — each ViolationType in each BoundaryMode
- Integration gates — RecallGate, ToolGate, MessageChecker under allow, deny, and ceremony-required conditions

### What Kind of Tests
- The attack simulation suite (test_attack_simulations.py) is the strongest existing test file — more of this
- Tests that verify fail-closed behavior — what happens when components are unavailable, inputs are malformed, or state is inconsistent
- Tests that document security invariants — if a test fails, it should be obvious which security property was violated

### What Not to Test
- The TUI (your feature creep canary doesn't need regression tests)
- Platform-specific enforcement paths that can't run in CI
- Configuration parsing minutiae that don't affect security decisions

---

## 5. Sandbox as the Enforcement Bridge

The sandbox module (namespaces, seccomp, cgroups) is the daemon's path from "cooperative enforcement" to real enforcement. This is the most valuable non-core feature.

### What the Sandbox Proves
- That boundary modes can translate into actual OS-level isolation
- That the daemon can move beyond "please respect my decisions" to "I will enforce my decisions"
- That the policy engine's abstractions map cleanly to kernel-level controls

### Where the Sandbox Goes Next
- Sandbox profiles that automatically tighten when the boundary mode escalates
- Sandbox telemetry that feeds back into the event logger — violations detected at the kernel level logged with the same hash chain
- Sandbox as the reference implementation for how enforcement modules consume policy decisions

---

## 6. Observability for Operators

The daemon has Prometheus metrics and SIEM integration, but the operator experience of running this in production is undefined.

### What Operators Need to Know
- Current boundary mode and why it's in that mode
- Recent policy decisions and their outcomes
- Tripwire status — what's armed, what's fired, what's been cleared
- Event log health — is the chain intact, when was it last verified
- Integration health — which systems are checking in, which have gone silent

### What Operators Need to Do
- Change modes through ceremony workflows that are auditable
- Query the event log for specific time ranges, event types, and decision outcomes
- Understand why a specific policy decision was made (decision trace)
- Export evidence bundles for compliance or incident response

---

## Priority Order

1. **Harden the core four** — this is the foundation; nothing else matters if the policy engine has untested edge cases
2. **Test coverage** — the mechanism for proving the core is solid
3. **Integration adoption** — the mechanism for the project becoming useful to others
4. **Custom policy language** — the mechanism for the project becoming useful to *diverse* others
5. **Sandbox enforcement** — the mechanism for moving beyond cooperative enforcement
6. **Operator observability** — the mechanism for running this in production with confidence

---

## Feature Roadmap (from docs/)


Strategic enhancements that strengthen core capabilities while addressing gaps—without sacrificing simplicity, determinism, or minimal attack surface.

---

## Design Principles for New Features

Every feature must pass these filters:

| Principle | Requirement |
|-----------|-------------|
| **Minimal dependencies** | No feature adds >1 new dependency |
| **Air-gap compatible** | Must work fully offline |
| **Deterministic** | Same inputs → same outputs (no ML black boxes) |
| **Fail-closed** | Unknown states → DENY |
| **Audit-first** | Every action logged immutably |
| **Ceremony-preserving** | High-risk ops require human oversight |

---

## Tier 1: Amplify Core Strengths

These features double down on what Boundary Daemon does better than enterprise tools.

### 1.1 Advanced Ceremony Framework

**Rationale:** The ceremony system is a unique differentiator. Expand it.

| Feature | Description | Effort |
|---------|-------------|--------|
| **Ceremony templates** | Pre-defined ceremony types (emergency access, data export, mode override) with customizable steps | Low |
| **Ceremony chains** | Multi-party ceremonies requiring N-of-M approvals | Medium |
| **Time-locked ceremonies** | Ceremonies that can only complete during specified windows | Low |
| **Ceremony delegation** | Temporary delegation with automatic expiry and full audit | Low |
| **Remote attestation ceremonies** | Require TPM attestation as ceremony step | Medium |
| **Dead-man ceremonies** | Auto-trigger if no human activity for N hours | Low |

**Implementation notes:**
- Build on existing `enhanced_ceremony.py`
- No new dependencies
- All ceremony actions hash-chained

### 1.2 Forensic-Grade Audit Enhancements

**Rationale:** Hash-chained logging exceeds many SIEMs. Make it even stronger.

| Feature | Description | Effort |
|---------|-------------|--------|
| **Merkle tree proofs** | Generate compact proofs for any event range without full log | Medium |
| **Cross-node log anchoring** | Cluster nodes periodically anchor hashes to each other | Medium |
| **External anchoring** | Optional: anchor daily root hash to external timestamping service | Low |
| **Log witness protocol** | Allow external parties to receive and countersign log hashes | Medium |
| **Selective disclosure proofs** | Prove specific events occurred without revealing others | High |
| **Log compaction with proofs** | Archive old logs while preserving verifiability | Medium |

**Implementation notes:**
- Merkle trees use existing SHA-256
- External anchoring works in RESTRICTED+ modes only
- Proofs exportable as standalone JSON files

### 1.3 Enhanced Air-Gap Capabilities

**Rationale:** Air-gap modes are purpose-built for high-security. Strengthen them.

| Feature | Description | Effort |
|---------|-------------|--------|
| **Sneakernet protocol** | Secure format for transferring data in/out of air-gapped systems | Medium |
| **QR-code ceremonies** | Approve ceremonies via QR scan from separate device | Medium |
| **Hardware token ceremonies** | YubiKey/OnlyKey integration for offline auth | Medium |
| **Offline threat intel** | Signed, dated threat intel packages for air-gapped systems | Low |
| **Air-gap verification** | Active probing to verify true network isolation | Low |
| **Data diode support** | One-way log export for air-gapped audit | Medium |

**Implementation notes:**
- QR ceremonies preserve determinism (no network)
- Hardware tokens via FIDO2/U2F (single dependency: `fido2`)
- Sneakernet format: signed, encrypted, size-limited bundles

---

## Tier 2: Strategic Gap Coverage

Address enterprise gaps without becoming an enterprise tool.

### 2.1 SIEM Integration Layer

**Rationale:** Don't replace SIEMs—feed them immutable, signed events.

| Feature | Description | Effort |
|---------|-------------|--------|
| **CEF/LEEF export** | Common Event Format for Splunk/QRadar/ArcSight | Low |
| **Syslog-ng structured data** | RFC 5424 structured syslog with signatures | Low |
| **Webhook notifications** | POST signed events to external endpoints | Low |
| **Kafka producer** | Stream events to Kafka topics | Medium |
| **S3/GCS log shipping** | Batch upload signed logs to cloud storage | Low |
| **Signature verification API** | Endpoint for SIEMs to verify event signatures | Low |

**Implementation notes:**
- All exports include original signatures
- SIEM can verify but cannot modify
- Export runs in separate process (isolation)
- Works in RESTRICTED+ modes only

### 2.2 Identity Federation (Lightweight)

**Rationale:** Enable SSO without becoming identity-dependent.

| Feature | Description | Effort |
|---------|-------------|--------|
| **OIDC token validation** | Accept OIDC tokens, map to local capabilities | Medium |
| **LDAP capability mapping** | Query LDAP groups → local capability sets | Medium |
| **PAM integration** | Use system PAM for initial auth, then issue BD tokens | Low |
| **Identity bridge mode** | Accept external identity, require local ceremony for sensitive ops | Low |
| **Offline identity cache** | Cache identity mappings for air-gap graceful degradation | Low |

**Implementation notes:**
- External identity is *advisory*—ceremonies still required for high-risk
- Local tokens remain source of truth
- LDAP/OIDC are optional adapters, not dependencies
- System continues working if IdP is unavailable

### 2.3 Compliance Automation

**Rationale:** Provide compliance evidence without requiring certifications.

| Feature | Description | Effort |
|---------|-------------|--------|
| **Control mapping export** | Generate NIST 800-53 / ISO 27001 control mapping | Low |
| **Compliance evidence bundles** | Export signed proof packages for auditors | Medium |
| **Policy-as-code validation** | Validate policies against compliance requirements | Medium |
| **Audit readiness reports** | Auto-generate compliance status reports | Low |
| **Retention policy enforcement** | Configurable log retention with sealed archives | Low |
| **Access review ceremonies** | Periodic ceremonies to review/confirm access grants | Low |

**Implementation notes:**
- Mappings are static YAML files (auditor-friendly)
- Evidence bundles are self-contained, verifiable offline
- No compliance SaaS dependencies

---

## Tier 3: Selective Capability Enhancement

Targeted improvements that don't compromise core design.

### 3.1 Deterministic Threat Detection

**Rationale:** Improve detection without ML black boxes.

| Feature | Description | Effort |
|---------|-------------|--------|
| **YARA rule engine** | Load YARA rules for file/memory scanning | Medium |
| **Sigma rule support** | Convert Sigma detection rules to local patterns | Medium |
| **IOC feeds (signed)** | Consume signed IOC feeds, verify before use | Low |
| **Behavioral baselines** | Statistical baselines with deterministic thresholds | Medium |
| **Attack pattern library** | MITRE ATT&CK patterns as deterministic rules | Medium |
| **Community rule sharing** | Import/export rule sets with signatures | Low |

**Implementation notes:**
- YARA is single C library, well-audited
- All rules are inspectable (no black boxes)
- Thresholds are explicit, tunable, auditable
- IOC feeds must be signed; unsigned feeds rejected

### 3.2 eBPF Observability (Optional Module)

**Rationale:** Gain kernel visibility without kernel driver complexity.

| Feature | Description | Effort |
|---------|-------------|--------|
| **eBPF process monitor** | Observe process creation, exec, exit | High |
| **eBPF file monitor** | Observe file opens, writes, deletes | High |
| **eBPF network monitor** | Observe socket operations | High |
| **Policy-driven filtering** | Only observe what policies care about | Medium |
| **Graceful degradation** | Full functionality without eBPF on older kernels | Medium |

**Implementation notes:**
- eBPF is read-only observation, not enforcement
- Optional module—core daemon works without it
- Single dependency: `bcc` or `libbpf`
- Provides visibility for better policy decisions
- Does NOT try to be an EDR

### 3.3 Orchestrator Integration

**Rationale:** Support deployment in container/K8s environments.

| Feature | Description | Effort |
|---------|-------------|--------|
| **Kubernetes admission webhook** | Policy decisions for pod creation | Medium |
| **Docker socket proxy** | Policy layer for Docker API calls | Medium |
| **Sidecar mode** | Run as container sidecar with shared namespaces | Low |
| **Pod security policy bridge** | Map boundary modes to K8s PSPs/PSS | Low |
| **Service mesh integration** | Policy hints for Istio/Linkerd | Medium |

**Implementation notes:**
- Admission webhook is pure policy (no enforcement)
- Enforcement relies on K8s, not daemon
- Maintains separation of concerns

---

## Tier 4: Usability Without Bloat

Quality-of-life improvements that don't add attack surface.

### 4.1 Local Query Interface

**Rationale:** Enable log analysis without external SIEM.

| Feature | Description | Effort |
|---------|-------------|--------|
| **SQLite log index** | Index events in local SQLite for fast queries | Medium |
| **Query CLI** | `boundaryctl query "event_type:VIOLATION after:2024-01-01"` | Low |
| **Event correlation rules** | Simple "if A then B within T" correlation | Medium |
| **Anomaly highlighting** | Flag statistical outliers in query results | Low |

**Implementation notes:**
- SQLite is single-file, no server
- Index is derived from authoritative hash-chained log
- Queries are read-only, never modify source

### 4.2 Terminal Dashboard

**Rationale:** Visibility without web UI attack surface.

| Feature | Description | Effort |
|---------|-------------|--------|
| **TUI dashboard** | Real-time status in terminal (ncurses/rich) | Medium |
| **Event stream view** | Live tail with filtering | Low |
| **Mode transition history** | Visual timeline of mode changes | Low |
| **Cluster status view** | Multi-node health at a glance | Low |

**Implementation notes:**
- Single dependency: `rich` or `textual`
- No network listeners
- Read-only view of daemon state

### 4.3 Configuration Validation

**Rationale:** Prevent misconfigurations that weaken security.

| Feature | Description | Effort |
|---------|-------------|--------|
| **Config linter** | Validate configs before daemon start | Low |
| **Policy simulator** | Test policy decisions without live daemon | Low |
| **Dry-run mode** | Run daemon in observation-only mode | Low |
| **Config diff** | Show effective changes between configs | Low |
| **Security posture score** | Score current config against best practices | Low |

---

## Anti-Features (Explicitly Not Planned)

These features would compromise core principles:

| Feature | Why Not |
|---------|---------|
| **Kernel driver** | Massively increases attack surface and complexity |
| **Cloud ML backend** | Breaks air-gap, adds latency, non-deterministic |
| **Full EDR capabilities** | Not the purpose; integrate with EDR instead |
| **Web management UI** | Attack surface; use terminal dashboard |
| **Mobile app** | Attack surface; use ceremony delegation |
| **Automatic updates** | Could be compromised; manual updates with signatures |
| **Agent-based scanning** | Deploy separate scanner, feed results to BD |
| **Deep packet inspection** | Use NGFW; BD handles policy, not inspection |

---

## Implementation Priority Matrix

| Priority | Feature | Value | Effort | Dependencies | Status |
|----------|---------|-------|--------|--------------|--------|
| **P0** | Ceremony templates | High | Low | None | Planned |
| **P0** | CEF/LEEF export | High | Low | None | ✅ Complete |
| **P0** | Config linter | High | Low | None | ✅ Complete |
| **P1** | Merkle tree proofs | High | Medium | None | Planned |
| **P1** | OIDC token validation | High | Medium | None (optional) | ✅ Complete |
| **P1** | YARA rule engine | High | Medium | yara-python | ✅ Complete |
| **P1** | Query CLI | Medium | Low | None | ✅ Complete |
| **P2** | N-of-M ceremonies | High | Medium | None | Planned |
| **P2** | Hardware token ceremonies | High | Medium | fido2 | Planned |
| **P2** | Control mapping export | Medium | Low | None | ✅ Complete |
| **P2** | Terminal dashboard | Medium | Medium | rich | ✅ Complete |
| **P2** | RAG injection detection | High | Medium | None | ✅ Complete |
| **P2** | Agent attestation | High | Medium | None | ✅ Complete |
| **P3** | eBPF observability | Medium | High | bcc/libbpf | ✅ Complete |
| **P3** | K8s admission webhook | Medium | Medium | None | Planned |
| **P3** | Sigma rule support | Medium | Medium | None | ✅ Complete |
| **P3** | LDAP mapping | Medium | Medium | None | ✅ Complete |
| **P3** | PAM integration | Medium | Low | None | ✅ Complete |
| **P3** | Evidence bundles | Medium | Medium | None | ✅ Complete |
| **P3** | Air-gap operations | Medium | Medium | None | ✅ Complete |
| **P3** | HSM support | High | High | pkcs11 | ✅ Complete |
| **P3** | Post-quantum crypto | Medium | Medium | liboqs | ✅ Complete |
| **P3** | Threat federation | Medium | High | None | ✅ Complete |
| **P3** | Mode advisor | Medium | Medium | None | ✅ Complete |
| **P3** | Case management | Medium | Medium | None | ✅ Complete |
| **P3** | Code integrity | High | Medium | None | ✅ Complete |
| **P3** | Agent containment | High | Medium | None | ✅ Complete |

---

## Dependency Budget

Current: ~4 core dependencies

| Tier | New Dependencies | Justification |
|------|------------------|---------------|
| Tier 1 | 0-1 (fido2) | Hardware tokens for ceremonies |
| Tier 2 | 0-1 (kafka-python) | Optional streaming export |
| Tier 3 | 1-2 (yara-python, bcc) | Detection and observability |
| Tier 4 | 0-1 (rich) | Terminal dashboard |

**Total new dependencies: 3-5 max, all optional modules**

---

## Success Metrics

| Metric | Previous | Current | Target |
|--------|----------|---------|--------|
| Core dependencies | ~4 | ~4 | <6 |
| Lines of code | ~15k | ~25k | <30k |
| Air-gap functionality | 90% | 100% | 100% ✅ |
| Ceremony coverage | 5 types | 10 types | 15 types |
| SIEM compatibility | 1 (syslog) | 5 formats | 5 formats ✅ |
| Compliance mappings | 0 | 3 frameworks | 3 frameworks ✅ |
| Detection rules | patterns | YARA + Sigma + MITRE | patterns + YARA + Sigma ✅ |
| AI/Agent security | 0 modules | 5 modules | 5 modules ✅ |
| Identity federation | 0 | 4 integrations | 4 integrations ✅ |

---

## Recently Completed Features

The following major features have been implemented:

### AI/Agent Security Stack ✅
- **Prompt Injection Detection** - Jailbreak, instruction injection, encoding bypass detection
- **Tool Output Validation** - Rate limiting, chain depth control, PII sanitization
- **Response Guardrails** - Content safety, hallucination detection, response sanitization
- **RAG Injection Detection** - Poisoned document detection, cross-document attack analysis
- **Agent Attestation** - Cryptographic identity, capability-based access control, delegation chains

### Threat Detection ✅
- **YARA Rule Engine** - File/memory scanning with YARA rules
- **Sigma Rule Support** - Sigma detection rule conversion
- **eBPF Observability** - Kernel visibility without kernel driver
- **MITRE ATT&CK Patterns** - Deterministic attack pattern matching

### Enterprise Integration ✅
- **CEF/LEEF Export** - Common Event Format for SIEM integration
- **OIDC Token Validation** - External identity provider support
- **Compliance Mapping** - NIST 800-53 / ISO 27001 control mapping

---

## Summary

This roadmap strengthens Boundary Daemon's unique position as:

1. **The ceremony authority** — No tool does human oversight better
2. **The audit anchor** — Forensic-grade, cryptographically verifiable logs
3. **The air-gap specialist** — Purpose-built for disconnected high-security
4. **The policy coordinator** — Integrates with, not replaces, security stack
5. **The AI security leader** — Comprehensive protection for AI agents and LLM systems

By focusing on these strengths while adding strategic integrations (SIEM, IdP, compliance), Boundary Daemon becomes more deployable in enterprise environments without becoming another bloated security agent.
