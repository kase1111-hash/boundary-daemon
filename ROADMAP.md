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
