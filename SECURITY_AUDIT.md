# Security Audit Report: Boundary Daemon (Agent Smith)

**Audit Date:** 2025-12-18 (Original) | **Updated:** 2026-01-01
**Auditor:** Security Review
**Status:** 🟡 MOST CRITICAL ISSUES FIXED

---

## Executive Summary

> **⚠️ UPDATE (2026-01-01)**: Many critical issues identified in this audit have been addressed.
> See the "Remediation Status" sections below for details on implemented fixes.

The Boundary Daemon now provides **policy decisions, audit logging, AND optional enforcement**.

- ✅ **What it DOES:** Logs security decisions, monitors environment, provides policy decisions
- ✅ **What it NOW ALSO DOES:** Network enforcement (iptables/nftables), USB enforcement (udev), process isolation (seccomp/containers)
- ⚠️ **Enforcement requires:** Root privileges and explicit enablement via environment variables

**Updated Verdict:** With enforcement modules enabled, this is a **functional security layer**. Without enforcement enabled, it remains an audit/policy system.

### Quick Findings Overview

**🔴 CRITICAL Issues - REMEDIATION STATUS**

| # | Issue | Original Status | Current Status |
|---|-------|-----------------|----------------|
| 1 | No Real Enforcement | 🔴 CRITICAL | ✅ FIXED - `daemon/enforcement/` modules |
| 2 | Network Not Blocked | 🔴 CRITICAL | ✅ FIXED - `network_enforcer.py`, `windows_firewall.py` |
| 3 | USB Not Prevented | 🔴 CRITICAL | ✅ FIXED - `usb_enforcer.py` (udev rules) |
| 4 | Lockdown Not Locked | 🔴 CRITICAL | ✅ FIXED - `process_enforcer.py` (seccomp + containers) |
| 5 | Race Conditions | 🔴 CRITICAL | 🟡 MITIGATED - External watchdog, fail-closed design |
| 6 | Daemon Killable | 🔴 CRITICAL | 🟡 MITIGATED - External watchdog in `process_enforcer.py` |

**🟡 HIGH Issues - REMEDIATION STATUS**

| # | Issue | Original Status | Current Status |
|---|-------|-----------------|----------------|
| 7 | Log Tampering | 🟡 HIGH | ✅ FIXED - `storage/log_hardening.py` (chattr +a) |
| 8 | No Human Verification | 🟡 HIGH | ✅ FIXED - `auth/biometric_verifier.py` |
| 9 | Weak Detection | 🟡 HIGH | 🟡 IMPROVED - Additional AI security modules |
| 10 | Clock Attacks | 🟡 HIGH | ✅ FIXED - `security/clock_monitor.py` |

**🟢 MEDIUM Issues - REMEDIATION STATUS**

| # | Issue | Original Status | Current Status |
|---|-------|-----------------|----------------|
| 11 | No API authentication | 🟢 MEDIUM | ✅ FIXED - `auth/api_auth.py` (token + capabilities) |
| 12 | No rate limiting | 🟢 MEDIUM | ✅ FIXED - `auth/persistent_rate_limiter.py` |
| 13 | No code integrity | 🟢 MEDIUM | ✅ FIXED - `integrity/code_signer.py`, `integrity_verifier.py` |
| 14 | Secrets in logs | 🟢 MEDIUM | ✅ FIXED - PII detection and redaction |

### What Actually Works

✅ **Hash Chain Integrity** - SHA-256 chains correctly detect log tampering
✅ **Policy Logic** - Memory class permissions are correctly evaluated
✅ **State Detection** - Network, USB, processes accurately monitored
✅ **Event Logging** - All operations comprehensively logged
✅ **API Interface** - Unix socket communication works properly

**But:** All working features are **detective** (notice violations), not **preventive** (stop violations).

### Is Anything Actually Secured?

**No - not as standalone system.**

This daemon is:
- An excellent **audit system**
- A useful **policy decision point**
- A good **monitoring framework**
- **NOT** an **enforcement mechanism**

For real data security, you need:
```
Layer 1: Kernel enforcement (SELinux, seccomp, eBPF)
Layer 2: Container isolation (namespaces, cgroups)
Layer 3: This daemon (policy + logging)           ← YOU ARE HERE
Layer 4: Application cooperation (Memory Vault, Agent-OS)
Layer 5: Hardware controls (disabled USB, air-gapped NIC)
```

Currently, only Layer 3 and 4 exist - and Layer 4 is voluntary.

### Severity Classification
- 🔴 **CRITICAL**: Complete bypass possible, no real enforcement
- 🟡 **HIGH**: Significant weakness, partial enforcement
- 🟢 **LOW**: Minor issue, defense-in-depth concern

---

## Critical Findings (Security Theater Issues)

### 🔴 CRITICAL #1: No Actual Enforcement - Only Logging

**Location:** Throughout all components
**Severity:** CRITICAL - This is the most serious issue

**Problem:**
The daemon does NOT prevent any operations - it only logs them. All the "enforcement" functions return boolean tuples like `(permitted, reason)`, but **nothing in this codebase actually blocks operations**. External systems can:
1. Call `check_recall_permission()` or `check_tool_permission()`
2. Receive `(False, "denied")`
3. **Completely ignore the denial and proceed anyway**

**Evidence:**
```python
# daemon/boundary_daemon.py:246
def check_recall_permission(self, memory_class: MemoryClass) -> tuple[bool, str]:
    # ... evaluation logic ...
    if decision == PolicyDecision.ALLOW:
        return (True, "Recall permitted")
    elif decision == PolicyDecision.DENY:
        return (False, f"Recall denied...")
    # ^^^ This just RETURNS a value. It doesn't PREVENT anything.
```

The Memory Vault or Agent-OS could do:
```python
permitted, reason = boundary.check_recall_permission(MemoryClass.TOP_SECRET)
# Even if permitted == False, nothing stops:
return secret_data  # ⚠️ No actual enforcement!
```

**Real Enforcement Would Require:**
- OS-level process isolation (containers, VMs)
- Kernel-level syscall filtering (seccomp-bpf, SELinux)
- Network firewall rules that the daemon controls
- Filesystem access controls (mandatory access control)
- Hardware-level protections (TPM, secure enclaves)

**Current State:** This is a **voluntary honor system** - other components must choose to respect the daemon's decisions.

---

### 🔴 CRITICAL #2: No Network Enforcement Whatsoever

**Location:** `daemon/state_monitor.py` - network detection
**Severity:** CRITICAL

**Problem:**
The daemon claims to enforce AIRGAP mode by blocking network access. In reality:
1. It *detects* network interfaces using `psutil`
2. It *logs* when network comes online in AIRGAP mode
3. It **does nothing to prevent network traffic**

**Evidence:**
```python
# state_monitor.py:192-234
def _check_network(self) -> Dict:
    # Checks IF network exists
    # Does NOT disable network
    # Does NOT install firewall rules
    # Does NOT block network syscalls
```

**What's Missing:**
- Actual firewall rules (iptables/nftables)
- Network namespace isolation
- Disabling network interfaces
- Blocking socket() syscalls via seccomp

**Attack Scenario:**
1. System enters AIRGAP mode
2. Malicious process opens network socket
3. Daemon detects it and enters LOCKDOWN
4. **Data already exfiltrated** - lockdown is too late

---

### 🔴 CRITICAL #3: USB "Protection" Is Detection-Only

**Location:** `daemon/tripwires.py:161-178`
**Severity:** CRITICAL

**Problem:**
COLDROOM mode claims to prevent USB insertion. Actually:
- Monitors `/sys/bus/usb/devices`
- Triggers lockdown if new USB detected
- **But USB device is already mounted and accessible**

The tripwire fires AFTER the USB device is already available to the system.

**Real Protection Would Require:**
- Blacklisting USB kernel modules
- Using `udev` rules to prevent mounting
- Physical USB port controls
- BIOS-level USB disabling

---

### 🔴 CRITICAL #4: Lockdown Mode Is Not Actually Locked Down

**Location:** `daemon/tripwires.py:350-430`
**Severity:** CRITICAL

**Problem:**
When LOCKDOWN is triggered:
1. A flag `self._in_lockdown = True` is set
2. Future permission checks return `False`
3. **But running processes continue uninterrupted**

**What's Missing:**
- No process termination
- No network shutdown
- No filesystem unmounting
- No screen blanking
- No memory wiping

A malicious agent that already has data in memory can continue exfiltrating it.

---

### 🔴 CRITICAL #5: Race Conditions in State Monitoring

**Location:** `daemon/state_monitor.py:124-146`
**Severity:** CRITICAL

**Problem:**
State monitoring polls every 1 second (default). This creates a ~1 second window where:
- Network can be activated
- USB can be inserted
- Data can be exfiltrated
- **Before daemon even notices**

```python
# state_monitor.py:76
def __init__(self, poll_interval: float = 1.0):
    self.poll_interval = poll_interval  # 1 second vulnerability window
```

**Attack:** Time operations to occur right after state poll.

---

### 🟡 HIGH #6: Daemon Can Be Killed

**Location:** All components
**Severity:** HIGH

**Problem:**
The daemon is a regular Python process that can be killed:
```bash
killall python3  # Daemon dies
# Or:
kill -9 <daemon_pid>
```

The code has a signal handler (`boundary_daemon.py:58-60`), but:
- `SIGKILL` cannot be caught
- Root user can always kill it
- Crashes leave system unprotected

**Mitigation in Code:**
The specs mention "If BD crashes → system enters Lockdown" but this is impossible if the daemon is killed - there's no external watchdog.

---

### 🟡 HIGH #7: Event Log Is Not Actually Tamper-Proof

**Location:** `daemon/event_logger.py`
**Severity:** HIGH

**Problem:**
While the event log uses hash chains (good!), the file is just a regular text file:
- Stored at `./logs/boundary_chain.log`
- Can be deleted: `rm ./logs/boundary_chain.log`
- Can be modified: `vi ./logs/boundary_chain.log`
- Can be replaced entirely

**Current Protection:** None - file permissions are default.

**Real Tamper-Proof Logging Requires:**
- Write-only append-only filesystem (chattr +a)
- Separate logging server
- Hardware security module (HSM)
- Blockchain with external validators
- Secure enclave storage

**Note:** The hash chain IS correctly implemented and WILL detect tampering if someone modifies the middle of the log. But nothing prevents deletion or replacement.

---

### 🟡 HIGH #8: No Human Presence Verification

**Location:** `daemon/integrations.py:254-264` (CeremonyManager)
**Severity:** HIGH

**Problem:**
The "human presence verification" uses keyboard input:
```python
response = input("Type 'PRESENT' to confirm physical presence: ")
return response.strip().upper() == 'PRESENT'
```

This can be automated:
```python
echo "PRESENT" | python daemon/boundary_daemon.py
```

**Real Human Verification Requires:**
- Biometric authentication
- Hardware security key (YubiKey)
- Video camera with face detection
- Physical button press

---

### 🟡 HIGH #9: External Model Detection Is Heuristic

**Location:** `state_monitor.py:303-312`
**Severity:** HIGH

**Problem:**
Detecting external AI API usage by grepping command lines:
```python
if any(endpoint in cmdline.lower() for endpoint in
       ['openai', 'anthropic', 'api.claude', 'api.openai']):
```

**Bypasses:**
- Use IP addresses instead of domain names
- Encode strings: `base64_decode('b3BlbmFp')`
- Use environment variables
- Use configuration files
- Proxy through localhost

---

### 🟡 HIGH #10: Clock Dependency (No Implementation)

**Location:** Mentioned in specs.md line 211 "If clocks drift → freeze mode transitions"
**Severity:** HIGH

**Problem:**
This protection is mentioned in the spec but **not implemented** in the code. An attacker with root can:
```bash
date -s "2020-01-01"  # Time travel attack
```

---

## Medium Severity Issues

### 🟢 #11: Python Type Hints Not Enforced
The codebase uses Python type hints but Python doesn't enforce them at runtime. A malicious caller could pass wrong types.

### 🟢 #12: No Code Signing or Integrity Checks
The daemon doesn't verify its own code hasn't been modified.

### 🟢 #13: Logging Secrets in Metadata
Event logs might contain sensitive information in metadata fields.

### 🟢 #14: No Rate Limiting
A malicious process could spam permission checks to create log bloat.

---

## What IS Actually Working

### ✅ Correctly Implemented Features:

1. **Hash Chain Integrity:** The event logger correctly implements SHA-256 hash chaining and can detect log tampering (event_logger.py:179-223)

2. **Policy Logic:** The policy engine correctly evaluates memory class permissions based on boundary mode (policy_engine.py:200-232)

3. **State Detection:** The state monitor accurately detects network interfaces, USB devices, and processes (state_monitor.py)

4. **Tripwire Logic:** The tripwire conditions are correctly evaluated (tripwires.py:84-136)

5. **API Interface:** The Unix socket API is properly implemented (boundary_api.py)

6. **Event Logging:** All security-relevant events are logged with proper metadata

**However:** All of these features are **detective controls** (they notice violations) not **preventive controls** (they stop violations).

---

## Architecture Analysis

### What This System IS:
- **An audit log** of security decisions
- **A policy decision point** that other systems can query
- **A monitoring system** that detects environmental changes
- **A coordination layer** for security-aware applications

### What This System IS NOT:
- **An enforcement mechanism** - it doesn't prevent operations
- **A sandbox** - it doesn't isolate processes
- **A firewall** - it doesn't block network traffic
- **A filesystem guard** - it doesn't control file access
- **A hardware controller** - it doesn't disable USB/network physically

---

## Fundamental Design Problem

The core issue is **architectural**: Python user-space daemon cannot enforce security against:
- Root users
- Kernel-level operations
- Hardware access
- Non-cooperative processes

This would require:
1. **Kernel module** for syscall interception
2. **Mandatory Access Control** (SELinux/AppArmor policies)
3. **Container/VM isolation** (separate memory spaces)
4. **Hardware controls** (disable USB in BIOS, air-gap network physically)
5. **Trusted Execution Environment** (Intel SGX, ARM TrustZone)

---

## Recommendations

### Immediate Actions Required:

1. **⚠️ DISCLOSURE**: Add prominent warning to README.md that this provides audit logging only, NOT enforcement

2. **🔒 RENAME**: Consider renaming from "Boundary Daemon" to "Boundary Auditor" to reflect actual capabilities

3. **📋 DOCUMENT**: Clearly document that external systems MUST respect daemon decisions - this is a contract, not enforcement

### For Real Security:

4. **Integration with OS Security:**
   - Add SELinux/AppArmor policy generation
   - Create iptables/nftables rules for network blocking
   - Use kernel security modules

5. **Process Isolation:**
   - Run protected workloads in separate containers
   - Use namespace isolation
   - Implement mandatory access control

6. **Hardware Integration:**
   - Script BIOS changes (disable USB)
   - Physical network switches (not software)
   - Hardware security module for logging

7. **Watchdog System:**
   - External process that monitors daemon health
   - Automatic system shutdown if daemon fails
   - Hardware watchdog timer

### Defense in Depth:

8. **Add kernel-level enforcement** (most important)
9. **Run daemon as PID 1 in a container** (harder to kill)
10. **Sign all code** and verify on startup
11. **Store logs on append-only filesystem**
12. **Add rate limiting** to API
13. **Implement real human verification** (hardware token)

---

## Conclusion

### Is this system securing anything?

**No** - Not in its current form.

The Boundary Daemon is well-architected and correctly implements its *intended* functionality. The code quality is good, the logging is comprehensive, and the policy logic is sound.

**However**, it provides **security theater** rather than real security:
- It *tells* you when rules are violated
- It *asks* other systems to follow the rules
- It *logs* everything that happens
- **But it cannot *enforce* anything**

### For Real Data Security:

This daemon should be **one component** in a defense-in-depth strategy:
- **Layer 1**: Kernel-level enforcement (SELinux, seccomp)
- **Layer 2**: Container isolation (Docker, Kubernetes)
- **Layer 3**: This daemon (policy decisions, audit logging)
- **Layer 4**: Application-level cooperation (Memory Vault, Agent-OS)
- **Layer 5**: Hardware controls (USB disabled, air-gapped network)

**As a standalone system**: It's an audit log with policy recommendations.
**As part of a larger system**: It could be valuable as the coordination layer.

### Final Verdict:

**The system is doing what it's designed to do - but what it's designed to do is insufficient for real data security.** It needs integration with OS-level enforcement mechanisms to move from "detection and logging" to "prevention and enforcement."

---

## Testing Performed

1. ✅ Event logger hash chain verification
2. ✅ Policy engine decision logic
3. ✅ Tripwire detection mechanisms
4. ✅ Mode transition handling
5. ✅ API client/server communication
6. ⚠️ Enforcement bypass tests (confirmed: bypassable)
7. ⚠️ Network blocking (confirmed: not blocked)
8. ⚠️ USB prevention (confirmed: not prevented)
9. ⚠️ Daemon kill test (confirmed: killable)
10. ⚠️ Log tampering test (confirmed: deletable)

---

## Code Quality Notes

**Positive:**
- Clean, readable code
- Good use of type hints
- Proper threading with locks
- Comprehensive error handling
- Minimal dependencies (good for security)
- Well-structured modular design

**Negative:**
- No input validation on API
- No authentication on Unix socket
- Missing rate limiting
- No self-integrity checks

---

## Remediation Details (2026-01-01 Update)

### Enforcement Modules Added

The following enforcement modules have been implemented to address critical issues:

#### 1. Network Enforcement (`daemon/enforcement/network_enforcer.py`)
- **Linux**: iptables/nftables rule management
- **Windows**: Windows Firewall via netsh/PowerShell (`windows_firewall.py`)
- **Mode-based rules**: Automatic rule application on mode transitions
- **Requirements**: Root privileges, `BOUNDARY_NETWORK_ENFORCE=1`

#### 2. USB Enforcement (`daemon/enforcement/usb_enforcer.py`)
- udev rules for device authorization
- Device baseline tracking
- Forcible unmount capabilities
- **Requirements**: Root privileges, `BOUNDARY_USB_ENFORCE=1`

#### 3. Process Enforcement (`daemon/enforcement/process_enforcer.py`)
- seccomp-bpf syscall filtering
- Container isolation (podman/docker)
- External watchdog process
- **Requirements**: Root privileges, `BOUNDARY_PROCESS_ENFORCE=1`

### Security Modules Added

#### Clock Protection (`daemon/security/clock_monitor.py`)
- Time manipulation detection (jumps, drift)
- NTP sync verification
- Monotonic time for rate limiting
- Secure timer class

#### API Authentication (`daemon/auth/api_auth.py`)
- Token-based authentication (256-bit entropy)
- Capability-based access control (9 capabilities)
- Constant-time token comparison

#### Rate Limiting (`daemon/auth/persistent_rate_limiter.py`)
- Per-command rate limits
- Persistence across restarts
- Monotonic clock (manipulation-resistant)

#### Log Hardening (`daemon/storage/log_hardening.py`)
- Linux chattr +a (append-only)
- Secure file permissions
- Integrity verification

#### Code Integrity (`daemon/integrity/`)
- Ed25519 code signing
- Runtime integrity verification
- Manifest-based verification

#### Biometric Verification (`daemon/auth/biometric_verifier.py`)
- Fingerprint recognition
- Facial recognition with liveness detection
- Template encryption

### AI/Agent Security Stack

New modules specifically for AI/LLM security:

- **Prompt Injection Detection** (`security/prompt_injection.py`) - 50+ patterns
- **Tool Output Validation** (`security/tool_validator.py`) - Chain depth, PII, rate limits
- **Response Guardrails** (`security/response_guardrails.py`) - Content safety, hallucination detection
- **RAG Injection Detection** (`security/rag_injection.py`) - Poisoned document detection
- **Agent Attestation** (`security/agent_attestation.py`) - Cryptographic identity, CBAC

### Remaining Recommendations

While most issues are addressed, consider:

1. **Hardware Security Key Support** - YubiKey/FIDO2 for ceremonies
2. **HSM Integration** - For enterprise key management
3. **FIPS 140-2/3 Certification** - For government deployments
4. **External Log Anchoring** - Blockchain or timestamping service

---

---

## Moltbook/OpenClaw Vulnerability Review (2026-02-19)

> Cross-referencing the Boundary Daemon against the 10 vulnerability categories
> identified in the [Moltbook/OpenClaw case study](https://github.com/kase1111-hash/Claude-prompts/blob/main/Moltbook-OpenClaw-Vulnerabilities.md).
> Each category is assessed against the codebase with specific file/line references.

### Vuln #1: Indirect Prompt Injection

**Status:** MITIGATED - Strong detection in place

The daemon has 50+ prompt injection patterns in `daemon/security/prompt_injection.py`
covering DAN attacks, encoding bypasses, delimiter injection, Unicode homoglyphs,
and zero-width character abuse. Detection operates at four sensitivity levels
(low, medium, high, paranoid).

**Remaining gap:** Pattern-based detection is inherently a blocklist approach.
Novel injection techniques not matching existing patterns will bypass detection.
Consider adding embedding-based semantic anomaly detection as a second layer.

### Vuln #2: Memory Poisoning / Time-Shifted Injection

**Status:** CRITICAL GAPS FIXED (this review)

| Finding | Severity | Location | Fix Applied |
|---------|----------|----------|-------------|
| External documents with UNKNOWN provenance silently passed through | CRITICAL | `daemon/security/rag_injection.py:345-359` | Yes - quarantine UNKNOWN docs |
| NatLangChain entries lack provenance tracking | HIGH | `daemon/messages/message_checker.py:35-66` | Yes - added `source_trust` field |
| RecallGate checks memory class but not source trustworthiness | HIGH | `daemon/integrations.py:47-74` | No - requires Memory Vault changes |
| Prompt injection detector lacked memory poisoning defense-in-depth | MEDIUM | `daemon/security/prompt_injection.py` | Existing patterns adequate |

**Fixes applied:**
- `rag_injection.py`: Documents with UNKNOWN provenance are now quarantined instead
  of silently passed through. Documents must be from trusted sources or have verified
  content hashes.
- `message_checker.py`: Added `source_trust` and `ingestion_context` fields to
  NatLangChainEntry with hash integrity protection. External/unknown entries now
  require cryptographic signatures.

### Vuln #3: Malicious Skills / Supply Chain

**Status:** HIGH - Unsigned runtime code paths

| Finding | Severity | Location |
|---------|----------|----------|
| `code_signer.py` exists but `verify_signature()` is never called at runtime | HIGH | `daemon/integrity/code_signer.py:438-469` |
| Dynamic module loading via `importlib.exec_module()` without signature check | HIGH | `daemon/boundary_daemon.py:47-54` |
| Optional modules loaded at startup without verification | HIGH | `daemon/boundary_daemon.py:74-170` |
| `features.py` uses `__import__()` for feature detection | MEDIUM | `daemon/features.py:43-49` |

**Recommendation:** Integrate `CodeSigner.verify_signature()` into the module loading
path in `boundary_daemon.py`. All modules should have Ed25519 signatures verified
before `exec_module()` is called.

### Vuln #4: Bot-to-Bot Social Engineering

**Status:** CRITICAL GAPS FIXED (this review)

| Finding | Severity | Location | Fix Applied |
|---------|----------|----------|-------------|
| Agent authority claims accepted without cryptographic proof | CRITICAL | `daemon/messages/message_checker.py:400-407` | Yes |
| No human-in-the-loop for destructive agent-to-agent commands | CRITICAL | `daemon/integrations.py:375-579` | Yes |
| Ceremony system is human-focused, not integrated with agent messages | HIGH | `daemon/integrations.py:509-579` | Partial |
| `requires_consent` flag is self-asserted by sending agent | HIGH | `daemon/messages/message_checker.py:405` | Yes |

**Fixes applied:**
- `message_checker.py`: Added destructive action pattern detection with mandatory
  `ceremony_completed` metadata requirement. Destructive actions (delete account,
  transfer funds, revoke permissions, etc.) now require human ceremony approval
  regardless of authority level.
- `message_checker.py`: Authority levels >= 2 now require cryptographic attestation
  tokens verified against the AgentAttestationSystem.

### Vuln #5: Credential Leakage

**Status:** HIGH - Multiple credential exposure vectors

| Finding | Severity | Location |
|---------|----------|----------|
| Plaintext bootstrap token fallback in `_write_bootstrap_fallback()` | HIGH | `daemon/auth/api_auth.py:495-528` |
| Predictable credential file paths (./config/, ~/.boundary-daemon/) | MEDIUM | Multiple TUI/API files |
| `BOUNDARY_API_TOKEN` env var support (inheritable, visible in /proc) | MEDIUM | `daemon/auth/secure_token_storage.py:583-614` |
| Config salt file in predictable location | MEDIUM | `daemon/config/secure_config.py:287-290` |
| Token files searchable via well-known directory scanning | MEDIUM | `boundary-tui/boundary_tui/client.py:527-549` |

**Fixes applied:**
- `prompt_injection.py`: Added credential exfiltration detection patterns to catch
  attempts to extract credentials through agent communication channels.

**Remaining recommendations:**
- Remove plaintext token fallback; fail-fast if encryption unavailable
- Deprecate `BOUNDARY_API_TOKEN` env var in favor of file-based tokens only
- Randomize credential file paths or use OS keychain integration

### Vuln #6: Unsandboxed Host Execution

**Status:** MITIGATED - Strong sandbox infrastructure

The daemon has comprehensive sandboxing via `daemon/sandbox/` (namespace isolation,
seccomp-bpf syscall filtering, cgroups v2 resource limits, per-sandbox firewall rules).
The `SandboxEnforcementBridge` integrates sandbox management with policy decisions.

**Remaining gap:** Sandbox modules are optional and require root. When running without
root, enforcement degrades silently. The `privilege_manager.py` tracks this, but
operators may not realize enforcement is absent.

### Vuln #7: Fetch-and-Execute

**Status:** HIGH - Multiple remote fetch patterns

| Finding | Severity | Location |
|---------|----------|----------|
| OIDC discovery fetches remote JSON without origin validation | HIGH | `daemon/identity/oidc_validator.py:168-187` |
| JWKS endpoint fetched from untrusted remote discovery response | HIGH | `daemon/identity/oidc_validator.py:189-217` |
| HTTP log shipper sends to configurable endpoints | MEDIUM | `daemon/external_integrations/siem/log_shipper.py:464-527` |
| Threat intel HTTP requests to AbuseIPDB/VirusTotal | MEDIUM | `daemon/security/threat_intel.py:419-469` |
| `importlib.exec_module()` on file-based module without verification | HIGH | `daemon/boundary_daemon.py:47-54` |

**Fixes applied:**
- `prompt_injection.py`: Added fetch-and-execute detection patterns (C2 check-in,
  heartbeat/beacon, remote content execution, periodic polling).

**Remaining recommendations:**
- Add TLS certificate pinning for OIDC endpoints
- Gate all external HTTP requests behind boundary mode checks (block in AIRGAP)
- Add code signature verification before `exec_module()`

### Vuln #8: Identity Spoofing / Impersonation

**Status:** CRITICAL GAPS FIXED (this review)

| Finding | Severity | Location | Fix Applied |
|---------|----------|----------|-------------|
| `sender_agent` accepted as plain string without verification | CRITICAL | `daemon/messages/message_checker.py:381-384` | Yes |
| `authority_level` self-asserted without cryptographic proof | CRITICAL | `daemon/messages/message_checker.py:400-407` | Yes |
| AgentAttestationSystem exists but NOT integrated with message checking | CRITICAL | `daemon/security/agent_attestation.py:509-694` | Yes |
| FileCoordinator accepts operations without node authentication | HIGH | `daemon/distributed/coordinators.py:141-169` | No |

**Fixes applied:**
- `message_checker.py`: Integrated attestation system verification. Messages with
  `authority_level >= 2` now require a valid `attestation_token` in metadata.
  The token's agent identity is cross-checked against the claimed `sender_agent`.
- `integrations.py`: MessageGate now accepts and forwards `attestation_system` to
  the MessageChecker for runtime verification.

### Vuln #9: Vibe-Coded Infrastructure

**Status:** LOW - Well-architected codebase

The Boundary Daemon does NOT exhibit "vibe-coded" characteristics:
- No hardcoded secrets found in source code
- Token generation uses `secrets.token_urlsafe()` (cryptographically secure)
- Token storage uses SHA-256 hashing (not plaintext)
- Token comparison uses `hmac.compare_digest()` (constant-time)
- Rate limiting persists across daemon restarts
- Configuration uses PBKDF2 with 480,000 iterations
- Log chain uses SHA-256 hash chains with Ed25519 signatures

The codebase demonstrates deliberate security engineering rather than
auto-generated or copy-paste patterns.

### Vuln #10: Uncontrolled Agent Coordination

**Status:** HIGH GAPS FIXED (this review)

| Finding | Severity | Location | Fix Applied |
|---------|----------|----------|-------------|
| No rate limiting on agent-to-agent messages | HIGH | `daemon/integrations.py:260-323` | Yes |
| FileCoordinator has no authentication for inter-node ops | HIGH | `daemon/distributed/coordinators.py:141-169` | No |
| Persistent rate limiter not tied to agent identity verification | MEDIUM | `daemon/auth/persistent_rate_limiter.py:393-444` | No |
| No audit trail for agent communication channel creation/destruction | MEDIUM | `daemon/boundary_daemon.py` | No |

**Fixes applied:**
- `integrations.py`: Added per-agent-pair rate limiting (200 messages/minute default)
  to the MessageGate to prevent runaway machine-speed coordination that outpaces
  human oversight.

### Summary of Fixes Applied in This Review

| File | Changes | Vulns Addressed |
|------|---------|-----------------|
| `daemon/messages/message_checker.py` | Attestation integration, destructive action detection, provenance tracking | #2, #4, #8 |
| `daemon/security/rag_injection.py` | UNKNOWN provenance document quarantine | #2 |
| `daemon/security/prompt_injection.py` | Fetch-execute, C2, credential exfil patterns | #5, #7 |
| `daemon/integrations.py` | Agent-to-agent rate limiting, attestation forwarding | #8, #10 |

### Remaining Open Items (Require Follow-Up)

1. **Supply Chain (Vuln #3):** Integrate `CodeSigner.verify_signature()` into runtime module loading
2. **Credential Leakage (Vuln #5):** Remove plaintext token fallback, deprecate env var support
3. **Fetch-Execute (Vuln #7):** Add TLS cert pinning for OIDC, gate HTTP behind mode checks
4. **Identity Spoofing (Vuln #8):** Add node authentication to FileCoordinator
5. **Agent Coordination (Vuln #10):** Add audit trail for channel lifecycle events

---

**Report Version:** 3.0
**Classification:** CONFIDENTIAL
**Distribution:** Security Team Only
**Last Updated:** 2026-02-19
