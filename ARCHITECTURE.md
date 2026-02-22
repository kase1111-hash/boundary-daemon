# Boundary Daemon Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         BOUNDARY DAEMON                              │
│                        (Agent Smith)                                 │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                  Main Service Orchestrator                  │   │
│  │                  (boundary_daemon.py)                       │   │
│  └──────┬─────────────────┬─────────────────┬──────────────┬──┘   │
│         │                 │                 │              │        │
│         ▼                 ▼                 ▼              ▼        │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────┐  ┌──────────────┐│
│  │   State     │  │   Policy    │  │ Tripwire │  │    Event     ││
│  │  Monitor    │  │   Engine    │  │  System  │  │   Logger     ││
│  └──────┬──────┘  └──────┬──────┘  └────┬─────┘  └──────┬───────┘│
│         │                │                │                │        │
│         │    ┌───────────┴────────────────┴────────────────┘        │
│         │    │                                                      │
│         │    ▼                                                      │
│         │  ┌──────────────────────────────────┐                    │
│         │  │      API Server (Unix Socket)    │                    │
│         │  │      (boundary_api.py)           │                    │
│         │  └────────────┬─────────────────────┘                    │
│         │               │                                           │
│         ▼               ▼                                           │
│  ┌──────────────┐   ┌─────────────────┐                           │
│  │ Environment  │   │  External Apps  │                           │
│  │   Sensors    │   │  • Memory Vault │                           │
│  │ • Network    │   │  • Agent-OS     │                           │
│  │ • Hardware   │   │  • synth-mind   │                           │
│  │ • Processes  │   │  • boundaryctl  │                           │
│  └──────────────┘   └─────────────────┘                           │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. State Monitor (`state_monitor.py`)

**Purpose**: Continuously sense the environment to detect trust conditions.

**Responsibilities**:
- Monitor network state (interfaces, connectivity, VPN)
- Detect hardware changes (USB devices, block devices, TPM)
- Track software state (processes, external model endpoints)
- Check human presence signals (keyboard, screen)

**Key Classes**:
- `StateMonitor` - Main monitoring loop
- `EnvironmentState` - Snapshot of current environment
- `NetworkState` - Online/offline enum
- `HardwareTrust` - Low/medium/high enum

**Data Flow**:
```
Environment → Poll (1Hz) → EnvironmentState → Callbacks → PolicyEngine
```

### 2. Policy Engine (`policy_engine.py`)

**Purpose**: Enforce boundary modes and evaluate policy decisions.

**Responsibilities**:
- Maintain current boundary mode
- Evaluate policy requests (recall, tool, model, IO)
- Enforce mode transitions
- Map memory classes to required modes

**Key Classes**:
- `PolicyEngine` - Main policy evaluator
- `BoundaryMode` - Enum of security modes (OPEN → LOCKDOWN)
- `PolicyRequest` - Request for permission
- `PolicyDecision` - ALLOW/DENY/CEREMONY

**Policy Function**:
```
(mode × environment × request) → decision
```

**Decision Matrix**:
| Request | OPEN | RESTRICTED | TRUSTED | AIRGAP | COLDROOM | LOCKDOWN |
|---------|------|------------|---------|--------|----------|----------|
| Memory 0-1 | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| Memory 2 | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| Memory 3 | ✗ | ✗ | ✓ | ✓ | ✓ | ✗ |
| Memory 4 | ✗ | ✗ | ✗ | ✓ | ✓ | ✗ |
| Memory 5 | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ |
| Network Tool | ✓ | ✓ | VPN | ✗ | ✗ | ✗ |
| USB Tool | ✓ | Ceremony | ✗ | ✗ | ✗ | ✗ |

### 3. Tripwire System (`tripwires.py`)

**Purpose**: Detect security violations and trigger lockdown.

**Responsibilities**:
- Monitor for boundary violations
- Trigger immediate lockdown on violation
- Track violation history
- Manage lockdown state

**Key Classes**:
- `TripwireSystem` - Violation detector
- `LockdownManager` - Lockdown state manager
- `TripwireViolation` - Record of violation
- `ViolationType` - Enum of violation types

**Tripwire Rules**:
```
IF mode >= AIRGAP AND network == ONLINE:
    → LOCKDOWN

IF mode >= COLDROOM AND usb_inserted:
    → LOCKDOWN

IF unauthorized_recall:
    → LOCKDOWN

IF daemon_health_check_failed:
    → LOCKDOWN
```

### 4. Event Logger (`event_logger.py`)

**Purpose**: Maintain immutable, tamper-evident audit log.

**Responsibilities**:
- Log all boundary events
- Maintain hash chain for integrity
- Verify chain integrity
- Export logs for archival

**Key Classes**:
- `EventLogger` - Main logging interface
- `BoundaryEvent` - Single event record
- `EventType` - Enum of event types

**Hash Chain Structure**:
```
Event 0: {data, hash_chain: "000...000"}
         hash = SHA256(Event 0)

Event 1: {data, hash_chain: hash(Event 0)}
         hash = SHA256(Event 1)

Event 2: {data, hash_chain: hash(Event 1)}
         ...
```

**Verification**:
```python
for each event:
    expected_hash = SHA256(previous_event)
    if event.hash_chain != expected_hash:
        return INVALID
```

### 5. Integrations (`integrations.py`)

**Purpose**: High-level interfaces for Agent OS components.

**Key Classes**:
- `RecallGate` - Memory Vault integration
- `ToolGate` - Agent-OS tool integration
- `CeremonyManager` - Human override system

**Integration Flow**:

**Memory Vault**:
```
Memory Vault
    ↓ check_recall(memory_class)
RecallGate
    ↓ check_recall_permission(memory_class)
BoundaryDaemon
    ↓ evaluate_policy(request, env)
PolicyEngine
    ↓ [ALLOW/DENY]
Return to Memory Vault
```

**Tool Execution**:
```
Agent-OS
    ↓ check_tool(tool_name, requirements)
ToolGate
    ↓ check_tool_permission(...)
BoundaryDaemon
    ↓ evaluate_policy(request, env)
PolicyEngine
    ↓ [ALLOW/DENY]
Return to Agent-OS
```

**Human Override Ceremony**:
```
1. Initiate override
2. Verify human presence (keyboard input)
3. Mandatory cooldown (30s)
4. Final confirmation
5. Execute override
6. Log to immutable chain
```

### 6. API Server (`boundary_api.py`)

**Purpose**: Unix socket interface for external components.

**Responsibilities**:
- Accept API requests via Unix socket
- Process commands (status, check_recall, check_tool, etc.)
- Return JSON responses
- Enforce permissions

**API Commands**:
- `status` - Get daemon status
- `check_recall` - Check memory permission
- `check_tool` - Check tool permission
- `set_mode` - Change boundary mode
- `get_events` - Retrieve recent events
- `verify_log` - Verify log integrity

**Request Format**:
```json
{
    "command": "check_recall",
    "params": {
        "memory_class": 3
    }
}
```

**Response Format**:
```json
{
    "success": true,
    "permitted": false,
    "reason": "Recall denied: requires TRUSTED mode, currently in OPEN"
}
```

### 7. Main Daemon (`boundary_daemon.py`)

**Purpose**: Orchestrate all components and provide unified interface.

**Responsibilities**:
- Initialize all subsystems
- Connect components via callbacks
- Provide public API methods
- Handle signals (SIGINT, SIGTERM)
- Periodic health checks

**Initialization Flow**:
```
1. Create EventLogger
2. Create StateMonitor
3. Create PolicyEngine
4. Create TripwireSystem
5. Create LockdownManager
6. Register callbacks between components
7. Start StateMonitor
8. Start enforcement loop
9. Create API server
```

**Callback Wiring**:
```
StateMonitor.on_change()
    ↓
PolicyEngine.update_environment()
TripwireSystem.check_violations()
    ↓ (if violation)
LockdownManager.trigger_lockdown()
PolicyEngine.transition_mode(LOCKDOWN)
```

## Data Flow

### Startup Sequence

```
1. Load configuration
2. Initialize event logger
3. Log DAEMON_START event
4. Initialize state monitor
5. Initialize policy engine (initial mode)
6. Initialize tripwire system
7. Register callbacks
8. Start state monitor thread
9. Start enforcement loop thread
10. Start API server thread
11. Ready to accept requests
```

### Request Processing

```
External Component (e.g., Memory Vault)
    ↓ Unix Socket / Python API
BoundaryAPIServer / BoundaryAPIClient
    ↓
BoundaryDaemon.check_recall_permission()
    ↓
PolicyEngine.evaluate_policy()
    ├─ Get current mode
    ├─ Get environment state
    └─ Apply policy rules
    ↓
Log decision to EventLogger
    ↓
Return decision to caller
```

### Tripwire Detection

```
StateMonitor polls environment (1Hz)
    ↓
Detect state change
    ↓
Callback to PolicyEngine.update_environment()
Callback to TripwireSystem.check_violations()
    ↓
Violation detected?
    ├─ No → Continue monitoring
    └─ Yes ↓
         Create TripwireViolation record
         Callback to violation handlers
         Log TRIPWIRE event
         LockdownManager.trigger_lockdown()
         PolicyEngine.transition_mode(LOCKDOWN)
         Display alert
```

### Mode Transition

```
Request mode change
    ↓
PolicyEngine.transition_mode(new_mode, operator, reason)
    ↓
Check if transition allowed
    ├─ From LOCKDOWN? Require human operator
    └─ Valid transition
    ↓
Update boundary state
Log MODE_CHANGE event
Notify callbacks
    ↓
All components see new mode
```

## Failure Modes

### Daemon Crash
```
Daemon process dies
    ↓
Systemd detects failure
    ↓
FailureAction=halt (in systemd service)
    ↓
System enters emergency mode
```

### Component Failures

**StateMonitor fails**:
```
Error in monitoring loop
    ↓
Log error
Continue with last known state
    ↓
Health check detects failure
    ↓
Trigger lockdown (fail-closed)
```

**PolicyEngine ambiguous**:
```
Cannot determine decision
    ↓
Fail closed: DENY
    ↓
Log ambiguity event
```

**EventLogger failure**:
```
Cannot write to log
    ↓
Raise exception
    ↓
Daemon should halt (critical failure)
```

**API Server failure**:
```
Socket error
    ↓
Log error
Attempt to restart server
    ↓
If persistent, continue daemon operation
External components cannot connect (fail-closed)
```

## Security Properties

### 1. Fail-Closed
- Unknown states → DENY
- Component failures → LOCKDOWN
- Ambiguous signals → DENY

### 2. Immutable Logging
- All events logged with hash chain
- Tamper detection via chain verification
- Append-only log file

### 3. Mandatory Enforcement
- Components MUST call check functions
- No bypass mechanism
- Architecture violation if bypassed

### 4. Deterministic Decisions
- Same inputs → same decision
- No randomness
- Reproducible for audit

### 5. Human Oversight
- Ceremony for overrides
- No silent bypasses
- Cooldown delays
- Immutable log entries

## Performance Characteristics

### Latency
- State monitoring: 1 Hz (1 second interval)
- Policy evaluation: < 1 ms
- API request: < 10 ms
- Log write: < 5 ms (with fsync)

### Resource Usage
- Memory: ~50 MB (steady state)
- CPU: < 1% (idle), < 5% (active monitoring)
- Disk: ~1 KB per event (log growth)
- Network: None (local only)

### Scalability
- Single daemon per host (default)
- Optional distributed coordination via `daemon/distributed/` (cluster manager, consensus)
- Handles ~1000 requests/sec
- Log size: ~1 GB per million events

## Thread Model

```
Main Thread:
    - Initialization
    - Signal handling
    - Cleanup

State Monitor Thread (daemon):
    - Continuous environment polling
    - Callback invocation

Enforcement Loop Thread:
    - Periodic health checks
    - Lockdown enforcement

API Server Thread (daemon):
    - Unix socket listener
    - Spawn client handler threads

Client Handler Threads (daemon, transient):
    - Process API requests
    - Return responses
```

## Dependencies

**External**:
- `psutil` - System monitoring (network, hardware, processes)
- `cryptography` - Encryption and key derivation (Fernet, PBKDF2)
- `pynacl` - Ed25519 digital signatures for event signing
- `cffi` - C library bindings (dependency of pynacl)

**Standard Library**:
- `socket` - Unix socket API
- `threading` - Concurrent components
- `json` - API serialization
- `hashlib` - Event log hashing (SHA-256)
- `signal` - Signal handling
- `os`, `sys` - System operations
- `subprocess` - External command execution
- `dataclasses` - Structured data types

**Minimalism**: By design, very few dependencies to reduce attack surface.

## Additional Components

### Authentication (`daemon/auth/`)

| Module | Purpose |
|--------|---------|
| `api_auth.py` | Token-based API authentication with capabilities |
| `enhanced_ceremony.py` | Multi-step human override with mandatory cooldown |
| `biometric_verifier.py` | Biometric authentication support |
| `secure_token_storage.py` | Encrypted token storage using Fernet |
| `persistent_rate_limiter.py` | Rate limiting with persistence across restarts |

### Enforcement (`daemon/enforcement/`)

Kernel-level enforcement modules (Linux only, requires root):

| Module | Purpose |
|--------|---------|
| `network_enforcer.py` | Network isolation via iptables/nftables rules |
| `usb_enforcer.py` | USB device control via udev |
| `process_enforcer.py` | Process isolation via containers (podman/docker) |
| `secure_process_termination.py` | Safe process termination with cleanup |
| `secure_profile_manager.py` | AppArmor/SELinux profile management |
| `protection_persistence.py` | Persistent enforcement rules storage |

### Security Monitoring (`daemon/security/`)

Multi-layer security detection and monitoring:

| Module | Purpose |
|--------|---------|
| `antivirus.py` | Malware scanning and detection |
| `daemon_integrity.py` | Self-verification and tampering detection |
| `dns_security.py` | DNS monitoring and spoofing detection |
| `arp_security.py` | ARP spoofing and MITM detection |
| `wifi_security.py` | WiFi security monitoring and rogue AP detection |
| `process_security.py` | Process anomaly detection |
| `traffic_anomaly.py` | Network traffic analysis |
| `file_integrity.py` | File change monitoring via hash verification |
| `code_advisor.py` | Code vulnerability analysis |
| `threat_intel.py` | Threat intelligence integration |
| `clock_monitor.py` | System clock verification and time attack detection |
| `secure_memory.py` | Memory protection utilities |

### AI/Agent Security (`daemon/security/`)

Specialized security for AI agents and LLM systems:

| Module | Purpose |
|--------|---------|
| `prompt_injection.py` | Jailbreak, instruction injection, and prompt manipulation detection |
| `tool_validator.py` | Tool output validation, sanitization, and rate limiting |
| `response_guardrails.py` | AI response safety, harmful content blocking, hallucination detection |
| `rag_injection.py` | RAG poisoning detection, indirect injection via retrieved documents |
| `agent_attestation.py` | Cryptographic agent identity, capability-based access control |

**AI Security Flow:**
```
User Input → Prompt Injection Detector → Agent
                                            ↓
                                      Tool Invocation
                                            ↓
                            Tool Validator (input/output)
                                            ↓
                                      RAG Pipeline
                                            ↓
                            RAG Injection Detector (documents)
                                            ↓
                                      Agent Response
                                            ↓
                            Response Guardrails (safety/hallucination)
                                            ↓
                                       User Output
```

**Agent Attestation System:**
```
Agent Registration → Identity Certificate → Attestation Token
                                                    ↓
                                            Capability Verification
                                                    ↓
                                            Action Binding (signed)
                                                    ↓
                                            Delegation Chains
```

### Storage (`daemon/storage/`)

| Module | Purpose |
|--------|---------|
| `append_only.py` | Append-only log file implementation |
| `log_hardening.py` | Log security hardening (chattr +a, permissions) |

### PII Detection (`daemon/pii/`)

| Module | Purpose |
|--------|---------|
| `detector.py` | PII pattern detection (SSN, email, phone, etc.) |
| `bypass_resistant_detector.py` | Advanced obfuscation-resistant PII detection |
| `filter.py` | PII filtering and redaction |

### Utilities (`daemon/utils/`)

| Module | Purpose |
|--------|---------|
| `error_handling.py` | Robust error handling framework with categorization, aggregation, and retry logic |

### Error Handling Framework

The error handling framework provides consistent error management:

```python
from daemon.utils.error_handling import (
    ErrorCategory,
    ErrorSeverity,
    handle_error,
    with_error_handling,
    safe_execute,
)

# Decorator usage
@with_error_handling(category=ErrorCategory.SECURITY, retry_count=3)
def my_function():
    ...

# Context manager usage
with safe_execute("operation_name", ErrorCategory.NETWORK) as result:
    result.value = risky_operation()
```

**Error Categories**: SECURITY, AUTH, NETWORK, FILESYSTEM, SYSTEM, CONFIG, PLATFORM, RESOURCE, EXTERNAL, UNKNOWN

**Error Severities**: INFO, WARNING, ERROR, CRITICAL, FATAL

### SIEM Integration (`daemon/integrations/siem/`)

Enterprise SIEM integration for security event streaming:

| Module | Purpose |
|--------|---------|
| `cef_leef.py` | CEF/LEEF event formatting for Splunk/QRadar/ArcSight |
| `log_shipper.py` | Event shipping via Kafka, S3, GCS, HTTP |
| `sandbox_events.py` | Real-time sandbox event streaming |
| `verification_api.py` | Signature verification API for SIEMs |

### Identity Federation (`daemon/identity/`)

External identity provider integration:

| Module | Purpose |
|--------|---------|
| `identity_manager.py` | Central identity management |
| `oidc_validator.py` | OIDC token validation |
| `ldap_mapper.py` | LDAP group to capability mapping |
| `pam_integration.py` | PAM integration for system auth |

### Compliance Automation (`daemon/compliance/`)

Compliance evidence and reporting:

| Module | Purpose |
|--------|---------|
| `control_mapping.py` | NIST 800-53 / ISO 27001 control mapping |
| `evidence_bundle.py` | Auditor evidence bundle generation |
| `access_review.py` | Periodic access review ceremonies |
| `zk_proofs.py` | Zero-knowledge proof support |

### Cryptographic Modules (`daemon/crypto/`)

Advanced cryptography support:

| Module | Purpose |
|--------|---------|
| `hsm_provider.py` | HSM abstraction (PKCS#11, CloudHSM, YubiHSM) |
| `post_quantum.py` | Post-quantum cryptography (Kyber, Dilithium) |

### eBPF Observability (`daemon/ebpf/`)

Kernel-level observability without kernel driver:

| Module | Purpose |
|--------|---------|
| `ebpf_observer.py` | eBPF event observer |
| `probes.py` | eBPF probe definitions |
| `policy_integration.py` | Policy-eBPF integration |

### Air-Gap Operations (`daemon/airgap/`)

Specialized modules for air-gapped environments:

| Module | Purpose |
|--------|---------|
| `data_diode.py` | One-way data transfer (log export) |
| `qr_ceremony.py` | QR code-based ceremonies |
| `sneakernet.py` | Secure sneakernet protocol |

### Threat Federation (`daemon/federation/`)

Multi-organization threat sharing:

| Module | Purpose |
|--------|---------|
| `threat_mesh.py` | Privacy-preserving threat intelligence sharing |

### Security Intelligence (`daemon/intelligence/`)

Intelligent security recommendations:

| Module | Purpose |
|--------|---------|
| `mode_advisor.py` | Predictive mode recommendations based on context |

### Alert Management (`daemon/alerts/`)

Alert lifecycle management:

| Module | Purpose |
|--------|---------|
| `case_manager.py` | Case lifecycle (NEW → INVESTIGATING → RESOLVED) |

### Code Integrity (`daemon/integrity/`)

Code signing and verification:

| Module | Purpose |
|--------|---------|
| `code_signer.py` | Ed25519 code signing utilities |
| `integrity_verifier.py` | Runtime integrity verification |

### Agent Containment (`daemon/containment/`)

AI agent behavior monitoring:

| Module | Purpose |
|--------|---------|
| `agent_profiler.py` | Agent behavior profiling and anomaly detection |

### Terminal UI (`daemon/tui/`)

Real-time visibility:

| Module | Purpose |
|--------|---------|
| `dashboard.py` | TUI dashboard for real-time status |

### Configuration Linting (`daemon/config/`)

Configuration validation:

| Module | Purpose |
|--------|---------|
| `linter.py` | Config validation and security posture scoring |

## Configuration

Configuration is minimal and security-focused:

```ini
[daemon]
initial_mode = open
log_dir = /var/log/boundary-daemon
socket_path = /var/run/boundary-daemon/boundary.sock

[tripwires]
enabled = true
auto_lockdown = true

[ceremony]
cooldown_seconds = 30

[security]
fail_closed = true
```

## Deployment Architectures

### Development Mode
```
Developer workstation
    ↓
Run daemon locally
    ↓
Unix socket in ./api/boundary.sock
Logs in ./logs/
```

### Production Mode
```
Agent OS host
    ↓
Systemd service
    ↓
Unix socket in /var/run/boundary-daemon/
Logs in /var/log/boundary-daemon/
    ↓
Start on boot
Auto-restart on failure
```

### Multi-Component Integration
```
Memory Vault ──┐
Agent-OS ──────┼──→ Unix Socket ──→ Boundary Daemon
synth-mind ────┘
```

## Implemented Enhancement Plans

The following enhancement plans have been implemented:

### Core Security (Plans 1-10)

1. **Plan 1: Kernel-Level Enforcement** - Network, USB, and process enforcement via iptables, udev, and containers (`daemon/enforcement/`)
2. **Plan 2: TPM Integration** - Hardware attestation and sealed secrets (`daemon/hardware/tpm_manager.py`)
3. **Plan 3: Cryptographic Log Signing** - Ed25519 signatures on events (`daemon/signed_event_logger.py`)
4. **Plan 4: Distributed Deployment** - Multi-host coordination (`daemon/distributed/`)
5. **Plan 5: Custom Policy DSL** - Policy language and evaluation (`daemon/policy/custom_policy_engine.py`)
6. **Plan 6: Biometric Authentication** - Biometric verification for ceremonies (`daemon/auth/biometric_verifier.py`)
7. **Plan 7: Code Vulnerability Advisor** - Code scanning (`daemon/security/code_advisor.py`)
8. **Plan 8: Log Watchdog Agent** - Log pattern monitoring (`daemon/watchdog/`)
9. **Plan 9: OpenTelemetry Integration** - Observability (`daemon/telemetry/otel_setup.py`)
10. **Plan 10: AI/Agent Security** - Comprehensive AI security stack:
    - Prompt injection detection (`daemon/security/prompt_injection.py`)
    - Tool output validation (`daemon/security/tool_validator.py`)
    - Response guardrails (`daemon/security/response_guardrails.py`)
    - RAG injection detection (`daemon/security/rag_injection.py`)
    - Agent attestation system (`daemon/security/agent_attestation.py`)

### Enterprise Features (Plans 11-20)

11. **Plan 11: SIEM Integration** - CEF/LEEF export, Kafka/S3 shipping (`daemon/integrations/siem/`)
12. **Plan 12: Identity Federation** - OIDC, LDAP, PAM integration (`daemon/identity/`)
13. **Plan 13: Compliance Automation** - NIST/ISO control mapping, evidence bundles (`daemon/compliance/`)
14. **Plan 14: Threat Detection** - YARA, Sigma, MITRE ATT&CK patterns (`daemon/detection/`)
15. **Plan 15: eBPF Observability** - Kernel visibility without drivers (`daemon/ebpf/`)
16. **Plan 16: Process Sandboxing** - Namespace, seccomp, cgroups isolation (`daemon/sandbox/`)
17. **Plan 17: Windows Support** - Windows Firewall enforcement (`daemon/enforcement/windows_firewall.py`)
18. **Plan 18: Air-Gap Operations** - Data diode, QR ceremonies, sneakernet (`daemon/airgap/`)
19. **Plan 19: HSM/Post-Quantum** - HSM support, quantum-resistant crypto (`daemon/crypto/`)
20. **Plan 20: Threat Federation** - Multi-host threat sharing (`daemon/federation/`)

### Additional Enhancements

21. **Alert Case Management** - Alert lifecycle and workflow (`daemon/alerts/`)
22. **Code Integrity** - Code signing and verification (`daemon/integrity/`)
23. **Agent Containment** - Behavior profiling and containment (`daemon/containment/`)
24. **Terminal Dashboard** - Real-time TUI visibility (`daemon/tui/`)
25. **Config Linting** - Configuration validation (`daemon/config/linter.py`)
26. **Mode Advisor** - Intelligent mode recommendations (`daemon/intelligence/`)

## Future Enhancements

Potential future additions (maintaining security principles):

1. **Hardware Security Key Support** - YubiKey/FIDO2 for ceremony verification
2. **Blockchain Log Anchoring** - External validation of log integrity
3. **Secure Enclave Integration** - Intel SGX/ARM TrustZone support
4. **Real-time Threat Intelligence** - Live threat feed integration
5. **N-of-M Ceremonies** - Multi-party ceremony approvals
6. **Merkle Tree Proofs** - Compact audit proofs without full log

---

**Architecture Principle**: "Simple, deterministic, fail-closed, immutable."

---

## Enforcement Model

The detailed enforcement model documentation has been merged into this file.
See the original content below.


**Understanding What the Boundary Daemon Does and Does Not Do**

---

## Executive Summary

The Boundary Daemon is a **policy decision and audit system**, not a security enforcement mechanism. It:

- **Monitors** environment state (network, USB, processes, hardware)
- **Evaluates** policies and returns allow/deny decisions
- **Logs** all security events with tamper-evident hash chains
- **Detects** violations and signals alerts

It does **NOT** prevent operations at the OS level. External systems must voluntarily respect daemon decisions.

---

## The Cooperation Model

### How the Daemon Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Calling Application                          │
│                     (Memory Vault, Agent-OS, etc.)                 │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  │ 1. "Can I access TOP_SECRET memory?"
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Boundary Daemon                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │   Policy    │  │    State    │  │    Event    │                 │
│  │   Engine    │  │   Monitor   │  │   Logger    │                 │
│  └─────────────┘  └─────────────┘  └─────────────┘                 │
│         │                                   │                       │
│         │ 2. Evaluate policy                │ 3. Log the request   │
│         ▼                                   ▼                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │         Return: (False, "Denied: mode OPEN < AIRGAP")       │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  │ 4. Decision returned
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Calling Application                          │
│                                                                     │
│  COOPERATIVE:                      NON-COOPERATIVE:                 │
│  ┌─────────────────────────┐      ┌─────────────────────────┐      │
│  │ if not permitted:       │      │ # Ignore the daemon     │      │
│  │     raise AccessDenied  │      │ return secret_data      │      │
│  └─────────────────────────┘      └─────────────────────────┘      │
│         ✅ Respects decision              ⚠️ Bypasses daemon       │
└─────────────────────────────────────────────────────────────────────┘
```

### The Critical Insight

**The daemon cannot prevent a non-cooperative application from ignoring its decisions.**

This is by design - the daemon is a Python user-space process. It cannot:
- Intercept system calls
- Block network traffic
- Prevent memory access
- Terminate processes

These capabilities require kernel-level or hardware-level enforcement.

---

## Defense in Depth Architecture

For actual security, deploy this daemon as **one layer** in a multi-layer architecture:

```
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 5: Hardware Controls                                          │
│ ─────────────────────────                                           │
│ • Physically disable USB ports                                      │
│ • Air-gap network (disconnect cable)                                │
│ • Hardware security modules (HSM)                                   │
│ • Trusted Platform Module (TPM)                                     │
│                                                                     │
│ Enforcement: PHYSICAL - Cannot be bypassed by software              │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 4: Kernel Enforcement                                         │
│ ──────────────────────────                                          │
│ • SELinux / AppArmor mandatory access control                       │
│ • seccomp-bpf syscall filtering                                     │
│ • eBPF network filtering                                            │
│ • iptables / nftables firewall rules                               │
│                                                                     │
│ Enforcement: HARD - Kernel blocks operations before they occur     │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 3: Container/Process Isolation                                │
│ ───────────────────────────────────                                 │
│ • Linux namespaces (network, PID, mount)                           │
│ • cgroups resource limits                                           │
│ • Container runtimes (podman, docker)                              │
│ • Virtual machines                                                  │
│                                                                     │
│ Enforcement: HARD - Isolated processes cannot access host resources│
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 2: BOUNDARY DAEMON (This System)                              │
│ ─────────────────────────────────────                               │
│ • Policy decision point                                             │
│ • Environment monitoring                                            │
│ • Audit logging with hash chains                                   │
│ • Violation detection                                               │
│ • Coordination between components                                   │
│                                                                     │
│ Enforcement: ADVISORY - Returns decisions, cannot block operations │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 1: Application Cooperation                                    │
│ ───────────────────────────────                                     │
│ • Memory Vault respects recall decisions                           │
│ • Agent-OS respects tool permissions                               │
│ • Applications check permissions before operations                 │
│                                                                     │
│ Enforcement: VOLUNTARY - Applications must choose to cooperate     │
└─────────────────────────────────────────────────────────────────────┘
```

### Layer Responsibilities

| Layer | Type | Can Prevent? | Examples |
|-------|------|--------------|----------|
| 5. Hardware | Physical | Yes | Disabled USB, air-gap, HSM |
| 4. Kernel | Hard | Yes | SELinux, seccomp, iptables |
| 3. Container | Hard | Yes | Namespaces, cgroups, VMs |
| **2. Daemon** | **Advisory** | **No** | **Policy decisions, logging** |
| 1. Application | Voluntary | Depends | Cooperative code |

### What Happens Without Each Layer

| Missing Layer | Consequence |
|---------------|-------------|
| No Layer 4-5 | Daemon decisions are suggestions only |
| No Layer 3 | Malicious code in same container can bypass |
| No Layer 2 | No central policy authority or audit trail |
| No Layer 1 | Even correct decisions are ignored |

---

## What the Daemon Actually Provides

### Detection & Monitoring

```python
# The daemon continuously monitors:
state = {
    "network": {
        "interfaces": ["eth0", "wlan0"],
        "internet_available": True,
        "vpn_active": False
    },
    "hardware": {
        "usb_devices": ["/dev/sda1"],
        "tpm_present": True
    },
    "processes": {
        "suspicious": ["curl api.openai.com"],
        "shell_escapes": []
    }
}
```

### Policy Decisions

```python
# Applications query the daemon for decisions:
permitted, reason = daemon.check_recall_permission(MemoryClass.TOP_SECRET)
# Returns: (False, "Denied: current mode OPEN requires AIRGAP for TOP_SECRET")

permitted, reason = daemon.check_tool_permission("wget", requires_network=True)
# Returns: (False, "Denied: network tools blocked in AIRGAP mode")
```

### Audit Logging

```json
{
    "timestamp": "2025-12-22T10:30:00Z",
    "event_type": "RECALL_ATTEMPT",
    "memory_class": "TOP_SECRET",
    "decision": "DENY",
    "reason": "Mode OPEN < required AIRGAP",
    "hash": "a1b2c3...",
    "prev_hash": "x9y8z7..."
}
```

### Violation Detection

```python
# Tripwires detect policy violations:
if network_detected and mode == AIRGAP:
    trigger_violation("NETWORK_IN_AIRGAP")
    transition_to_lockdown()
```

---

## Enabling Hard Enforcement

The daemon includes optional enforcement modules that CAN provide hard enforcement when properly configured:

### Network Enforcer

```bash
# Enable network enforcement (requires root)
export BOUNDARY_NETWORK_ENFORCE=1
sudo python daemon/boundary_daemon.py

# This will:
# - Install iptables/nftables rules on mode transitions
# - Block network traffic in AIRGAP/LOCKDOWN modes
# - Allow only VPN in TRUSTED mode
```

### USB Enforcer

```bash
# Enable USB enforcement (requires root)
export BOUNDARY_USB_ENFORCE=1
sudo python daemon/boundary_daemon.py

# This will:
# - Install udev rules to block USB devices
# - De-authorize USB storage in restricted modes
# - Block all USB in LOCKDOWN mode
```

### Process Enforcer

```bash
# Enable process enforcement (requires root + container runtime)
export BOUNDARY_PROCESS_ENFORCE=1
sudo python daemon/boundary_daemon.py

# This will:
# - Apply seccomp-bpf filters to managed processes
# - Run workloads in isolated containers
# - Block dangerous syscalls based on mode
```

### Requirements for Enforcement

| Enforcer | Requirements |
|----------|--------------|
| Network | Root, iptables/nftables |
| USB | Root, udev |
| Process | Root, seccomp, podman/docker |

**Without these prerequisites, enforcers log warnings but cannot block operations.**

---

## External Watchdog System

The daemon includes a hardened external watchdog that monitors the daemon and triggers emergency lockdown if it fails. This addresses the critical vulnerability: "Daemon Can Be Killed."

### Architecture

```
                    ┌─────────────────────────────────────┐
                    │              systemd                 │
                    │  (restarts services, WatchdogSec)   │
                    └─────────────────────────────────────┘
                                     │
                                     ▼
                    ┌─────────────────────────────────────┐
                    │        boundary-daemon.service       │
                    │  (policy decisions, enforcement)     │
                    └─────────────────────────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
          ┌─────────────────┐             ┌─────────────────────┐
          │ Primary Watchdog │◄───────────►│ Secondary Watchdog  │
          │  (monitors daemon)│             │  (monitors primary) │
          └─────────────────┘             └─────────────────────┘
                    │                                 │
                    └────────────────┬────────────────┘
                                     ▼
                            ┌─────────────────┐
                            │    LOCKDOWN     │
                            │  (iptables)     │
                            └─────────────────┘
```

### Features

| Feature | Description |
|---------|-------------|
| **Cryptographic Heartbeats** | HMAC-SHA256 challenge-response authentication |
| **Process Hardening** | prctl protections, signal handlers |
| **Systemd Integration** | Uses sd_notify for kernel-level monitoring |
| **Hardware Watchdog** | Optional /dev/watchdog integration |
| **Multi-Watchdog** | Primary + secondary for redundancy |
| **Fail-Closed** | Triggers iptables lockdown on failure |

### Quick Setup

```bash
# Install with setup script
sudo ./scripts/setup-watchdog.sh --install

# Or with redundant secondary watchdog
sudo ./scripts/setup-watchdog.sh --install --secondary

# Check status
sudo ./scripts/setup-watchdog.sh --status
```

### Manual Setup

```bash
# 1. Copy service files
sudo cp systemd/boundary-daemon.service /etc/systemd/system/
sudo cp systemd/boundary-watchdog.service /etc/systemd/system/

# 2. Create directories
sudo mkdir -p /var/log/boundary-daemon /var/run/boundary-daemon
sudo chmod 700 /var/log/boundary-daemon /var/run/boundary-daemon

# 3. Install and enable
sudo systemctl daemon-reload
sudo systemctl enable boundary-daemon boundary-watchdog
sudo systemctl start boundary-daemon boundary-watchdog

# 4. Verify
sudo systemctl status boundary-daemon boundary-watchdog
```

### What Happens on Daemon Failure

When the watchdog detects the daemon is unresponsive:

1. **Challenge-Response Fails**: Daemon doesn't respond to cryptographic heartbeat
2. **Failure Counter Increments**: 3 consecutive failures trigger lockdown
3. **Emergency Lockdown**:
   - All iptables policies set to DROP
   - Syslog alert sent
   - Wall message broadcast
   - Lockdown indicator file created
4. **Manual Intervention Required**: System stays locked until admin recovers

### Monitoring Watchdog Status

```bash
# Check service status
sudo systemctl status boundary-watchdog

# View watchdog logs
sudo journalctl -u boundary-watchdog -f

# Check for lockdown state
cat /var/run/boundary-daemon/LOCKDOWN
```

### Redundancy with Secondary Watchdog

For maximum protection, run a secondary watchdog that monitors both the daemon AND the primary watchdog:

```bash
# Enable secondary watchdog
sudo cp systemd/boundary-watchdog-secondary.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable boundary-watchdog-secondary
sudo systemctl start boundary-watchdog-secondary
```

The secondary watchdog:
- Monitors the primary watchdog's heartbeat socket
- Triggers lockdown if both daemon AND primary watchdog fail
- Makes it much harder to silently disable monitoring

---

## Log Tamper-Proofing

The daemon's audit logs use multiple layers of protection to prevent tampering.

### Protection Layers

| Layer | Protection | Prevents |
|-------|------------|----------|
| **Hash Chains** | SHA-256 blockchain-style linking | Modification, insertion |
| **Ed25519 Signatures** | Cryptographic signing per event | Forgery, repudiation |
| **File Permissions** | 0o600 (owner read/write only) | Unauthorized access |
| **chattr +a** | Linux append-only attribute | Deletion, truncation |
| **Log Sealing** | chattr +i (immutable) + checksum | Post-rotation tampering |
| **Remote Syslog** | Off-system backup | Local tampering |

### How Hash Chains Work

```
Event 1                Event 2                Event 3
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ timestamp    │      │ timestamp    │      │ timestamp    │
│ event_type   │      │ event_type   │      │ event_type   │
│ details      │      │ details      │      │ details      │
│ metadata     │      │ metadata     │      │ metadata     │
│              │      │              │      │              │
│ hash_chain:  │─────►│ hash_chain:  │─────►│ hash_chain:  │
│ 0000...0000  │      │ SHA256(E1)   │      │ SHA256(E2)   │
└──────────────┘      └──────────────┘      └──────────────┘
    Genesis               Links to E1           Links to E2
```

Any modification to Event 2 changes its hash, breaking the chain for Event 3.

### Enabling Full Protection

```bash
# Run daemon as root for chattr support
sudo python daemon/boundary_daemon.py

# Files are created with secure permissions by default:
# - Log files: 0o600 (owner read/write)
# - Log directories: 0o700 (owner only)
# - With root: chattr +a applied (append-only)
```

### Log Sealing

When rotating logs or finalizing an audit period:

```python
from daemon.event_logger import EventLogger

logger = EventLogger("/var/log/boundary-daemon/events.log")
# ... logging events ...

# Seal the log (makes it immutable)
success, msg = logger.seal_log()
# Creates: events.log.sealed (checkpoint with hash)
# Sets: chmod 0o400 + chattr +i
```

### Checking Protection Status

```python
status = logger.get_protection_status()
# Returns:
# {
#     'path': '/var/log/boundary-daemon/events.log',
#     'exists': True,
#     'permissions': '600',
#     'is_append_only': True,
#     'is_immutable': False,
#     'is_sealed': False,
# }
```

### Using the Log Hardener

For additional protection, use the dedicated LogHardener module:

```python
from daemon.storage.log_hardening import LogHardener, HardeningMode

hardener = LogHardener(
    log_path="/var/log/boundary-daemon/events.log",
    mode=HardeningMode.STRICT,  # Fail if protection unavailable
    fail_on_degraded=True,
)

# Apply hardening
status = hardener.harden()
print(f"Protection: {status.status.value}")
print(f"Append-only: {status.is_append_only}")

# Verify integrity
is_valid, issues = hardener.verify_integrity()
```

### What Can Still Be Tampered

Even with full protection, these attacks are possible:

| Attack | Mitigation |
|--------|------------|
| Root removes chattr | Remote syslog backup, external monitoring |
| Delete entire log | Watchdog detects missing file |
| System clock manipulation | Clock monitor module detects jumps |
| Boot from USB, modify disk | TPM PCR sealing, full disk encryption |

**True tamper-proofing requires defense-in-depth** including remote logging, hardware security (TPM), and external monitoring.

---

## Security Considerations

### What IS Protected

When properly integrated with cooperating systems:

| Asset | Protection Mechanism |
|-------|---------------------|
| Audit trail | Hash-chained immutable log with file hardening |
| Policy consistency | Centralized decision authority |
| Violation detection | Continuous monitoring + tripwires |
| Mode transitions | Logged with operator attribution |

### What IS NOT Protected

Without kernel/hardware enforcement:

| Risk | Why Not Protected |
|------|-------------------|
| Malicious code | Can ignore daemon decisions |
| Root user | Can kill daemon, modify logs |
| Network exfiltration | Detection is after-the-fact |
| USB data theft | Detection after mounting |

### Attack Scenarios

**Scenario 1: Non-cooperative Application**
```python
# Malicious code simply ignores the daemon
secret = memory_vault.read_raw(memory_id)  # Never calls check_recall
send_to_external_server(secret)  # Daemon never knew
```

**Scenario 2: Race Condition**
```
T=0.0: Daemon polls - network offline ✓
T=0.1: Attacker enables WiFi
T=0.5: Attacker exfiltrates data
T=1.0: Daemon polls - detects network, triggers lockdown
       (Too late - data already exfiltrated)
```

**Scenario 3: Daemon Termination**
```bash
sudo kill -9 $(pgrep boundary_daemon)
# System continues operating with no policy checks
```

---

## Recommendations

### For Development/Testing

The daemon works well as-is for:
- Developing security-aware applications
- Testing policy logic
- Creating audit trails
- Coordinating between components

### For Production Security

Add enforcement layers:

1. **Run in containers** with network=none for sensitive workloads
2. **Use SELinux/AppArmor** policies to restrict processes
3. **Deploy iptables rules** independent of daemon
4. **Enable daemon enforcers** with root privileges
5. **Use hardware controls** for highest-sensitivity data

### Integration Checklist

- [ ] All components call daemon before sensitive operations
- [ ] Components raise exceptions on DENY (don't ignore)
- [ ] Kernel-level enforcement matches daemon modes
- [ ] Container isolation for workload separation
- [ ] Hardware controls for physical security
- [ ] Log forwarding to external SIEM
- [x] Watchdog to detect daemon failure (see [External Watchdog System](#external-watchdog-system))
- [x] Log tamper-proofing enabled (see [Log Tamper-Proofing](#log-tamper-proofing))

---

## Conclusion

The Boundary Daemon is a valuable component for:
- **Policy coordination** across distributed systems
- **Audit logging** with cryptographic integrity
- **Environment monitoring** and violation detection
- **Decision authority** that other systems respect

It is NOT a standalone security solution. For actual data protection, combine with kernel-level and hardware-level enforcement mechanisms.

**Think of it as:** A security guard who checks IDs and logs visitors, but cannot physically stop someone who runs past them. The guard is useful, but you also need locked doors (kernel enforcement) and walls (hardware controls).

---

## See Also

- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) - Detailed security audit findings
- [SPEC.md](SPEC.md) - Complete technical specification
- [test_bypass_vulnerability.py](test_bypass_vulnerability.py) - Proof-of-concept bypass demonstrations

---

## Module Map


A comprehensive guide to the Boundary Daemon module organization.

## Overview

```
daemon/                      # ~120 Python modules
├── [21 root modules]       # Core daemon functionality
├── security/      (23)     # Security checks & detection
├── enforcement/   (15)     # Kernel-level enforcement
├── tui/           (10)     # Terminal dashboard
├── sandbox/        (8)     # Process sandboxing
├── auth/           (7)     # Authentication & ceremonies
├── detection/      (6)     # Threat detection engines
├── identity/       (5)     # Identity & access management
├── compliance/     (5)     # Regulatory compliance
├── ebpf/           (4)     # eBPF kernel integration
├── storage/        (4)     # Secure log storage
├── pii/            (4)     # PII detection & filtering
├── audio/          (4)     # Text-to-speech & voice
├── cli/            (4)     # Command-line tools
├── integrity/      (3)     # Code signing & verification
├── distributed/    (3)     # Multi-instance coordination
├── watchdog/       (3)     # Process monitoring
├── telemetry/      (3)     # Metrics & tracing
├── crypto/         (3)     # Cryptographic utilities
├── config/         (3)     # Configuration management
├── alerts/         (2)     # Alert case management
├── hardware/       (2)     # TPM & hardware security
├── api/            (2)     # REST/gRPC API
├── policy/         (2)     # Policy definitions
├── wallpaper/      (2)     # Desktop wallpaper integration
├── messages/       (2)     # Message validation
├── utils/          (2)     # Error handling utilities
└── external_integrations/  # SIEM & external systems
```

## Core Modules (Root Level)

These are the heart of the daemon. Start here when learning the codebase.

| Module | Lines | Purpose |
|--------|-------|---------|
| `boundary_daemon.py` | ~3,800 | **Main orchestrator** - coordinates all components |
| `policy_engine.py` | ~1,200 | Evaluates requests against current mode |
| `state_monitor.py` | ~800 | Monitors environment (network, USB, processes) |
| `tripwires.py` | ~600 | Detects violations, triggers lockdown |
| `event_logger.py` | ~500 | Hash-chain audit logging |
| `constants.py` | ~300 | All enums and constants |
| `features.py` | ~200 | Feature detection (what's available) |

### Supporting Core Modules

| Module | Purpose |
|--------|---------|
| `health_monitor.py` | Daemon health checks |
| `resource_monitor.py` | CPU/memory monitoring |
| `memory_monitor.py` | Memory usage tracking |
| `queue_monitor.py` | Event queue monitoring |
| `privilege_manager.py` | Privilege escalation handling |
| `redundant_event_logger.py` | Backup logging |
| `signed_event_logger.py` | Cryptographically signed logs |
| `integrations.py` | Third-party integrations |
| `monitoring_report.py` | AI-generated reports (uses Ollama) |
| `dreaming.py` | Background analysis mode |
| `tray.py` | System tray icon |
| `logging_config.py` | Logging setup |

## Module Categories

### Security (`daemon/security/`) - 23 modules

The largest module group. Handles all security detection and protection.

```
security/
├── daemon_integrity.py      # Runtime integrity verification
├── file_integrity.py        # File system monitoring
├── prompt_injection.py      # LLM prompt injection detection
├── rag_injection.py         # RAG poisoning detection
├── response_guardrails.py   # Output safety checks
├── antivirus.py             # Malware scanning (ClamAV)
├── process_security.py      # Process isolation
├── dns_security.py          # DNS query monitoring
├── arp_security.py          # ARP spoofing detection
├── wifi_security.py         # WiFi security checks
├── clock_monitor.py         # Time manipulation detection
├── siem_integration.py      # SIEM forwarding
├── threat_intel.py          # Threat intelligence feeds
├── hardening.py             # System hardening checks
└── ...
```

**Key Entry Points:**
- `prompt_injection.py` - AI safety checks
- `daemon_integrity.py` - Self-protection
- `antivirus.py` - Malware detection

### Enforcement (`daemon/enforcement/`) - 15 modules

Kernel-level enforcement. **Requires root/admin privileges.**

```
enforcement/
├── network_enforcer.py      # iptables/nftables rules
├── usb_enforcer.py          # udev rules for USB
├── process_enforcer.py      # seccomp-bpf filters
├── firewall_integration.py  # Cross-platform firewall
├── windows_firewall.py      # Windows-specific
├── mac_profiles.py          # macOS profiles
├── disk_encryption.py       # Encryption verification
├── secure_process_termination.py  # Safe process kill
├── protection_persistence.py      # Survive reboots
└── ...
```

**Key Entry Points:**
- `network_enforcer.py` - Network isolation
- `usb_enforcer.py` - USB device control

### Sandbox (`daemon/sandbox/`) - 8 modules

Process sandboxing using Linux namespaces, cgroups, seccomp.

```
sandbox/
├── sandbox_manager.py       # Main sandbox orchestrator
├── namespace.py             # Linux namespace isolation
├── cgroups.py               # Resource limits (cgroups v2)
├── seccomp_filter.py        # System call filtering
├── network_policy.py        # Per-sandbox network rules
├── profile_config.py        # Sandbox profiles
└── mac_profiles.py          # macOS sandbox profiles
```

**Key Entry Points:**
- `sandbox_manager.py` - Create/manage sandboxes

### Authentication (`daemon/auth/`) - 7 modules

Multi-factor authentication and ceremonies.

```
auth/
├── enhanced_ceremony.py     # Mode change ceremonies
├── advanced_ceremony.py     # High-security ceremonies
├── biometric_verifier.py    # Fingerprint/face auth
├── api_auth.py              # API authentication
├── secure_token_storage.py  # Token management
├── persistent_rate_limiter.py  # Rate limiting
└── __init__.py
```

**Key Entry Points:**
- `enhanced_ceremony.py` - Mode transitions

### Detection (`daemon/detection/`) - 6 modules

Threat detection engines using industry standards.

```
detection/
├── yara_engine.py           # YARA rule matching
├── sigma_engine.py          # Sigma rule detection
├── mitre_attack.py          # MITRE ATT&CK mapping
├── ioc_feeds.py             # IOC feed integration
├── event_publisher.py       # Detection event publishing
└── __init__.py
```

**Key Entry Points:**
- `yara_engine.py` - Pattern matching
- `sigma_engine.py` - Log-based detection

### eBPF (`daemon/ebpf/`) - 4 modules

Low-level kernel observability. **Linux only, requires BCC.**

```
ebpf/
├── ebpf_observer.py         # Main eBPF manager
├── probes.py                # Kernel probe definitions
├── policy_integration.py    # Connect eBPF to policy
└── __init__.py
```

### Identity (`daemon/identity/`) - 5 modules

Enterprise identity integration.

```
identity/
├── identity_manager.py      # Identity orchestration
├── pam_integration.py       # Linux PAM modules
├── ldap_mapper.py           # LDAP/AD integration
├── oidc_validator.py        # OIDC/OAuth2 validation
└── __init__.py
```

### PII (`daemon/pii/`) - 4 modules

Personal data protection.

```
pii/
├── detector.py              # PII pattern detection
├── filter.py                # PII redaction
├── bypass_resistant_detector.py  # Anti-evasion detection
└── __init__.py
```

### CLI (`daemon/cli/`) - 4 modules

Command-line tools for administrators.

```
cli/
├── boundaryctl.py           # Main CLI tool
├── sandboxctl.py            # Sandbox management
├── queryctl.py              # Query daemon state
└── __init__.py
```

**Usage:**
```bash
python -m daemon.cli.boundaryctl status
python -m daemon.cli.sandboxctl list
```

### Integrity (`daemon/integrity/`) - 3 modules

Code signing and verification.

```
integrity/
├── code_signer.py           # Sign release artifacts
├── integrity_verifier.py    # Verify at runtime
└── __init__.py
```

**Key Entry Points:**
- `code_signer.py` - Build-time signing
- `integrity_verifier.py` - Runtime verification

### Storage (`daemon/storage/`) - 4 modules

Tamper-evident log storage.

```
storage/
├── append_only.py           # Append-only log store
├── forensic_audit.py        # Forensic analysis support
├── log_hardening.py         # Log protection
└── __init__.py
```

### Distributed (`daemon/distributed/`) - 3 modules

Multi-instance coordination.

```
distributed/
├── cluster_manager.py       # Cluster coordination
├── coordinators.py          # Leader election, consensus
└── __init__.py
```

### Telemetry (`daemon/telemetry/`) - 3 modules

Observability and metrics.

```
telemetry/
├── otel_setup.py            # OpenTelemetry setup
├── prometheus_metrics.py    # Prometheus exporter
└── __init__.py
```

### Other Modules

| Directory | Purpose |
|-----------|---------|
| `compliance/` | SOC2, HIPAA, PCI-DSS checks |
| `watchdog/` | Process health monitoring |
| `crypto/` | Post-quantum cryptography |
| `config/` | Configuration validation |
| `alerts/` | Alert case management |
| `hardware/` | TPM integration |
| `api/` | REST/gRPC server |
| `policy/` | Policy definitions |
| `wallpaper/` | Desktop integration |
| `audio/` | TTS/STT engines |
| `messages/` | Message validation |
| `utils/` | Error handling |
| `external_integrations/` | SIEM connectors |

## Data Flow

```
                        ┌─────────────┐
                        │   User/     │
                        │   Agent     │
                        └──────┬──────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│                    boundary_daemon.py                     │
│                   (Main Orchestrator)                     │
└────┬─────────────┬──────────────┬─────────────┬─────────┘
     │             │              │             │
     ▼             ▼              ▼             ▼
┌─────────┐  ┌──────────┐  ┌───────────┐  ┌───────────┐
│ state_  │  │ policy_  │  │ tripwires │  │  event_   │
│ monitor │  │ engine   │  │   .py     │  │  logger   │
└────┬────┘  └────┬─────┘  └─────┬─────┘  └─────┬─────┘
     │            │              │              │
     │            ▼              │              │
     │     ┌───────────┐         │              │
     │     │ ALLOW/    │         │              │
     │     │ DENY      │◄────────┘              │
     │     └───────────┘                        │
     │                                          │
     ▼                                          ▼
┌──────────────────┐                    ┌──────────────────┐
│   enforcement/   │                    │    storage/      │
│ (kernel rules)   │                    │ (audit logs)     │
└──────────────────┘                    └──────────────────┘
```

## Module Dependencies

### Internal Dependencies

```
boundary_daemon.py
├── policy_engine.py
├── state_monitor.py
├── tripwires.py
├── event_logger.py
├── constants.py
└── features.py

policy_engine.py
├── constants.py
└── event_logger.py

enforcement/*
├── constants.py
└── event_logger.py

security/*
├── constants.py
└── event_logger.py
```

### External Dependencies by Module

| Module | Required | Optional |
|--------|----------|----------|
| `enforcement/` | - | `iptables`, `nftables`, `udevadm` |
| `ebpf/` | `bcc` | - |
| `detection/yara_engine.py` | `yara-python` | - |
| `detection/sigma_engine.py` | `sigma-cli` | - |
| `security/antivirus.py` | - | `clamd` |
| `audio/` | - | `pyttsx3`, `speechrecognition` |
| `monitoring_report.py` | - | `ollama` |
| `hardware/tpm_manager.py` | - | `tpm2-tools` |

## Finding Your Way

### By Task

| Task | Start Here |
|------|------------|
| Understand policy decisions | `policy_engine.py` |
| Add a security check | `security/` |
| Add kernel enforcement | `enforcement/` |
| Modify sandbox behavior | `sandbox/sandbox_manager.py` |
| Add authentication method | `auth/` |
| Add threat detection | `detection/` |
| Add compliance check | `compliance/` |
| Integrate external system | `external_integrations/` |

### By Platform

| Platform | Key Modules |
|----------|-------------|
| Linux | `enforcement/`, `sandbox/`, `ebpf/`, `identity/pam_integration.py` |
| Windows | `enforcement/windows_firewall.py`, `tray.py` |
| macOS | `enforcement/mac_profiles.py`, `sandbox/mac_profiles.py` |

## Archived Modules

The following modules were archived (see `archive/`) as they were not integrated:

- `intelligence/` - Mode advisor AI
- `containment/` - Agent profiler
- `blockchain/` - Blockchain audit trail
- `federation/` - Threat mesh federation
- `airgap/` - Airgap enforcement (duplicated by `enforcement/`)

These can be restored if needed by moving back to `daemon/`.

## Quick Reference

```bash
# Run the daemon
python -m daemon.boundary_daemon

# Run TUI dashboard
python -m daemon.tui.dashboard --matrix

# CLI tools
python -m daemon.cli.boundaryctl status
python -m daemon.cli.sandboxctl list

# Check available features
python -m daemon.features

# Run tests
pytest tests/ -v
```
