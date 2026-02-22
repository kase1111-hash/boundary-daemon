# Boundary Daemon User Guide

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Security Modes](#security-modes)
5. [Monitoring Features](#monitoring-features)
6. [Ollama Integration](#ollama-integration)
7. [Configuration](#configuration)
8. [Command Line Tools](#command-line-tools)
9. [API Reference](#api-reference)
10. [Troubleshooting](#troubleshooting)

---

## Overview

The Boundary Daemon (Agent Smith) is a trust boundary enforcement system that monitors and controls security boundaries for AI agent systems. It provides:

- **Security Mode Enforcement**: Six security modes from permissive to complete lockdown
- **Real-time Monitoring**: Memory, CPU, disk, network, and health monitoring
- **Cryptographic Logging**: Signed, tamper-evident event logs
- **AI-Powered Analysis**: Natural language queries via Ollama integration
- **Config Encryption**: Sensitive configuration encrypted at rest

### Platform Support

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| Core Daemon | ✅ | ✅ | ✅ |
| Monitoring | ✅ | ✅ | ✅ |
| Config Encryption | ✅ | ✅ | ✅ |
| Ollama Integration | ✅ | ✅ | ✅ |
| Network Enforcement | ✅ (iptables/nftables) | ⚠️ Partial (Windows Firewall) | ❌ |
| USB Enforcement | ✅ (udev) | ❌ | ❌ |
| Process Enforcement | ✅ (seccomp, namespaces) | ❌ | ❌ |

---

## Installation

### Prerequisites

- Python 3.9 or higher (supports 3.9, 3.10, 3.11, 3.12, 3.13)
- Ollama (optional, for AI features)

### Windows Installation

1. **Install Python** from https://python.org

2. **Clone or download** the repository

3. **Build the executable**:
   ```batch
   build.bat
   ```
   This will:
   - Install dependencies (psutil, cryptography, pynacl)
   - Build `dist\boundary-daemon.exe`
   - Copy configuration files

4. **Run the daemon**:
   ```batch
   cd dist
   boundary-daemon.exe
   ```

### Linux Installation

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the daemon**:
   ```bash
   # Development mode
   python run_daemon.py

   # With full enforcement (requires root)
   sudo python run_daemon.py
   ```

### Installing Ollama (Optional)

For AI-powered reports and natural language queries:

1. **Install Ollama**:
   - Windows: Download from https://ollama.ai
   - Linux: `curl https://ollama.ai/install.sh | sh`

2. **Pull a model**:
   ```bash
   ollama pull llama3.2
   ```

3. **Start Ollama** (runs as a service on Windows, or run `ollama serve` on Linux)

---

## Quick Start

### Starting the Daemon

```batch
# Windows
boundary-daemon.exe

# Linux
python run_daemon.py
```

### First Run Output

On first run, you'll see:
```
======================================================================
Boundary Daemon - Trust Boundary Enforcement System
======================================================================
Verifying daemon integrity...
Initializing Boundary Daemon (Agent Smith)...
Generated new signing key at .\logs\signing.key
Signed event logging enabled
[AUTH] Bootstrap admin token created (ENCRYPTED): config\bootstrap_token.enc
Boundary Daemon initialized in OPEN mode
Boundary Daemon running. Close this window or press Ctrl+Break to stop.
======================================================================
```

### Stopping the Daemon

- **Windows**: Close the window or press `Ctrl+Break`
- **Linux**: Press `Ctrl+C`

---

## Security Modes

The daemon operates in **six security modes**, from most permissive to most restrictive:

| Mode | Network | Memory Classes | Tools | Use Case |
|------|---------|----------------|-------|----------|
| **OPEN** | ✓ Online | 0-1 | All | Casual use |
| **RESTRICTED** | ✓ Online | 0-2 | Most | Research |
| **TRUSTED** | VPN only | 0-3 | No USB | Serious work |
| **AIRGAP** | ✗ Offline | 0-4 | No network | High-value IP |
| **COLDROOM** | ✗ Offline | 0-5 | Display only | Crown jewels |
| **LOCKDOWN** | ✗ Blocked | None | None | Emergency |

### OPEN Mode (Default)
```
Mode: OPEN
Description: Permissive monitoring mode
Behavior: All operations allowed, events logged
Memory Access: PUBLIC, INTERNAL only
Use Case: Development, testing, initial setup
```

### RESTRICTED Mode
```
Mode: RESTRICTED
Description: Active monitoring with warnings
Behavior: Operations allowed but flagged if suspicious
Memory Access: Up to CONFIDENTIAL
Use Case: Normal operation with oversight
```

### TRUSTED Mode
```
Mode: TRUSTED
Description: VPN-only network access
Behavior: USB storage blocked, VPN required
Memory Access: Up to SECRET
Use Case: Serious work requiring network
Requires: VPN connection
```

### AIRGAP Mode
```
Mode: AIRGAP
Description: Network isolation enforced
Behavior: External network access blocked
Memory Access: Up to TOP_SECRET
Use Case: Sensitive operations, data processing
Requires: Linux with root privileges (for enforcement)
```

### COLDROOM Mode
```
Mode: COLDROOM
Description: Maximum isolation
Behavior: Display-only, minimal I/O
Memory Access: All including CROWN_JEWEL
Use Case: Crown jewel IP protection
Requires: Linux with root privileges (for enforcement)
```

### LOCKDOWN Mode
```
Mode: LOCKDOWN
Description: Emergency response
Behavior: All external access blocked, no memory access
Memory Access: None
Use Case: Security incident response
Requires: Linux with root privileges (for enforcement)
```

### Memory Classification

| Level | Name | Minimum Mode |
|-------|------|--------------|
| 0 | PUBLIC | OPEN |
| 1 | INTERNAL | OPEN |
| 2 | CONFIDENTIAL | RESTRICTED |
| 3 | SECRET | TRUSTED |
| 4 | TOP_SECRET | AIRGAP |
| 5 | CROWN_JEWEL | COLDROOM |

### Changing Modes

Modes can be changed via the API:
```python
from api.boundary_api import BoundaryAPIClient

client = BoundaryAPIClient()
client.set_mode("RESTRICTED")
```

Or using the CLI:
```bash
boundaryctl set-mode RESTRICTED
```

**Note:** Transitioning to higher security modes (AIRGAP, COLDROOM, LOCKDOWN) may require a ceremony (human verification) depending on configuration.

---

## Monitoring Features

### Memory Monitor

Tracks daemon memory usage to detect leaks and excessive consumption.

**Metrics:**
- `current_mb`: Current RAM usage in megabytes
- `peak_mb`: Highest RAM usage since startup
- `warning_threshold_mb`: Warning level (default: 500 MB)
- `critical_threshold_mb`: Critical level (default: 1000 MB)
- `leak_detected`: Boolean indicating potential memory leak

**Configuration:**
```
Displayed as:
  Memory monitor available (interval: 5.0s)
    RSS warning: 500.0 MB, critical: 1000.0 MB
    Leak detection: enabled
```

### Resource Monitor

Tracks system resources including CPU, disk, file descriptors, and network connections.

**Metrics:**
- `cpu_percent`: Current CPU usage percentage
- `fd_count`: Open file descriptors
- `thread_count`: Active threads
- `disk_used_percent`: Disk usage percentage
- `connection_count`: Active network connections

**Thresholds:**
- File descriptor warning: 70% of system limit
- Disk warning: 90% (configurable)
- Disk critical: 95%

**Configuration:**
```
Displayed as:
  Resource monitor available (interval: 10.0s)
    FD warning: 70.0%, Disk warning: 90.0%
```

### Health Monitor

Performs periodic health checks on the daemon.

**Metrics:**
- `status`: healthy, degraded, or unhealthy
- `last_heartbeat`: Time of last successful check
- `uptime_seconds`: How long the daemon has been running
- `issues`: List of active problems

**Configuration:**
```
Displayed as:
  Health monitor available (check interval: 30.0s)
    Heartbeat timeout: 60.0s
```

### Queue Monitor

Monitors event processing queues for backlogs.

**Metrics:**
- `current_depth`: Events waiting to be processed
- `peak_depth`: Highest queue size seen
- `total_processed`: Total events handled
- `is_backed_up`: Whether queue is backing up

**Thresholds:**
- Warning depth: 100 events
- Critical depth: 500 events

**Configuration:**
```
Displayed as:
  Queue monitor available (sample interval: 5.0s)
    Warning depth: 100, Critical depth: 500
```

### Clock Monitor

Monitors system time and NTP synchronization.

**Purpose:**
- Ensures accurate timestamps in logs
- Detects time drift that could affect security

---

## Ollama Integration

The daemon integrates with Ollama for AI-powered features:

### Checking Ollama Status

```batch
python query_daemon.py --check
```

Output:
```
Ollama Status:
  Endpoint: http://localhost:11434
  Available: Yes
  Model: llama3.2
  Model Available: Yes
```

### Generating AI Reports

Generate a monitoring report with AI analysis:

```batch
python generate_report.py
```

Output includes:
- Current daemon state
- Resource metrics
- AI-generated analysis and recommendations

**Options:**
```batch
# Full report with AI analysis
python generate_report.py

# Health-focused report
python generate_report.py --type health

# Raw report without AI
python generate_report.py --no-interpret

# Show raw JSON data
python generate_report.py --raw

# Use different model
python generate_report.py --model llama3.1
```

### Natural Language Queries

Query the daemon using natural language:

```batch
# Single query
python query_daemon.py "What is the memory usage?"

# Interactive mode
python query_daemon.py --interactive
```

**Example Queries:**
- "What is the current memory usage?"
- "Are there any critical issues?"
- "What security mode is the daemon in?"
- "Is the system healthy?"
- "How much disk space is being used?"
- "What is the CPU usage?"
- "Are there any memory leaks?"
- "How long has the daemon been running?"
- "What alerts have occurred recently?"

**Interactive Mode:**
```
You: What is the memory usage?
Daemon: The daemon is currently using 45.2 MB of RAM, which is well
        below the warning threshold of 500 MB...

You: Any issues?
Daemon: The system is healthy with no critical issues detected...

You: quit
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OLLAMA_ENDPOINT` | Ollama API URL | `http://localhost:11434` |
| `OLLAMA_MODEL` | Ollama model to use | `llama3.2` |
| `BOUNDARY_DISK_WARNING_PERCENT` | Disk warning threshold | `90` |
| `BOUNDARY_POLICY_DIR` | Custom policy directory | (disabled) |
| `BOUNDARY_SECURITY_DIR` | Security advisor directory | (disabled) |
| `BOUNDARY_WATCHDOG_DIR` | Log watchdog directory | (disabled) |
| `BOUNDARY_TELEMETRY_DIR` | Telemetry directory | (disabled) |

### Configuration Files

**Location:** `config/` directory

| File | Purpose |
|------|---------|
| `bootstrap_token.enc` | Encrypted admin API token |
| `manifest.json` | Integrity verification manifest (auto-generated) |
| `signing.key` | Manifest signing key |

### Logs

**Location:** `logs/` directory

| File | Purpose |
|------|---------|
| `boundary_chain.log` | Signed event log chain |
| `signing.key` | Event log signing key |

---

## Command Line Tools

### boundary-daemon.exe / run_daemon.py

The main daemon executable.

```batch
# Windows
boundary-daemon.exe

# Linux
python run_daemon.py
```

### generate_report.py

Generate monitoring reports with optional AI analysis.

```batch
python generate_report.py [options]

Options:
  --type TYPE       Report type: full, summary, alerts, health (default: full)
  --no-interpret    Skip AI analysis
  --raw             Show raw JSON data
  --check           Check Ollama status
  --endpoint URL    Ollama endpoint (default: http://localhost:11434)
  --model MODEL     Ollama model (default: llama3.2)
```

**Examples:**
```batch
# Full report with AI
python generate_report.py

# Health report only
python generate_report.py --type health

# Check Ollama connection
python generate_report.py --check
```

### query_daemon.py

Query the daemon using natural language.

```batch
python query_daemon.py [question] [options]

Options:
  --interactive, -i    Run in interactive mode
  --check, -c          Check system status
  --json, -j           Output as JSON
  --endpoint URL       Ollama endpoint
  --model MODEL        Ollama model
```

**Examples:**
```batch
# Single query
python query_daemon.py "What is the memory usage?"

# Interactive mode
python query_daemon.py -i

# JSON output
python query_daemon.py -j "System status?"

# Check status
python query_daemon.py --check
```

### build.bat (Windows)

Build the Windows executable.

```batch
build.bat
```

This script:
1. Checks Python installation
2. Installs PyInstaller if needed
3. Installs dependencies from requirements.txt
4. Builds boundary-daemon.exe
5. Copies configuration files to dist/

---

## API Reference

### Python Client

```python
from api.boundary_api import BoundaryAPIClient

client = BoundaryAPIClient()
```

### Available Methods

#### Status and Mode

```python
# Get current status
status = client.get_status()

# Get current mode
mode = client.get_mode()

# Set mode (OPEN, RESTRICTED, TRUSTED, AIRGAP, COLDROOM, LOCKDOWN)
client.set_mode("RESTRICTED")
```

#### Monitoring

```python
# Generate report with AI analysis
report = client.generate_report(
    report_type="full",      # full, summary, alerts, health
    interpret=True,          # Enable AI analysis
    custom_prompt=None,      # Custom prompt for AI
    ollama_model=None,       # Override model
)

# Get raw report (no AI)
raw_report = client.get_raw_report(report_type="full")

# Get report history
history = client.get_report_history(limit=10)
```

#### Ollama Integration

```python
# Check Ollama status
status = client.check_ollama_status()
# Returns: {'available': True, 'model': 'llama3.2', ...}

# Natural language query
result = client.query("What is the memory usage?")
print(result['answer'])
```

#### Event Logging

```python
# Get recent events
events = client.get_events(limit=100)

# Get events by type
alerts = client.get_events_by_type("ALERT", limit=50)
```

---

## Troubleshooting

### Common Issues

#### "cryptography library not available"

**Solution:** Install the cryptography package:
```batch
pip install cryptography>=41.0.0
```

#### "Ollama is not available"

**Solution:**
1. Install Ollama from https://ollama.ai
2. Start Ollama: `ollama serve`
3. Pull a model: `ollama pull llama3.2`

#### "Module not loaded" for network/USB/process

**Explanation:** These modules require Linux-specific features (iptables, udev, seccomp) and are not available on Windows. This is expected behavior.

On Windows, you'll see:
```
Network enforcement: Windows mode (iptables/nftables not available)
USB enforcement: Windows mode (udev not available)
Process enforcement: Windows mode (seccomp not available)
```

#### Manifest signature invalid

**Explanation:** This occurs when the signing key changes between restarts. In development mode, the manifest is automatically regenerated.

**For production:** Use a persistent signing key stored securely.

#### Disk space warnings

**Solution:** Either free up disk space or adjust the threshold:
```batch
set BOUNDARY_DISK_WARNING_PERCENT=95
boundary-daemon.exe
```

### Log Files

Check these files for debugging:

| File | Contains |
|------|----------|
| `logs/boundary_chain.log` | All daemon events |
| Console output | Real-time status and errors |

### Getting Help

1. Check this user guide
2. Review console output for error messages
3. Use `python query_daemon.py --check` to verify Ollama status
4. Report issues at the project repository

---

## Security Considerations

### Config Encryption

Sensitive configuration (tokens, credentials) is encrypted using:
- **Algorithm:** Fernet (AES-128-CBC with HMAC-SHA256)
- **Key Derivation:** PBKDF2-HMAC-SHA256 with 480,000 iterations
- **Key Source:** Machine-specific (tied to machine ID)

### Event Log Signing

All events are cryptographically signed using:
- **Algorithm:** Ed25519 digital signatures
- **Chain Integrity:** Each event includes hash of previous event
- **Verification:** Use `verify_chain()` to check integrity

### Running as Administrator

For full security enforcement on Linux, run as root:
```bash
sudo python run_daemon.py
```

On Windows, some features work without Administrator, but enforcement modules require Linux.

### Best Practices

1. **Production:** Use a persistent signing key
2. **Production:** Set `allow_missing_manifest=False`
3. **Production:** Run in RESTRICTED or higher mode
4. **Development:** OPEN mode is acceptable
5. **Always:** Keep Ollama running locally (not exposed to network)

---

## Version Information

- **Current Version:** See startup banner
- **Python Required:** 3.9+ (supports 3.9, 3.10, 3.11, 3.12, 3.13)
- **Supported Platforms:** Windows 10+, Linux (kernel 4.4+)

---

## Appendix: Security Modes Quick Reference

| Mode | Network | USB | Processes | Logging | Use Case |
|------|---------|-----|-----------|---------|----------|
| OPEN | Allowed | Allowed | Allowed | Yes | Development |
| RESTRICTED | Monitored | Monitored | Monitored | Yes | Research |
| TRUSTED | VPN only | No USB | Controlled | Yes | Serious work |
| AIRGAP | Blocked | Controlled | Controlled | Yes | High-value IP |
| COLDROOM | Blocked | Blocked | Display only | Yes | Crown jewels |
| LOCKDOWN | Blocked | Blocked | Blocked | Yes | Emergency |

---

## Appendix: Monitoring Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Memory | 500 MB | 1000 MB |
| Disk | 90% | 95% |
| File Descriptors | 70% of limit | N/A |
| Queue Depth | 100 events | 500 events |
| Heartbeat | N/A | 60s timeout |

---

## AI/Agent Security Features

The Boundary Daemon includes comprehensive security features specifically designed for AI agents and LLM systems.

### Prompt Injection Detection

Detects and blocks prompt injection attacks across 10+ categories:

```python
from daemon.security.prompt_injection import get_prompt_injection_detector

detector = get_prompt_injection_detector(sensitivity="high")
result = detector.analyze(user_input)

if not result.is_safe:
    print(f"Blocked: {result.action.value}")
    for detection in result.detections:
        print(f"  - {detection.injection_type.value}: {detection.description}")
```

**Detection Categories:**
- Jailbreaks (DAN, "ignore instructions")
- Instruction injection
- Prompt extraction attempts
- Delimiter injection (XML, markdown)
- Encoding bypasses (Base64, Unicode)
- Authority escalation
- Tool abuse attempts
- Memory poisoning

### Tool Output Validation

Validates and sanitizes tool outputs:

```python
from daemon.security.tool_validator import get_tool_validator, ToolPolicy

validator = get_tool_validator()

# Register tool policies
validator.register_policy(ToolPolicy(
    name="web_search",
    max_output_size=10_000,
    max_calls_per_minute=10,
    sanitize_pii=True,
))

# Start a tool call and validate output
call_id, violation = validator.start_tool_call(
    tool_name="web_search",
    tool_input={"query": "example"},
)
result = validator.validate_output("web_search", tool_output, call_id)
```

### Response Guardrails

Ensures AI responses meet safety standards:

```python
from daemon.security.response_guardrails import get_response_guardrails

guardrails = get_response_guardrails()
result = guardrails.analyze(response_text)

if not result.passed:
    response_text = result.modified_response or response_text
    for v in result.violations:
        print(f"  - {v.category.value}: {v.description}")
```

### RAG Injection Detection

Detects poisoned documents in RAG pipelines:

```python
from daemon.security.rag_injection import get_rag_detector, RetrievedDocument

detector = get_rag_detector()
result = detector.analyze_documents(retrieved_documents, query=user_query)

if not result.is_safe:
    print(f"Documents blocked: {result.documents_blocked}")
    for threat in result.threats:
        print(f"  - {threat.threat_type.value}: {threat.description}")
# Use only safe documents
safe_docs = result.safe_documents
```

### Agent Attestation

Cryptographic identity for AI agents:

```python
from daemon.security.agent_attestation import (
    get_attestation_system,
    AgentCapability,
    TrustLevel,
)
from datetime import timedelta

attestation = get_attestation_system()

# Register an agent
identity = attestation.register_agent(
    agent_name="research_agent",
    agent_type="tool",
    capabilities={AgentCapability.FILE_READ, AgentCapability.NETWORK_LOCAL},
    trust_level=TrustLevel.STANDARD,
)

# Issue attestation token
token = attestation.issue_token(
    agent_id=identity.agent_id,
    capabilities={AgentCapability.FILE_READ},
    validity=timedelta(hours=1),
)

# Verify token before action
result = attestation.verify_token(
    token,
    required_capabilities={AgentCapability.FILE_READ},
)
if result.is_valid:
    # Perform action
    pass
```

---

## SIEM Integration

Export security events to enterprise SIEMs:

### CEF/LEEF Format

```python
from daemon.integrations.siem.cef_leef import CEFExporter

exporter = CEFExporter()
cef_events = exporter.format_events(daemon.get_events())
```

### Log Shipping

```python
from daemon.integrations.siem.log_shipper import create_shipper, ShipperConfig, ShipperProtocol

config = ShipperConfig(
    protocol=ShipperProtocol.KAFKA,
    kafka_bootstrap_servers="broker:9092",
    kafka_topic="boundary-events",
)
shipper = create_shipper(config)
shipper.start()
for event in events:
    shipper.add_event(event)
shipper.stop()
```

**Supported Destinations:**
- Kafka
- Amazon S3
- Google Cloud Storage
- HTTP/HTTPS endpoints
- File

---

## Process Sandboxing

Isolate processes with security constraints:

```bash
# Create a sandbox profile
sandboxctl create --name research --mode RESTRICTED

# Run process in sandbox
sandboxctl run --profile research python my_agent.py

# List active sandboxes
sandboxctl list

# Terminate sandbox
sandboxctl stop research
```

**Sandbox Features:**
- Linux namespace isolation (PID, network, mount)
- Seccomp syscall filtering
- Cgroups resource limits
- Per-sandbox network policies
- AppArmor/SELinux profiles

---

## CLI Reference

### boundaryctl

Main control CLI for the daemon:

```bash
# Check status
boundaryctl status

# Watch live events
boundaryctl watch

# Set security mode
boundaryctl set-mode RESTRICTED

# Check tool permission
boundaryctl check-tool web_browser

# Check memory recall permission
boundaryctl check-recall CONFIDENTIAL

# Verify log integrity
boundaryctl verify

# View recent events
boundaryctl events --limit 50
```

### authctl

Authentication management:

```bash
# Create new token
authctl create-token --name api-client --capabilities read,write

# List tokens
authctl list-tokens

# Revoke token
authctl revoke-token <token-id>
```

### sandboxctl

Sandbox management:

```bash
# List profiles
sandboxctl profiles

# Create sandbox
sandboxctl create --name myapp --mode AIRGAP

# Run in sandbox
sandboxctl run --profile myapp ./my_application

# Monitor sandbox
sandboxctl monitor myapp

# Stop sandbox
sandboxctl stop myapp
```

---

## API Contracts


Versioned guarantees for integrators. If a contract is not listed here, it is not guaranteed.

---

## 1. Transport

| Property | Contract |
|---|---|
| Protocol | Unix domain socket, JSON over stream |
| Socket discovery | 1. `BOUNDARY_DAEMON_SOCKET` env var, 2. `/var/run/boundary-daemon/boundary.sock`, 3. `~/.agent-os/api/boundary.sock`, 4. `./api/boundary.sock` |
| Message framing | Single JSON object per request, single JSON object per response |
| Max message size | 64 KiB (65536 bytes) |
| Encoding | UTF-8 |

**Stability:** The 4-level socket discovery order will not change in v1.x releases. New levels may be appended.

---

## 2. Request Format

```json
{
  "command": "<string>",
  "params": { ... },
  "token": "<string, optional>"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `command` | string | yes | One of the commands listed in section 4 |
| `params` | object | no | Command-specific parameters (defaults to `{}`) |
| `token` | string | no | API token prefixed with `bd_`. Required unless anonymous access is enabled. |

**Stability:** These three top-level fields will not change in v1.x.

---

## 3. Response Format

### Success

```json
{
  "success": true,
  "permitted": true,
  "reason": "Allowed in current mode",
  ...command-specific fields...
}
```

### Denial

```json
{
  "success": true,
  "permitted": false,
  "reason": "Mode OPEN does not meet minimum AIRGAP for TOP_SECRET"
}
```

### Error

```json
{
  "success": false,
  "error": "Human-readable error message",
  "auth_error": true
}
```

| Field | Type | Guaranteed | Notes |
|---|---|---|---|
| `success` | boolean | yes | `false` only for transport/auth errors, not policy denials |
| `permitted` | boolean | yes (for check commands) | Policy decision result |
| `reason` | string | yes | Human-readable explanation |
| `error` | string | on failure | Error description |
| `auth_error` | boolean | on auth failure | Present and `true` when token is invalid |

**Stability:** `success`, `permitted`, and `reason` are guaranteed present in their respective contexts for all v1.x releases. Additional fields may be added but will never be removed.

---

## 4. Commands

### 4.1 Policy Check Commands

#### `check_recall`

Check if memory recall is permitted in current mode.

| Param | Type | Required | Description |
|---|---|---|---|
| `memory_class` | int (0-5) | yes | Memory classification level |
| `memory_id` | string | no | Memory identifier for audit logging |

Response: `{ permitted, reason }`

**Fail-closed:** Unknown `memory_class` values result in `permitted: false`.

#### `check_tool`

Check if tool execution is permitted.

| Param | Type | Required | Description |
|---|---|---|---|
| `tool_name` | string | yes | Tool identifier |
| `requires_network` | boolean | no | Tool needs network access (default: false) |
| `requires_filesystem` | boolean | no | Tool needs filesystem access (default: false) |
| `requires_usb` | boolean | no | Tool needs USB access (default: false) |
| `context` | object | no | Additional context for audit logging |

Response: `{ permitted, reason }`

**Fail-closed:** Unknown tools with resource requirements are denied in restrictive modes.

#### `check_message`

Check message content for policy compliance.

| Param | Type | Required | Description |
|---|---|---|---|
| `content` | string | yes | Message content |
| `source` | string | no | Source identifier: `natlangchain`, `agent_os`, `unknown` |
| `context` | object | no | Additional context |

Response: `{ permitted, reason, result_type, violations, redacted_content }`

#### `check_natlangchain`

Check a NatLangChain blockchain entry.

| Param | Type | Required | Description |
|---|---|---|---|
| `author` | string | yes | Entry author |
| `intent` | string | yes | Intent description (prose) |
| `timestamp` | string | yes | ISO 8601 timestamp |
| `signature` | string | no | Cryptographic signature |
| `previous_hash` | string | no | Hash of previous entry |
| `metadata` | object | no | Additional metadata |

Response: `{ permitted, reason, result_type, violations }`

#### `check_agentos`

Check an Agent-OS inter-agent message.

| Param | Type | Required | Description |
|---|---|---|---|
| `sender_agent` | string | yes | Sending agent identifier |
| `recipient_agent` | string | yes | Receiving agent identifier |
| `content` | string | yes | Message content |
| `message_type` | string | no | `request`, `response`, `notification`, `command` |
| `authority_level` | int (0-5) | no | Authority level (default: 0) |
| `timestamp` | string | no | ISO 8601 timestamp (auto-generated if omitted) |
| `requires_consent` | boolean | no | Whether consent is required |
| `metadata` | object | no | Additional metadata |

Response: `{ permitted, reason, result_type, violations }`

### 4.2 Status Commands

#### `status`

Get daemon status. No parameters.

Response:
```json
{
  "success": true,
  "status": {
    "mode": "restricted",
    "online": true,
    "network_state": "online",
    "hardware_trust": "high",
    "lockdown_active": false,
    "tripwire_count": 0,
    "uptime_seconds": 3600.5
  }
}
```

#### `verify_log`

Verify event log integrity. No parameters.

Response: `{ success, valid, error }`

### 4.3 Mode Commands

#### `set_mode`

Request mode change (requires `SET_MODE` capability).

| Param | Type | Required | Description |
|---|---|---|---|
| `mode` | string | yes | Target mode: `open`, `restricted`, `trusted`, `airgap`, `coldroom` |
| `operator` | string | no | `human` or `system` (default: `human`) |
| `reason` | string | no | Reason for change |

Response: `{ success, message }`

**Constraint:** Cannot exit LOCKDOWN via `set_mode`. Use ceremony override instead.

### 4.4 Token Management Commands

#### `create_token`

Create a new API token (requires `MANAGE_TOKENS` capability).

| Param | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Human-readable name |
| `capabilities` | array | yes | Capability names or set names (`readonly`, `operator`, `admin`) |
| `expires_in_days` | int | no | Days until expiration (default: 365, null = never) |

#### `revoke_token`

Revoke a token (requires `MANAGE_TOKENS` capability).

| Param | Type | Required | Description |
|---|---|---|---|
| `token_id` | string | yes | Token ID (first 8 chars of hash) |

#### `list_tokens`

List tokens (requires `MANAGE_TOKENS` capability). Token hashes are never exposed.

---

## 5. Authentication

| Property | Contract |
|---|---|
| Token format | `bd_` prefix + 43 chars URL-safe base64 |
| Token storage | SHA-256 hash only; plaintext never persisted |
| Token validation | Constant-time comparison via `hmac.compare_digest` |
| Capability model | Capability-based; `ADMIN` implies all capabilities |
| Unknown commands | Denied (fail-closed) |

### Capability Matrix

| Capability | Commands |
|---|---|
| `STATUS` | `status` |
| `READ_EVENTS` | `get_events` |
| `VERIFY_LOG` | `verify_log` |
| `CHECK_RECALL` | `check_recall` |
| `CHECK_TOOL` | `check_tool` |
| `CHECK_MESSAGE` | `check_message`, `check_natlangchain`, `check_agentos` |
| `SET_MODE` | `set_mode` |
| `MANAGE_TOKENS` | `create_token`, `revoke_token`, `list_tokens`, `rate_limit_status` |
| `ADMIN` | All of the above |

### Predefined Capability Sets

| Set Name | Includes |
|---|---|
| `readonly` | STATUS, READ_EVENTS, VERIFY_LOG, CHECK_RECALL, CHECK_TOOL, CHECK_MESSAGE |
| `operator` | readonly + SET_MODE |
| `admin` | ADMIN (all) |

---

## 6. Rate Limiting

| Layer | Default | Window |
|---|---|---|
| Per-token | 100 requests | 60 seconds |
| Per-command | Varies (see below) | 60 seconds |
| Global | 1000 requests | 60 seconds |

### Per-Command Limits

| Command | Max/minute | Rationale |
|---|---|---|
| `check_recall` | 500 | Memory operations are frequent |
| `check_tool` | 300 | Tool calls are frequent |
| `check_message` | 200 | Content validation |
| `status` | 200 | Health checks |
| `set_mode` | 10 | Mode changes should be rare |
| `create_token` | 5 | Token creation is infrequent |

### Rate Limit Response Headers

Rate limit status is included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 45
X-RateLimit-Window: 60
```

**Stability:** Rate limit defaults may change between minor versions. The header format is stable.

---

## 7. Fail-Closed Guarantees

These are **hard invariants** — they hold regardless of daemon state:

| Scenario | Behavior |
|---|---|
| Daemon unreachable | Client returns `permitted: false` |
| Token invalid/missing | `success: false, auth_error: true` |
| Unknown command | `success: false, error: "Unknown command"` |
| Unknown memory class | `permitted: false` |
| Unknown request type | `permitted: false` (policy engine deny) |
| MessageChecker unavailable | All message checks return `permitted: false` |
| LOCKDOWN mode | All policy checks return `permitted: false` |
| Rate limit exceeded | `success: false` with retry-after information |

**Stability:** Fail-closed behavior will never be relaxed. New failure modes will always default to denial.

---

## 8. Latency Expectations

| Operation | Target | Notes |
|---|---|---|
| Policy check (local) | < 1 ms | No I/O, deterministic matrix lookup |
| Socket round-trip | < 5 ms | Unix domain socket, local only |
| Client timeout | 5 seconds | Default; configurable per-client |
| Client retry | 3 attempts | Exponential backoff: 0.5s, 1s, 2s |
| Log verification | < 100 ms | Scales with log size |

---

## 9. Versioning

| Property | Contract |
|---|---|
| Version scheme | Semantic versioning (major.minor.patch) |
| Breaking changes | Major version bump only |
| New fields in responses | May be added in minor versions |
| Field removal | Major version bump only |
| New commands | May be added in minor versions |
| Command removal | Major version bump only |

**Current version:** 1.0.0

---

## 10. Integration Quick Reference

### Python (shared client)

```python
from boundary_client import BoundaryClient

client = BoundaryClient()  # Auto-discovers socket
decision = client.check_recall(memory_class=3)
if decision.permitted:
    # proceed
```

### Python (Memory Vault)

```python
from boundary import RecallGate

gate = RecallGate()
if gate.can_recall(memory_class=3, memory_id="mem-001"):
    memory = vault.retrieve("mem-001")
```

### TypeScript (Agent-OS)

```typescript
import { AgentOSBoundaryIntegration } from './boundary';

const boundary = new AgentOSBoundaryIntegration();
if (await boundary.toolGate.canExecute('shell', { network: true })) {
    // proceed
}
```

### Decorator (Python)

```python
from boundary_client import boundary_protected

@boundary_protected(requires_network=True, memory_class=2)
def fetch_confidential_data():
    # Automatically denied if policy check fails
    ...
```

---

## Monitoring Metrics


Comprehensive catalog of all security rules, tests, threats, and monitoring points.

## Summary Statistics

| Category | Count | Performance Impact |
|----------|-------|-------------------|
| **Policy Rules** | 15 | Low - evaluated on request |
| **Security Tests** | 516 test cases | N/A - test time only |
| **Attack Vectors** | 78+ | N/A - detection patterns |
| **Monitoring Points** | 47 | Medium - 1Hz polling |
| **API Commands** | 23 | Low - on-demand |
| **Security Gates** | 38 | Low - evaluated on request |
| **Event Types** | 26 | Low - async logging |
| **Enforcement Modules** | 11 | Low - triggered on change |
| **Integration Modules** | 12 | N/A - external repos |

**Total Active Monitoring Elements: 743+**

---

## Monitoring Intervals (Performance Configuration)

### Core Polling Intervals

| Monitor | Interval | Config Location |
|---------|----------|-----------------|
| State Monitor | 1.0s | `constants.py:STATE_POLL_INTERVAL` |
| Health Check | 60.0s | `constants.py:HEALTH_CHECK_INTERVAL` |
| Heartbeat | 10.0s | `health_monitor.py:heartbeat_interval` |
| Enforcement Loop | 5.0s | `constants.py:ENFORCEMENT_INTERVAL` |
| File Integrity | 60.0s | `constants.py:INTEGRITY_CHECK_INTERVAL` |
| Dead-man Check | 60.0s | `constants.py:DEAD_MAN_CHECK_INTERVAL` |
| Memory Sampling | 5.0s | `memory_monitor.py:sample_interval` |
| Resource Sampling | 10.0s | `resource_monitor.py:sample_interval` |
| Mode Advisor | 60.0s | `mode_advisor.py:evaluation_interval` |
| Log Redundancy | 60.0s | `redundant_event_logger.py:health_check_interval` |

### Cache TTLs (Performance Optimization)

| Cache | TTL | Max Size |
|-------|-----|----------|
| Threat Intel | 3600s (1h) | 10,000 entries |
| LDAP Groups | 300s (5m) | Unlimited |
| LDAP Users | 60s (1m) | Unlimited |
| OIDC JWKS | 3600s (1h) | Single |
| OIDC Tokens | 300s (5m) | Unlimited |
| Identity | 300s (5m) | Unlimited |
| TPM PCRs | 5s | 24 entries |
| Malware Bazaar | 3600s (1h) | 10,000 entries |
| Daemon Status | 1s | Single |

---

## Detailed Component Counts

### 1. Policy Rules (15)

**Core Policy Files:**
- `config/policies.d/00-examples.yaml` - 6 example rules
- `config/policies.d/10-organization-policies.yaml.example` - 5 template rules
- `daemon/policy_engine.py` - 4 evaluation methods

**Named Rules:**
1. Block external models in AIRGAP/COLDROOM
2. Require VPN for confidential memories
3. Allow safe filesystem tools in OPEN/RESTRICTED
4. Block network tools in AIRGAP
5. Limit SECRET access to business hours
6. No USB in COLDROOM
7. Require VPN for all network operations
8. Block unauthorized API access
9. Contractor hours restriction
10. CROWN_JEWEL requires COLDROOM
11. Whitelist approved tools only
12. Rate limit enforcement per mode
13. Authority level validation
14. Reflection depth limits
15. Cross-agent communication rules

### 2. Security Tests (516 cases)

| Test File | Cases | Coverage |
|-----------|-------|----------|
| test_attack_simulations.py | 75 | Attack prevention |
| test_state_monitor.py | 59 | State detection |
| test_privilege_manager.py | 48 | Privilege control |
| test_policy_engine.py | 48 | Policy evaluation |
| test_health_monitor.py | 45 | Health checking |
| test_event_logger.py | 37 | Event logging |
| test_tripwires.py | 36 | Violation detection |
| test_api_auth.py | 34 | Authentication |
| test_log_hardening.py | 27 | Log security |
| test_append_only.py | 27 | Append-only storage |
| test_constants.py | 26 | Configuration |
| test_integrations.py | 16 | Integrations |
| test_security_stack_e2e.py | 11 | End-to-end |
| test_security_integration.py | 27 | Cross-repo security |

### 3. Attack Vectors (78+)

**64 Attack Simulations by Category:**

| Category | Count | Examples |
|----------|-------|----------|
| Cellular Attacks | 5 | 2G downgrade, IMSI catcher, tower switching |
| WiFi Attacks | 9 | Evil twin, deauth, rogue AP, handshake capture |
| DNS Attacks | 8 | Tunneling, rebinding, spoofing, TLD abuse |
| ARP Attacks | 5 | Spoofing, gateway impersonation, MITM |
| Threat Intel | 7 | TOR exit, C2, botnet, beaconing |
| File Integrity | 8 | Modification, SUID, world writable |
| Traffic Anomaly | 8 | Port scan, exfiltration, ICMP tunnel |
| Process Security | 8 | ptrace, LD_PRELOAD, memfd exec |
| Network Bypass | 6 | VPN tunnel, bridge, protocol abuse |

**14 MITRE ATT&CK Tactics:**
TA0001-TA0011, TA0040, TA0042, TA0043

**10 Violation Types:**
1. NETWORK_IN_AIRGAP
2. USB_IN_COLDROOM
3. UNAUTHORIZED_RECALL
4. DAEMON_TAMPERING
5. MODE_INCOMPATIBLE
6. EXTERNAL_MODEL_VIOLATION
7. SUSPICIOUS_PROCESS
8. HARDWARE_TRUST_DEGRADED
9. CLOCK_MANIPULATION
10. NETWORK_TRUST_VIOLATION

### 4. Monitoring Points (47)

**State Monitor (42 methods):**
- Core: `_check_network`, `_check_hardware`, `_check_software`, `_check_human_presence`
- Security: `_check_dns_security`, `_check_arp_security`, `_check_wifi_security`
- Intel: `_check_threat_intel`, `_check_file_integrity`, `_check_traffic_anomaly`
- Process: `_check_process_security`, `_check_specialty_networks`
- Devices: `_detect_lora_devices`, `_detect_thread_devices`, `_detect_cellular_security_threats`

**Tripwire Checks (5):**
1. `_check_network_in_airgap`
2. `_check_usb_in_coldroom`
3. `_check_external_model_violations`
4. `_check_suspicious_processes`
5. `_check_hardware_trust`

**Configurable Monitors (13):**
```python
monitor_lora: bool = True
monitor_thread: bool = True
monitor_cellular_security: bool = True
monitor_wimax: bool = False      # Disabled - obsolete
monitor_irda: bool = False       # Disabled - legacy
monitor_ant_plus: bool = True
monitor_dns_security: bool = True
monitor_arp_security: bool = True
monitor_wifi_security: bool = True
monitor_threat_intel: bool = True
monitor_file_integrity: bool = True
monitor_traffic_anomaly: bool = True
monitor_process_security: bool = True
```

### 5. API Commands (23)

| Category | Commands |
|----------|----------|
| Token (3) | create_token, revoke_token, list_tokens |
| Policy (4) | check_recall, check_tool, check_message, set_mode |
| Status (6) | status, rate_limit_status, get_health_stats, get_monitoring_summary, get_resource_stats, check_ollama_status |
| Log (2) | get_events, verify_log |
| Integration (3) | check_natlangchain, check_agentos, check_message |
| Reporting (5) | get_memory_stats, get_queue_stats, generate_report, get_raw_report, get_report_history |

### 6. Security Gates (38)

**By Category:**

| Category | Gates | Count |
|----------|-------|-------|
| Core | check_recall, check_tool, check_message | 3 |
| Cryptographic | verify_key_derivation, verify_merkle_proof, verify_cryptographic_signature, verify_zkp_proof | 4 |
| Semantic | classify_intent_semantics, detect_semantic_drift, detect_cross_language_injection, verify_llm_consensus | 4 |
| Economic | verify_stake_escrow, verify_stake_burned, verify_effort_proof, verify_w3c_credential | 4 |
| Cognitive | check_reflection_intensity, check_identity_mutation, check_agent_attestation | 3 |
| Contract | verify_contract_signature, verify_memory_not_revoked, check_contract_delegation_depth, verify_constitution_integrity | 4 |
| Execution | verify_execution_confidence, detect_political_activity, verify_sunset_deadline, prevent_posthumous_revocation | 4 |
| Dispute | check_counter_proposal_limit, verify_settlement_honors_constraints, check_dispute_class_mode_requirement | 3 |
| SIEM | verify_detection_rule_signature, audit_rule_state_change, correlate_siem_event | 3 |
| Rate Limit | check_entity_rate_limit | 1 |
| Consent | verify_memory_consent, verify_physical_token_presented | 2 |
| Middleware | initiate_ceremony, check_anomaly_score, get_graduated_permission | 3 |

### 7. Event Types (26)

| Category | Types |
|----------|-------|
| System (4) | MODE_CHANGE, DAEMON_START, DAEMON_STOP, OVERRIDE |
| Security (9) | VIOLATION, TRIPWIRE, POLICY_DECISION, RECALL_ATTEMPT, TOOL_REQUEST, BIOMETRIC_ATTEMPT, SECURITY_SCAN, CLOCK_JUMP, CLOCK_DRIFT |
| API (4) | API_REQUEST, MESSAGE_CHECK, HEALTH_CHECK, NTP_SYNC_LOST |
| Rate Limit (4) | RATE_LIMIT_TOKEN, RATE_LIMIT_GLOBAL, RATE_LIMIT_COMMAND, RATE_LIMIT_UNBLOCK |
| PII (3) | PII_DETECTED, PII_BLOCKED, PII_REDACTED |
| General (2) | ALERT, INFO |

---

## Performance Recommendations

### Current Architecture (Optimized)

The daemon uses several performance optimizations:

1. **Tiered Polling Intervals:**
   - Critical (1s): State monitor
   - Standard (5-10s): Memory, resources, enforcement
   - Background (60s): Health, integrity, dead-man

2. **Caching Strategy:**
   - Threat intel: 1-hour TTL, 10K max entries
   - Identity: 5-minute TTL
   - TPM PCRs: 5-second TTL

3. **Async Processing:**
   - Event logging is asynchronous
   - Background threads for non-critical monitors
   - Rate limiting prevents CPU spikes

4. **Configurable Monitors:**
   - Legacy monitors (WiMAX, IrDA) disabled by default
   - Each monitor can be individually toggled

### Resource Usage Estimate

| Component | CPU Impact | Memory | Notes |
|-----------|-----------|--------|-------|
| State Monitor | ~1% | ~10MB | 1Hz polling |
| Health Monitor | <0.1% | ~5MB | 60s interval |
| Memory Monitor | ~0.5% | ~20MB | 5s sampling, history |
| Resource Monitor | ~0.5% | ~15MB | 10s sampling, history |
| Event Logger | <0.1% | ~50MB | Async, hash chains |
| Tripwires | ~0.5% | ~5MB | Per-check evaluation |
| **Total** | **~3%** | **~105MB** | Normal operation |

### Tuning for High-Security Environments

For maximum monitoring without performance issues:

```ini
[daemon]
poll_interval = 1.0          # Keep at 1Hz for real-time

[health]
check_interval = 30.0        # Increase frequency
heartbeat_interval = 5.0     # More frequent heartbeats

[memory]
sample_interval = 2.0        # More frequent sampling
history_size = 1800          # 1 hour at 2s

[resource]
sample_interval = 5.0        # More frequent
history_size = 720           # 1 hour at 5s

[threat_intel]
cache_ttl = 1800            # 30 min (fresher data)
max_cache_size = 50000      # More entries

[monitors]
all_enabled = true          # Enable all monitors
```

### Tuning for Resource-Constrained Environments

```ini
[daemon]
poll_interval = 5.0          # Reduce to 5Hz

[health]
check_interval = 120.0       # 2 minutes
heartbeat_interval = 30.0    # 30 seconds

[memory]
sample_interval = 30.0       # Less frequent
history_size = 120           # 1 hour at 30s

[monitors]
monitor_wimax = false
monitor_irda = false
monitor_ant_plus = false
monitor_traffic_anomaly = false  # Most CPU-intensive
```

---

## Module Watch Capability Matrix

All modules can be monitored with the following granularity:

| Module | Real-time | Historical | Alerting | Audit |
|--------|-----------|------------|----------|-------|
| Policy Engine | ✅ | ✅ | ✅ | ✅ |
| State Monitor | ✅ | ✅ | ✅ | ✅ |
| Tripwires | ✅ | ✅ | ✅ | ✅ |
| Event Logger | ✅ | ✅ | ✅ | ✅ |
| Health Monitor | ✅ | ✅ | ✅ | ✅ |
| Memory Monitor | ✅ | ✅ | ✅ | ✅ |
| Resource Monitor | ✅ | ✅ | ✅ | ✅ |
| API Layer | ✅ | ✅ | ✅ | ✅ |
| Enforcement | ✅ | ✅ | ✅ | ✅ |
| Security Gates | ✅ | ✅ | ✅ | ✅ |
| Integrations | ✅ | ✅ | ✅ | ✅ |

**Conclusion:** All 47 monitoring points can be watched continuously at 1Hz without significant performance impact (<3% CPU, ~105MB RAM on a modern system).

---

*Generated: 2026-01-02*
*Daemon Version: 0.1.0-alpha*

---

## Integration


> **Note:** This document has been consolidated. For comprehensive integration documentation, see:
> - **[integrations/INTEGRATION_GUIDE.md](integrations/INTEGRATION_GUIDE.md)** - Complete ecosystem integration guide
> - **[integrations/README.md](integrations/README.md)** - Quick reference and package list
> - **[integrations/SECURITY_INTEGRATION.md](integrations/SECURITY_INTEGRATION.md)** - Attack vectors prevented
> - **[integrations/ADVANCED_RULES.md](integrations/ADVANCED_RULES.md)** - Advanced policy gates (47 rules)

---

## Quick Start

### Mandatory Callers

The following components MUST call the Boundary Daemon:

1. **Memory Vault** - Before any memory recall
2. **Agent-OS** - Before any tool execution
3. **synth-mind** - Before reflection loops
4. **External Model Adapters** - Before API calls

### Python Integration

```python
from api.boundary_api import BoundaryAPIClient

client = BoundaryAPIClient(socket_path='./api/boundary.sock')

# Check memory recall permission
permitted, reason = client.check_recall(memory_class=3)
if not permitted:
    raise PermissionError(f"Recall denied: {reason}")

# Check tool execution permission
permitted, reason = client.check_tool(
    tool_name='wget',
    requires_network=True
)
```

### Unix Socket API

```bash
echo '{"command": "check_recall", "params": {"memory_class": 3}}' | \
    nc -U ./api/boundary.sock
```

---

## Boundary Modes Reference

| Mode | Network | Memory Classes | Tools | Use Case |
|------|---------|----------------|-------|----------|
| OPEN | Full | 0-1 | All | Casual use |
| RESTRICTED | Monitored | 0-2 | Most | Research |
| TRUSTED | VPN only | 0-3 | No USB | Serious work |
| AIRGAP | None | 0-4 | No network | High-value IP |
| COLDROOM | None | 0-5 | Display only | Crown jewels |
| LOCKDOWN | Blocked | None | None | Emergency |

---

## Architecture Principles

1. **Mandatory Enforcement**: Components MUST NOT bypass the daemon
2. **Fail-Closed**: Ambiguity defaults to DENY
3. **Immutable Logging**: All decisions logged with hash chain and Ed25519 signatures
4. **Human Override**: Requires ceremony, never silent
5. **Deterministic**: Same inputs → same decision

---

For detailed integration instructions, code examples, and repository-specific guides, see **[integrations/INTEGRATION_GUIDE.md](integrations/INTEGRATION_GUIDE.md)**.
