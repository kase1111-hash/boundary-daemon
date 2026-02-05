# Module Map

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
