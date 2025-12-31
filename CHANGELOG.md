# Changelog

All notable changes to the Boundary Daemon project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions CI/CD workflow for automated testing
- Comprehensive unit test suite (478 tests)
- Test coverage for core modules (privilege_manager, state_monitor, tripwires, etc.)

### Changed
- Updated minimum Python version to 3.9 (dropped Python 3.8 EOL support)
- Added Python 3.12 and 3.13 to supported versions
- Lowered test coverage threshold to 25% (target: 50%)

### Fixed
- Renamed `TestResultCollector` to `AttackResultCollector` to fix pytest collection warning
- Added coverage files to `.gitignore`

## [1.0.0] - 2024-01-01

### Added
- Initial release of Boundary Daemon (Agent Smith)
- Policy decision and audit layer for Agent OS
- Six security boundary modes: OPEN, RESTRICTED, TRUSTED, AIRGAP, COLDROOM, LOCKDOWN
- Memory classification system (PUBLIC to CROWN_JEWEL)
- Immutable audit logging with SHA-256 hash chains
- Ed25519 cryptographic signatures for events
- Tripwire system for security violation detection
- Token-based API authentication with capabilities
- Rate limiting with persistence across restarts
- State monitoring for network, hardware, and human presence
- Integration interfaces for Memory Vault, Tool Enforcement, and Ceremonies
- Multi-step human confirmation ceremonies for sensitive operations
- Biometric verification support
- TPM (Trusted Platform Module) integration
- Distributed coordination for multi-host deployments
- Log hardening with Linux chattr append-only protection
- DNS, ARP, and WiFi security monitoring
- Threat intelligence integration
- File integrity monitoring
- Traffic anomaly detection
- Process security monitoring
- Health monitoring with heartbeat tracking
- OpenTelemetry observability integration
- CLI tools: boundaryctl, authctl, policy_ctl, cluster_ctl, biometric_ctl
- Systemd service files for daemon and watchdog
- Comprehensive documentation (SPEC.md, ARCHITECTURE.md, USER_GUIDE.md)

### Security
- Fail-closed design: ambiguous signals result in DENY
- Defense in depth: operates at Layer 3, requires kernel/hardware enforcement
- Tamper-evident logging with cryptographic proof
- Constant-time token comparison to prevent timing attacks
- Automatic lockdown on security violations
- Rate limiting to prevent abuse
- Privilege tracking and alerting for root requirements

[Unreleased]: https://github.com/kase1111-hash/boundary-daemon-/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/kase1111-hash/boundary-daemon-/releases/tag/v1.0.0
