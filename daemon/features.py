"""
Feature Detection Module for Boundary Daemon

Centralizes all optional feature detection and provides diagnostics
for understanding which capabilities are available at runtime.

Usage:
    from daemon.features import FEATURES, get_feature_status, log_feature_summary

    if FEATURES.ENFORCEMENT:
        from daemon.enforcement import NetworkEnforcer
"""

import logging
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform.startswith('linux')
IS_MACOS = sys.platform == 'darwin'


@dataclass
class FeatureInfo:
    """Information about a feature's availability."""
    available: bool
    reason: str = ""
    dependencies: List[str] = field(default_factory=list)
    platform_notes: str = ""


def _check_import(module_path: str, items: Optional[List[str]] = None) -> Tuple[bool, str]:
    """
    Check if a module can be imported.

    Returns:
        Tuple of (available, reason)
    """
    try:
        if items:
            module = __import__(module_path, fromlist=items)
            for item in items:
                getattr(module, item)
        else:
            __import__(module_path)
        return True, "OK"
    except ImportError as e:
        return False, f"ImportError: {e}"
    except Exception as e:
        return False, f"Error: {e}"


class Features:
    """
    Centralized feature availability tracking.

    All features are checked once at import time and cached.
    """

    def __init__(self):
        self._features: Dict[str, FeatureInfo] = {}
        self._detect_all()

    def _detect_all(self):
        """Detect availability of all optional features."""

        # Core optional features
        self._detect_feature(
            "ENHANCED_LOGGING",
            "daemon.logging_config",
            ["get_logger"],
            "Enhanced logging with structured output"
        )

        self._detect_feature(
            "API_SERVER",
            "api.boundary_api",
            ["BoundaryAPIServer"],
            "REST API server for external tools"
        )

        self._detect_feature(
            "SIGNED_LOGGING",
            "daemon.signed_event_logger",
            ["SignedEventLogger"],
            "Ed25519 signed event logging",
            dependencies=["pynacl"]
        )

        # Enforcement features (Linux-only)
        self._detect_feature(
            "ENFORCEMENT",
            "daemon.enforcement",
            ["NetworkEnforcer", "USBEnforcer", "ProcessEnforcer"],
            "Kernel-level enforcement",
            platform_notes="Linux only - requires root and iptables/udev/seccomp"
        )

        self._detect_feature(
            "PROTECTION_PERSISTENCE",
            "daemon.enforcement",
            ["ProtectionPersistenceManager", "CleanupPolicy"],
            "Protection state persistence across restarts"
        )

        self._detect_feature(
            "PRIVILEGE_MANAGER",
            "daemon.privilege_manager",
            ["PrivilegeManager", "EnforcementModule"],
            "Privilege tracking for enforcement modules"
        )

        # Hardware features
        self._detect_feature(
            "TPM",
            "daemon.hardware",
            ["TPMManager"],
            "TPM 2.0 integration for hardware trust",
            dependencies=["tpm2-pytss"],
            platform_notes="Requires TPM 2.0 hardware"
        )

        # Distributed features
        self._detect_feature(
            "DISTRIBUTED",
            "daemon.distributed",
            ["ClusterManager", "FileCoordinator"],
            "Multi-node cluster coordination"
        )

        # Policy features
        self._detect_feature(
            "CUSTOM_POLICY",
            "daemon.policy",
            ["CustomPolicyEngine"],
            "Custom policy language support"
        )

        # Auth features
        self._detect_feature(
            "BIOMETRIC",
            "daemon.auth",
            ["BiometricVerifier", "EnhancedCeremonyManager"],
            "Biometric authentication support"
        )

        # Security features
        self._detect_feature(
            "SECURITY_ADVISOR",
            "daemon.security",
            ["CodeVulnerabilityAdvisor"],
            "Code vulnerability analysis"
        )

        self._detect_feature(
            "CLOCK_MONITOR",
            "daemon.security.clock_monitor",
            ["ClockMonitor", "ClockStatus"],
            "System clock drift detection"
        )

        self._detect_feature(
            "DAEMON_INTEGRITY",
            "daemon.security.daemon_integrity",
            ["DaemonIntegrityProtector", "verify_daemon_integrity"],
            "Binary tampering detection"
        )

        self._detect_feature(
            "NETWORK_ATTESTATION",
            "daemon.security.network_attestation",
            ["NetworkAttestor", "NetworkTrustLevel"],
            "Network trust verification"
        )

        # Watchdog features
        self._detect_feature(
            "WATCHDOG",
            "daemon.watchdog",
            ["LogWatchdog", "WatchdogConfig"],
            "Log monitoring watchdog"
        )

        self._detect_feature(
            "HARDENED_WATCHDOG",
            "daemon.watchdog",
            ["DaemonWatchdogEndpoint", "generate_shared_secret"],
            "Hardened daemon watchdog with shared secrets",
            platform_notes="Unix sockets required - limited on Windows"
        )

        # Telemetry
        self._detect_feature(
            "TELEMETRY",
            "daemon.telemetry",
            ["TelemetryManager", "TelemetryConfig"],
            "OpenTelemetry integration",
            dependencies=["opentelemetry-api", "opentelemetry-sdk"]
        )

        # Message checking
        self._detect_feature(
            "MESSAGE_CHECKER",
            "daemon.messages",
            ["MessageChecker", "MessageSource"],
            "NatLangChain/Agent-OS message validation"
        )

        # Config
        self._detect_feature(
            "SECURE_CONFIG",
            "daemon.config",
            ["SecureConfigStorage", "load_secure_config"],
            "Encrypted configuration storage"
        )

        # Logging redundancy
        self._detect_feature(
            "REDUNDANT_LOGGING",
            "daemon.redundant_event_logger",
            ["RedundantEventLogger", "create_redundant_logger"],
            "Multi-backend logging redundancy"
        )

        # Monitoring features
        self._detect_feature(
            "MEMORY_MONITOR",
            "daemon.memory_monitor",
            ["MemoryMonitor", "create_memory_monitor"],
            "Memory leak detection"
        )

        self._detect_feature(
            "RESOURCE_MONITOR",
            "daemon.resource_monitor",
            ["ResourceMonitor", "create_resource_monitor"],
            "System resource monitoring"
        )

        self._detect_feature(
            "HEALTH_MONITOR",
            "daemon.health_monitor",
            ["HealthMonitor", "create_health_monitor"],
            "Component health monitoring"
        )

        self._detect_feature(
            "QUEUE_MONITOR",
            "daemon.queue_monitor",
            ["QueueMonitor", "create_queue_monitor"],
            "Queue backpressure monitoring"
        )

        self._detect_feature(
            "REPORT_GENERATOR",
            "daemon.monitoring_report",
            ["MonitoringReportGenerator", "create_report_generator"],
            "Monitoring report generation"
        )

        # AI features
        self._detect_feature(
            "OLLAMA",
            "daemon.monitoring_report",
            ["OllamaClient", "OllamaConfig"],
            "Ollama LLM integration for reports"
        )

        # Antivirus
        self._detect_feature(
            "ANTIVIRUS",
            "daemon.security.antivirus",
            ["AntivirusEngine"],
            "Malware scanning engine"
        )

        # SIEM
        self._detect_feature(
            "SIEM",
            "daemon.siem",
            ["SIEMShipper"],
            "SIEM event shipping"
        )

    def _detect_feature(
        self,
        name: str,
        module_path: str,
        items: List[str],
        description: str,
        dependencies: Optional[List[str]] = None,
        platform_notes: str = ""
    ):
        """Detect a single feature and store its info."""
        available, reason = _check_import(module_path, items)

        self._features[name] = FeatureInfo(
            available=available,
            reason=reason if not available else description,
            dependencies=dependencies or [],
            platform_notes=platform_notes
        )

    def __getattr__(self, name: str) -> bool:
        """Allow FEATURES.ENFORCEMENT style access."""
        if name.startswith('_'):
            raise AttributeError(name)
        if name in self._features:
            return self._features[name].available
        raise AttributeError(f"Unknown feature: {name}")

    def get_info(self, name: str) -> Optional[FeatureInfo]:
        """Get detailed info about a feature."""
        return self._features.get(name)

    def get_all(self) -> Dict[str, FeatureInfo]:
        """Get all feature information."""
        return self._features.copy()

    def get_available(self) -> List[str]:
        """Get list of available feature names."""
        return [name for name, info in self._features.items() if info.available]

    def get_unavailable(self) -> List[str]:
        """Get list of unavailable feature names."""
        return [name for name, info in self._features.items() if not info.available]


# Singleton instance
FEATURES = Features()


def get_feature_status() -> Dict[str, dict]:
    """
    Get a dictionary of all features with their status.

    Returns:
        Dict mapping feature name to status dict with keys:
        - available: bool
        - reason: str (description if available, error if not)
        - dependencies: list of required packages
        - platform_notes: platform-specific notes
    """
    return {
        name: {
            "available": info.available,
            "reason": info.reason,
            "dependencies": info.dependencies,
            "platform_notes": info.platform_notes
        }
        for name, info in FEATURES.get_all().items()
    }


def log_feature_summary(log_level: int = logging.INFO):
    """
    Log a summary of feature availability.

    Args:
        log_level: Logging level for the output
    """
    available = FEATURES.get_available()
    unavailable = FEATURES.get_unavailable()

    logger.log(log_level, f"Feature Summary: {len(available)} available, {len(unavailable)} unavailable")

    if available:
        logger.log(log_level, f"  Available: {', '.join(sorted(available))}")

    if unavailable:
        logger.log(log_level, f"  Unavailable: {', '.join(sorted(unavailable))}")
        for name in sorted(unavailable):
            info = FEATURES.get_info(name)
            if info:
                logger.debug(f"    {name}: {info.reason}")


def print_feature_report():
    """Print a human-readable feature availability report."""
    print("\n" + "=" * 60)
    print("BOUNDARY DAEMON FEATURE AVAILABILITY REPORT")
    print("=" * 60)
    print(f"\nPlatform: {'Windows' if IS_WINDOWS else 'Linux' if IS_LINUX else 'macOS' if IS_MACOS else sys.platform}")
    print()

    all_features = FEATURES.get_all()
    available = [(n, i) for n, i in all_features.items() if i.available]
    unavailable = [(n, i) for n, i in all_features.items() if not i.available]

    print(f"Available Features ({len(available)}):")
    print("-" * 40)
    for name, info in sorted(available):
        print(f"  [+] {name}")
        if info.platform_notes:
            print(f"      Note: {info.platform_notes}")

    print(f"\nUnavailable Features ({len(unavailable)}):")
    print("-" * 40)
    for name, info in sorted(unavailable):
        print(f"  [-] {name}")
        print(f"      Reason: {info.reason}")
        if info.dependencies:
            print(f"      Install: pip install {' '.join(info.dependencies)}")
        if info.platform_notes:
            print(f"      Note: {info.platform_notes}")

    print("\n" + "=" * 60)


# Export convenience for common checks
def is_enforcement_available() -> bool:
    """Check if kernel-level enforcement is available."""
    return FEATURES.ENFORCEMENT and not IS_WINDOWS


def is_full_security_available() -> bool:
    """Check if full security stack is available."""
    return all([
        FEATURES.ENFORCEMENT,
        FEATURES.SIGNED_LOGGING,
        FEATURES.DAEMON_INTEGRITY,
        not IS_WINDOWS
    ])


if __name__ == "__main__":
    # Allow running as script for diagnostics
    print_feature_report()
