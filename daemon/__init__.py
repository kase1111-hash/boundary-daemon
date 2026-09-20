"""
Boundary Daemon - Core Components
"""

# Import centralized constants (SECURITY: Addresses hardcoded magic values)
from .constants import (
    Timeouts,
    BufferSizes,
    Permissions,
    Paths,
    Crypto,
    TimeThresholds,
    RateLimits,
    Retries,
    NetworkConstants,
    DetectionThresholds,
    Limits,
    EssentialProcesses,
    RuntimeConfig,
    DEFAULT_TIMEOUT,
    SECURE_FILE_MODE,
    SECURE_DIR_MODE,
    KDF_ITERATIONS,
)

from .state_monitor import StateMonitor, EnvironmentState, NetworkState, HardwareTrust
from .policy_engine import PolicyEngine, BoundaryMode, PolicyRequest, PolicyDecision, Operator, MemoryClass
from .tripwires import TripwireSystem, LockdownManager, TripwireViolation, ViolationType
from .event_logger import EventLogger, EventType, BoundaryEvent
from .signed_event_logger import SignedEventLogger
from .boundary_daemon import BoundaryDaemon

# Import enforcement module (Plan 1: Kernel-Level Enforcement)
try:
    from .enforcement import (
        NetworkEnforcer, FirewallBackend, NetworkEnforcementError,
        USBEnforcer, USBEnforcementError, USBDeviceClass,
        ProcessEnforcer, ProcessEnforcementError, ContainerRuntime, IsolationLevel, ContainerConfig, ExternalWatchdog
    )
    ENFORCEMENT_AVAILABLE = True
except ImportError:
    ENFORCEMENT_AVAILABLE = False
    NetworkEnforcer = None  # type: ignore[assignment,misc]
    FirewallBackend = None  # type: ignore[assignment,misc]
    NetworkEnforcementError = None  # type: ignore[assignment,misc]
    USBEnforcer = None  # type: ignore[assignment,misc]
    USBEnforcementError = None  # type: ignore[assignment,misc]
    USBDeviceClass = None  # type: ignore[assignment,misc]
    ProcessEnforcer = None  # type: ignore[assignment,misc]
    ProcessEnforcementError = None  # type: ignore[assignment,misc]
    ContainerRuntime = None  # type: ignore[assignment,misc]
    IsolationLevel = None  # type: ignore[assignment,misc]
    ContainerConfig = None  # type: ignore[assignment,misc]
    ExternalWatchdog = None  # type: ignore[assignment,misc]

# Import hardware module (Plan 2: TPM Integration)
try:
    from .hardware import (
        TPMManager, TPMError, TPMNotAvailableError,
        TPMSealingError, TPMUnsealingError, TPMAttestationError, SealedSecret
    )
    TPM_AVAILABLE = True
except ImportError:
    TPM_AVAILABLE = False
    TPMManager = None  # type: ignore[assignment,misc]
    TPMError = None  # type: ignore[assignment,misc]
    TPMNotAvailableError = None  # type: ignore[assignment,misc]
    TPMSealingError = None  # type: ignore[assignment,misc]
    TPMUnsealingError = None  # type: ignore[assignment,misc]
    TPMAttestationError = None  # type: ignore[assignment,misc]
    SealedSecret = None  # type: ignore[assignment,misc]

# Import distributed module (Plan 4: Distributed Deployment)
try:
    from .distributed import (
        ClusterManager, ClusterNode, ClusterState,
        FileCoordinator, Coordinator
    )
    DISTRIBUTED_AVAILABLE = True
except ImportError:
    DISTRIBUTED_AVAILABLE = False
    ClusterManager = None  # type: ignore[assignment,misc]
    ClusterNode = None  # type: ignore[assignment,misc]
    ClusterState = None  # type: ignore[assignment,misc]
    FileCoordinator = None  # type: ignore[assignment,misc]
    Coordinator = None  # type: ignore[assignment,misc]

# Import custom policy module (Plan 5: Custom Policy Language)
try:
    from .policy import (
        CustomPolicyEngine, PolicyRule, PolicyAction
    )
    CUSTOM_POLICY_AVAILABLE = True
except ImportError:
    CUSTOM_POLICY_AVAILABLE = False
    CustomPolicyEngine = None  # type: ignore[assignment,misc]
    PolicyRule = None  # type: ignore[assignment,misc]
    PolicyAction = None  # type: ignore[assignment,misc]

# Import auth module (Plan 6: Biometric Authentication)
try:
    from .auth import (
        BiometricVerifier, BiometricType, BiometricResult,
        EnhancedCeremonyManager, BiometricCeremonyConfig
    )
    BIOMETRIC_AVAILABLE = True
except ImportError:
    BIOMETRIC_AVAILABLE = False
    BiometricVerifier = None  # type: ignore[assignment,misc]
    BiometricType = None  # type: ignore[assignment,misc]
    BiometricResult = None  # type: ignore[assignment,misc]
    EnhancedCeremonyManager = None  # type: ignore[assignment,misc]
    BiometricCeremonyConfig = None  # type: ignore[assignment,misc]

# Import security module (Plan 7: Code Vulnerability Advisor)
try:
    from .security import (
        CodeVulnerabilityAdvisor, SecurityAdvisory,
        AdvisorySeverity, AdvisoryStatus, ScanResult
    )
    SECURITY_ADVISOR_AVAILABLE = True
except ImportError:
    SECURITY_ADVISOR_AVAILABLE = False
    CodeVulnerabilityAdvisor = None  # type: ignore[assignment,misc]
    SecurityAdvisory = None  # type: ignore[assignment,misc]
    AdvisorySeverity = None  # type: ignore[assignment,misc]
    AdvisoryStatus = None  # type: ignore[assignment,misc]
    ScanResult = None  # type: ignore[assignment,misc]

# Import watchdog module (Plan 8: Log Watchdog Agent)
try:
    from .watchdog import (
        LogWatchdog, WatchdogAlert, WatchdogConfig,
        AlertSeverity, AlertStatus
    )
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    LogWatchdog = None  # type: ignore[assignment,misc]
    WatchdogAlert = None  # type: ignore[assignment,misc]
    WatchdogConfig = None  # type: ignore[assignment,misc]
    AlertSeverity = None  # type: ignore[assignment,misc]
    AlertStatus = None  # type: ignore[assignment,misc]

# Import telemetry module (Plan 9: OpenTelemetry Integration)
try:
    from .telemetry import (
        TelemetryManager, TelemetryConfig, ExportMode,
        RedactionProcessor, instrument,
        OTEL_AVAILABLE, OTLP_AVAILABLE
    )
    TELEMETRY_AVAILABLE = True
except ImportError:
    TELEMETRY_AVAILABLE = False
    TelemetryManager = None  # type: ignore[assignment,misc]
    TelemetryConfig = None  # type: ignore[assignment,misc]
    ExportMode = None  # type: ignore[assignment,misc]
    RedactionProcessor = None  # type: ignore[assignment,misc]
    instrument = None  # type: ignore[assignment]
    OTEL_AVAILABLE = False
    OTLP_AVAILABLE = False

__all__ = [
    # Constants (SECURITY: Centralized configuration)
    'Timeouts', 'BufferSizes', 'Permissions', 'Paths', 'Crypto',
    'TimeThresholds', 'RateLimits', 'Retries', 'NetworkConstants',
    'DetectionThresholds', 'Limits', 'EssentialProcesses', 'RuntimeConfig',
    'DEFAULT_TIMEOUT', 'SECURE_FILE_MODE', 'SECURE_DIR_MODE', 'KDF_ITERATIONS',
    # Core components
    'StateMonitor', 'EnvironmentState', 'NetworkState', 'HardwareTrust',
    'PolicyEngine', 'BoundaryMode', 'PolicyRequest', 'PolicyDecision', 'Operator', 'MemoryClass',
    'TripwireSystem', 'LockdownManager', 'TripwireViolation', 'ViolationType',
    'EventLogger', 'EventType', 'BoundaryEvent',
    'SignedEventLogger',  # Plan 3: Cryptographic Log Signing
    'BoundaryDaemon',
    # Enforcement (Plan 1)
    'NetworkEnforcer', 'FirewallBackend', 'NetworkEnforcementError',
    'USBEnforcer', 'USBEnforcementError', 'USBDeviceClass',
    'ProcessEnforcer', 'ProcessEnforcementError', 'ContainerRuntime', 'IsolationLevel', 'ContainerConfig', 'ExternalWatchdog',
    'ENFORCEMENT_AVAILABLE',
    # Hardware (Plan 2: TPM)
    'TPMManager', 'TPMError', 'TPMNotAvailableError',
    'TPMSealingError', 'TPMUnsealingError', 'TPMAttestationError', 'SealedSecret',
    'TPM_AVAILABLE',
    # Distributed (Plan 4)
    'ClusterManager', 'ClusterNode', 'ClusterState',
    'FileCoordinator', 'Coordinator',
    'DISTRIBUTED_AVAILABLE',
    # Custom Policy (Plan 5)
    'CustomPolicyEngine', 'PolicyRule', 'PolicyAction',
    'CUSTOM_POLICY_AVAILABLE',
    # Biometric Authentication (Plan 6)
    'BiometricVerifier', 'BiometricType', 'BiometricResult',
    'EnhancedCeremonyManager', 'BiometricCeremonyConfig',
    'BIOMETRIC_AVAILABLE',
    # Security Advisor (Plan 7)
    'CodeVulnerabilityAdvisor', 'SecurityAdvisory',
    'AdvisorySeverity', 'AdvisoryStatus', 'ScanResult',
    'SECURITY_ADVISOR_AVAILABLE',
    # Log Watchdog (Plan 8)
    'LogWatchdog', 'WatchdogAlert', 'WatchdogConfig',
    'AlertSeverity', 'AlertStatus',
    'WATCHDOG_AVAILABLE',
    # Telemetry (Plan 9)
    'TelemetryManager', 'TelemetryConfig', 'ExportMode',
    'RedactionProcessor', 'instrument',
    'OTEL_AVAILABLE', 'OTLP_AVAILABLE',
    'TELEMETRY_AVAILABLE'
]
