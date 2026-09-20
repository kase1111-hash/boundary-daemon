"""
Security Module for Boundary Daemon

Provides:
- Advisory-only code vulnerability scanning using local LLMs
- Native DNS resolution without external tool dependencies
- Daemon binary integrity protection

NOTE: Antivirus scanning has been extracted to the standalone
boundary-antivirus package. See boundary-antivirus/README.md.

SECURITY: The native DNS resolver addresses the vulnerability:
"DNS Response Verification Uses External Tools" by providing
pure Python DNS packet construction and parsing.

SECURITY: The daemon integrity module addresses the vulnerability:
"No Integrity Protection on Daemon Binary" by providing cryptographic
verification of all daemon code files.
"""

from .code_advisor import (
    CodeVulnerabilityAdvisor,
    SecurityAdvisory,
    AdvisorySeverity,
    AdvisoryStatus,
    ScanResult
)

from .native_dns_resolver import (
    NativeDNSResolver,
    SecureDNSVerifier,
    DNSType,
    DNSResponse,
    DNSRecord,
)

# Secure memory utilities (SECURITY: Secret zeroing after use)
try:
    from .secure_memory import (
        SecureBytes,
        secure_zero_memory,
        secure_key_context,
        secure_compare,
        generate_secure_random,
    )
    SECURE_MEMORY_AVAILABLE = True
except ImportError:
    SECURE_MEMORY_AVAILABLE = False
    SecureBytes = None  # type: ignore[assignment,misc]
    secure_zero_memory = None  # type: ignore[assignment]
    secure_key_context = None  # type: ignore[assignment]
    secure_compare = None  # type: ignore[assignment]
    generate_secure_random = None  # type: ignore[assignment]

# Daemon integrity protection (SECURITY: Binary tampering prevention)
try:
    from .daemon_integrity import (
        DaemonIntegrityProtector,
        IntegrityConfig,
        IntegrityStatus,
        IntegrityAction,
        IntegrityManifest,
        IntegrityCheckResult,
        verify_daemon_integrity,
    )
    DAEMON_INTEGRITY_AVAILABLE = True
except ImportError:
    DAEMON_INTEGRITY_AVAILABLE = False
    DaemonIntegrityProtector = None  # type: ignore[assignment,misc]
    IntegrityConfig = None  # type: ignore[assignment,misc]
    IntegrityStatus = None  # type: ignore[assignment,misc]
    IntegrityAction = None  # type: ignore[assignment,misc]
    IntegrityManifest = None  # type: ignore[assignment,misc]
    IntegrityCheckResult = None  # type: ignore[assignment,misc]
    verify_daemon_integrity = None  # type: ignore[assignment]

# Prompt injection detection (SECURITY: AI/Agent jailbreak prevention)
try:
    from .prompt_injection import (
        PromptInjectionDetector,
        InjectionType,
        InjectionPattern,
        InjectionDetection,
        DetectionSeverity,
        DetectionAction,
        DetectionResult,
        get_prompt_injection_detector,
        configure_prompt_injection_detector,
    )
    PROMPT_INJECTION_AVAILABLE = True
except ImportError:
    PROMPT_INJECTION_AVAILABLE = False
    PromptInjectionDetector = None  # type: ignore[assignment,misc]
    InjectionType = None  # type: ignore[assignment,misc]
    InjectionPattern = None  # type: ignore[assignment,misc]
    InjectionDetection = None  # type: ignore[assignment,misc]
    DetectionSeverity = None  # type: ignore[assignment,misc]
    DetectionAction = None  # type: ignore[assignment,misc]
    DetectionResult = None  # type: ignore[assignment,misc]
    get_prompt_injection_detector = None  # type: ignore[assignment]
    configure_prompt_injection_detector = None  # type: ignore[assignment]

# Tool output validation (SECURITY: AI tool response validation)
try:
    from .tool_validator import (
        ToolOutputValidator,
        ToolPolicy,
        ToolCall,
        ToolValidationResult,
        ValidationResult,
        ViolationType,
        ValidationViolation,
        SanitizationAction,
        get_tool_validator,
        configure_tool_validator,
    )
    TOOL_VALIDATOR_AVAILABLE = True
except ImportError:
    TOOL_VALIDATOR_AVAILABLE = False
    ToolOutputValidator = None  # type: ignore[assignment,misc]
    ToolPolicy = None  # type: ignore[assignment,misc]
    ToolCall = None  # type: ignore[assignment,misc]
    ToolValidationResult = None  # type: ignore[assignment,misc]
    ValidationResult = None  # type: ignore[assignment,misc]
    ViolationType = None  # type: ignore[assignment,misc]
    ValidationViolation = None  # type: ignore[assignment,misc]
    SanitizationAction = None  # type: ignore[assignment,misc]
    get_tool_validator = None  # type: ignore[assignment]
    configure_tool_validator = None  # type: ignore[assignment]

# Response guardrails (SECURITY: AI response safety validation)
try:
    from .response_guardrails import (
        ResponseGuardrails,
        GuardrailPolicy,
        GuardrailResult,
        GuardrailViolation,
        GuardrailSeverity,
        GuardrailAction,
        ContentCategory,
        HallucinationIndicator,
        HallucinationDetection,
        get_response_guardrails,
        configure_response_guardrails,
    )
    RESPONSE_GUARDRAILS_AVAILABLE = True
except ImportError:
    RESPONSE_GUARDRAILS_AVAILABLE = False
    ResponseGuardrails = None  # type: ignore[assignment,misc]
    GuardrailPolicy = None  # type: ignore[assignment,misc]
    GuardrailResult = None  # type: ignore[assignment,misc]
    GuardrailViolation = None  # type: ignore[assignment,misc]
    GuardrailSeverity = None  # type: ignore[assignment,misc]
    GuardrailAction = None  # type: ignore[assignment,misc]
    ContentCategory = None  # type: ignore[assignment,misc]
    HallucinationIndicator = None  # type: ignore[assignment,misc]
    HallucinationDetection = None  # type: ignore[assignment,misc]
    get_response_guardrails = None  # type: ignore[assignment]
    configure_response_guardrails = None  # type: ignore[assignment]

# RAG injection detection (SECURITY: RAG poisoning prevention)
try:
    from .rag_injection import (
        RAGInjectionDetector,
        RAGThreatType,
        RAGAnalysisResult,
        RAGThreat,
        RetrievedDocument,
        DocumentTrustLevel,
        ThreatSeverity,
        get_rag_detector,
        configure_rag_detector,
    )
    # Aliases for consistency
    RAGDetectionResult = RAGAnalysisResult
    get_rag_injection_detector = get_rag_detector
    configure_rag_injection_detector = configure_rag_detector
    RAG_INJECTION_AVAILABLE = True
except ImportError:
    RAG_INJECTION_AVAILABLE = False
    RAGInjectionDetector = None  # type: ignore[assignment,misc]
    RAGThreatType = None  # type: ignore[assignment,misc]
    RAGAnalysisResult = None  # type: ignore[assignment,misc]
    RAGDetectionResult = None  # type: ignore[assignment,misc]
    RAGThreat = None  # type: ignore[assignment,misc]
    RetrievedDocument = None  # type: ignore[assignment,misc]
    DocumentTrustLevel = None  # type: ignore[assignment,misc]
    ThreatSeverity = None  # type: ignore[assignment,misc]
    get_rag_detector = None  # type: ignore[assignment]
    get_rag_injection_detector = None  # type: ignore[assignment]
    configure_rag_detector = None  # type: ignore[assignment]
    configure_rag_injection_detector = None  # type: ignore[assignment]

# Agent attestation (SECURITY: Cryptographic agent identity)
try:
    from .agent_attestation import (
        AgentAttestationSystem,
        AgentIdentity,
        AttestationToken,
        AttestationResult,
        AttestationStatus,
        AgentCapability,
        TrustLevel,
        ActionBinding,
        get_attestation_system,
        configure_attestation_system,
    )
    AGENT_ATTESTATION_AVAILABLE = True
except ImportError:
    AGENT_ATTESTATION_AVAILABLE = False
    AgentAttestationSystem = None  # type: ignore[assignment,misc]
    AgentIdentity = None  # type: ignore[assignment,misc]
    AttestationToken = None  # type: ignore[assignment,misc]
    AttestationResult = None  # type: ignore[assignment,misc]
    AttestationStatus = None  # type: ignore[assignment,misc]
    AgentCapability = None  # type: ignore[assignment,misc]
    TrustLevel = None  # type: ignore[assignment,misc]
    ActionBinding = None  # type: ignore[assignment,misc]
    get_attestation_system = None  # type: ignore[assignment]
    configure_attestation_system = None  # type: ignore[assignment]

__all__ = [
    # Code advisor
    'CodeVulnerabilityAdvisor',
    'SecurityAdvisory',
    'AdvisorySeverity',
    'AdvisoryStatus',
    'ScanResult',
    # Native DNS Resolver (SECURITY: No external tools)
    'NativeDNSResolver',
    'SecureDNSVerifier',
    'DNSType',
    'DNSResponse',
    'DNSRecord',
    # Daemon integrity (SECURITY: Binary tampering prevention)
    'DaemonIntegrityProtector',
    'IntegrityConfig',
    'IntegrityStatus',
    'IntegrityAction',
    'IntegrityManifest',
    'IntegrityCheckResult',
    'verify_daemon_integrity',
    'DAEMON_INTEGRITY_AVAILABLE',
    # Secure memory (SECURITY: Secret zeroing)
    'SecureBytes',
    'secure_zero_memory',
    'secure_key_context',
    'secure_compare',
    'generate_secure_random',
    'SECURE_MEMORY_AVAILABLE',
    # Prompt injection detection (SECURITY: AI/Agent jailbreak prevention)
    'PromptInjectionDetector',
    'InjectionType',
    'InjectionPattern',
    'InjectionDetection',
    'DetectionSeverity',
    'DetectionAction',
    'DetectionResult',
    'get_prompt_injection_detector',
    'configure_prompt_injection_detector',
    'PROMPT_INJECTION_AVAILABLE',
    # Tool output validation (SECURITY: AI tool response validation)
    'ToolOutputValidator',
    'ToolPolicy',
    'ToolCall',
    'ToolValidationResult',
    'ValidationResult',
    'ViolationType',
    'ValidationViolation',
    'SanitizationAction',
    'get_tool_validator',
    'configure_tool_validator',
    'TOOL_VALIDATOR_AVAILABLE',
    # Response guardrails (SECURITY: AI response safety validation)
    'ResponseGuardrails',
    'GuardrailPolicy',
    'GuardrailResult',
    'GuardrailViolation',
    'GuardrailSeverity',
    'GuardrailAction',
    'ContentCategory',
    'HallucinationIndicator',
    'HallucinationDetection',
    'get_response_guardrails',
    'configure_response_guardrails',
    'RESPONSE_GUARDRAILS_AVAILABLE',
    # RAG injection detection (SECURITY: RAG poisoning prevention)
    'RAGInjectionDetector',
    'RAGThreatType',
    'RAGAnalysisResult',
    'RAGDetectionResult',  # Alias
    'RAGThreat',
    'RetrievedDocument',
    'DocumentTrustLevel',
    'ThreatSeverity',
    'get_rag_detector',
    'get_rag_injection_detector',  # Alias
    'configure_rag_detector',
    'configure_rag_injection_detector',  # Alias
    'RAG_INJECTION_AVAILABLE',
    # Agent attestation (SECURITY: Cryptographic agent identity)
    'AgentAttestationSystem',
    'AgentIdentity',
    'AttestationToken',
    'AttestationResult',
    'AttestationStatus',
    'AgentCapability',
    'TrustLevel',
    'ActionBinding',
    'get_attestation_system',
    'configure_attestation_system',
    'AGENT_ATTESTATION_AVAILABLE',
]
