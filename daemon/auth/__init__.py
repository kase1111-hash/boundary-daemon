"""
Authentication Module for Boundary Daemon

Provides:
- Biometric authentication (fingerprint and facial recognition)
- Enhanced ceremonies with biometric verification
- Advanced ceremony framework:
  - Ceremony templates (pre-defined ceremony types)
  - N-of-M multi-party ceremonies
  - Time-locked ceremonies
  - Dead-man triggers
  - Hardware token (FIDO2/YubiKey) integration
"""

from .biometric_verifier import BiometricVerifier, BiometricType, BiometricResult
from .enhanced_ceremony import EnhancedCeremonyManager, BiometricCeremonyConfig

# Advanced ceremony framework
from .advanced_ceremony import (
    # Enums
    CeremonyType,
    CeremonySeverity,
    HardwareTokenType,
    # Data classes
    CeremonyStep,
    CeremonyTemplate,
    Approver,
    ApprovalRecord,
    NofMCeremonyState,
    TimeWindow,
    DeadManTrigger,
    HardwareToken,
    # Templates
    CEREMONY_TEMPLATES,
    # Managers
    NofMCeremonyManager,
    TimeLockedCeremony,
    DeadManCeremony,
    HardwareTokenCeremony,
    AdvancedCeremonyManager,
)

__all__ = [
    # Biometric authentication
    'BiometricVerifier',
    'BiometricType',
    'BiometricResult',

    # Enhanced ceremonies
    'EnhancedCeremonyManager',
    'BiometricCeremonyConfig',

    # Advanced ceremony enums
    'CeremonyType',
    'CeremonySeverity',
    'HardwareTokenType',

    # Advanced ceremony data classes
    'CeremonyStep',
    'CeremonyTemplate',
    'Approver',
    'ApprovalRecord',
    'NofMCeremonyState',
    'TimeWindow',
    'DeadManTrigger',
    'HardwareToken',

    # Pre-defined templates
    'CEREMONY_TEMPLATES',

    # Advanced ceremony managers
    'NofMCeremonyManager',
    'TimeLockedCeremony',
    'DeadManCeremony',
    'HardwareTokenCeremony',
    'AdvancedCeremonyManager',
]
