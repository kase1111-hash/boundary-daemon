"""
External Integrations Module for Boundary Daemon

Provides integrations with external systems:
- SIEM (Security Information and Event Management)
  - CEF/LEEF format export
  - Kafka, S3, GCS log shipping
  - Signature verification API

For RecallGate, ToolGate, and CeremonyManager, import from daemon.integrations:
    from daemon.integrations import RecallGate, ToolGate, CeremonyManager
"""

# Import SIEM integration
from .siem import (
    # CEF/LEEF
    CEFExporter,
    LEEFExporter,
    SIEMFormat,
    CEFSeverity,
    format_event_cef,
    format_event_leef,
    # Log shippers
    LogShipper,
    ShipperProtocol,
    S3Shipper,
    GCSShipper,
    KafkaShipper,
    ShipperConfig,
    # Verification API
    SignatureVerificationAPI,
    VerificationRequest,
    VerificationResponse,
    BatchVerificationResult,
)

__all__ = [
    # SIEM CEF/LEEF
    'CEFExporter',
    'LEEFExporter',
    'SIEMFormat',
    'CEFSeverity',
    'format_event_cef',
    'format_event_leef',

    # Log shippers
    'LogShipper',
    'ShipperProtocol',
    'S3Shipper',
    'GCSShipper',
    'KafkaShipper',
    'ShipperConfig',

    # Verification API
    'SignatureVerificationAPI',
    'VerificationRequest',
    'VerificationResponse',
    'BatchVerificationResult',
]
