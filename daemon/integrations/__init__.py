"""
Integrations Module for Boundary Daemon

Provides integrations with external systems:
- SIEM (Security Information and Event Management)
  - CEF/LEEF format export
  - Kafka, S3, GCS log shipping
  - Signature verification API
- RecallGate and ToolGate (existing)
- CeremonyManager (existing)
"""

# Note: RecallGate, ToolGate, CeremonyManager are in daemon/integrations.py
# They are not re-exported here to avoid circular imports.
# Import them directly: from daemon.integrations import RecallGate, ToolGate, CeremonyManager

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
