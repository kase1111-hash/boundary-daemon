"""
SIEM Integration Module for Boundary Daemon

Provides integration with Security Information and Event Management systems:
- CEF/LEEF format export (Splunk, QRadar, ArcSight)
- Kafka producer for streaming events
- S3/GCS log shipping for cloud SIEMs
- Signature verification API for SIEM consumers
"""

from .cef_leef import (
    CEFExporter,
    LEEFExporter,
    SIEMFormat,
    CEFSeverity,
    format_event_cef,
    format_event_leef,
)

from .log_shipper import (
    LogShipper,
    ShipperProtocol,
    S3Shipper,
    GCSShipper,
    KafkaShipper,
    ShipperConfig,
)

from .verification_api import (
    SignatureVerificationAPI,
    VerificationRequest,
    VerificationResponse,
    BatchVerificationResult,
)

__all__ = [
    # CEF/LEEF exporters
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
