"""
Air-Gap Enhancement Module for Boundary Daemon

Provides secure mechanisms for air-gapped systems:
- Sneakernet Protocol: Secure signed bundles for offline data transfer
- QR-Code Ceremonies: Approve operations via QR scan from separate device
- Data Diode Support: One-way log export for asymmetric data flow
"""

from .sneakernet import (
    SneakernetBundle,
    SneakernetExporter,
    SneakernetImporter,
    BundleType,
    BundleManifest,
)

from .qr_ceremony import (
    QRCeremonyChallenge,
    QRCeremonyResponse,
    QRCeremonyManager,
    QRDisplayMode,
)

from .data_diode import (
    DataDiodeMode,
    DiodeExportFormat,
    DataDiodeExporter,
    DiodeChannel,
)

__all__ = [
    # Sneakernet protocol
    'SneakernetBundle',
    'SneakernetExporter',
    'SneakernetImporter',
    'BundleType',
    'BundleManifest',

    # QR ceremonies
    'QRCeremonyChallenge',
    'QRCeremonyResponse',
    'QRCeremonyManager',
    'QRDisplayMode',

    # Data diode
    'DataDiodeMode',
    'DiodeExportFormat',
    'DataDiodeExporter',
    'DiodeChannel',
]
