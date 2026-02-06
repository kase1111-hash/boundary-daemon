"""
Boundary Antivirus - Standalone Malware Detection Engine

Extracted from Boundary Daemon as an independent security scanning package.
Provides keylogger detection, malware scanning, process monitoring,
and real-time file system surveillance.

Usage:
    from boundary_antivirus import AntivirusScanner, RealTimeMonitor

    scanner = AntivirusScanner()
    results = scanner.full_scan()
"""

from .scanner import (
    AntivirusScanner,
    RealTimeMonitor,
    StartupMonitor,
    ThreatIndicator,
    ThreatLevel,
    ThreatCategory,
    KeyloggerSignatures,
    ScreenSharingSignatures,
    NetworkMonitoringSignatures,
    ScanResult,
)

__all__ = [
    'AntivirusScanner',
    'RealTimeMonitor',
    'StartupMonitor',
    'ThreatIndicator',
    'ThreatLevel',
    'ThreatCategory',
    'KeyloggerSignatures',
    'ScreenSharingSignatures',
    'NetworkMonitoringSignatures',
    'ScanResult',
]

__version__ = "0.1.0"
