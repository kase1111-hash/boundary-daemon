"""
Control Mapping for Compliance Frameworks

Maps Boundary Daemon capabilities to compliance controls:
- NIST 800-53 (Federal Information Security)
- ISO 27001 (Information Security Management)
- SOC 2 Type II (Service Organization Controls)
- PCI DSS (Payment Card Industry)

Generates exportable mapping documents for auditors.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List

logger = logging.getLogger(__name__)


class ControlFramework(Enum):
    """Supported compliance frameworks."""
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"


class ComplianceStatus(Enum):
    """Status of control implementation."""
    IMPLEMENTED = "implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    PLANNED = "planned"
    NOT_APPLICABLE = "not_applicable"
    NOT_IMPLEMENTED = "not_implemented"


@dataclass
class NISTControl:
    """NIST 800-53 control definition."""
    control_id: str  # e.g., "AC-2"
    control_name: str
    control_family: str
    description: str
    priority: str = "P1"  # P1, P2, P3
    baseline: str = "Moderate"  # Low, Moderate, High


@dataclass
class ISOControl:
    """ISO 27001 control definition."""
    control_id: str  # e.g., "A.9.1.1"
    control_name: str
    domain: str
    objective: str
    description: str


@dataclass
class MappedControl:
    """A control mapped to Boundary Daemon capabilities."""
    framework: ControlFramework
    control_id: str
    control_name: str
    status: ComplianceStatus
    daemon_features: List[str]
    implementation_notes: str
    evidence_types: List[str]
    gaps: List[str] = field(default_factory=list)
    compensating_controls: List[str] = field(default_factory=list)


# NIST 800-53 Controls relevant to Boundary Daemon
NIST_CONTROLS = {
    "AC-2": NISTControl(
        control_id="AC-2",
        control_name="Account Management",
        control_family="Access Control",
        description="Manage information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
    ),
    "AC-3": NISTControl(
        control_id="AC-3",
        control_name="Access Enforcement",
        control_family="Access Control",
        description="Enforce approved authorizations for logical access to information and system resources.",
    ),
    "AC-6": NISTControl(
        control_id="AC-6",
        control_name="Least Privilege",
        control_family="Access Control",
        description="Employ the principle of least privilege, allowing only authorized accesses for users.",
    ),
    "AU-2": NISTControl(
        control_id="AU-2",
        control_name="Audit Events",
        control_family="Audit and Accountability",
        description="Determine that the information system is capable of auditing defined events.",
    ),
    "AU-3": NISTControl(
        control_id="AU-3",
        control_name="Content of Audit Records",
        control_family="Audit and Accountability",
        description="Ensure audit records contain information that establishes what type of event occurred.",
    ),
    "AU-9": NISTControl(
        control_id="AU-9",
        control_name="Protection of Audit Information",
        control_family="Audit and Accountability",
        description="Protect audit information and audit tools from unauthorized access, modification, and deletion.",
    ),
    "AU-10": NISTControl(
        control_id="AU-10",
        control_name="Non-repudiation",
        control_family="Audit and Accountability",
        description="Provide irrefutable evidence that an action occurred.",
    ),
    "CM-3": NISTControl(
        control_id="CM-3",
        control_name="Configuration Change Control",
        control_family="Configuration Management",
        description="Document and control changes to the information system.",
    ),
    "IA-2": NISTControl(
        control_id="IA-2",
        control_name="Identification and Authentication",
        control_family="Identification and Authentication",
        description="Uniquely identify and authenticate organizational users.",
    ),
    "SC-7": NISTControl(
        control_id="SC-7",
        control_name="Boundary Protection",
        control_family="System and Communications Protection",
        description="Monitor and control communications at external boundaries and key internal boundaries.",
    ),
    "SI-4": NISTControl(
        control_id="SI-4",
        control_name="Information System Monitoring",
        control_family="System and Information Integrity",
        description="Monitor the information system to detect attacks and indicators of potential attacks.",
    ),
    "SI-7": NISTControl(
        control_id="SI-7",
        control_name="Software, Firmware, and Information Integrity",
        control_family="System and Information Integrity",
        description="Employ integrity verification tools to detect unauthorized changes.",
    ),
}

# ISO 27001 Controls relevant to Boundary Daemon
ISO_CONTROLS = {
    "A.9.1.1": ISOControl(
        control_id="A.9.1.1",
        control_name="Access control policy",
        domain="Access Control",
        objective="Limit access to information and information processing facilities",
        description="An access control policy shall be established, documented and reviewed.",
    ),
    "A.9.2.1": ISOControl(
        control_id="A.9.2.1",
        control_name="User registration and de-registration",
        domain="Access Control",
        objective="Ensure authorized user access and prevent unauthorized access",
        description="A formal user registration and de-registration process shall be implemented.",
    ),
    "A.9.4.1": ISOControl(
        control_id="A.9.4.1",
        control_name="Information access restriction",
        domain="Access Control",
        objective="Prevent unauthorized access to systems and applications",
        description="Access to information and application system functions shall be restricted.",
    ),
    "A.12.4.1": ISOControl(
        control_id="A.12.4.1",
        control_name="Event logging",
        domain="Operations Security",
        objective="Record events and generate evidence",
        description="Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.",
    ),
    "A.12.4.2": ISOControl(
        control_id="A.12.4.2",
        control_name="Protection of log information",
        domain="Operations Security",
        objective="Protect logs against tampering",
        description="Logging facilities and log information shall be protected against tampering and unauthorized access.",
    ),
    "A.12.4.3": ISOControl(
        control_id="A.12.4.3",
        control_name="Administrator and operator logs",
        domain="Operations Security",
        objective="Log system administrator activities",
        description="System administrator and system operator activities shall be logged and the logs protected and regularly reviewed.",
    ),
    "A.14.2.2": ISOControl(
        control_id="A.14.2.2",
        control_name="System change control procedures",
        domain="System Development",
        objective="Control changes to systems",
        description="Changes to systems within the development lifecycle shall be controlled.",
    ),
    "A.18.1.3": ISOControl(
        control_id="A.18.1.3",
        control_name="Protection of records",
        domain="Compliance",
        objective="Protect records from loss, destruction, and falsification",
        description="Records shall be protected from loss, destruction, falsification, unauthorized access and unauthorized release.",
    ),
}


@dataclass
class ControlMapping:
    """Complete mapping of daemon capabilities to framework controls."""
    framework: ControlFramework
    version: str
    generated_at: datetime
    daemon_version: str
    mappings: List[MappedControl]
    summary: Dict[str, int] = field(default_factory=dict)


class ControlMappingExporter:
    """
    Exports control mappings for compliance frameworks.

    Usage:
        exporter = ControlMappingExporter()
        mapping = exporter.generate_nist_mapping()
        exporter.export_to_json(mapping, "nist_mapping.json")
        exporter.export_to_csv(mapping, "nist_mapping.csv")
    """

    def __init__(self, daemon_version: str = "1.0.0"):
        self.daemon_version = daemon_version

        # Daemon feature to control mappings
        self._feature_controls = self._build_feature_mappings()

    def _build_feature_mappings(self) -> Dict[str, List[str]]:
        """Build mappings from daemon features to controls."""
        return {
            # Logging features
            "hash_chained_logging": ["AU-2", "AU-3", "AU-9", "AU-10", "A.12.4.1", "A.12.4.2"],
            "signed_event_logger": ["AU-9", "AU-10", "A.12.4.2", "A.18.1.3"],
            "append_only_storage": ["AU-9", "A.12.4.2", "A.18.1.3"],

            # Access control features
            "policy_engine": ["AC-3", "AC-6", "A.9.1.1", "A.9.4.1"],
            "boundary_modes": ["AC-3", "SC-7", "A.9.4.1"],
            "recall_gate": ["AC-3", "AC-6", "A.9.4.1"],
            "tool_gate": ["AC-3", "AC-6", "A.9.4.1"],

            # Authentication features
            "ceremony_system": ["IA-2", "AC-6", "A.9.2.1"],
            "biometric_verifier": ["IA-2", "A.9.4.1"],
            "hardware_token": ["IA-2", "A.9.4.1"],
            "n_of_m_ceremonies": ["AC-6", "A.9.2.1"],

            # Integrity features
            "tripwire_system": ["SI-4", "SI-7", "A.12.4.1"],
            "daemon_integrity": ["SI-7", "A.14.2.2"],
            "file_integrity": ["SI-7", "A.14.2.2"],

            # Monitoring features
            "state_monitor": ["SI-4", "A.12.4.1"],
            "network_monitor": ["SC-7", "SI-4"],
            "process_monitor": ["SI-4", "A.12.4.3"],

            # Configuration features
            "mode_transitions": ["CM-3", "A.14.2.2"],
            "policy_updates": ["CM-3", "A.14.2.2"],
        }

    def generate_nist_mapping(self) -> ControlMapping:
        """Generate NIST 800-53 control mapping."""
        mappings: List[MappedControl] = []

        for control_id, control in NIST_CONTROLS.items():
            # Find daemon features that map to this control
            features = []
            for feature, controls in self._feature_controls.items():
                if control_id in controls:
                    features.append(feature)

            if features:
                status = ComplianceStatus.IMPLEMENTED
                impl_notes = f"Implemented via: {', '.join(features)}"
            else:
                status = ComplianceStatus.NOT_APPLICABLE
                impl_notes = "Not directly applicable to daemon scope"

            mapping = MappedControl(
                framework=ControlFramework.NIST_800_53,
                control_id=control_id,
                control_name=control.control_name,
                status=status,
                daemon_features=features,
                implementation_notes=impl_notes,
                evidence_types=self._get_evidence_types(features),
            )
            mappings.append(mapping)

        # Calculate summary
        summary = {}
        for status in ComplianceStatus:
            summary[status.value] = len([m for m in mappings if m.status == status])

        return ControlMapping(
            framework=ControlFramework.NIST_800_53,
            version="Rev 5",
            generated_at=datetime.utcnow(),
            daemon_version=self.daemon_version,
            mappings=mappings,
            summary=summary,
        )

    def generate_iso_mapping(self) -> ControlMapping:
        """Generate ISO 27001 control mapping."""
        mappings: List[MappedControl] = []

        for control_id, control in ISO_CONTROLS.items():
            # Find daemon features that map to this control
            features = []
            for feature, controls in self._feature_controls.items():
                if control_id in controls:
                    features.append(feature)

            if features:
                status = ComplianceStatus.IMPLEMENTED
                impl_notes = f"Implemented via: {', '.join(features)}"
            else:
                status = ComplianceStatus.NOT_APPLICABLE
                impl_notes = "Not directly applicable to daemon scope"

            mapping = MappedControl(
                framework=ControlFramework.ISO_27001,
                control_id=control_id,
                control_name=control.control_name,
                status=status,
                daemon_features=features,
                implementation_notes=impl_notes,
                evidence_types=self._get_evidence_types(features),
            )
            mappings.append(mapping)

        # Calculate summary
        summary = {}
        for status in ComplianceStatus:
            summary[status.value] = len([m for m in mappings if m.status == status])

        return ControlMapping(
            framework=ControlFramework.ISO_27001,
            version="2022",
            generated_at=datetime.utcnow(),
            daemon_version=self.daemon_version,
            mappings=mappings,
            summary=summary,
        )

    def _get_evidence_types(self, features: List[str]) -> List[str]:
        """Determine evidence types for features."""
        evidence = set()

        evidence_map = {
            "hash_chained_logging": ["event_logs", "hash_chain_verification"],
            "signed_event_logger": ["signatures", "public_key_export"],
            "append_only_storage": ["storage_configuration", "chattr_verification"],
            "policy_engine": ["policy_configuration", "decision_logs"],
            "ceremony_system": ["ceremony_logs", "approval_records"],
            "tripwire_system": ["violation_alerts", "lockdown_logs"],
            "state_monitor": ["state_snapshots", "monitoring_logs"],
        }

        for feature in features:
            if feature in evidence_map:
                evidence.update(evidence_map[feature])

        return list(evidence)

    def export_to_json(
        self,
        mapping: ControlMapping,
        output_path: str,
    ) -> bool:
        """Export mapping to JSON file."""
        try:
            data = {
                "framework": mapping.framework.value,
                "version": mapping.version,
                "generated_at": mapping.generated_at.isoformat() + "Z",
                "daemon_version": mapping.daemon_version,
                "summary": mapping.summary,
                "mappings": [
                    {
                        "control_id": m.control_id,
                        "control_name": m.control_name,
                        "status": m.status.value,
                        "daemon_features": m.daemon_features,
                        "implementation_notes": m.implementation_notes,
                        "evidence_types": m.evidence_types,
                        "gaps": m.gaps,
                        "compensating_controls": m.compensating_controls,
                    }
                    for m in mapping.mappings
                ],
            }

            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Exported mapping to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export mapping: {e}")
            return False

    def export_to_csv(
        self,
        mapping: ControlMapping,
        output_path: str,
    ) -> bool:
        """Export mapping to CSV file."""
        try:
            import csv

            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)

                # Header
                writer.writerow([
                    "Control ID",
                    "Control Name",
                    "Status",
                    "Daemon Features",
                    "Implementation Notes",
                    "Evidence Types",
                    "Gaps",
                ])

                # Data rows
                for m in mapping.mappings:
                    writer.writerow([
                        m.control_id,
                        m.control_name,
                        m.status.value,
                        "; ".join(m.daemon_features),
                        m.implementation_notes,
                        "; ".join(m.evidence_types),
                        "; ".join(m.gaps),
                    ])

            logger.info(f"Exported mapping to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export mapping: {e}")
            return False


if __name__ == '__main__':
    print("Testing Control Mapping Exporter...")

    exporter = ControlMappingExporter(daemon_version="1.0.0")

    # Generate NIST mapping
    nist_mapping = exporter.generate_nist_mapping()
    print(f"\nNIST 800-53 Mapping:")
    print(f"  Framework: {nist_mapping.framework.value}")
    print(f"  Version: {nist_mapping.version}")
    print(f"  Controls mapped: {len(nist_mapping.mappings)}")
    print(f"  Summary: {nist_mapping.summary}")

    print("\n  Sample mappings:")
    for m in nist_mapping.mappings[:3]:
        print(f"    {m.control_id}: {m.control_name}")
        print(f"      Status: {m.status.value}")
        print(f"      Features: {m.daemon_features}")

    # Generate ISO mapping
    iso_mapping = exporter.generate_iso_mapping()
    print(f"\nISO 27001 Mapping:")
    print(f"  Framework: {iso_mapping.framework.value}")
    print(f"  Controls mapped: {len(iso_mapping.mappings)}")
    print(f"  Summary: {iso_mapping.summary}")

    print("\nControl mapping test complete.")
