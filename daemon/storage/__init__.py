"""
Storage Module for Boundary Daemon

Provides:
- Log hardening (chattr, permissions, sealing)
- Append-only storage with integrity checkpoints
- Forensic audit capabilities:
  - Merkle tree proofs for event verification
  - Cross-node log anchoring
  - Log witness protocol for external verification
  - Selective disclosure proofs
"""

# Log hardening
from .log_hardening import (
    LogHardener,
    HardeningMode,
    ProtectionStatus,
)

# Append-only storage
from .append_only import (
    AppendOnlyMode,
    AppendOnlyStorage,
    IntegrityCheckpoint,
    RemoteSyslogConfig,
)

# Forensic audit capabilities
from .forensic_audit import (
    # Merkle tree
    MerkleTree,
    MerkleNode,
    MerkleProof,
    RangeProof,
    # Cross-node anchoring
    LogAnchor,
    CrossNodeAnchorRecord,
    CrossNodeAnchoringManager,
    # Log witness protocol
    WitnessCommitment,
    LogWitness,
    LogWitnessManager,
    # Selective disclosure
    SelectiveDisclosureProof,
    SelectiveDisclosureManager,
    # Unified manager
    ForensicAuditManager,
)

__all__ = [
    # Log hardening
    'LogHardener',
    'HardeningMode',
    'ProtectionStatus',

    # Append-only storage
    'AppendOnlyMode',
    'AppendOnlyStorage',
    'IntegrityCheckpoint',
    'RemoteSyslogConfig',

    # Merkle tree
    'MerkleTree',
    'MerkleNode',
    'MerkleProof',
    'RangeProof',

    # Cross-node anchoring
    'LogAnchor',
    'CrossNodeAnchorRecord',
    'CrossNodeAnchoringManager',

    # Log witness protocol
    'WitnessCommitment',
    'LogWitness',
    'LogWitnessManager',

    # Selective disclosure
    'SelectiveDisclosureProof',
    'SelectiveDisclosureManager',

    # Unified manager
    'ForensicAuditManager',
]
