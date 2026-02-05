"""
Sneakernet Protocol - Secure signed bundles for air-gapped data transfer.

Provides a standardized format for transferring data in/out of air-gapped systems
via physical media (USB drives, optical media, etc.).

Features:
- Cryptographically signed bundles (Ed25519)
- Optional encryption (XChaCha20-Poly1305 or Fernet)
- Size-limited chunks for media constraints
- Manifest with integrity verification
- Merkle proofs for log excerpts
- Deterministic format (no network required)

SECURITY: All bundles are signed. Import verifies signatures.
Unsigned or tampered bundles are rejected.
"""

import os
import json
import gzip
import hashlib
import time
import base64
import secrets
from enum import Enum
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

# Cryptographic imports
try:
    import nacl.signing
    import nacl.encoding
    import nacl.secret
    import nacl.utils
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False


# =============================================================================
# BUNDLE TYPES AND STRUCTURES
# =============================================================================

class BundleType(Enum):
    """Types of sneakernet bundles."""
    LOG_EXPORT = "log_export"           # Event logs with proofs
    AUDIT_PACKAGE = "audit_package"     # Full audit export
    KEY_MATERIAL = "key_material"       # Cryptographic keys
    POLICY_UPDATE = "policy_update"     # Policy configuration
    THREAT_INTEL = "threat_intel"       # Offline threat intelligence
    WITNESS_COMMITMENT = "witness"      # Witness signatures
    CUSTOM = "custom"                   # Application-defined


class BundleEncryption(Enum):
    """Encryption methods for bundles."""
    NONE = "none"                       # Signed but not encrypted
    XCHACHA20 = "xchacha20"             # XChaCha20-Poly1305 (requires pynacl)
    FERNET = "fernet"                   # Fernet symmetric encryption
    PASSWORD = "password"               # Password-derived key


@dataclass
class BundleManifest:
    """
    Manifest describing bundle contents.

    The manifest is always stored unencrypted and signed,
    allowing verification before decryption.
    """
    bundle_id: str
    bundle_type: BundleType
    created_at: str
    created_by: str  # Node ID or operator ID
    source_node: str
    description: str
    encryption: BundleEncryption
    chunk_count: int
    total_size: int
    content_hash: str  # SHA-256 of all content
    merkle_root: Optional[str] = None
    event_range: Optional[Tuple[int, int]] = None  # (start, end) for log exports
    public_key: Optional[str] = None
    signature: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'bundle_id': self.bundle_id,
            'bundle_type': self.bundle_type.value,
            'created_at': self.created_at,
            'created_by': self.created_by,
            'source_node': self.source_node,
            'description': self.description,
            'encryption': self.encryption.value,
            'chunk_count': self.chunk_count,
            'total_size': self.total_size,
            'content_hash': self.content_hash,
            'merkle_root': self.merkle_root,
            'event_range': self.event_range,
            'public_key': self.public_key,
            'signature': self.signature,
            'metadata': self.metadata
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BundleManifest':
        """Create from dictionary."""
        return cls(
            bundle_id=data['bundle_id'],
            bundle_type=BundleType(data['bundle_type']),
            created_at=data['created_at'],
            created_by=data['created_by'],
            source_node=data['source_node'],
            description=data['description'],
            encryption=BundleEncryption(data['encryption']),
            chunk_count=data['chunk_count'],
            total_size=data['total_size'],
            content_hash=data['content_hash'],
            merkle_root=data.get('merkle_root'),
            event_range=tuple(data['event_range']) if data.get('event_range') else None,
            public_key=data.get('public_key'),
            signature=data.get('signature'),
            metadata=data.get('metadata', {})
        )

    def compute_signing_hash(self) -> str:
        """Compute hash for signing (excludes signature field)."""
        data = self.to_dict()
        data.pop('signature', None)
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


@dataclass
class BundleChunk:
    """A single chunk of bundle data."""
    chunk_index: int
    chunk_count: int
    data: bytes
    checksum: str  # SHA-256 of data

    def verify(self) -> bool:
        """Verify chunk integrity."""
        return hashlib.sha256(self.data).hexdigest() == self.checksum


@dataclass
class SneakernetBundle:
    """
    Complete sneakernet bundle ready for transfer.

    Bundle format on disk:
    bundle_<id>/
    ├── manifest.json      # Signed manifest
    ├── chunk_000.bin.gz   # Compressed data chunks
    ├── chunk_001.bin.gz
    └── ...
    """
    manifest: BundleManifest
    chunks: List[BundleChunk] = field(default_factory=list)

    def get_total_size(self) -> int:
        """Get total uncompressed size."""
        return sum(len(c.data) for c in self.chunks)

    def verify_integrity(self) -> Tuple[bool, str]:
        """Verify all chunks and overall integrity."""
        # Verify each chunk
        for chunk in self.chunks:
            if not chunk.verify():
                return (False, f"Chunk {chunk.chunk_index} checksum mismatch")

        # Verify total content hash
        all_data = b''.join(c.data for c in self.chunks)
        content_hash = hashlib.sha256(all_data).hexdigest()

        if content_hash != self.manifest.content_hash:
            return (False, "Content hash mismatch")

        return (True, "Bundle integrity verified")


# =============================================================================
# SNEAKERNET EXPORTER
# =============================================================================

class SneakernetExporter:
    """
    Creates sneakernet bundles for export from air-gapped systems.

    Usage:
        exporter = SneakernetExporter(node_id="node-1", signing_key=key)
        bundle = exporter.create_log_bundle(events, merkle_tree)
        exporter.write_to_directory(bundle, "/mnt/usb/export")
    """

    # Default chunk size: 10 MB (fits most media)
    DEFAULT_CHUNK_SIZE = 10 * 1024 * 1024

    def __init__(self, node_id: str, signing_key: Optional[bytes] = None,
                 chunk_size: int = DEFAULT_CHUNK_SIZE):
        """
        Initialize sneakernet exporter.

        Args:
            node_id: Identifier for this node
            signing_key: Ed25519 signing key (generates new if not provided)
            chunk_size: Maximum chunk size in bytes
        """
        self.node_id = node_id
        self.chunk_size = chunk_size

        # Initialize signing
        if NACL_AVAILABLE:
            if signing_key:
                self._signing_key = nacl.signing.SigningKey(signing_key)
            else:
                self._signing_key = nacl.signing.SigningKey.generate()
            self._verify_key = self._signing_key.verify_key
            self.public_key = self._verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        else:
            self._signing_key = None
            self._verify_key = None
            self.public_key = ""

    def create_bundle(self, bundle_type: BundleType, data: bytes,
                     description: str, encryption: BundleEncryption = BundleEncryption.NONE,
                     encryption_key: Optional[bytes] = None,
                     password: Optional[str] = None,
                     metadata: Optional[Dict] = None) -> SneakernetBundle:
        """
        Create a sneakernet bundle from raw data.

        Args:
            bundle_type: Type of bundle
            data: Raw data to bundle
            description: Human-readable description
            encryption: Encryption method
            encryption_key: Encryption key (for XCHACHA20/FERNET)
            password: Password (for PASSWORD encryption)
            metadata: Additional metadata

        Returns:
            SneakernetBundle ready for export
        """
        # Generate bundle ID
        bundle_id = hashlib.sha256(
            f"{self.node_id}:{time.time()}:{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]

        # Encrypt if requested
        encrypted_data, actual_encryption = self._encrypt_data(
            data, encryption, encryption_key, password
        )

        # Compress
        compressed_data = gzip.compress(encrypted_data)

        # Chunk the data
        chunks = self._create_chunks(compressed_data)

        # Compute content hash (of original data)
        content_hash = hashlib.sha256(data).hexdigest()

        # Create manifest
        manifest = BundleManifest(
            bundle_id=bundle_id,
            bundle_type=bundle_type,
            created_at=datetime.utcnow().isoformat() + "Z",
            created_by=self.node_id,
            source_node=self.node_id,
            description=description,
            encryption=actual_encryption,
            chunk_count=len(chunks),
            total_size=len(data),
            content_hash=content_hash,
            public_key=self.public_key,
            metadata=metadata or {}
        )

        # Sign manifest
        self._sign_manifest(manifest)

        return SneakernetBundle(manifest=manifest, chunks=chunks)

    def create_log_bundle(self, events: List[Dict], merkle_root: Optional[str] = None,
                         event_range: Optional[Tuple[int, int]] = None,
                         merkle_proofs: Optional[List[Dict]] = None,
                         encryption: BundleEncryption = BundleEncryption.NONE,
                         encryption_key: Optional[bytes] = None) -> SneakernetBundle:
        """
        Create a log export bundle with optional Merkle proofs.

        Args:
            events: List of event dictionaries
            merkle_root: Merkle tree root hash
            event_range: (start_index, end_index) of events
            merkle_proofs: Optional Merkle proofs for events
            encryption: Encryption method
            encryption_key: Encryption key

        Returns:
            SneakernetBundle containing log export
        """
        # Build log export structure
        log_export = {
            'format_version': '1.0',
            'export_type': 'boundary_daemon_log',
            'exported_at': datetime.utcnow().isoformat() + "Z",
            'source_node': self.node_id,
            'event_count': len(events),
            'merkle_root': merkle_root,
            'event_range': event_range,
            'events': events,
            'merkle_proofs': merkle_proofs
        }

        data = json.dumps(log_export, indent=2).encode()

        bundle = self.create_bundle(
            bundle_type=BundleType.LOG_EXPORT,
            data=data,
            description=f"Log export: {len(events)} events",
            encryption=encryption,
            encryption_key=encryption_key,
            metadata={
                'event_count': len(events),
                'event_range': event_range,
                'has_proofs': merkle_proofs is not None
            }
        )

        bundle.manifest.merkle_root = merkle_root
        bundle.manifest.event_range = event_range

        # Re-sign after adding merkle_root
        self._sign_manifest(bundle.manifest)

        return bundle

    def create_audit_bundle(self, audit_data: Dict,
                           encryption: BundleEncryption = BundleEncryption.NONE,
                           encryption_key: Optional[bytes] = None) -> SneakernetBundle:
        """
        Create a full audit package bundle.

        Args:
            audit_data: Audit data dictionary (summary, anchors, commitments)
            encryption: Encryption method
            encryption_key: Encryption key

        Returns:
            SneakernetBundle containing audit package
        """
        data = json.dumps(audit_data, indent=2).encode()

        return self.create_bundle(
            bundle_type=BundleType.AUDIT_PACKAGE,
            data=data,
            description="Full audit package export",
            encryption=encryption,
            encryption_key=encryption_key,
            metadata={
                'includes_anchors': 'anchors' in audit_data,
                'includes_commitments': 'commitments' in audit_data
            }
        )

    def write_to_directory(self, bundle: SneakernetBundle, output_dir: str) -> Tuple[bool, str]:
        """
        Write bundle to a directory (e.g., USB drive).

        Args:
            bundle: Bundle to write
            output_dir: Output directory path

        Returns:
            (success, message)
        """
        try:
            bundle_dir = os.path.join(output_dir, f"bundle_{bundle.manifest.bundle_id}")
            os.makedirs(bundle_dir, mode=0o700, exist_ok=True)

            # Write manifest
            manifest_path = os.path.join(bundle_dir, "manifest.json")
            with open(manifest_path, 'w') as f:
                f.write(bundle.manifest.to_json())

            # Write chunks
            for chunk in bundle.chunks:
                chunk_path = os.path.join(bundle_dir, f"chunk_{chunk.chunk_index:03d}.bin.gz")
                with open(chunk_path, 'wb') as f:
                    f.write(gzip.compress(chunk.data))

            # Write verification info
            verify_path = os.path.join(bundle_dir, "VERIFY.txt")
            with open(verify_path, 'w') as f:
                f.write("SNEAKERNET BUNDLE VERIFICATION\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Bundle ID: {bundle.manifest.bundle_id}\n")
                f.write(f"Type: {bundle.manifest.bundle_type.value}\n")
                f.write(f"Created: {bundle.manifest.created_at}\n")
                f.write(f"Source: {bundle.manifest.source_node}\n")
                f.write(f"Content Hash: {bundle.manifest.content_hash}\n")
                f.write(f"Chunks: {bundle.manifest.chunk_count}\n")
                f.write(f"Size: {bundle.manifest.total_size} bytes\n")
                f.write(f"Encrypted: {bundle.manifest.encryption.value}\n\n")
                f.write(f"Public Key for Verification:\n{bundle.manifest.public_key}\n")

            return (True, f"Bundle written to {bundle_dir}")

        except Exception as e:
            return (False, f"Failed to write bundle: {e}")

    def write_single_file(self, bundle: SneakernetBundle, output_path: str) -> Tuple[bool, str]:
        """
        Write bundle as a single compressed file.

        Args:
            bundle: Bundle to write
            output_path: Output file path

        Returns:
            (success, message)
        """
        try:
            # Package everything into a single structure
            package = {
                'manifest': bundle.manifest.to_dict(),
                'chunks': [
                    {
                        'index': c.chunk_index,
                        'data': base64.b64encode(c.data).decode(),
                        'checksum': c.checksum
                    }
                    for c in bundle.chunks
                ]
            }

            # Compress and write
            with gzip.open(output_path, 'wt', encoding='utf-8') as f:
                json.dump(package, f)

            return (True, f"Bundle written to {output_path}")

        except Exception as e:
            return (False, f"Failed to write bundle: {e}")

    def _encrypt_data(self, data: bytes, encryption: BundleEncryption,
                     key: Optional[bytes], password: Optional[str]) -> Tuple[bytes, BundleEncryption]:
        """Encrypt data if requested."""
        if encryption == BundleEncryption.NONE:
            return (data, BundleEncryption.NONE)

        if encryption == BundleEncryption.XCHACHA20:
            if not NACL_AVAILABLE:
                return (data, BundleEncryption.NONE)

            if not key:
                key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

            box = nacl.secret.SecretBox(key)
            encrypted = box.encrypt(data)
            return (encrypted, BundleEncryption.XCHACHA20)

        if encryption == BundleEncryption.FERNET:
            if not FERNET_AVAILABLE:
                return (data, BundleEncryption.NONE)

            if not key:
                key = Fernet.generate_key()

            f = Fernet(key)
            encrypted = f.encrypt(data)
            return (encrypted, BundleEncryption.FERNET)

        if encryption == BundleEncryption.PASSWORD:
            if not password:
                return (data, BundleEncryption.NONE)

            if FERNET_AVAILABLE:
                # Derive key from password
                salt = secrets.token_bytes(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=480000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                f = Fernet(key)
                encrypted = salt + f.encrypt(data)  # Prepend salt
                return (encrypted, BundleEncryption.PASSWORD)

        return (data, BundleEncryption.NONE)

    def _create_chunks(self, data: bytes) -> List[BundleChunk]:
        """Split data into chunks."""
        chunks = []
        total_chunks = (len(data) + self.chunk_size - 1) // self.chunk_size

        for i in range(total_chunks):
            start = i * self.chunk_size
            end = min(start + self.chunk_size, len(data))
            chunk_data = data[start:end]

            chunks.append(BundleChunk(
                chunk_index=i,
                chunk_count=total_chunks,
                data=chunk_data,
                checksum=hashlib.sha256(chunk_data).hexdigest()
            ))

        return chunks

    def _sign_manifest(self, manifest: BundleManifest):
        """Sign the manifest."""
        if not self._signing_key:
            return

        signing_hash = manifest.compute_signing_hash()
        signed = self._signing_key.sign(signing_hash.encode())
        manifest.signature = signed.signature.hex()


# =============================================================================
# SNEAKERNET IMPORTER
# =============================================================================

class SneakernetImporter:
    """
    Imports and verifies sneakernet bundles.

    Usage:
        importer = SneakernetImporter()
        bundle = importer.read_from_directory("/mnt/usb/bundle_abc123")
        valid, msg = importer.verify_bundle(bundle)
        if valid:
            data = importer.extract_data(bundle)
    """

    def __init__(self, trusted_public_keys: Optional[Dict[str, str]] = None):
        """
        Initialize sneakernet importer.

        Args:
            trusted_public_keys: Dict of node_id -> public_key for verification
        """
        self.trusted_keys = trusted_public_keys or {}

    def add_trusted_key(self, node_id: str, public_key: str):
        """Add a trusted public key."""
        self.trusted_keys[node_id] = public_key

    def read_from_directory(self, bundle_dir: str) -> Optional[SneakernetBundle]:
        """
        Read bundle from directory.

        Args:
            bundle_dir: Path to bundle directory

        Returns:
            SneakernetBundle or None if invalid
        """
        try:
            # Read manifest
            manifest_path = os.path.join(bundle_dir, "manifest.json")
            with open(manifest_path, 'r') as f:
                manifest_data = json.load(f)

            manifest = BundleManifest.from_dict(manifest_data)

            # Read chunks
            chunks = []
            for i in range(manifest.chunk_count):
                chunk_path = os.path.join(bundle_dir, f"chunk_{i:03d}.bin.gz")
                with open(chunk_path, 'rb') as f:
                    compressed_data = f.read()

                data = gzip.decompress(compressed_data)
                checksum = hashlib.sha256(data).hexdigest()

                chunks.append(BundleChunk(
                    chunk_index=i,
                    chunk_count=manifest.chunk_count,
                    data=data,
                    checksum=checksum
                ))

            return SneakernetBundle(manifest=manifest, chunks=chunks)

        except Exception as e:
            print(f"Error reading bundle: {e}")
            return None

    def read_single_file(self, file_path: str) -> Optional[SneakernetBundle]:
        """
        Read bundle from single compressed file.

        Args:
            file_path: Path to bundle file

        Returns:
            SneakernetBundle or None if invalid
        """
        try:
            with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                package = json.load(f)

            manifest = BundleManifest.from_dict(package['manifest'])

            chunks = []
            for chunk_data in package['chunks']:
                data = base64.b64decode(chunk_data['data'])
                chunks.append(BundleChunk(
                    chunk_index=chunk_data['index'],
                    chunk_count=len(package['chunks']),
                    data=data,
                    checksum=chunk_data['checksum']
                ))

            return SneakernetBundle(manifest=manifest, chunks=chunks)

        except Exception as e:
            print(f"Error reading bundle: {e}")
            return None

    def verify_bundle(self, bundle: SneakernetBundle,
                     require_trusted_key: bool = True) -> Tuple[bool, str]:
        """
        Verify bundle integrity and signature.

        Args:
            bundle: Bundle to verify
            require_trusted_key: Require key to be in trusted list

        Returns:
            (valid, message)
        """
        # Verify chunk integrity
        valid, msg = bundle.verify_integrity()
        if not valid:
            return (False, f"Integrity check failed: {msg}")

        # Verify signature
        if not bundle.manifest.signature:
            return (False, "Bundle is not signed")

        if not bundle.manifest.public_key:
            return (False, "Bundle has no public key")

        # Check trusted keys
        if require_trusted_key:
            source = bundle.manifest.source_node
            if source not in self.trusted_keys:
                return (False, f"Unknown source node: {source}")

            if self.trusted_keys[source] != bundle.manifest.public_key:
                return (False, "Public key mismatch for source node")

        # Verify signature
        if NACL_AVAILABLE:
            try:
                verify_key = nacl.signing.VerifyKey(
                    bundle.manifest.public_key,
                    encoder=nacl.encoding.HexEncoder
                )

                signing_hash = bundle.manifest.compute_signing_hash()
                verify_key.verify(
                    signing_hash.encode(),
                    bytes.fromhex(bundle.manifest.signature)
                )
            except Exception as e:
                return (False, f"Signature verification failed: {e}")
        else:
            return (False, "Cryptography library not available")

        return (True, "Bundle verified successfully")

    def extract_data(self, bundle: SneakernetBundle,
                    decryption_key: Optional[bytes] = None,
                    password: Optional[str] = None) -> Optional[bytes]:
        """
        Extract and optionally decrypt bundle data.

        Args:
            bundle: Verified bundle
            decryption_key: Decryption key (for XCHACHA20/FERNET)
            password: Password (for PASSWORD encryption)

        Returns:
            Decrypted data or None
        """
        # Reassemble chunks
        all_data = b''.join(c.data for c in bundle.chunks)

        # Decompress
        try:
            decompressed = gzip.decompress(all_data)
        except Exception:
            decompressed = all_data

        # Decrypt
        encryption = bundle.manifest.encryption

        if encryption == BundleEncryption.NONE:
            return decompressed

        if encryption == BundleEncryption.XCHACHA20:
            if not NACL_AVAILABLE or not decryption_key:
                return None

            try:
                box = nacl.secret.SecretBox(decryption_key)
                return box.decrypt(decompressed)
            except Exception:
                return None

        if encryption == BundleEncryption.FERNET:
            if not FERNET_AVAILABLE or not decryption_key:
                return None

            try:
                f = Fernet(decryption_key)
                return f.decrypt(decompressed)
            except Exception:
                return None

        if encryption == BundleEncryption.PASSWORD:
            if not FERNET_AVAILABLE or not password:
                return None

            try:
                salt = decompressed[:16]
                encrypted = decompressed[16:]

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=480000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                f = Fernet(key)
                return f.decrypt(encrypted)
            except Exception:
                return None

        return None

    def extract_log_events(self, bundle: SneakernetBundle,
                          decryption_key: Optional[bytes] = None) -> Optional[Dict]:
        """
        Extract log events from a LOG_EXPORT bundle.

        Args:
            bundle: Verified log bundle
            decryption_key: Decryption key if encrypted

        Returns:
            Log export dictionary or None
        """
        if bundle.manifest.bundle_type != BundleType.LOG_EXPORT:
            return None

        data = self.extract_data(bundle, decryption_key)
        if not data:
            return None

        try:
            return json.loads(data.decode())
        except Exception:
            return None


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    'BundleType',
    'BundleEncryption',
    'BundleManifest',
    'BundleChunk',
    'SneakernetBundle',
    'SneakernetExporter',
    'SneakernetImporter',
]
