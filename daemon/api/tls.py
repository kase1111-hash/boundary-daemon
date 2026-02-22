"""
TLS Helper Module for Boundary Daemon HTTP Servers

Provides shared TLS configuration for:
- Health Check Server
- Verification API
- Prometheus Metrics Exporter

Usage:
    from daemon.api.tls import create_ssl_context, generate_self_signed_cert

    # Use existing certificates
    ctx = create_ssl_context("/path/to/cert.pem", "/path/to/key.pem")

    # Generate self-signed cert for development
    certfile, keyfile = generate_self_signed_cert("/tmp/certs")
"""

import ssl
import logging
import os
import tempfile
import subprocess
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def create_ssl_context(
    certfile: str,
    keyfile: str,
    client_auth: bool = False,
    ca_file: Optional[str] = None,
) -> ssl.SSLContext:
    """Create a hardened TLS server context.

    Args:
        certfile: Path to PEM certificate file
        keyfile: Path to PEM private key file
        client_auth: If True, require client certificates (mTLS)
        ca_file: CA bundle for client cert verification

    Returns:
        Configured SSLContext

    Raises:
        FileNotFoundError: If cert/key files don't exist
        ssl.SSLError: If cert/key are invalid
    """
    if not os.path.isfile(certfile):
        raise FileNotFoundError(f"TLS certificate not found: {certfile}")
    if not os.path.isfile(keyfile):
        raise FileNotFoundError(f"TLS private key not found: {keyfile}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20"
    )
    ctx.load_cert_chain(certfile, keyfile)

    if client_auth and ca_file:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(ca_file)

    return ctx


def generate_self_signed_cert(
    output_dir: str,
    hostname: str = "localhost",
    days: int = 365,
) -> Tuple[str, str]:
    """Generate a self-signed certificate for development use.

    Args:
        output_dir: Directory to write cert/key files
        hostname: Common Name for the certificate
        days: Certificate validity period

    Returns:
        (certfile_path, keyfile_path)

    Raises:
        RuntimeError: If openssl is not available
    """
    certfile = os.path.join(output_dir, "boundary-daemon.crt")
    keyfile = os.path.join(output_dir, "boundary-daemon.key")

    if os.path.isfile(certfile) and os.path.isfile(keyfile):
        return certfile, keyfile

    os.makedirs(output_dir, exist_ok=True)

    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", keyfile, "-out", certfile,
                "-days", str(days), "-nodes",
                "-subj", f"/CN={hostname}",
            ],
            check=True,
            capture_output=True,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "openssl not found — cannot generate self-signed certificate. "
            "Install openssl or provide --tls-cert and --tls-key."
        )

    # Restrict key file permissions
    os.chmod(keyfile, 0o600)

    logger.info(f"Generated self-signed certificate: {certfile}")
    return certfile, keyfile
