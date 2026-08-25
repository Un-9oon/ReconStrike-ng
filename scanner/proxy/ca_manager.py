"""Certificate Authority manager for the DAST interception proxy.

Generates a self-signed Root CA on first run and dynamically creates
per-domain certificates signed by that CA for TLS interception.  The
Root CA is stored at ~/.reconstrike/ca/ and only needs to be imported
into the tester's browser once.

No certificates are ever sent to or installed on the target server.
"""

import os
import datetime
import ipaddress
from pathlib import Path

from scanner.log import logger

# Default CA storage directory
CA_DIR = Path.home() / ".reconstrike" / "ca"


def _ensure_cryptography():
    """Check that the cryptography library is available."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        return True
    except ImportError:
        logger.error(
            "DAST Proxy requires the 'cryptography' package. "
            "Install it with: pip install cryptography"
        )
        return False


def generate_root_ca(ca_dir: Path | str | None = None,
                     cn: str = "ReconStrike-ng DAST Proxy CA",
                     validity_days: int = 3650) -> tuple[Path, Path]:
    """Generate a self-signed Root CA key and certificate.

    Args:
        ca_dir:         Directory to store the CA files. Defaults to ~/.reconstrike/ca/
        cn:             Common Name for the CA certificate.
        validity_days:  How many days the CA is valid for (default: 10 years).

    Returns:
        Tuple of (ca_key_path, ca_cert_path).

    Raises:
        ImportError: If the cryptography library is not installed.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    ca_dir = Path(ca_dir) if ca_dir else CA_DIR
    ca_dir.mkdir(parents=True, exist_ok=True)

    key_path = ca_dir / "ca.key"
    cert_path = ca_dir / "ca.crt"

    # Don't regenerate if already exists
    if key_path.exists() and cert_path.exists():
        logger.info("DAST: Using existing CA from %s", ca_dir)
        return key_path, cert_path

    logger.info("DAST: Generating new Root CA certificate...")

    # Generate RSA private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build the CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ReconStrike-ng Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    # Save key (restricted permissions)
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)

    # Save certificate
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    logger.info("DAST: Root CA generated at %s", ca_dir)
    logger.info("DAST: Import %s into your browser's trusted root store to use the proxy.", cert_path)

    return key_path, cert_path


def generate_domain_cert(domain: str,
                         ca_key_path: Path | str,
                         ca_cert_path: Path | str,
                         cache_dir: Path | str | None = None) -> tuple[bytes, bytes]:
    """Generate a certificate for a specific domain, signed by our Root CA.

    Args:
        domain:        The domain name (e.g., "example.com").
        ca_key_path:   Path to the CA private key.
        ca_cert_path:  Path to the CA certificate.
        cache_dir:     Optional directory to cache generated certs.

    Returns:
        Tuple of (cert_pem_bytes, key_pem_bytes).
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Check cache first
    if cache_dir:
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        safe_name = domain.replace("*", "_wildcard_").replace(":", "_")
        cached_cert = cache_dir / f"{safe_name}.crt"
        cached_key = cache_dir / f"{safe_name}.key"
        if cached_cert.exists() and cached_key.exists():
            return cached_cert.read_bytes(), cached_key.read_bytes()

    # Load CA credentials
    ca_key_pem = Path(ca_key_path).read_bytes()
    ca_cert_pem = Path(ca_cert_path).read_bytes()

    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    # Generate domain key
    domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build Subject Alternative Names
    san_entries = [x509.DNSName(domain)]
    # Also add wildcard
    if not domain.startswith("*."):
        san_entries.append(x509.DNSName(f"*.{domain}"))
    # Try to add as IP if it looks like one
    try:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(domain)))
    except ValueError:
        pass

    now = datetime.datetime.now(datetime.timezone.utc)
    domain_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(domain_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = domain_cert.public_bytes(serialization.Encoding.PEM)
    key_pem = domain_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Cache if directory specified
    if cache_dir:
        cached_cert.write_bytes(cert_pem)
        cached_key.write_bytes(key_pem)
        os.chmod(cached_key, 0o600)

    return cert_pem, key_pem


def get_ca_paths(ca_dir: Path | str | None = None) -> tuple[Path, Path] | None:
    """Get existing CA paths if they exist, or None."""
    ca_dir = Path(ca_dir) if ca_dir else CA_DIR
    key_path = ca_dir / "ca.key"
    cert_path = ca_dir / "ca.crt"
    if key_path.exists() and cert_path.exists():
        return key_path, cert_path
    return None
