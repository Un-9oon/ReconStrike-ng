import os
import datetime
import ipaddress
from pathlib import Path

from scanner.log import logger

CA_DIR = Path.home() / ".reconstrike-ng" / "ca"


def _ensure_cryptography():
    try:
        from cryptography import x509
        return True
    except ImportError:
        logger.error("DAST Proxy requires 'cryptography'. Install with: pip install cryptography")
        return False


def generate_root_ca(ca_dir: Path | str | None = None,
                     cn: str = "ReconStrike DAST Proxy CA",
                     validity_days: int = 3650) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    ca_dir = Path(ca_dir) if ca_dir else CA_DIR
    ca_dir.mkdir(parents=True, exist_ok=True)

    key_path = ca_dir / "ca.key"
    cert_path = ca_dir / "ca.crt"

    if key_path.exists() and cert_path.exists():
        logger.info("DAST: Using existing CA from %s", ca_dir)
        return key_path, cert_path

    logger.info("DAST: Generating new Root CA certificate...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ReconStrike Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    logger.info("DAST: Root CA generated at %s", ca_dir)
    logger.info("DAST: Import %s into your browser's trusted root store.", cert_path)
    return key_path, cert_path


def generate_domain_cert(domain: str, ca_key_path: Path | str,
                         ca_cert_path: Path | str,
                         cache_dir: Path | str | None = None) -> tuple[bytes, bytes]:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    if cache_dir:
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        safe_name = domain.replace("*", "_wildcard_").replace(":", "_")
        cached_cert = cache_dir / "{}.crt".format(safe_name)
        cached_key = cache_dir / "{}.key".format(safe_name)
        if cached_cert.exists() and cached_key.exists():
            return cached_cert.read_bytes(), cached_key.read_bytes()

    ca_key = serialization.load_pem_private_key(Path(ca_key_path).read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())

    domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    san_entries = [x509.DNSName(domain)]
    if not domain.startswith("*."):
        san_entries.append(x509.DNSName("*.{}".format(domain)))
    try:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(domain)))
    except ValueError:
        pass

    now = datetime.datetime.now(datetime.timezone.utc)
    domain_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .issuer_name(ca_cert.subject)
        .public_key(domain_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = domain_cert.public_bytes(serialization.Encoding.PEM)
    key_pem = domain_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    if cache_dir:
        cached_cert.write_bytes(cert_pem)
        cached_key.write_bytes(key_pem)
        os.chmod(cached_key, 0o600)

    return cert_pem, key_pem


def get_ca_paths(ca_dir: Path | str | None = None) -> tuple[Path, Path] | None:
    ca_dir = Path(ca_dir) if ca_dir else CA_DIR
    key_path, cert_path = ca_dir / "ca.key", ca_dir / "ca.crt"
    return (key_path, cert_path) if key_path.exists() and cert_path.exists() else None
