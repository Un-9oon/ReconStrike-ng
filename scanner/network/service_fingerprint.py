"""Service fingerprinting and banner grabbing for identified open ports.

Sends protocol-specific probes to determine the exact service, version,
and operating system behind each open port.  Supports 20+ protocols
including HTTP, SSH, FTP, SMTP, MySQL, Redis, MongoDB, and more.
"""

import re
import socket
import ssl
import struct
import time
from dataclasses import dataclass

from scanner.log import logger
from scanner.network.port_scanner import PortResult


# ---------------------------------------------------------------------------
# Protocol probe definitions
# ---------------------------------------------------------------------------
@dataclass
class ServiceProbe:
    """Definition for a protocol-specific fingerprinting probe."""
    name: str
    ports: list[int]       # Ports this probe applies to (empty = any)
    send: bytes            # Bytes to send (empty = just grab banner)
    match: list[tuple]     # List of (regex_pattern, service_name) for matching
    tls: bool = False      # Whether to wrap in TLS
    timeout: float = 3.0


# Protocol probes ordered by specificity
PROBES = [
    # HTTP / HTTPS
    ServiceProbe(
        name="HTTP",
        ports=[80, 8080, 8000, 8008, 8888, 3000, 5000, 8081, 9090, 10000],
        send=b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        match=[
            (r"HTTP/[\d.]+ \d+.*Server: ([^\r\n]+)", "HTTP"),
            (r"HTTP/[\d.]+ \d+", "HTTP"),
        ],
    ),
    ServiceProbe(
        name="HTTPS",
        ports=[443, 8443, 4443, 9443],
        send=b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        match=[
            (r"HTTP/[\d.]+ \d+.*Server: ([^\r\n]+)", "HTTPS"),
            (r"HTTP/[\d.]+ \d+", "HTTPS"),
        ],
        tls=True,
    ),

    # SSH
    ServiceProbe(
        name="SSH",
        ports=[22, 2222, 22222],
        send=b"",  # SSH sends banner on connect
        match=[
            (r"SSH-(\d+\.\d+)-(\S+)", "SSH"),
        ],
    ),

    # FTP
    ServiceProbe(
        name="FTP",
        ports=[21, 2121],
        send=b"",
        match=[
            (r"220[- ].*([Ff][Tt][Pp]|FileZilla|vsftpd|ProFTPD|Pure-FTP)", "FTP"),
            (r"220[- ]", "FTP"),
        ],
    ),

    # SMTP
    ServiceProbe(
        name="SMTP",
        ports=[25, 465, 587, 2525],
        send=b"EHLO probe\r\n",
        match=[
            (r"220[- ].*?(Postfix|Exim|Sendmail|Exchange|Haraka|hMailServer)", "SMTP"),
            (r"220[- ]", "SMTP"),
        ],
    ),

    # POP3
    ServiceProbe(
        name="POP3",
        ports=[110, 995],
        send=b"",
        match=[
            (r"\+OK.*?(Dovecot|Courier|Cyrus|UW POP)", "POP3"),
            (r"\+OK", "POP3"),
        ],
    ),

    # IMAP
    ServiceProbe(
        name="IMAP",
        ports=[143, 993],
        send=b"",
        match=[
            (r"\* OK.*?(Dovecot|Courier|Cyrus|Exchange)", "IMAP"),
            (r"\* OK", "IMAP"),
        ],
    ),

    # MySQL / MariaDB
    ServiceProbe(
        name="MySQL",
        ports=[3306, 3307],
        send=b"",
        match=[
            (r"(\d+\.\d+\.\d+).*?MariaDB", "MariaDB"),
            (r"(\d+\.\d+\.\d+[-\w]*)\x00", "MySQL"),
            (r"mysql|MariaDB", "MySQL"),
        ],
        timeout=2.0,
    ),

    # PostgreSQL
    ServiceProbe(
        name="PostgreSQL",
        ports=[5432, 5433],
        send=b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  # SSLRequest
        match=[
            (r"[NS]", "PostgreSQL"),
        ],
        timeout=2.0,
    ),

    # Redis
    ServiceProbe(
        name="Redis",
        ports=[6379, 6380],
        send=b"PING\r\n",
        match=[
            (r"\+PONG", "Redis"),
            (r"-NOAUTH", "Redis"),
            (r"-ERR", "Redis"),
            (r"\$\d+\r\nredis_version:(\S+)", "Redis"),
        ],
    ),

    # MongoDB
    ServiceProbe(
        name="MongoDB",
        ports=[27017, 27018, 27019],
        send=b"",
        match=[
            (r"It looks like you are trying to access MongoDB", "MongoDB"),
            (r"ismaster", "MongoDB"),
        ],
    ),

    # Memcached
    ServiceProbe(
        name="Memcached",
        ports=[11211],
        send=b"stats\r\n",
        match=[
            (r"STAT version (\S+)", "Memcached"),
            (r"STAT pid", "Memcached"),
            (r"ERROR", "Memcached"),
        ],
    ),

    # RDP
    ServiceProbe(
        name="RDP",
        ports=[3389],
        # RDP negotiation request (TPKT + X.224 CR)
        send=bytes.fromhex(
            "030000130ee00000000000010008000b000000"
        ),
        match=[
            (r"\x03\x00", "RDP"),
        ],
    ),

    # Telnet
    ServiceProbe(
        name="Telnet",
        ports=[23, 2323],
        send=b"",
        match=[
            (r"\xff[\xfb\xfd\xfe]", "Telnet"),
            (r"[Ll]ogin:|[Uu]sername:", "Telnet"),
        ],
    ),

    # DNS
    ServiceProbe(
        name="DNS",
        ports=[53],
        # DNS query for version.bind TXT CH
        send=bytes.fromhex(
            "001e00000001000000000000"
            "0776657273696f6e0462696e640000100003"
        ),
        match=[
            (r".", "DNS"),
        ],
        timeout=2.0,
    ),

    # LDAP
    ServiceProbe(
        name="LDAP",
        ports=[389, 636, 3268, 3269],
        send=b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
        match=[
            (r"\x30", "LDAP"),
        ],
    ),

    # SMB
    ServiceProbe(
        name="SMB",
        ports=[445, 139],
        # SMB negotiate protocol request
        send=bytes.fromhex(
            "00000085ff534d4272000000001853c0"
            "0000000000000000000000000000fffe"
            "00000000006200025043204e4554574f"
            "524b2050524f4752414d20312e300002"
            "4c414e4d414e312e30000244662f534d"
            "6220536572766572000002444e545f4c"
            "4d302e31320002534d4220322e303032"
            "0002534d4220322e3f3f3f00"
        ),
        match=[
            (r"\xff\x53\x4d\x42", "SMB"),
            (r"\xfe\x53\x4d\x42", "SMBv2"),
        ],
    ),

    # VNC
    ServiceProbe(
        name="VNC",
        ports=[5900, 5901, 5902, 5903],
        send=b"",
        match=[
            (r"RFB (\d+\.\d+)", "VNC"),
        ],
    ),

    # Generic banner grab (fallback for unknown ports)
    ServiceProbe(
        name="Generic",
        ports=[],  # Applies to any port not matched above
        send=b"\r\n",
        match=[
            (r"(.+)", "Unknown"),
        ],
        timeout=2.0,
    ),
]


# ---------------------------------------------------------------------------
# Fingerprinting engine
# ---------------------------------------------------------------------------
def _grab_banner(host: str, port: int, probe: ServiceProbe) -> tuple[str, str, str]:
    """Send a probe and grab the response banner.

    Returns:
        (service_name, version_string, raw_banner)
    """
    banner = ""
    service = ""
    version = ""

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(probe.timeout)
        sock.connect((host, port))

        if probe.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        # Send probe data if any
        if probe.send:
            sock.sendall(probe.send)

        # Read response
        try:
            data = sock.recv(4096)
            banner = data.decode("utf-8", errors="replace").strip()
        except (socket.timeout, ConnectionResetError):
            pass

        sock.close()

    except (socket.error, ssl.SSLError, OSError):
        return service, version, banner

    # Match response against patterns
    for pattern, svc_name in probe.match:
        try:
            m = re.search(pattern, banner, re.DOTALL | re.IGNORECASE)
            if m:
                service = svc_name
                if m.lastindex and m.lastindex >= 1:
                    version = m.group(1).strip()
                break
        except re.error:
            continue

    return service, version, banner


def _get_tls_info(host: str, port: int) -> dict:
    """Extract TLS certificate information from a port."""
    info = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    info["subject"] = dict(x[0] for x in cert.get("subject", ()))
                    info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                    info["not_before"] = cert.get("notBefore", "")
                    info["not_after"] = cert.get("notAfter", "")
                    info["serial"] = cert.get("serialNumber", "")
                    san = cert.get("subjectAltName", ())
                    info["san"] = [v for _, v in san]

                info["cipher"] = ssock.cipher()
                info["tls_version"] = ssock.version()
    except Exception:
        pass
    return info


def fingerprint_port(host: str, port_result: PortResult) -> PortResult:
    """Fingerprint a single open port — identify the service, version, and banner.

    Tries applicable protocol probes in order and returns the first match.
    """
    port = port_result.port

    # Find applicable probes for this port
    applicable = [p for p in PROBES if port in p.ports]
    if not applicable:
        # Use generic probe as fallback
        applicable = [p for p in PROBES if p.name == "Generic"]

    for probe in applicable:
        service, version, banner = _grab_banner(host, port, probe)
        if service:
            port_result.service = service
            port_result.version = version
            port_result.banner = banner[:500]  # Cap banner length
            return port_result

    # If no probe matched but port is in our known list, use the default name
    from scanner.network.port_scanner import SERVICE_NAMES
    if port in SERVICE_NAMES and not port_result.service:
        port_result.service = SERVICE_NAMES[port]

    return port_result


def fingerprint_host(host: str, open_ports: list[PortResult]) -> list[PortResult]:
    """Fingerprint all open ports on a host.

    Args:
        host:       IP address of the host.
        open_ports: List of PortResult objects from the port scanner.

    Returns:
        Updated list with service, version, and banner fields populated.
    """
    logger.info("Network: Fingerprinting %d open ports on %s", len(open_ports), host)

    for port_result in open_ports:
        try:
            fingerprint_port(host, port_result)
        except Exception as e:
            logger.debug("Network: Fingerprint error on %s:%d — %s",
                         host, port_result.port, e)

    return open_ports
