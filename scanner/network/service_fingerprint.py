import re
import socket
import ssl
from dataclasses import dataclass

from scanner.log import logger
from scanner.network.port_scanner import PortResult


@dataclass
class ServiceProbe:
    name: str
    ports: list[int]
    send: bytes
    match: list[tuple]
    tls: bool = False
    timeout: float = 3.0


PROBES = [
    ServiceProbe("HTTP", [80, 8080, 8000, 8008, 8888, 3000, 5000, 8081, 9090, 10000],
        b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r"HTTP/[\d.]+ \d+.*Server: ([^\r\n]+)", "HTTP"), (r"HTTP/[\d.]+ \d+", "HTTP")]),
    ServiceProbe("HTTPS", [443, 8443, 4443, 9443],
        b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r"HTTP/[\d.]+ \d+.*Server: ([^\r\n]+)", "HTTPS"), (r"HTTP/[\d.]+ \d+", "HTTPS")],
        tls=True),
    ServiceProbe("SSH", [22, 2222, 22222], b"",
        [(r"SSH-(\d+\.\d+)-(\S+)", "SSH")]),
    ServiceProbe("FTP", [21, 2121], b"",
        [(r"220[- ].*([Ff][Tt][Pp]|FileZilla|vsftpd|ProFTPD|Pure-FTP)", "FTP"),
         (r"220[- ]", "FTP")]),
    ServiceProbe("SMTP", [25, 465, 587, 2525], b"EHLO probe\r\n",
        [(r"220[- ].*?(Postfix|Exim|Sendmail|Exchange|Haraka|hMailServer)", "SMTP"),
         (r"220[- ]", "SMTP")]),
    ServiceProbe("POP3", [110, 995], b"",
        [(r"\+OK.*?(Dovecot|Courier|Cyrus|UW POP)", "POP3"), (r"\+OK", "POP3")]),
    ServiceProbe("IMAP", [143, 993], b"",
        [(r"\* OK.*?(Dovecot|Courier|Cyrus|Exchange)", "IMAP"), (r"\* OK", "IMAP")]),
    ServiceProbe("MySQL", [3306, 3307], b"",
        [(r"(\d+\.\d+\.\d+).*?MariaDB", "MariaDB"),
         (r"(\d+\.\d+\.\d+[-\w]*)\x00", "MySQL"),
         (r"mysql|MariaDB", "MySQL")], timeout=2.0),
    ServiceProbe("PostgreSQL", [5432, 5433],
        b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
        [(r"[NS]", "PostgreSQL")], timeout=2.0),
    ServiceProbe("Redis", [6379, 6380], b"PING\r\n",
        [(r"\+PONG", "Redis"), (r"-NOAUTH", "Redis"), (r"-ERR", "Redis"),
         (r"\$\d+\r\nredis_version:(\S+)", "Redis")]),
    ServiceProbe("MongoDB", [27017, 27018, 27019], b"",
        [(r"It looks like you are trying to access MongoDB", "MongoDB"),
         (r"ismaster", "MongoDB")]),
    ServiceProbe("Memcached", [11211], b"stats\r\n",
        [(r"STAT version (\S+)", "Memcached"), (r"STAT pid", "Memcached"),
         (r"ERROR", "Memcached")]),
    ServiceProbe("RDP", [3389],
        bytes.fromhex("030000130ee00000000000010008000b000000"),
        [(r"\x03\x00", "RDP")]),
    ServiceProbe("Telnet", [23, 2323], b"",
        [(r"\xff[\xfb\xfd\xfe]", "Telnet"), (r"[Ll]ogin:|[Uu]sername:", "Telnet")]),
    ServiceProbe("DNS", [53],
        bytes.fromhex("001e000000010000000000000776657273696f6e0462696e640000100003"),
        [(r".", "DNS")], timeout=2.0),
    ServiceProbe("LDAP", [389, 636, 3268, 3269],
        b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
        [(r"\x30", "LDAP")]),
    ServiceProbe("SMB", [445, 139],
        bytes.fromhex(
            "00000085ff534d4272000000001853c0"
            "0000000000000000000000000000fffe"
            "00000000006200025043204e4554574f"
            "524b2050524f4752414d20312e300002"
            "4c414e4d414e312e30000244662f534d"
            "6220536572766572000002444e545f4c"
            "4d302e31320002534d4220322e303032"
            "0002534d4220322e3f3f3f00"),
        [(r"\xff\x53\x4d\x42", "SMB"), (r"\xfe\x53\x4d\x42", "SMBv2")]),
    ServiceProbe("VNC", [5900, 5901, 5902, 5903], b"",
        [(r"RFB (\d+\.\d+)", "VNC")]),
    # Generic fallback
    ServiceProbe("Generic", [], b"\r\n", [(r"(.+)", "Unknown")], timeout=2.0),
]


def _grab_banner(host: str, port: int, probe: ServiceProbe) -> tuple[str, str, str]:
    banner = service = version = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(probe.timeout)
        sock.connect((host, port))

        if probe.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            logger.debug("Fingerprint: TLS probe to %s:%d with verification disabled (expected for fingerprinting)", host, port)
            sock = ctx.wrap_socket(sock, server_hostname=host)

        if probe.send:
            sock.sendall(probe.send)

        try:
            banner = sock.recv(4096).decode("utf-8", errors="replace").strip()
        except (socket.timeout, ConnectionResetError):
            pass
        sock.close()
    except (socket.error, ssl.SSLError, OSError):
        return service, version, banner

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
                    info["san"] = [v for _, v in cert.get("subjectAltName", ())]
                info["cipher"] = ssock.cipher()
                info["tls_version"] = ssock.version()
    except (OSError, ssl.SSLError):
        pass
    return info


def fingerprint_port(host: str, port_result: PortResult) -> PortResult:
    port = port_result.port
    applicable = [p for p in PROBES if port in p.ports]
    if not applicable:
        applicable = [p for p in PROBES if p.name == "Generic"]

    for probe in applicable:
        service, version, banner = _grab_banner(host, port, probe)
        if service:
            port_result.service = service
            port_result.version = version
            port_result.banner = banner[:500]
            return port_result

    from scanner.network.port_scanner import SERVICE_NAMES
    if port in SERVICE_NAMES and not port_result.service:
        port_result.service = SERVICE_NAMES[port]

    return port_result


def fingerprint_host(host: str, open_ports: list[PortResult]) -> list[PortResult]:
    logger.info("Network: Fingerprinting %d open ports on %s", len(open_ports), host)
    for pr in open_ports:
        try:
            fingerprint_port(host, pr)
        except (OSError, ssl.SSLError) as e:
            logger.debug("Network: Fingerprint error on %s:%d -- %s", host, pr.port, e)
    return open_ports
