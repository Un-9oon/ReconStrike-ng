import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession

COMMON_PORTS = {
    21: ("FTP", Severity.MEDIUM), 22: ("SSH", Severity.INFO), 23: ("Telnet", Severity.HIGH),
    25: ("SMTP", Severity.LOW), 53: ("DNS", Severity.INFO), 80: ("HTTP", Severity.INFO),
    110: ("POP3", Severity.LOW), 111: ("RPCBind", Severity.MEDIUM), 135: ("MSRPC", Severity.MEDIUM),
    139: ("NetBIOS", Severity.MEDIUM), 143: ("IMAP", Severity.LOW), 443: ("HTTPS", Severity.INFO),
    445: ("SMB", Severity.HIGH), 993: ("IMAPS", Severity.INFO), 995: ("POP3S", Severity.INFO),
    1433: ("MSSQL", Severity.HIGH), 1521: ("Oracle", Severity.HIGH), 2049: ("NFS", Severity.HIGH),
    2375: ("Docker API (unencrypted)", Severity.CRITICAL), 2376: ("Docker API", Severity.MEDIUM),
    3306: ("MySQL", Severity.HIGH), 3389: ("RDP", Severity.MEDIUM), 5432: ("PostgreSQL", Severity.HIGH),
    5672: ("RabbitMQ", Severity.MEDIUM), 5900: ("VNC", Severity.HIGH), 6379: ("Redis", Severity.HIGH),
    6443: ("Kubernetes API", Severity.HIGH), 8080: ("HTTP Proxy/Alt", Severity.LOW),
    8443: ("HTTPS Alt", Severity.INFO), 8888: ("HTTP Alt", Severity.LOW),
    9090: ("Management Console", Severity.MEDIUM), 9200: ("Elasticsearch", Severity.HIGH),
    9300: ("Elasticsearch Transport", Severity.HIGH), 11211: ("Memcached", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH), 27018: ("MongoDB", Severity.HIGH),
}

DANGEROUS_SERVICES = {
    "Telnet", "SMB", "MSSQL", "Oracle", "MySQL", "PostgreSQL", "VNC",
    "Redis", "MongoDB", "Elasticsearch", "Memcached", "NFS",
    "Docker API (unencrypted)", "Kubernetes API", "NetBIOS", "RPCBind",
}

BANNER_GRAB_PORTS = {21, 22, 23, 25, 80, 110, 143, 3306, 6379, 11211, 27017}

_DETECTION = (
    "Performed TCP connect scan against common service ports (21-27017) with banner grabbing. "
    "Identified exposed services that should not be publicly accessible (databases, Docker API, Redis, etc.)."
)


def _scan_port(host, port, timeout=2.0):
    banner = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            if port in BANNER_GRAB_PORTS:
                try:
                    if port in (80, 443, 8080):
                        sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                    sock.settimeout(2)
                    banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                except OSError as e:
                    logger.debug("portscan _scan_port: socket operation failed: %s", e)
            sock.close()
            return port, True, banner
        sock.close()
    except OSError as e:
        logger.debug("portscan _scan_port: socket operation failed: %s", e)
    return port, False, ""


def run(session: ScanSession) -> None:
    logger.info("\n[*] Running port scan...")

    parsed = urlparse(session.config.target)
    hostname = parsed.netloc.split(":")[0]

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        logger.warning(" [!] Cannot resolve hostname: {}".format(hostname))
        return

    logger.info(" [*] Scanning {} ({}) -- {} ports...".format(hostname, ip, len(COMMON_PORTS)))

    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(_scan_port, ip, port): port for port in COMMON_PORTS}
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                service_name, _ = COMMON_PORTS[port]
                open_ports.append((port, service_name, banner))

    open_ports.sort(key=lambda x: x[0])

    if not open_ports:
        logger.info(" [+] No commonly targeted ports found open.")
        return

    web_ports = {80, 443, 8080, 8443}
    target_port = parsed.port

    for port, service, banner in open_ports:
        _, default_severity = COMMON_PORTS[port]

        if port in web_ports or port == target_port:
            continue

        is_dangerous = service in DANGEROUS_SERVICES
        if service == "Docker API (unencrypted)":
            severity = Severity.CRITICAL
        elif is_dangerous:
            severity = Severity.HIGH
        else:
            severity = default_severity

        evidence = "Port: {}\nService: {}\nHost: {} ({})".format(port, service, hostname, ip)
        if banner:
            evidence += "\nBanner: {}".format(banner[:200])

        nmap_cmd = "nmap -sV -p {} {}".format(port, hostname)

        if is_dangerous:
            session.add_finding(Finding(
                title="Exposed Service: {} (port {})".format(service, port),
                severity=severity,
                description=(
                    "{svc} service is exposed on port {port}. This service should not be publicly accessible "
                    "as it may allow unauthorized data access, command execution, or lateral movement."
                ).format(svc=service, port=port),
                evidence=evidence,
                remediation=(
                    "1. Restrict access to {svc} (port {port}) using firewall rules.\n"
                    "2. Only allow connections from trusted IPs.\n"
                    "3. Use VPN or SSH tunneling for remote access.\n"
                    "4. Enable authentication if not already configured."
                ).format(svc=service, port=port),
                url=session.config.target,
                module="portscan",
                cwe="CWE-284",
                confirmed=True,
                location="Port {} ({}) on {} ({})".format(port, service, hostname, ip),
                curl_command=nmap_cmd,
                reproduction_steps=(
                    "1. Run: nmap -p {port} {host}\n"
                    "2. Port {port} is open and running {svc}.\n"
                    "3. Run: {cmd} for version detection."
                ).format(port=port, host=hostname, svc=service, cmd=nmap_cmd),
                developer_fix=(
                    "1. Firewall rule to block external access:\n"
                    "   iptables -A INPUT -p tcp --dport {port} -j DROP\n"
                    "   # Or allow only specific IPs:\n"
                    "   iptables -A INPUT -p tcp --dport {port} -s TRUSTED_IP -j ACCEPT\n\n"
                    "2. Cloud security groups: Remove port {port} from public-facing rules.\n"
                    "3. Bind to localhost: Configure {svc} to listen on 127.0.0.1 only."
                ).format(port=port, svc=service),
                affected_component="{} service on port {}".format(service, port),
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                detection_method=_DETECTION,
            ))
        elif severity != Severity.INFO:
            session.add_finding(Finding(
                title="Open Port: {} ({})".format(service, port),
                severity=severity,
                description="{} is accessible on port {}. Review if this service needs to be publicly exposed.".format(service, port),
                evidence=evidence,
                remediation="Review if port {} ({}) needs to be publicly accessible. Apply firewall rules.".format(port, service),
                url=session.config.target,
                module="portscan",
                cwe="CWE-284",
                confirmed=True,
                location="Port {} ({}) on {} ({})".format(port, service, hostname, ip),
                curl_command=nmap_cmd,
                developer_fix="If not needed publicly:\n  iptables -A INPUT -p tcp --dport {} -j DROP".format(port),
                detection_method=_DETECTION,
            ))

    port_list = ", ".join("{}({})".format(p, s) for p, s, _ in open_ports)
    logger.info(" [+] Open ports: {}".format(port_list))
