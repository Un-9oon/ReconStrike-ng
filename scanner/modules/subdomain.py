import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "vpn", "remote",
    "admin", "panel", "cp", "cpanel", "whm", "webmin",
    "api", "api2", "api-v2", "rest", "graphql",
    "dev", "development", "staging", "stage", "stg", "test", "testing",
    "uat", "qa", "sandbox", "demo", "beta", "alpha", "preview",
    "app", "application", "portal", "gateway",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "git", "gitlab", "github", "svn", "bitbucket",
    "ci", "jenkins", "travis", "drone", "build",
    "monitor", "monitoring", "grafana", "kibana", "prometheus", "nagios",
    "log", "logs", "syslog", "elk",
    "backup", "bak", "old", "legacy", "archive",
    "internal", "intranet", "private", "corp", "corporate",
    "auth", "login", "sso", "oauth", "identity",
    "docs", "doc", "documentation", "wiki", "help", "support",
    "blog", "forum", "community",
    "shop", "store", "cart", "payment", "pay",
    "proxy", "gateway", "lb", "loadbalancer",
    "docker", "k8s", "kubernetes", "rancher", "swarm",
    "status", "health", "ping",
    "crm", "erp", "hr",
    "s3", "storage", "minio",
    "rabbitmq", "kafka", "queue",
    "vault", "secrets",
    "prometheus", "alertmanager",
]

INTERESTING_SUBDOMAINS = {
    "admin", "panel", "cpanel", "whm", "webmin", "dev", "staging", "stage",
    "test", "testing", "uat", "qa", "sandbox", "internal", "intranet",
    "private", "backup", "bak", "old", "legacy", "git", "gitlab", "jenkins",
    "docker", "k8s", "kubernetes", "db", "database", "mysql", "postgres",
    "redis", "mongo", "elastic", "grafana", "kibana", "prometheus", "vault",
}


def _resolve_subdomain(subdomain: str, domain: str) -> tuple[str, str | None]:
    fqdn = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except socket.gaierror:
        return fqdn, None


def run(session: ScanSession) -> None:
    logger.info("\n[*] Enumerating subdomains...")

    parsed = urlparse(session.config.target)
    domain = parsed.netloc.split(":")[0]

    parts = domain.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) > 2 else domain

    found_subdomains = []

    _, wildcard_ip = _resolve_subdomain("vulnscan-wildcard-check-xz9q7", base_domain)
    if wildcard_ip:
        logger.warning(f" [!] Wildcard DNS detected (*.{base_domain} -> {wildcard_ip}), filtering results...")

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {
            executor.submit(_resolve_subdomain, sub, base_domain): sub
            for sub in COMMON_SUBDOMAINS
        }
        for future in as_completed(futures):
            fqdn, ip = future.result()
            if ip:
                if wildcard_ip and ip == wildcard_ip:
                    continue
                sub = futures[future]
                found_subdomains.append((fqdn, ip, sub))

    found_subdomains.sort(key=lambda x: x[0])

    if not found_subdomains:
        logger.info(" [*] No subdomains found via DNS brute force.")
        return

    logger.info(f" [+] Found {len(found_subdomains)} subdomains:")
    for fqdn, ip, _ in found_subdomains:
        logger.info(f" {fqdn} -> {ip}")

    interesting = [(fqdn, ip, sub) for fqdn, ip, sub in found_subdomains if sub in INTERESTING_SUBDOMAINS]

    if interesting:
        interesting_list = ", ".join(f"{fqdn} ({ip})" for fqdn, ip, _ in interesting)
        session.add_finding(Finding(
            title="Sensitive Subdomains Discovered",
            severity=Severity.MEDIUM,
            description=(
                f"Found {len(interesting)} potentially sensitive subdomains that may expose "
                f"internal services, development environments, admin interfaces, or databases."
            ),
            evidence=f"Subdomains: {interesting_list}",
            remediation=(
                "1. Internal/dev/staging services should not be publicly resolvable.\n"
                "2. Use split-horizon DNS for internal services.\n"
                "3. Restrict access via firewall or VPN.\n"
                "4. Remove DNS records for decommissioned services."
            ),
            url=session.config.target,
            module="subdomain",
            cwe="CWE-200",
            confirmed=True,
            location=f"DNS records for {base_domain}",
            curl_command=f"dig +short {interesting[0][0]}" if interesting else "",
            reproduction_steps=(
                f"1. Run: dig +short {interesting[0][0]}\n"
                f"2. The subdomain resolves to {interesting[0][1]}.\n"
                f"3. Sensitive subdomains found: {', '.join(s[0] for s in interesting[:5])}"
            ) if interesting else "",
            developer_fix=(
                f"1. Remove public DNS records for internal services:\n"
                f"   Delete A/CNAME records for dev, staging, internal subdomains.\n"
                f"2. Use split-horizon DNS:\n"
                f"   Internal DNS returns private IPs; external DNS returns nothing.\n"
                f"3. Firewall: Block external access to non-public subdomains.\n"
                f"4. If services must be public, require VPN or SSO authentication."
            ),
            affected_component=f"DNS configuration for {base_domain}",
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage",
            detection_method="DNS brute-force enumeration using a wordlist of common subdomain names. Resolved each candidate via DNS lookup, filtered wildcard responses, and flagged sensitive subdomains (admin, staging, internal, database).",
        ))

    all_list = "\n".join(f"  {fqdn} -> {ip}" for fqdn, ip, _ in found_subdomains)
    session.add_finding(Finding(
        title=f"Subdomain Enumeration: {len(found_subdomains)} Found",
        severity=Severity.INFO,
        description=f"DNS brute force discovered {len(found_subdomains)} subdomains for {base_domain}.",
        evidence=f"Subdomains:\n{all_list}",
        remediation="Review all subdomains and ensure only intended services are publicly accessible.",
        url=session.config.target,
        module="subdomain",
        cwe="CWE-200",
        confirmed=True,
        location=f"DNS records for {base_domain}",
        curl_command=f"for sub in www mail admin dev staging; do dig +short $sub.{base_domain}; done",
        detection_method="DNS brute-force enumeration using a wordlist of common subdomain names. Resolved each candidate via DNS lookup, filtered wildcard responses, and flagged sensitive subdomains (admin, staging, internal, database).",
    ))
