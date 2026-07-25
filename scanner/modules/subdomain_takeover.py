import re
import socket
from urllib.parse import urlparse

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "blog", "dev", "staging", "test",
    "api", "app", "cdn", "docs", "git", "jenkins", "jira", "login",
    "m", "media", "monitor", "ns1", "ns2", "portal", "shop", "smtp",
    "ssh", "ssl", "status", "store", "support", "vpn", "webmail",
    "beta", "demo", "go", "help", "img", "internal", "lab", "legacy",
    "mx", "new", "old", "ops", "preview", "prod", "sandbox", "secure",
    "stage", "static", "uat", "web", "wiki", "assets", "backup",
    "board", "calendar", "chat", "ci", "cloud", "cms", "crm", "db",
    "deploy", "download", "edge", "email", "files", "forum", "gateway",
    "grafana", "hub", "info", "intranet", "kibana", "log", "manage",
    "metrics", "news", "office", "pages", "panel", "proxy", "redirect",
    "registry", "repo", "reports", "search", "service", "sso", "track",
]


SERVICE_FINGERPRINTS = {
    "AWS S3": {
        "cnames": ["s3.amazonaws.com", ".s3-website", "s3-", ".amazonaws.com"],
        "signatures": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "<Code>NoSuchBucket</Code>",
        ],
    },
    "GitHub Pages": {
        "cnames": ["github.io", "github.com"],
        "signatures": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html",
        ],
    },
    "Heroku": {
        "cnames": ["herokuapp.com", "herokussl.com", "herokudns.com"],
        "signatures": [
            "no-such-app.herokuapp.com",
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
            "There's nothing here, yet.",
        ],
    },
    "Azure (Web Apps)": {
        "cnames": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net", "azure-api.net"],
        "signatures": [
            "404 Web Site not found",
            "Error 404 - Web app not found",
        ],
    },
    "Azure Blob Storage": {
        "cnames": ["blob.core.windows.net"],
        "signatures": [
            "BlobNotFound",
            "The specified container does not exist",
            "<Code>ContainerNotFound</Code>",
        ],
    },
    "Shopify": {
        "cnames": ["myshopify.com"],
        "signatures": [
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
        ],
    },
    "Fastly": {
        "cnames": ["fastly.net", "fastlylb.net", "global.prod.fastly.net"],
        "signatures": [
            "Fastly error: unknown domain",
            "Fastly - unknown domain:",
        ],
    },
    "Pantheon": {
        "cnames": ["pantheonsite.io", "pantheon.io"],
        "signatures": [
            "404 error unknown site!",
            "The gods are wise, but do not know",
        ],
    },
    "Tumblr": {
        "cnames": ["domains.tumblr.com"],
        "signatures": [
            "Whatever you were looking for doesn't currently exist at this address",
            "There's nothing here.",
        ],
    },
    "WordPress.com": {
        "cnames": ["wordpress.com"],
        "signatures": [
            "Do you want to register",
        ],
    },
    "Ghost": {
        "cnames": ["ghost.io"],
        "signatures": [
            "The thing you were looking for is no longer here",
            "Ghost(Pro)",
        ],
    },
    "Surge.sh": {
        "cnames": ["surge.sh"],
        "signatures": [
            "project not found",
        ],
    },
    "Bitbucket": {
        "cnames": ["bitbucket.io"],
        "signatures": [
            "Repository not found",
        ],
    },
    "Unbounce": {
        "cnames": ["unbouncepages.com"],
        "signatures": [
            "The requested URL was not found on this server",
            "The page you were looking for doesn't exist",
        ],
    },
    "Help Scout": {
        "cnames": ["helpscoutdocs.com"],
        "signatures": [
            "No settings were found for this company",
        ],
    },
    "Cargo Collective": {
        "cnames": ["cargocollective.com"],
        "signatures": [
            "404 Not Found",
        ],
    },
    "Statuspage.io": {
        "cnames": ["statuspage.io"],
        "signatures": [
            "You are being <a href=\"https://www.atlassian.com/software/statuspage",
            "StatusPage",
        ],
    },
    "Fly.io": {
        "cnames": ["fly.dev", "shw.io"],
        "signatures": [
            "404 Not Found",
        ],
    },
    "Netlify": {
        "cnames": ["netlify.app", "netlify.com"],
        "signatures": [
            "Not Found - Request ID:",
        ],
    },
    "Vercel": {
        "cnames": ["vercel.app", "now.sh"],
        "signatures": [
            "DEPLOYMENT_NOT_FOUND",
            "The deployment could not be found",
        ],
    },
    "Zendesk": {
        "cnames": ["zendesk.com"],
        "signatures": [
            "Help Center Closed",
            "this help center no longer exists",
        ],
    },
    "Teamwork": {
        "cnames": ["teamwork.com"],
        "signatures": [
            "Oops - We didn't find your site",
        ],
    },
    "Helpjuice": {
        "cnames": ["helpjuice.com"],
        "signatures": [
            "We could not find what you're looking for",
        ],
    },
    "Tilda": {
        "cnames": ["tilda.ws"],
        "signatures": [
            "Please renew your subscription",
        ],
    },
    "Canny": {
        "cnames": ["canny.io"],
        "signatures": [
            "Company Not Found",
            "There is no such company",
        ],
    },
}


def _resolve_cname(hostname: str) -> str:
    """Resolve CNAME record for a hostname using DNS."""
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "CNAME", hostname],
            capture_output=True, text=True, timeout=5,
        )
        cname = result.stdout.strip().rstrip(".")
        if cname:
            return cname
    except Exception as e:
        logger.debug("subdomain_takeover _resolve_cname: operation failed: %s", e)

    try:
        result = socket.getaddrinfo(hostname, None)
        if result:
            return result[0][4][0]
    except Exception as e:
        logger.debug("subdomain_takeover _resolve_cname: socket operation failed: %s", e)

    return ""


def _host_resolves(hostname: str) -> bool:
    """Check if a hostname resolves to an IP."""
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False


def _extract_subdomains_from_urls(session: ScanSession) -> set:
    """Extract unique subdomains from crawled URLs."""
    base_parsed = urlparse(session.config.target)
    base_domain = base_parsed.hostname or ""

    parts = base_domain.split(".")
    if len(parts) >= 2:
        root_domain = ".".join(parts[-2:])
    else:
        root_domain = base_domain

    subdomains = set()
    for url in session.crawled_urls:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if hostname.endswith(root_domain) and hostname != root_domain:
            subdomains.add(hostname)

    return subdomains


def _brute_force_subdomains(session: ScanSession) -> set:
    """Brute-force common subdomains against the target domain."""
    base_parsed = urlparse(session.config.target)
    base_domain = base_parsed.hostname or ""

    parts = base_domain.split(".")
    if len(parts) >= 2:
        root_domain = ".".join(parts[-2:])
    else:
        root_domain = base_domain

    discovered = set()
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{root_domain}"
        if _host_resolves(fqdn):
            discovered.add(fqdn)

    return discovered


def _check_takeover(session: ScanSession, subdomain: str) -> None:
    """Check a single subdomain for potential takeover."""
    cname = _resolve_cname(subdomain)
    if not cname:
        return

    cname_lower = cname.lower()

    for service_name, fingerprint in SERVICE_FINGERPRINTS.items():
        cname_match = any(
            indicator.lower() in cname_lower
            for indicator in fingerprint["cnames"]
        )
        if not cname_match:
            continue

        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            try:
                resp = session.get(url, allow_redirects=True)
            except Exception as e:
                logger.debug("subdomain_takeover _check_takeover: request failed: %s", e)
                continue

            if not resp:
                if not _host_resolves(subdomain):
                    _report_dangling_cname(session, subdomain, cname, service_name)
                    return
                continue

            body = resp.text or ""
            for signature in fingerprint["signatures"]:
                if signature.lower() in body.lower():
                    curl_cmd = f"curl -k -s -o /dev/null -w '%{{http_code}}' '{url}'"
                    dig_cmd = f"dig +short CNAME {subdomain}"

                    session.add_finding(Finding(
                        title=f"Subdomain Takeover: {subdomain} ({service_name})",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The subdomain '{subdomain}' has a CNAME record pointing to "
                            f"'{cname}' ({service_name}), but the resource appears to be "
                            f"decommissioned or unclaimed. An attacker can register this "
                            f"resource on {service_name} and serve malicious content on "
                            f"the victim's subdomain, enabling phishing, cookie theft, "
                            f"and session hijacking."
                        ),
                        evidence=(
                            f"Subdomain: {subdomain}\n"
                            f"CNAME Target: {cname}\n"
                            f"Service: {service_name}\n"
                            f"HTTP Status: {resp.status_code}\n"
                            f"Fingerprint Matched: {signature}\n"
                            f"Response excerpt: {body[:500]}"
                        ),
                        remediation=(
                            f"1. Remove the DNS CNAME record for {subdomain} if the "
                            f"   {service_name} resource is no longer needed.\n"
                            f"2. Or reclaim the resource on {service_name}.\n"
                            f"3. Audit all DNS records for similar dangling references."
                        ),
                        url=url,
                        module="subdomain_takeover",
                        cwe="CWE-284",
                        confirmed=True,
                        location=f"DNS CNAME: {subdomain} -> {cname}",
                        curl_command=f"{dig_cmd} && {curl_cmd}",
                        reproduction_steps=(
                            f"1. Resolve the CNAME for {subdomain}:\n"
                            f"   $ {dig_cmd}\n"
                            f"   Result: {cname}\n"
                            f"2. Visit {url} in a browser\n"
                            f"3. Observe the {service_name} error page with fingerprint: '{signature}'\n"
                            f"4. Register the unclaimed resource on {service_name}\n"
                            f"5. Serve arbitrary content on {subdomain}"
                        ),
                        developer_fix=(
                            f"Remove the dangling DNS record:\n"
                            f"  Delete CNAME: {subdomain} -> {cname}\n\n"
                            f"Or reclaim the {service_name} resource:\n"
                            f"  Register/create the resource that '{cname}' points to on {service_name}.\n\n"
                            f"Prevention:\n"
                            f"  - Maintain an inventory of all DNS records\n"
                            f"  - When decommissioning a service, remove DNS records FIRST\n"
                            f"  - Regularly audit DNS records for dangling references\n"
                            f"  - Use monitoring to detect changes in DNS resolution"
                        ),
                        affected_component=f"DNS / {service_name} integration",
                        references=(
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover\n"
                            "https://github.com/EdOverflow/can-i-take-over-xyz\n"
                            "https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers"
                        ),
                        detection_method=(
                            f"Resolved CNAME for {subdomain}, identified it points to "
                            f"{service_name} ({cname}). HTTP response matched known "
                            f"decommissioned-service fingerprint: '{signature}'."
                        ),
                    ))
                    return
        return


def _report_dangling_cname(
    session: ScanSession, subdomain: str, cname: str, service_name: str
) -> None:
    """Report a dangling CNAME that does not resolve."""
    dig_cmd = f"dig +short CNAME {subdomain}"
    nslookup_cmd = f"nslookup {cname}"

    session.add_finding(Finding(
        title=f"Dangling CNAME (Potential Takeover): {subdomain}",
        severity=Severity.HIGH,
        description=(
            f"The subdomain '{subdomain}' has a CNAME record pointing to "
            f"'{cname}' ({service_name}), but the target does not resolve to "
            f"any IP address. This strongly suggests the {service_name} resource "
            f"has been deleted, making it a candidate for subdomain takeover."
        ),
        evidence=(
            f"Subdomain: {subdomain}\n"
            f"CNAME Target: {cname}\n"
            f"Service: {service_name}\n"
            f"DNS Resolution: NXDOMAIN / no IP\n"
            f"The CNAME target does not resolve."
        ),
        remediation=(
            f"Remove the dangling CNAME record for {subdomain} or "
            f"reclaim the {service_name} resource."
        ),
        url=f"https://{subdomain}",
        module="subdomain_takeover",
        cwe="CWE-284",
        confirmed=False,
        location=f"DNS CNAME: {subdomain} -> {cname}",
        curl_command=f"{dig_cmd} && {nslookup_cmd}",
        reproduction_steps=(
            f"1. Check CNAME:\n   $ {dig_cmd}\n   Result: {cname}\n"
            f"2. Verify the CNAME target does not resolve:\n   $ {nslookup_cmd}\n"
            f"3. The target returns NXDOMAIN, indicating the resource is gone\n"
            f"4. Attempt to register the resource on {service_name}"
        ),
        developer_fix=(
            f"Remove the dangling DNS CNAME record:\n"
            f"  Delete: {subdomain} CNAME {cname}\n\n"
            f"Implement a DNS record lifecycle process:\n"
            f"  - Track all external CNAME records in a configuration management system\n"
            f"  - Before decommissioning a cloud resource, remove the DNS record first\n"
            f"  - Schedule periodic DNS audits to catch stale records"
        ),
        affected_component=f"DNS / {service_name} integration",
        references=(
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover\n"
            "https://github.com/EdOverflow/can-i-take-over-xyz"
        ),
        detection_method=(
            f"Resolved CNAME for {subdomain} and found it points to {service_name} "
            f"({cname}), but the CNAME target itself does not resolve (NXDOMAIN). "
            f"This indicates a decommissioned service with a dangling DNS reference."
        ),
    ))


def _check_nxdomain_subdomains(session: ScanSession) -> None:
    """Look for subdomains with CNAME but no resolution (quick takeover signal)."""
    base_parsed = urlparse(session.config.target)
    base_domain = base_parsed.hostname or ""
    parts = base_domain.split(".")
    if len(parts) >= 2:
        root_domain = ".".join(parts[-2:])
    else:
        root_domain = base_domain

    for sub in COMMON_SUBDOMAINS[:30]:
        fqdn = f"{sub}.{root_domain}"
        cname = _resolve_cname(fqdn)
        if not cname:
            continue

        if not _host_resolves(fqdn):
            for service_name, fingerprint in SERVICE_FINGERPRINTS.items():
                if any(ind.lower() in cname.lower() for ind in fingerprint["cnames"]):
                    _report_dangling_cname(session, fqdn, cname, service_name)
                    break


def run(session: ScanSession) -> None:
    """Run subdomain takeover checks."""
    print("\n[*] Testing for subdomain takeover vulnerabilities...")

    subdomains = _extract_subdomains_from_urls(session)

    brute_forced = _brute_force_subdomains(session)
    subdomains.update(brute_forced)

    if subdomains:
        print(f"  [+] Found {len(subdomains)} subdomains to check")

    for subdomain in subdomains:
        _check_takeover(session, subdomain)

    _check_nxdomain_subdomains(session)
