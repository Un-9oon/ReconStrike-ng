import re
from urllib.parse import urljoin

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger


def run(session: ScanSession) -> None:
    logger.info("\n[*] Checking for security misconfigurations...")
    _check_methods(session)
    _check_clickjacking(session)
    _check_open_redirect(session)
    _check_host_header_injection(session)
    _check_crlf_injection(session)


def _check_methods(session: ScanSession):
    resp = session.session.options(session.config.target, timeout=session.config.timeout, verify=session.config.verify_ssl)
    allow = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
    if not allow:
        return

    dangerous = {"PUT", "DELETE", "TRACE", "CONNECT"}
    allowed = {m.strip().upper() for m in allow.split(",")}
    found = dangerous & allowed
    curl_cmd = f"curl -k -X OPTIONS -I '{session.config.target}'"

    if "TRACE" in found:
        trace_resp = session.session.request("TRACE", session.config.target,
                                              timeout=session.config.timeout, verify=session.config.verify_ssl)
        if trace_resp.status_code == 200 and "TRACE" in trace_resp.text.upper():
            session.add_finding(Finding(
                title="HTTP TRACE Method Enabled",
                severity=Severity.MEDIUM,
                description="TRACE method is enabled, potentially allowing Cross-Site Tracing (XST) attacks that can steal credentials via JavaScript.",
                evidence=f"TRACE response status: {trace_resp.status_code}\nAllow header: {allow}",
                remediation="Disable the TRACE HTTP method on the web server.",
                url=session.config.target,
                module="misconfig",
                cwe="CWE-16",
                confirmed=True,
                location="HTTP TRACE method on web server",
                request_method="TRACE",
                response_status=trace_resp.status_code,
                curl_command=f"curl -k -X TRACE '{session.config.target}'",
                reproduction_steps=(
                    f"1. Send an HTTP TRACE request to {session.config.target}\n"
                    f"2. The server responds with HTTP 200 and echoes the request.\n"
                    f"3. Run: curl -k -X TRACE '{session.config.target}'"
                ),
                developer_fix=(
                    "Apache: Add to httpd.conf:\n  TraceEnable Off\n"
                    "Nginx: TRACE is disabled by default.\n"
                    "IIS: Use URL Rewrite to block TRACE requests."
                ),
                affected_component="Web server configuration",
                references="https://owasp.org/www-community/attacks/Cross_Site_Tracing",
                detection_method="Tested server configuration: sent OPTIONS requests to enumerate allowed HTTP methods, checked for missing X-Frame-Options (clickjacking), tested open redirect via manipulated parameters, and injected Host/CRLF headers to detect misrouting.",
            ))

    dangerous_found = found - {"TRACE"}
    if dangerous_found:
        session.add_finding(Finding(
            title=f"Dangerous HTTP Methods Enabled: {', '.join(dangerous_found)}",
            severity=Severity.LOW,
            description=f"Server allows potentially dangerous HTTP methods: {', '.join(dangerous_found)}.",
            evidence=f"Allow header: {allow}",
            remediation="Disable unnecessary HTTP methods (PUT, DELETE) unless required by the API.",
            url=session.config.target,
            module="misconfig",
            cwe="CWE-16",
            confirmed=True,
            location="HTTP methods allowed by web server",
            curl_command=curl_cmd,
            developer_fix=(
                "Apache: <LimitExcept GET POST>\n  Deny from all\n</LimitExcept>\n"
                "Nginx: if ($request_method !~ ^(GET|POST|HEAD)$ ) { return 405; }"
            ),
            affected_component="Web server configuration",
            detection_method="Tested server configuration: sent OPTIONS requests to enumerate allowed HTTP methods, checked for missing X-Frame-Options (clickjacking), tested open redirect via manipulated parameters, and injected Host/CRLF headers to detect misrouting.",
        ))


def _check_clickjacking(session: ScanSession):
    resp = session.get(session.config.target)
    if not resp:
        return

    xfo = resp.headers.get("X-Frame-Options", "").lower()
    csp = resp.headers.get("Content-Security-Policy", "")

    if not xfo and "frame-ancestors" not in csp.lower():
        if "text/html" in resp.headers.get("Content-Type", ""):
            curl_cmd = f"curl -kI '{session.config.target}'"
            session.add_finding(Finding(
                title="Clickjacking: No Frame Protection",
                severity=Severity.MEDIUM,
                description="The page can be embedded in iframes on attacker-controlled sites, enabling clickjacking attacks where users unknowingly click hidden elements.",
                evidence="No X-Frame-Options header and no CSP frame-ancestors directive found in response headers.",
                remediation="Add X-Frame-Options: DENY header or CSP frame-ancestors 'none' directive.",
                url=session.config.target,
                module="misconfig",
                cwe="CWE-1021",
                confirmed=True,
                location="HTTP response headers",
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Send: {curl_cmd}\n"
                    f"2. Check response headers - no X-Frame-Options or CSP frame-ancestors.\n"
                    f"3. Create an HTML page: <iframe src=\"{session.config.target}\"></iframe>\n"
                    f"4. The target page loads inside the iframe."
                ),
                developer_fix=(
                    "Apache: Header always set X-Frame-Options \"DENY\"\n"
                    "Nginx: add_header X-Frame-Options \"DENY\" always;\n"
                    "Express: app.use(helmet.frameguard({ action: 'deny' }))\n"
                    "Or use CSP: Content-Security-Policy: frame-ancestors 'none'"
                ),
                affected_component="Web server / application response headers",
                references="https://owasp.org/www-community/attacks/Clickjacking",
                detection_method="Tested server configuration: sent OPTIONS requests to enumerate allowed HTTP methods, checked for missing X-Frame-Options (clickjacking), tested open redirect via manipulated parameters, and injected Host/CRLF headers to detect misrouting.",
            ))


def _check_open_redirect(session: ScanSession):
    redirect_params = ["url", "redirect", "next", "return", "returnUrl", "redirect_uri",
                        "continue", "dest", "destination", "go", "target", "rurl", "return_to"]
    evil_target = "https://evil-vulnscan-test.com"

    for url in list(session.crawled_urls)[:5]:
        for param in redirect_params[:6]:
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={evil_target}"
            resp = session.get(test_url, allow_redirects=False)
            if not resp:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if location.startswith(evil_target) or location.startswith("//evil-vulnscan-test.com"):
                    curl_cmd = f"curl -k -I '{test_url}'"
                    session.add_finding(Finding(
                        title=f"Open Redirect via '{param}' Parameter",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The '{param}' parameter allows redirecting users to arbitrary external domains. "
                            f"An attacker can craft URLs that appear to be from the legitimate site but redirect "
                            f"to phishing pages or malware distribution sites."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Test URL: {test_url}\n"
                            f"Redirect Status: {resp.status_code}\n"
                            f"Location Header: {location}"
                        ),
                        remediation=(
                            "1. Validate redirect targets against a whitelist of allowed domains.\n"
                            "2. Only allow relative paths (starting with /).\n"
                            "3. Show an interstitial warning page before redirecting to external sites."
                        ),
                        url=url,
                        module="misconfig",
                        cwe="CWE-601",
                        confirmed=True,
                        location=f"URL parameter '{param}'",
                        parameter=param,
                        payload=evil_target,
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Craft URL: {test_url}\n"
                            f"2. The server responds with HTTP {resp.status_code} redirect.\n"
                            f"3. Location header points to: {location}\n"
                            f"4. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"File: Server-side redirect handler that uses '{param}' parameter.\n\n"
                            f"VULNERABLE: redirect(request.params['{param}'])\n"
                            f"SECURE:\n"
                            f"  target = request.params['{param}']\n"
                            f"  if not target.startswith('/'):\n"
                            f"      return error(400, 'Invalid redirect')\n"
                            f"  # Or validate against domain whitelist\n"
                            f"  parsed = urlparse(target)\n"
                            f"  if parsed.netloc and parsed.netloc != 'yourdomain.com':\n"
                            f"      return error(400, 'Invalid redirect')"
                        ),
                        affected_component=f"Redirect handler using '{param}' parameter",
                        references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                        detection_method="Tested server configuration: sent OPTIONS requests to enumerate allowed HTTP methods, checked for missing X-Frame-Options (clickjacking), tested open redirect via manipulated parameters, and injected Host/CRLF headers to detect misrouting.",
                    ))
                    return


def _check_host_header_injection(session: ScanSession):
    evil_host = "evil-vulnscan-test.com"

    normal_resp = session.get(session.config.target)
    if not normal_resp:
        return

    resp = session.get(session.config.target, headers={"Host": evil_host})
    if not resp:
        return

    if evil_host in resp.text:
        security_contexts = re.findall(
            r'(?:href|action|src)\s*=\s*["\']https?://' + re.escape(evil_host) + r'[^"\']*["\']',
            resp.text, re.IGNORECASE
        )
        if not security_contexts:
            return

        if any(p in resp.text.lower() for p in ("reset", "password", "verify", "confirm", "activate", "token")):
            curl_cmd = f"curl -k -H 'Host: {evil_host}' '{session.config.target}'"
            session.add_finding(Finding(
                title="Host Header Injection in Sensitive Context",
                severity=Severity.MEDIUM,
                description=(
                    "The application reflects the Host header in URLs on pages with password reset or verification "
                    "functionality. An attacker can poison password reset links to point to their server."
                ),
                evidence=f"Injected Host: {evil_host}\nReflected in: {security_contexts[0][:100]}",
                remediation="Validate the Host header server-side. Use a whitelist of allowed hostnames.",
                url=session.config.target,
                module="misconfig",
                cwe="CWE-644",
                confirmed=True,
                location="Host header reflection in generated URLs",
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Send a request with Host: {evil_host}\n"
                    f"2. The injected hostname appears in generated URLs.\n"
                    f"3. Run: {curl_cmd}"
                ),
                developer_fix=(
                    "Use a configured base URL instead of the Host header:\n"
                    "  BASE_URL = 'https://yourdomain.com'  # From config, not request\n"
                    "  reset_link = f'{BASE_URL}/reset?token={token}'\n\n"
                    "Or validate the Host header:\n"
                    "  ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']\n"
                    "  if request.host not in ALLOWED_HOSTS: return 400"
                ),
                affected_component="URL generation using Host header",
                references="https://portswigger.net/web-security/host-header",
                detection_method="Tested server configuration: sent OPTIONS requests to enumerate allowed HTTP methods, checked for missing X-Frame-Options (clickjacking), tested open redirect via manipulated parameters, and injected Host/CRLF headers to detect misrouting.",
            ))


def _check_crlf_injection(session: ScanSession):
    payloads = [
        "%0d%0aX-Injected: vulnscan",
        "%0aX-Injected: vulnscan",
        "\r\nX-Injected: vulnscan",
    ]

    for payload in payloads:
        test_url = f"{session.config.target}/{payload}"
        resp = session.get(test_url, allow_redirects=False)
        if not resp:
            continue

        if "x-injected" in {k.lower() for k in resp.headers}:
            curl_cmd = f"curl -kI '{test_url}'"
            session.add_finding(Finding(
                title="CRLF Injection / HTTP Response Splitting",
                severity=Severity.HIGH,
                description=(
                    "The server is vulnerable to CRLF injection, allowing HTTP response splitting. "
                    "An attacker can inject arbitrary HTTP headers, potentially enabling cache poisoning, "
                    "XSS via injected headers, or session fixation."
                ),
                evidence=f"Payload: {payload}\nInjected header 'X-Injected: vulnscan' appeared in response headers.",
                remediation="Sanitize CRLF characters (\\r\\n) from all user input used in HTTP headers or redirects.",
                url=session.config.target,
                module="misconfig",
                cwe="CWE-113",
                confirmed=True,
                location="URL path / HTTP response headers",
                payload=payload,
                request_method="GET",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Send a request with CRLF characters in the URL path.\n"
                    f"2. Test URL: {test_url}\n"
                    f"3. The injected header 'X-Injected' appears in the response.\n"
                    f"4. Run: {curl_cmd}"
                ),
                developer_fix=(
                    "Strip or encode CRLF characters from all user input before using in HTTP responses:\n"
                    "  Python: value = value.replace('\\r', '').replace('\\n', '')\n"
                    "  PHP: header() already prevents this in PHP 5.1.2+\n"
                    "  Node.js: Sanitize before res.setHeader() calls\n"
                    "  Also: URL-decode input before sanitizing to catch %0d%0a"
                ),
                affected_component="HTTP response header generation",
                references="https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
                detection_method="Tested server configuration: sent OPTIONS requests to enumerate allowed HTTP methods, checked for missing X-Frame-Options (clickjacking), tested open redirect via manipulated parameters, and injected Host/CRLF headers to detect misrouting.",
            ))
            return
