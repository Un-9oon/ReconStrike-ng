from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "description": "HTTP Strict Transport Security (HSTS) header is missing. This allows downgrade attacks and cookie hijacking.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        "cwe": "CWE-319",
        "dev_fix": "Web Server Config",
        "dev_detail": (
            "Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
            "Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
            "Express.js: app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }))"
        ),
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, leading to XSS via content type confusion.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
        "cwe": "CWE-16",
        "dev_fix": "Web Server Config",
        "dev_detail": (
            "Apache: Header always set X-Content-Type-Options \"nosniff\"\n"
            "Nginx: add_header X-Content-Type-Options \"nosniff\" always;\n"
            "Express.js: app.use(helmet.noSniff())"
        ),
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options header is missing. The site may be vulnerable to clickjacking attacks.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
        "cwe": "CWE-1021",
        "dev_fix": "Web Server Config",
        "dev_detail": (
            "Apache: Header always set X-Frame-Options \"DENY\"\n"
            "Nginx: add_header X-Frame-Options \"DENY\" always;\n"
            "Express.js: app.use(helmet.frameguard({ action: 'deny' }))\n"
            "Or use CSP: Content-Security-Policy: frame-ancestors 'none'"
        ),
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "Content-Security-Policy header is missing. This increases the impact of XSS vulnerabilities.",
        "remediation": "Implement a strict Content-Security-Policy header.",
        "cwe": "CWE-16",
        "dev_fix": "Web Server Config / Application Code",
        "dev_detail": (
            "Start restrictive and loosen as needed:\n"
            "  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;\n"
            "Use nonce-based approach for inline scripts:\n"
            "  Content-Security-Policy: script-src 'nonce-{random}'\n"
            "  <script nonce=\"{random}\">...</script>"
        ),
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy header is missing. Sensitive URL paths and query params may leak via Referer header.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
        "cwe": "CWE-16",
        "dev_fix": "Web Server Config",
        "dev_detail": (
            "Apache: Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
            "Nginx: add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
            "HTML meta: <meta name=\"referrer\" content=\"strict-origin-when-cross-origin\">"
        ),
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy header is missing. Browser features like camera, microphone, geolocation are not restricted.",
        "remediation": "Add a Permissions-Policy header restricting unnecessary browser features.",
        "cwe": "CWE-16",
        "dev_fix": "Web Server Config",
        "dev_detail": (
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()\n"
            "Adjust based on your application's actual feature requirements."
        ),
    },
}

DANGEROUS_HEADERS = {
    "X-Powered-By": "Technology stack disclosed",
    "X-AspNet-Version": "ASP.NET version disclosed",
    "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
}

SESSION_COOKIE_NAMES = {
    "sessionid", "session_id", "phpsessid", "jsessionid", "asp.net_sessionid",
    "connect.sid", "laravel_session", "ci_session", "cakephp", "_session",
    "sid", "sess", "token", "auth", "jwt",
}

_DETECTION = (
    "Inspected HTTP response headers for missing or misconfigured security headers "
    "by comparing against OWASP recommended values."
)


def _is_session_cookie(cookie):
    name_lower = cookie.name.lower()
    return any(s in name_lower for s in SESSION_COOKIE_NAMES) or len(cookie.value) >= 20


def run(session: ScanSession) -> None:
    logger.info("\n[*] Checking security headers...")
    resp = session.get(session.config.target)
    if not resp:
        return

    headers = resp.headers
    all_headers_str = "\n".join("  {}: {}".format(k, v) for k, v in headers.items())
    curl_cmd = "curl -kI '{}'".format(session.config.target)
    present = {k.lower() for k in headers}

    for header_name, info in SECURITY_HEADERS.items():
        if header_name.lower() in present:
            continue
        session.add_finding(Finding(
            title="Missing Security Header: {}".format(header_name),
            severity=info["severity"],
            description=info["description"],
            evidence="Response headers do not contain '{}'\n\nAll response headers:\n{}".format(
                header_name, all_headers_str),
            remediation=info["remediation"],
            url=session.config.target,
            module="headers",
            cwe=info["cwe"],
            confirmed=True,
            location="HTTP response headers from {}".format(session.config.target),
            request_method="GET",
            response_status=resp.status_code,
            response_headers=all_headers_str,
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Send an HTTP request to {}\n"
                "2. Inspect the response headers.\n"
                "3. The '{}' header is absent from the response.\n"
                "4. Run: {}"
            ).format(session.config.target, header_name, curl_cmd),
            developer_fix="Component: {}\n\n{}".format(info['dev_fix'], info['dev_detail']),
            affected_component=info["dev_fix"],
            references="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{}".format(header_name),
            detection_method=_DETECTION,
        ))

    csp = headers.get("Content-Security-Policy", "")
    if csp:
        for directive, desc, fix in [
            ("unsafe-inline",
             "Content-Security-Policy contains 'unsafe-inline' which weakens XSS protection by allowing inline script execution.",
             "Replace 'unsafe-inline' with nonce-based CSP:\n"
             "1. Generate a random nonce per request.\n"
             "2. Set header: Content-Security-Policy: script-src 'nonce-{random}'\n"
             "3. Add nonce attribute to all inline scripts: <script nonce=\"{random}\">"),
            ("unsafe-eval",
             "Content-Security-Policy contains 'unsafe-eval' which allows JavaScript eval() and similar dynamic code execution.",
             "Remove 'unsafe-eval' from your CSP directive. Refactor JavaScript to avoid eval(), "
             "new Function(), and setTimeout/setInterval with string arguments."),
        ]:
            if directive in csp:
                session.add_finding(Finding(
                    title="CSP Allows {}".format(directive),
                    severity=Severity.MEDIUM,
                    description=desc,
                    evidence="CSP Header Value: {}".format(csp),
                    remediation="Remove '{}' and use safer alternatives.".format(directive),
                    url=session.config.target,
                    module="headers",
                    cwe="CWE-16",
                    confirmed=True,
                    location="Content-Security-Policy response header",
                    curl_command=curl_cmd,
                    developer_fix=fix,
                    detection_method=_DETECTION,
                ))

    for header_name, desc in DANGEROUS_HEADERS.items():
        value = headers.get(header_name, "")
        if not value:
            continue
        session.add_finding(Finding(
            title="Information Disclosure: {}".format(desc),
            severity=Severity.LOW,
            description="The '{}' header reveals server information. Attackers use this to identify known vulnerabilities in specific software versions.".format(header_name),
            evidence="{}: {}\n\nFull response headers:\n{}".format(header_name, value, all_headers_str),
            remediation="Remove or suppress the '{}' header in production.".format(header_name),
            url=session.config.target,
            module="headers",
            cwe="CWE-200",
            confirmed=True,
            location="HTTP response header '{}'".format(header_name),
            curl_command=curl_cmd,
            response_headers="{}: {}".format(header_name, value),
            developer_fix=(
                "Apache: Header unset {h}\n"
                "Nginx: proxy_hide_header {h};\n"
                "PHP: header_remove('{h}'); in php.ini set expose_php = Off\n"
                "Express.js: app.disable('x-powered-by') or use helmet()"
            ).format(h=header_name),
            affected_component="Web server / application configuration",
            detection_method=_DETECTION,
        ))

    for cookie in resp.cookies:
        if not _is_session_cookie(cookie):
            continue

        cookie_detail = (
            "Cookie Name: {}\nCookie Domain: {}\nCookie Path: {}\nValue (truncated): {}..."
        ).format(cookie.name, cookie.domain or 'not set', cookie.path or '/', cookie.value[:20])

        cookie_checks = []
        if session.config.target.startswith("https") and not cookie.secure:
            cookie_checks.append((
                "Cookie Missing Secure Flag: {}".format(cookie.name),
                Severity.MEDIUM,
                "Session cookie '{}' is not marked Secure. It will be transmitted over unencrypted HTTP, exposing it to network sniffing.".format(cookie.name),
                "Add the Secure flag to all session cookies.",
                "CWE-614",
                "Add Secure flag when setting '{c}':\n"
                "PHP: session.cookie_secure = 1\n"
                "Express: res.cookie('{c}', value, {{ secure: true }})\n"
                "Django: SESSION_COOKIE_SECURE = True".format(c=cookie.name),
            ))

        if not cookie.has_nonstandard_attr("HttpOnly"):
            cookie_checks.append((
                "Cookie Missing HttpOnly Flag: {}".format(cookie.name),
                Severity.MEDIUM,
                "Session cookie '{}' is not marked HttpOnly. JavaScript can access this cookie, making it vulnerable to XSS-based session theft.".format(cookie.name),
                "Add the HttpOnly flag to session cookies.",
                "CWE-1004",
                "Add HttpOnly flag when setting '{c}':\n"
                "PHP: session.cookie_httponly = 1\n"
                "Express: res.cookie('{c}', value, {{ httpOnly: true }})\n"
                "Django: SESSION_COOKIE_HTTPONLY = True".format(c=cookie.name),
            ))

        if not cookie.has_nonstandard_attr("SameSite"):
            cookie_checks.append((
                "Cookie Missing SameSite Attribute: {}".format(cookie.name),
                Severity.LOW,
                "Session cookie '{}' lacks the SameSite attribute, making it susceptible to CSRF attacks.".format(cookie.name),
                "Add 'SameSite=Strict' or 'SameSite=Lax' to cookies.",
                "CWE-1275",
                "Add SameSite attribute when setting '{c}':\n"
                "PHP: session.cookie_samesite = \"Strict\"\n"
                "Express: res.cookie('{c}', value, {{ sameSite: 'strict' }})\n"
                "Django: SESSION_COOKIE_SAMESITE = 'Strict'".format(c=cookie.name),
            ))

        for title, severity, desc, remed, cwe, dev_fix in cookie_checks:
            session.add_finding(Finding(
                title=title,
                severity=severity,
                description=desc,
                evidence=cookie_detail,
                remediation=remed,
                url=session.config.target,
                module="headers",
                cwe=cwe,
                confirmed=True,
                location="Set-Cookie response header for '{}'".format(cookie.name),
                developer_fix=dev_fix,
                detection_method=_DETECTION,
            ))
