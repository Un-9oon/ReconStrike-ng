import re
from dataclasses import dataclass

from scanner.core import Severity
from scanner.log import logger
from scanner.proxy.history import HttpTransaction


@dataclass
class PassiveFinding:
    title: str
    severity: Severity
    description: str
    evidence: str
    url: str
    category: str
    cwe: str = ""
    remediation: str = ""


REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "HSTS header missing -- browser does not enforce HTTPS connections.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cwe": "CWE-319",
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "CSP header missing -- no protection against XSS and data injection attacks.",
        "remediation": "Add a Content-Security-Policy header that restricts script and resource sources.",
        "cwe": "CWE-693",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": "X-Content-Type-Options header missing -- browser may MIME-sniff responses.",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "cwe": "CWE-693",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options header missing -- page can be embedded in iframes (clickjacking risk).",
        "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
        "cwe": "CWE-1021",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy header missing -- full URL may leak in referer headers.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-200",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy header missing -- no restrictions on browser features.",
        "remediation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "cwe": "CWE-693",
    },
    "X-XSS-Protection": {
        "severity": Severity.INFO,
        "description": "X-XSS-Protection header not set (deprecated but still checked by some browsers).",
        "remediation": "Add header: X-XSS-Protection: 0 (CSP is the modern replacement).",
        "cwe": "CWE-79",
    },
}

SENSITIVE_PATTERNS = [
    (r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "API Key", Severity.HIGH),
    (r"(?:secret[_-]?key|secretkey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "Secret Key", Severity.CRITICAL),
    (r"(?:access[_-]?token|accesstoken)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})", "Access Token", Severity.HIGH),
    (r"(?:bearer\s+)([a-zA-Z0-9_\-\.]+)", "Bearer Token", Severity.HIGH),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity.CRITICAL),
    (r"(?:aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})", "AWS Secret Key", Severity.CRITICAL),
    (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "Private Key", Severity.CRITICAL),
    (r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{4,})", "Password", Severity.HIGH),
    (r"(?:mongodb|mysql|postgresql|redis)://[^\s'\"]+", "Database Connection String", Severity.CRITICAL),
    (r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", "Internal IP Address", Severity.LOW),
    (r"\b(172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b", "Internal IP Address", Severity.LOW),
    (r"\b(192\.168\.\d{1,3}\.\d{1,3})\b", "Internal IP Address", Severity.LOW),
    (r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b", "Email Address", Severity.INFO),
    (r"\b\d{3}-\d{2}-\d{4}\b", "Potential SSN", Severity.HIGH),
    (r"\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13})\b", "Potential Credit Card Number", Severity.HIGH),
]

ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python Stack Trace", Severity.MEDIUM),
    (r"at\s+\S+\.java:\d+\)", "Java Stack Trace", Severity.MEDIUM),
    (r"System\.(\w+Exception|NullReferenceException)", ".NET Exception", Severity.MEDIUM),
    (r"(?:Fatal error|Parse error|Warning):\s+.*?\s+in\s+\S+\.php\s+on line\s+\d+",
     "PHP Error", Severity.MEDIUM),
    (r"(?:TypeError|ReferenceError|SyntaxError):\s+", "JavaScript Error", Severity.LOW),
    (r"SQLSTATE\[\w+\]", "SQL Error (possible injection)", Severity.HIGH),
    (r"(?:mysql_|pg_|sqlite_|ora-).*?error", "Database Error Disclosure", Severity.MEDIUM),
    (r"(?:debug|DEBUG)\s*[:=]\s*(?:true|True|1)", "Debug Mode Enabled", Severity.MEDIUM),
]


def analyze_transaction(txn: HttpTransaction) -> list[PassiveFinding]:
    findings = []
    is_html = "text/html" in txn.content_type
    is_json = "application/json" in txn.content_type
    is_text = is_html or is_json or "text/" in txn.content_type

    # Missing security headers (HTML 200s only)
    if is_html and txn.status_code == 200:
        resp_lower = {k.lower() for k in txn.response_headers}
        for header_name, info in REQUIRED_SECURITY_HEADERS.items():
            if header_name.lower() not in resp_lower:
                findings.append(PassiveFinding(
                    title="Missing Security Header: {}".format(header_name),
                    severity=info["severity"], description=info["description"],
                    evidence="Response to {} {} does not include {}".format(txn.method, txn.url, header_name),
                    url=txn.url, category="missing_header",
                    cwe=info["cwe"], remediation=info["remediation"],
                ))

    # Insecure cookies
    for hdr_name, hdr_val in txn.response_headers.items():
        if hdr_name.lower() != "set-cookie":
            continue
        cookie_name = hdr_val.split("=")[0].strip() if "=" in hdr_val else ""
        lower_cookie = hdr_val.lower()

        checks = []
        if "; secure" not in lower_cookie and txn.url.startswith("https"):
            checks.append(("Cookie Without Secure Flag: {}".format(cookie_name), Severity.MEDIUM,
                           "Cookie set without Secure flag on HTTPS. May be sent over HTTP.",
                           "CWE-614", "Add the Secure flag to the Set-Cookie header."))
        if "; httponly" not in lower_cookie:
            checks.append(("Cookie Without HttpOnly Flag: {}".format(cookie_name), Severity.LOW,
                           "Cookie accessible via JavaScript. XSS can steal it.",
                           "CWE-1004", "Add the HttpOnly flag to the Set-Cookie header."))
        if "samesite" not in lower_cookie:
            checks.append(("Cookie Without SameSite Attribute: {}".format(cookie_name), Severity.LOW,
                           "Cookie missing SameSite attribute, potentially vulnerable to CSRF.",
                           "CWE-352", "Add SameSite=Lax or SameSite=Strict to the Set-Cookie header."))

        for title, sev, desc, cwe, rem in checks:
            findings.append(PassiveFinding(
                title=title, severity=sev, description=desc,
                evidence="Set-Cookie: {}".format(hdr_val[:200]),
                url=txn.url, category="insecure_cookie", cwe=cwe, remediation=rem,
            ))

    # Sensitive data in response body
    if is_text and txn.response_body:
        body = txn.response_body[:50000]
        for pattern, data_type, severity in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                unique = list(set(matches[:5]))
                masked = [m[:4] + "****" + m[-2:] if len(m) > 6 else "****"
                          for m in unique if isinstance(m, str)]
                findings.append(PassiveFinding(
                    title="Sensitive Data in Response: {}".format(data_type),
                    severity=severity,
                    description="{} detected in response body. Found {} instance(s).".format(data_type, len(matches)),
                    evidence="Matches (masked): {}".format(", ".join(masked)),
                    url=txn.url, category="data_leakage", cwe="CWE-200",
                    remediation="Remove or mask {} values from API responses.".format(data_type),
                ))

    # Error disclosure
    if is_text and txn.response_body:
        body = txn.response_body[:50000]
        for pattern, error_type, severity in ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(PassiveFinding(
                    title="Information Disclosure: {}".format(error_type),
                    severity=severity,
                    description="{} detected in response. Reveals internal application details.".format(error_type),
                    evidence="Pattern matched in response body at {}".format(txn.url),
                    url=txn.url, category="info_disclosure", cwe="CWE-209",
                    remediation="Show generic error pages in production. Log details server-side only.",
                ))

    # CORS wildcard
    acao = txn.response_headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        acac = txn.response_headers.get("Access-Control-Allow-Credentials", "").lower()
        sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
        desc = "ACAO is *, allowing any website to make cross-origin requests."
        if acac == "true":
            desc += " Combined with Allow-Credentials: true, this is critical."
        findings.append(PassiveFinding(
            title="CORS Wildcard Origin", severity=sev, description=desc,
            evidence="Access-Control-Allow-Origin: *", url=txn.url,
            category="cors", cwe="CWE-942",
            remediation="Restrict CORS to specific trusted origins. Never use * with credentials.",
        ))

    # Server version disclosure
    server_header = txn.response_headers.get("Server", "")
    if server_header and re.search(r"[\d.]+", server_header):
        findings.append(PassiveFinding(
            title="Server Version Disclosure", severity=Severity.LOW,
            description="Server header reveals version: {}".format(server_header),
            evidence="Server: {}".format(server_header), url=txn.url,
            category="version_disclosure", cwe="CWE-200",
            remediation="Remove or anonymize the Server header.",
        ))

    powered_by = txn.response_headers.get("X-Powered-By", "")
    if powered_by:
        findings.append(PassiveFinding(
            title="Technology Disclosure: X-Powered-By: {}".format(powered_by),
            severity=Severity.LOW,
            description="X-Powered-By header reveals backend technology: {}".format(powered_by),
            evidence="X-Powered-By: {}".format(powered_by), url=txn.url,
            category="version_disclosure", cwe="CWE-200",
            remediation="Remove the X-Powered-By header from responses.",
        ))

    # JWT in URL
    if re.search(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.", txn.url):
        findings.append(PassiveFinding(
            title="JWT Token in URL", severity=Severity.HIGH,
            description="JWT in URL gets logged by servers, proxies, and browser history.",
            evidence="URL contains JWT: {}".format(txn.url[:200]), url=txn.url,
            category="token_leakage", cwe="CWE-598",
            remediation="Send JWT tokens in the Authorization header instead of the URL.",
        ))

    return findings
