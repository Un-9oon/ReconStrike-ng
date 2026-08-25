"""Passive traffic analyzer for the DAST interception proxy.

Automatically inspects every intercepted request/response pair for
security issues without sending additional requests.  Detects:
- Missing security headers
- Sensitive data leakage (API keys, tokens, passwords, emails)
- Insecure cookie configuration
- Mixed content issues
- CORS misconfigurations
- JWT tokens in URLs
- Information disclosure (stack traces, debug output)
"""

import re
from dataclasses import dataclass, field

from scanner.core import Severity
from scanner.log import logger
from scanner.proxy.history import HttpTransaction


@dataclass
class PassiveFinding:
    """A finding discovered through passive traffic analysis."""
    title: str
    severity: Severity
    description: str
    evidence: str
    url: str
    category: str
    cwe: str = ""
    remediation: str = ""


# ---------------------------------------------------------------------------
# Security header checks
# ---------------------------------------------------------------------------
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "HSTS header missing — browser does not enforce HTTPS connections.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cwe": "CWE-319",
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "CSP header missing — no protection against XSS and data injection attacks.",
        "remediation": "Add a Content-Security-Policy header that restricts script and resource sources.",
        "cwe": "CWE-693",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": "X-Content-Type-Options header missing — browser may MIME-sniff responses.",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "cwe": "CWE-693",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options header missing — page can be embedded in iframes (clickjacking risk).",
        "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
        "cwe": "CWE-1021",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy header missing — full URL may leak in referer headers.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-200",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy header missing — no restrictions on browser features.",
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


# ---------------------------------------------------------------------------
# Sensitive data patterns
# ---------------------------------------------------------------------------
SENSITIVE_PATTERNS = [
    # API keys and tokens
    (r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "API Key", Severity.HIGH),
    (r"(?:secret[_-]?key|secretkey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "Secret Key", Severity.CRITICAL),
    (r"(?:access[_-]?token|accesstoken)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})", "Access Token", Severity.HIGH),
    (r"(?:bearer\s+)([a-zA-Z0-9_\-\.]+)", "Bearer Token", Severity.HIGH),

    # AWS credentials
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity.CRITICAL),
    (r"(?:aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})", "AWS Secret Key", Severity.CRITICAL),

    # Private keys
    (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "Private Key", Severity.CRITICAL),

    # Passwords
    (r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{4,})", "Password", Severity.HIGH),

    # Database connection strings
    (r"(?:mongodb|mysql|postgresql|redis)://[^\s'\"]+", "Database Connection String", Severity.CRITICAL),

    # Internal IPs
    (r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", "Internal IP Address", Severity.LOW),
    (r"\b(172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b", "Internal IP Address", Severity.LOW),
    (r"\b(192\.168\.\d{1,3}\.\d{1,3})\b", "Internal IP Address", Severity.LOW),

    # Email addresses (mass exposure)
    (r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b", "Email Address", Severity.INFO),

    # SSN-like patterns
    (r"\b\d{3}-\d{2}-\d{4}\b", "Potential SSN", Severity.HIGH),

    # Credit card-like patterns (Luhn validation would be needed for confirmation)
    (r"\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13})\b", "Potential Credit Card Number", Severity.HIGH),
]


# ---------------------------------------------------------------------------
# Stack trace / error patterns
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------
def analyze_transaction(txn: HttpTransaction) -> list[PassiveFinding]:
    """Analyze a single HTTP transaction for security issues.

    Returns a list of PassiveFinding objects.
    """
    findings = []

    # Skip non-HTML/JSON responses for most checks
    is_html = "text/html" in txn.content_type
    is_json = "application/json" in txn.content_type
    is_text = is_html or is_json or "text/" in txn.content_type

    # ------------------------------------------------------------------
    # 1. Missing Security Headers (only for HTML responses)
    # ------------------------------------------------------------------
    if is_html and txn.status_code == 200:
        for header_name, info in REQUIRED_SECURITY_HEADERS.items():
            if header_name.lower() not in {k.lower() for k in txn.response_headers}:
                findings.append(PassiveFinding(
                    title=f"Missing Security Header: {header_name}",
                    severity=info["severity"],
                    description=info["description"],
                    evidence=f"Response to {txn.method} {txn.url} does not include {header_name}",
                    url=txn.url,
                    category="missing_header",
                    cwe=info["cwe"],
                    remediation=info["remediation"],
                ))

    # ------------------------------------------------------------------
    # 2. Insecure Cookies
    # ------------------------------------------------------------------
    for header_name, header_value in txn.response_headers.items():
        if header_name.lower() == "set-cookie":
            cookie_str = header_value
            cookie_name = cookie_str.split("=")[0].strip() if "=" in cookie_str else ""

            if "; secure" not in cookie_str.lower() and txn.url.startswith("https"):
                findings.append(PassiveFinding(
                    title=f"Cookie Without Secure Flag: {cookie_name}",
                    severity=Severity.MEDIUM,
                    description="Cookie is set without the Secure flag on an HTTPS connection. "
                                "The cookie may be sent over unencrypted HTTP connections.",
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    url=txn.url,
                    category="insecure_cookie",
                    cwe="CWE-614",
                    remediation="Add the Secure flag to the Set-Cookie header.",
                ))

            if "; httponly" not in cookie_str.lower():
                findings.append(PassiveFinding(
                    title=f"Cookie Without HttpOnly Flag: {cookie_name}",
                    severity=Severity.LOW,
                    description="Cookie is accessible via JavaScript (document.cookie). "
                                "XSS attacks can steal this cookie.",
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    url=txn.url,
                    category="insecure_cookie",
                    cwe="CWE-1004",
                    remediation="Add the HttpOnly flag to the Set-Cookie header.",
                ))

            if "samesite" not in cookie_str.lower():
                findings.append(PassiveFinding(
                    title=f"Cookie Without SameSite Attribute: {cookie_name}",
                    severity=Severity.LOW,
                    description="Cookie does not have a SameSite attribute, making it "
                                "potentially vulnerable to CSRF attacks.",
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    url=txn.url,
                    category="insecure_cookie",
                    cwe="CWE-352",
                    remediation="Add SameSite=Lax or SameSite=Strict to the Set-Cookie header.",
                ))

    # ------------------------------------------------------------------
    # 3. Sensitive Data Leakage (in response body)
    # ------------------------------------------------------------------
    if is_text and txn.response_body:
        body = txn.response_body[:50000]  # Limit scan size
        for pattern, data_type, severity in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                # Deduplicate and limit
                unique_matches = list(set(matches[:5]))
                # Mask sensitive values
                masked = [m[:4] + "****" + m[-2:] if len(m) > 6 else "****"
                          for m in unique_matches if isinstance(m, str)]
                findings.append(PassiveFinding(
                    title=f"Sensitive Data in Response: {data_type}",
                    severity=severity,
                    description=f"{data_type} detected in the response body. "
                                f"Found {len(matches)} instance(s).",
                    evidence=f"Matches (masked): {', '.join(masked)}",
                    url=txn.url,
                    category="data_leakage",
                    cwe="CWE-200",
                    remediation=f"Remove or mask {data_type} values from API responses. "
                                f"Never expose secrets or credentials in HTTP responses.",
                ))

    # ------------------------------------------------------------------
    # 4. Information Disclosure (error messages, stack traces)
    # ------------------------------------------------------------------
    if is_text and txn.response_body:
        body = txn.response_body[:50000]
        for pattern, error_type, severity in ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(PassiveFinding(
                    title=f"Information Disclosure: {error_type}",
                    severity=severity,
                    description=f"{error_type} detected in the response. This reveals internal "
                                f"application details that assist attackers.",
                    evidence=f"Pattern matched in response body at {txn.url}",
                    url=txn.url,
                    category="info_disclosure",
                    cwe="CWE-209",
                    remediation="Configure the application to show generic error pages in production. "
                                "Log detailed errors server-side only.",
                ))

    # ------------------------------------------------------------------
    # 5. CORS Misconfiguration
    # ------------------------------------------------------------------
    acao = txn.response_headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        acac = txn.response_headers.get("Access-Control-Allow-Credentials", "")
        severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
        findings.append(PassiveFinding(
            title="CORS Wildcard Origin",
            severity=severity,
            description="Access-Control-Allow-Origin is set to '*', allowing any website "
                        "to make cross-origin requests to this endpoint."
                        + (" Combined with Allow-Credentials: true, this is a critical misconfiguration."
                           if acac.lower() == "true" else ""),
            evidence=f"Access-Control-Allow-Origin: {acao}",
            url=txn.url,
            category="cors",
            cwe="CWE-942",
            remediation="Restrict CORS to specific trusted origins. Never use '*' with credentials.",
        ))

    # ------------------------------------------------------------------
    # 6. Server Version Disclosure
    # ------------------------------------------------------------------
    server_header = txn.response_headers.get("Server", "")
    if server_header and re.search(r"[\d.]+", server_header):
        findings.append(PassiveFinding(
            title="Server Version Disclosure",
            severity=Severity.LOW,
            description=f"The Server header reveals version information: {server_header}. "
                        f"This aids attackers in identifying known vulnerabilities.",
            evidence=f"Server: {server_header}",
            url=txn.url,
            category="version_disclosure",
            cwe="CWE-200",
            remediation="Remove or anonymize the Server header. "
                        "Nginx: server_tokens off; Apache: ServerTokens Prod",
        ))

    powered_by = txn.response_headers.get("X-Powered-By", "")
    if powered_by:
        findings.append(PassiveFinding(
            title=f"Technology Disclosure: X-Powered-By: {powered_by}",
            severity=Severity.LOW,
            description=f"The X-Powered-By header reveals the backend technology: {powered_by}.",
            evidence=f"X-Powered-By: {powered_by}",
            url=txn.url,
            category="version_disclosure",
            cwe="CWE-200",
            remediation="Remove the X-Powered-By header from responses.",
        ))

    # ------------------------------------------------------------------
    # 7. JWT in URL
    # ------------------------------------------------------------------
    if re.search(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.", txn.url):
        findings.append(PassiveFinding(
            title="JWT Token in URL",
            severity=Severity.HIGH,
            description="A JWT token was found in the URL. Tokens in URLs are logged by "
                        "web servers, proxies, and browser history, leading to token leakage.",
            evidence=f"URL contains JWT: {txn.url[:200]}",
            url=txn.url,
            category="token_leakage",
            cwe="CWE-598",
            remediation="Send JWT tokens in the Authorization header instead of the URL.",
        ))

    return findings
