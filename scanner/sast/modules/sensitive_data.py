import re
from scanner.core import Finding, Severity, ScanSession

SENSITIVE_PATTERNS = [
    ("Logging password data", r"(?i)\b(?:log|logger|logging)\b.*password", Severity.MEDIUM, "CWE-532"),
    ("Printing password data", r"(?i)\bprint\s*\(.*password", Severity.MEDIUM, "CWE-532"),
    ("Logging secret/token", r"(?i)\b(?:log|logger|logging)\b.*(?:secret|token|api_key)", Severity.MEDIUM, "CWE-532"),
    ("SSL verification disabled (verify=False)", r"\bverify\s*=\s*False\b", Severity.HIGH, "CWE-295"),
    ("SSL CERT_NONE", r"\bCERT_NONE\b", Severity.HIGH, "CWE-295"),
    ("SSL hostname check disabled", r"\bcheck_hostname\s*=\s*False\b", Severity.HIGH, "CWE-295"),
    ("DEBUG mode enabled", r"(?m)^\s*DEBUG\s*=\s*True\b", Severity.MEDIUM, "CWE-489"),
    ("debug flag enabled", r"(?m)^\s*debug\s*=\s*True\b", Severity.MEDIUM, "CWE-489"),
    ("CORS wildcard origin", r"""(?i)Access-Control-Allow-Origin.*\*""", Severity.MEDIUM, "CWE-942"),
    ("CORS wildcard (framework)", r"""(?i)CORS\(.*origins\s*=\s*['"]\*""", Severity.MEDIUM, "CWE-942"),
]


def run(session: ScanSession, files_to_scan: list[str]) -> None:
    from scanner.sast.sast_engine import _scan_lines
    _scan_lines(
        session, files_to_scan, SENSITIVE_PATTERNS,
        module="sast_sensitive_data",
        severity_col=2, cwe_col=3,
        remediation=(
            "1. Never log sensitive data (passwords, tokens, secrets).\n"
            "2. Always verify SSL certificates in production (verify=True).\n"
            "3. Ensure DEBUG is False in production.\n"
            "4. Configure CORS with specific allowed origins, not wildcards."
        ),
        dev_fix="Review and remove logging of sensitive values. Enable SSL verification. "
                "Disable debug mode for production. Use explicit CORS origins.",
        refs="https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
    )
