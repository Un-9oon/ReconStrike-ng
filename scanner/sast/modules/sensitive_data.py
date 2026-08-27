import re
from scanner.core import Finding, Severity, ScanSession

SENSITIVE_PATTERNS = [
    # Logging sensitive data
    ("Logging password data", r"(?i)\b(?:log|logger|logging)\b.*password", Severity.MEDIUM, "CWE-532"),
    ("Printing password data", r"(?i)\bprint\s*\(.*password", Severity.MEDIUM, "CWE-532"),
    ("Logging secret/token", r"(?i)\b(?:log|logger|logging)\b.*(?:secret|token|api_key)", Severity.MEDIUM, "CWE-532"),

    # Disabled SSL verification
    ("SSL verification disabled (verify=False)", r"\bverify\s*=\s*False\b", Severity.HIGH, "CWE-295"),
    ("SSL CERT_NONE", r"\bCERT_NONE\b", Severity.HIGH, "CWE-295"),
    ("SSL hostname check disabled", r"\bcheck_hostname\s*=\s*False\b", Severity.HIGH, "CWE-295"),

    # Debug mode in production
    ("DEBUG mode enabled", r"(?m)^\s*DEBUG\s*=\s*True\b", Severity.MEDIUM, "CWE-489"),
    ("debug flag enabled", r"(?m)^\s*debug\s*=\s*True\b", Severity.MEDIUM, "CWE-489"),

    # CORS wildcard
    ("CORS wildcard origin", r"""(?i)Access-Control-Allow-Origin.*\*""", Severity.MEDIUM, "CWE-942"),
    ("CORS wildcard (framework)", r"""(?i)CORS\(.*origins\s*=\s*['"]\*""", Severity.MEDIUM, "CWE-942"),
]


def run(session: ScanSession, files_to_scan: list[str]) -> None:
    for file_path in files_to_scan:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()

            for line_idx, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                for desc, pattern, severity, cwe in SENSITIVE_PATTERNS:
                    if re.search(pattern, line):
                        snippet = stripped
                        if len(snippet) > 80:
                            snippet = snippet[:80] + "..."

                        session.add_finding(Finding(
                            title=f"Sensitive Data Exposure: {desc}",
                            severity=severity,
                            description=(
                                f"A sensitive data exposure risk was detected: {desc}. "
                                f"This can leak credentials, weaken transport security, or "
                                f"expose debug information to attackers."
                            ),
                            evidence=(
                                f"File: {file_path}\n"
                                f"Line: {line_idx + 1}\n"
                                f"Snippet: {snippet}"
                            ),
                            remediation=(
                                "1. Never log sensitive data (passwords, tokens, secrets).\n"
                                "2. Always verify SSL certificates in production (verify=True).\n"
                                "3. Ensure DEBUG is False in production deployments.\n"
                                "4. Configure CORS with specific allowed origins, not wildcards.\n"
                                "5. Use structured logging and redact sensitive fields."
                            ),
                            url="local://sast",
                            module="sast_sensitive_data",
                            cwe=cwe,
                            confirmed=True,
                            location=f"{file_path}:{line_idx + 1}",
                            parameter=desc,
                            payload="",
                            request_method="SAST",
                            response_status=0,
                            curl_command="",
                            reproduction_steps=f"Inspect line {line_idx + 1} of {file_path}",
                            developer_fix=(
                                "Review and remove any logging of sensitive values. "
                                "Enable SSL verification. Disable debug mode for production. "
                                "Configure CORS with explicit allowed origins."
                            ),
                            affected_component=f"File: {file_path}",
                            references="https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                            detection_method="SAST regex pattern matching on source files.",
                        ))
        except Exception:
            pass
