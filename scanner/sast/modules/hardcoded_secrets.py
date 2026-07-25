import re
from scanner.core import Finding, Severity, ScanSession

# Simple pattern list for demonstration
SECRET_PATTERNS = {
    "AWS Access Key ID": r"(?i)AKIA[0-9A-Z]{16}",
    "Generic Private Key": r"-----BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----",
    "Stripe Standard API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Generic Password/Secret assignment": r"(?i)(password|secret|api_key|token)\s*=\s*['\"]([^'\"]{5,})['\"]"
}

def run(session: ScanSession, files_to_scan: list[str]) -> None:
    for file_path in files_to_scan:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()

            for line_idx, line in enumerate(lines):
                for name, pattern in SECRET_PATTERNS.items():
                    match = re.search(pattern, line)
                    if match:
                        snippet = line.strip()
                        if len(snippet) > 80:
                            snippet = snippet[:80] + "..."
                            
                        # Adding finding to session
                        session.add_finding(Finding(
                            title=f"Hardcoded Secret Detected ({name})",
                            severity=Severity.HIGH if "Generic Password" not in name else Severity.MEDIUM,
                            description=(
                                f"A hardcoded secret matching the pattern for '{name}' was found in the source code. "
                                f"Hardcoded credentials can lead to unauthorized access and should be stored securely."
                            ),
                            evidence=(
                                f"File: {file_path}\n"
                                f"Line: {line_idx + 1}\n"
                                f"Snippet: {snippet}"
                            ),
                            remediation=(
                                "1. Remove the secret from the source code repository immediately.\n"
                                "2. Rotate/revoke the compromised secret.\n"
                                "3. Store secrets in environment variables, a secure vault, or AWS Secrets Manager/Azure Key Vault."
                            ),
                            url="local://sast",
                            module="sast_secrets",
                            cwe="CWE-798",
                            confirmed=True,
                            location=f"{file_path}:{line_idx + 1}",
                            parameter=name,
                            payload="",
                            request_method="SAST",
                            response_status=0,
                            curl_command="",
                            reproduction_steps=f"Inspect line {line_idx + 1} of {file_path}",
                            developer_fix=(
                                f"Use environment variables or a configuration provider to inject the value at runtime. "
                                f"For example, in Python: `os.environ.get('SECRET_KEY')` instead of `SECRET_KEY = 'val'`"
                            ),
                            affected_component=f"File: {file_path}",
                            references="https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                            detection_method="SAST regex pattern matching on source files.",
                        ))
        except Exception as e:
            # Skip unreadable files
            pass
