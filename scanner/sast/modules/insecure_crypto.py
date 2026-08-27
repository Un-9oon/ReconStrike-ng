import re
from scanner.core import Finding, Severity, ScanSession

CRYPTO_PATTERNS = [
    # MD5 usage
    ("MD5 hash usage", r"\bmd5\(", Severity.MEDIUM, "CWE-328"),
    ("hashlib.md5() usage", r"\bhashlib\.md5\(", Severity.MEDIUM, "CWE-328"),
    # SHA1 usage
    ("SHA1 hash usage", r"\bSHA1\b", Severity.MEDIUM, "CWE-328"),
    ("hashlib.sha1() usage", r"\bhashlib\.sha1\(", Severity.MEDIUM, "CWE-328"),
    # ECB mode
    ("AES ECB mode", r"\bMODE_ECB\b", Severity.HIGH, "CWE-327"),
    ("AES ECB mode (explicit)", r"\bAES\.new\(.*ECB", Severity.HIGH, "CWE-327"),
    # DES usage
    ("DES encryption (weak)", r"\bDES\.new\(", Severity.HIGH, "CWE-327"),
    ("Triple DES encryption", r"\bDES3\.new\(", Severity.MEDIUM, "CWE-327"),
    # Weak random
    ("random.random() for security", r"\brandom\.random\(\)", Severity.MEDIUM, "CWE-338"),
    ("Math.random() for security", r"\bMath\.random\(\)", Severity.MEDIUM, "CWE-338"),
    # Hardcoded IV
    ("Hardcoded initialization vector", r"""\biv\s*=\s*b['"]""", Severity.MEDIUM, "CWE-329"),
]

# Patterns that upgrade severity to HIGH when found near password context
PASSWORD_CONTEXT = re.compile(r"(?i)(password|passwd|pwd)")


def run(session: ScanSession, files_to_scan: list[str]) -> None:
    for file_path in files_to_scan:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()

            for line_idx, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                for desc, pattern, base_severity, cwe in CRYPTO_PATTERNS:
                    if re.search(pattern, line):
                        # Upgrade severity if used in password context
                        severity = base_severity
                        if PASSWORD_CONTEXT.search(line) and "md5" in desc.lower() or "sha1" in desc.lower():
                            severity = Severity.HIGH

                        snippet = stripped
                        if len(snippet) > 80:
                            snippet = snippet[:80] + "..."

                        session.add_finding(Finding(
                            title=f"Insecure Cryptography: {desc}",
                            severity=severity,
                            description=(
                                f"Weak or insecure cryptographic usage detected: {desc}. "
                                f"Using weak algorithms or modes can allow attackers to decrypt "
                                f"data, forge signatures, or predict values."
                            ),
                            evidence=(
                                f"File: {file_path}\n"
                                f"Line: {line_idx + 1}\n"
                                f"Snippet: {snippet}"
                            ),
                            remediation=(
                                "1. Replace MD5/SHA1 with SHA-256 or better (SHA-3, BLAKE2).\n"
                                "2. For password hashing, use bcrypt, scrypt, or Argon2.\n"
                                "3. Replace ECB mode with CBC, GCM, or CTR with proper IV/nonce.\n"
                                "4. Replace DES with AES-256.\n"
                                "5. Use secrets module or os.urandom() for cryptographic randomness."
                            ),
                            url="local://sast",
                            module="sast_insecure_crypto",
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
                                "Replace the weak cryptographic primitive with a modern, "
                                "secure alternative. For hashing use SHA-256+, for passwords "
                                "use bcrypt/Argon2, for encryption use AES-GCM."
                            ),
                            affected_component=f"File: {file_path}",
                            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/",
                            detection_method="SAST regex pattern matching on source files.",
                        ))
        except Exception:
            pass
