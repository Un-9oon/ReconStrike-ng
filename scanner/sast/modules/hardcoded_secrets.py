import re
from scanner.core import Finding, Severity, ScanSession

SECRET_PATTERNS = {
    "AWS Access Key ID": r"(?i)AKIA[0-9A-Z]{16}",
    "Generic Private Key": r"-----BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----",
    "Stripe Standard API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Generic Password/Secret assignment": r"(?i)(password|secret|api_key|token)\s*=\s*['\"]([^'\"]{5,})['\"]"
}


def run(session: ScanSession, files_to_scan: list[str]) -> None:
    from scanner.sast.sast_engine import _sast_finding

    for fpath in files_to_scan:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()
        except (OSError, UnicodeDecodeError):
            continue

        for line_idx, line in enumerate(lines):
            for name, pattern in SECRET_PATTERNS.items():
                if not re.search(pattern, line):
                    continue
                snip = line.strip()
                if len(snip) > 80:
                    snip = snip[:80] + "..."

                sev = Severity.MEDIUM if "Generic Password" in name else Severity.HIGH
                _sast_finding(
                    session,
                    "Hardcoded Secret Detected ({})".format(name), sev,
                    "A hardcoded secret matching '{}' was found. "
                    "Hardcoded credentials can lead to unauthorized access.".format(name),
                    fpath, line_idx + 1, snip,
                    "1. Remove the secret from source code.\n"
                    "2. Rotate/revoke the compromised secret.\n"
                    "3. Use env vars or a secrets vault instead.",
                    "sast_secrets", "CWE-798",
                    "Use environment variables or a config provider instead of hardcoded values. "
                    "E.g. os.environ.get('SECRET_KEY')",
                    "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                )
