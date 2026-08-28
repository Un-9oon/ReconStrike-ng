import re
from scanner.core import Finding, Severity, ScanSession

CRYPTO_PATTERNS = [
    ("MD5 hash usage", r"\bmd5\(", Severity.MEDIUM, "CWE-328"),
    ("hashlib.md5() usage", r"\bhashlib\.md5\(", Severity.MEDIUM, "CWE-328"),
    ("SHA1 hash usage", r"\bSHA1\b", Severity.MEDIUM, "CWE-328"),
    ("hashlib.sha1() usage", r"\bhashlib\.sha1\(", Severity.MEDIUM, "CWE-328"),
    ("AES ECB mode", r"\bMODE_ECB\b", Severity.HIGH, "CWE-327"),
    ("AES ECB mode (explicit)", r"\bAES\.new\(.*ECB", Severity.HIGH, "CWE-327"),
    ("DES encryption (weak)", r"\bDES\.new\(", Severity.HIGH, "CWE-327"),
    ("Triple DES encryption", r"\bDES3\.new\(", Severity.MEDIUM, "CWE-327"),
    ("random.random() for security", r"\brandom\.random\(\)", Severity.MEDIUM, "CWE-338"),
    ("Math.random() for security", r"\bMath\.random\(\)", Severity.MEDIUM, "CWE-338"),
    ("Hardcoded initialization vector", r"""\biv\s*=\s*b['"]""", Severity.MEDIUM, "CWE-329"),
]

PASSWORD_CONTEXT = re.compile(r"(?i)(password|passwd|pwd)")


def run(session: ScanSession, files_to_scan: list[str]) -> None:
    from scanner.sast.sast_engine import _sast_finding

    for fpath in files_to_scan:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()
        except (OSError, UnicodeDecodeError):
            continue

        for line_idx, line in enumerate(lines):
            s = line.strip()
            if s.startswith("#") or s.startswith("//"):
                continue

            for desc, pattern, base_sev, cwe in CRYPTO_PATTERNS:
                if not re.search(pattern, line):
                    continue

                sev = base_sev
                if PASSWORD_CONTEXT.search(line) and ("md5" in desc.lower() or "sha1" in desc.lower()):
                    sev = Severity.HIGH

                snip = s[:80] + "..." if len(s) > 80 else s
                _sast_finding(
                    session, "Insecure Cryptography: {}".format(desc), sev,
                    "Weak crypto usage: {}. Can allow decryption, forgery, or value prediction.".format(desc),
                    fpath, line_idx + 1, snip,
                    "1. Replace MD5/SHA1 with SHA-256+ (SHA-3, BLAKE2).\n"
                    "2. For passwords, use bcrypt, scrypt, or Argon2.\n"
                    "3. Replace ECB mode with GCM or CTR with proper IV.\n"
                    "4. Replace DES with AES-256.\n"
                    "5. Use secrets module or os.urandom() for crypto randomness.",
                    "sast_insecure_crypto", cwe,
                    "Replace the weak primitive with a modern alternative. "
                    "Hashing: SHA-256+, passwords: bcrypt/Argon2, encryption: AES-GCM.",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/",
                )
