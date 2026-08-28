import re
from scanner.core import Finding, Severity, ScanSession

SQL_PATTERNS = [
    ("String concatenation in SELECT", r"""(?i)(['"]SELECT\s.+?['"])\s*\+"""),
    ("String concatenation in INSERT", r"""(?i)(['"]INSERT\s.+?['"])\s*\+"""),
    ("String concatenation in UPDATE", r"""(?i)(['"]UPDATE\s.+?['"])\s*\+"""),
    ("String concatenation in DELETE", r"""(?i)(['"]DELETE\s.+?['"])\s*\+"""),
    ("f-string in SELECT", r"""(?i)f['"]SELECT\s.*\{"""),
    ("f-string in INSERT", r"""(?i)f['"]INSERT\s.*\{"""),
    ("f-string in UPDATE", r"""(?i)f['"]UPDATE\s.*\{"""),
    ("f-string in DELETE", r"""(?i)f['"]DELETE\s.*\{"""),
    (".format() on SQL string", r"""(?i)(['"]SELECT\s.+?['"]).format\("""),
    (".format() on SQL INSERT", r"""(?i)(['"]INSERT\s.+?['"]).format\("""),
    (".format() on SQL UPDATE", r"""(?i)(['"]UPDATE\s.+?['"]).format\("""),
    (".format() on SQL DELETE", r"""(?i)(['"]DELETE\s.+?['"]).format\("""),
    ("% formatting in SQL", r"""(?i)(['"]SELECT\s.+?['"])\s*%\s*\("""),
]


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
            if s.startswith("#") or s.startswith("//") or s.startswith("--"):
                continue

            for desc, pattern in SQL_PATTERNS:
                if not re.search(pattern, line):
                    continue
                snip = s[:80] + "..." if len(s) > 80 else s
                _sast_finding(
                    session, "Potential SQL Injection: {}".format(desc), Severity.HIGH,
                    "Dynamic SQL via {} allows query manipulation.".format(desc.lower()),
                    fpath, line_idx + 1, snip,
                    "1. Use parameterized queries / prepared statements.\n"
                    "2. Use an ORM instead of raw SQL.\n"
                    "3. Use query placeholders (?, %s) with bound parameters.\n"
                    "4. Validate and sanitize all user input.",
                    "sast_sql_injection", "CWE-89",
                    "Replace string interpolation in SQL with parameterized queries. "
                    "E.g. cursor.execute(\"SELECT * FROM users WHERE id=?\", (uid,))",
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                )
