import re
from scanner.core import Finding, Severity, ScanSession

# Patterns that detect string concatenation or interpolation in SQL statements
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
    for file_path in files_to_scan:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()

            for line_idx, line in enumerate(lines):
                stripped = line.strip()
                # Skip comment lines
                if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("--"):
                    continue

                for desc, pattern in SQL_PATTERNS:
                    if re.search(pattern, line):
                        snippet = stripped
                        if len(snippet) > 80:
                            snippet = snippet[:80] + "..."

                        session.add_finding(Finding(
                            title=f"Potential SQL Injection: {desc}",
                            severity=Severity.HIGH,
                            description=(
                                f"A potential SQL injection vulnerability was detected. "
                                f"Dynamic SQL construction via {desc.lower()} allows attackers to "
                                f"manipulate queries, potentially reading, modifying, or deleting data."
                            ),
                            evidence=(
                                f"File: {file_path}\n"
                                f"Line: {line_idx + 1}\n"
                                f"Snippet: {snippet}"
                            ),
                            remediation=(
                                "1. Use parameterized queries / prepared statements.\n"
                                "2. Use an ORM (SQLAlchemy, Django ORM, Eloquent) instead of raw SQL.\n"
                                "3. If raw SQL is required, use query placeholders (?, %s) with bound parameters.\n"
                                "4. Validate and sanitize all user input before use in queries."
                            ),
                            url="local://sast",
                            module="sast_sql_injection",
                            cwe="CWE-89",
                            confirmed=True,
                            location=f"{file_path}:{line_idx + 1}",
                            parameter=desc,
                            payload="",
                            request_method="SAST",
                            response_status=0,
                            curl_command="",
                            reproduction_steps=f"Inspect line {line_idx + 1} of {file_path}",
                            developer_fix=(
                                "Replace string concatenation/interpolation in SQL with parameterized "
                                "queries. For example, instead of f\"SELECT * FROM users WHERE id={uid}\" "
                                "use cursor.execute(\"SELECT * FROM users WHERE id=?\", (uid,))"
                            ),
                            affected_component=f"File: {file_path}",
                            references="https://owasp.org/www-community/attacks/SQL_Injection",
                            detection_method="SAST regex pattern matching on source files.",
                        ))
        except Exception:
            pass
