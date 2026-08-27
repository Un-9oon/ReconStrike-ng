import re
from scanner.core import Finding, Severity, ScanSession

PATH_TRAVERSAL_PATTERNS = [
    # open() with f-string or format containing user input
    ("open() with f-string interpolation", r"""\bopen\(\s*f['"].*\{"""),
    ("open() with .format()", r"""\bopen\(.*\.format\("""),
    ("open() with string concatenation", r"""\bopen\(\s*[a-zA-Z_]+\s*\+"""),
    # os.path.join with request/user input
    ("os.path.join with request data", r"""\bos\.path\.join\(.*request\."""),
    ("os.path.join with user param", r"""\bos\.path\.join\(.*(?:user_input|filename|file_name|filepath|path_param)"""),
    # Direct request param to file operations
    ("File read from request parameter", r"""(?:request\.(?:GET|POST|args|form|params).*(?:open|read|send_file))"""),
    ("send_file with user input", r"""\bsend_file\(.*(?:request\.|filename|user)"""),
    # PHP file operations with user input
    ("file_get_contents with variable", r"""\bfile_get_contents\(\s*\$"""),
    ("include/require with variable (PHP)", r"""\b(?:include|require)(?:_once)?\s*\(\s*\$"""),
    # Node.js fs operations
    ("fs.readFile with user input", r"""\bfs\.(?:readFile|readFileSync)\(.*(?:req\.|params|query)"""),
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

                for desc, pattern in PATH_TRAVERSAL_PATTERNS:
                    if re.search(pattern, line):
                        snippet = stripped
                        if len(snippet) > 80:
                            snippet = snippet[:80] + "..."

                        session.add_finding(Finding(
                            title=f"Path Traversal Risk: {desc}",
                            severity=Severity.HIGH,
                            description=(
                                f"A potential path traversal vulnerability was detected: {desc}. "
                                f"If user-controlled input reaches file system operations without "
                                f"proper validation, attackers can read or write arbitrary files."
                            ),
                            evidence=(
                                f"File: {file_path}\n"
                                f"Line: {line_idx + 1}\n"
                                f"Snippet: {snippet}"
                            ),
                            remediation=(
                                "1. Validate and sanitize all file paths derived from user input.\n"
                                "2. Use os.path.realpath() and verify the result is within the expected directory.\n"
                                "3. Reject paths containing '..' or absolute path characters.\n"
                                "4. Use a whitelist of allowed filenames where possible.\n"
                                "5. Chroot or sandbox file access to a specific directory."
                            ),
                            url="local://sast",
                            module="sast_path_traversal",
                            cwe="CWE-22",
                            confirmed=True,
                            location=f"{file_path}:{line_idx + 1}",
                            parameter=desc,
                            payload="",
                            request_method="SAST",
                            response_status=0,
                            curl_command="",
                            reproduction_steps=f"Inspect line {line_idx + 1} of {file_path}",
                            developer_fix=(
                                "Resolve the full canonical path with os.path.realpath() and "
                                "verify it starts with the expected base directory before "
                                "performing any file operation."
                            ),
                            affected_component=f"File: {file_path}",
                            references="https://owasp.org/www-community/attacks/Path_Traversal",
                            detection_method="SAST regex pattern matching on source files.",
                        ))
        except Exception:
            pass
