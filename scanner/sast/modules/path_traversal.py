import re
from scanner.core import Finding, Severity, ScanSession

PATH_TRAVERSAL_PATTERNS = [
    ("open() with f-string interpolation", r"""\bopen\(\s*f['"].*\{"""),
    ("open() with .format()", r"""\bopen\(.*\.format\("""),
    ("open() with string concatenation", r"""\bopen\(\s*[a-zA-Z_]+\s*\+"""),
    ("os.path.join with request data", r"""\bos\.path\.join\(.*request\."""),
    ("os.path.join with user param", r"""\bos\.path\.join\(.*(?:user_input|filename|file_name|filepath|path_param)"""),
    ("File read from request parameter", r"""(?:request\.(?:GET|POST|args|form|params).*(?:open|read|send_file))"""),
    ("send_file with user input", r"""\bsend_file\(.*(?:request\.|filename|user)"""),
    ("file_get_contents with variable (PHP)", r"""\bfile_get_contents\(\s*\$"""),
    ("include/require with variable (PHP)", r"""\b(?:include|require)(?:_once)?\s*\(\s*\$"""),
    ("fs.readFile with user input (Node)", r"""\bfs\.(?:readFile|readFileSync)\(.*(?:req\.|params|query)"""),
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
            if s.startswith("#") or s.startswith("//"):
                continue

            for desc, pattern in PATH_TRAVERSAL_PATTERNS:
                if not re.search(pattern, line):
                    continue
                snip = s[:80] + "..." if len(s) > 80 else s
                _sast_finding(
                    session, "Path Traversal Risk: {}".format(desc), Severity.HIGH,
                    "Potential path traversal: {}. Unvalidated file paths can "
                    "let attackers read or write arbitrary files.".format(desc),
                    fpath, line_idx + 1, snip,
                    "1. Validate and sanitize file paths from user input.\n"
                    "2. Use os.path.realpath() and verify it stays in the expected dir.\n"
                    "3. Reject paths containing '..' or absolute path chars.\n"
                    "4. Whitelist allowed filenames where possible.",
                    "sast_path_traversal", "CWE-22",
                    "Resolve the canonical path with os.path.realpath() and verify "
                    "it starts with the expected base directory.",
                    "https://owasp.org/www-community/attacks/Path_Traversal",
                )
