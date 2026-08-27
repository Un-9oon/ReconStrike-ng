import re
from scanner.core import Finding, Severity, ScanSession

# Patterns: (description, regex, severity, languages hint)
DANGEROUS_PATTERNS = [
    # Python command injection sinks
    ("os.system() call", r"\bos\.system\(", Severity.HIGH, ".py"),
    ("subprocess with shell=True", r"\bsubprocess\.call\(.*shell\s*=\s*True", Severity.HIGH, ".py"),
    ("eval() call (Python)", r"(?<!\w)eval\(", Severity.HIGH, ".py"),
    ("exec() call (Python)", r"(?<!\w)exec\(", Severity.HIGH, ".py"),
    ("pickle.loads() deserialization", r"\bpickle\.loads?\(", Severity.HIGH, ".py"),
    ("yaml.load() without SafeLoader", r"\byaml\.load\((?!.*SafeLoader)(?!.*safe_load)", Severity.MEDIUM, ".py"),

    # PHP dangerous functions
    ("eval() call (PHP)", r"\beval\s*\(", Severity.HIGH, ".php"),
    ("system() call (PHP)", r"\bsystem\s*\(", Severity.HIGH, ".php"),
    ("exec() call (PHP)", r"\bexec\s*\(", Severity.HIGH, ".php"),
    ("passthru() call (PHP)", r"\bpassthru\s*\(", Severity.HIGH, ".php"),
    ("shell_exec() call (PHP)", r"\bshell_exec\s*\(", Severity.HIGH, ".php"),
    ("unserialize() call (PHP)", r"\bunserialize\s*\(", Severity.HIGH, ".php"),

    # JavaScript / TypeScript
    ("eval() call (JS)", r"\beval\s*\(", Severity.HIGH, ".js"),
    ("Function() constructor (JS)", r"\bFunction\s*\(", Severity.MEDIUM, ".js"),
    ("setTimeout with string argument", r"\bsetTimeout\s*\(\s*['\"]", Severity.MEDIUM, ".js"),
    ("innerHTML assignment", r"\.innerHTML\s*=", Severity.MEDIUM, ".js"),
]


def run(session: ScanSession, files_to_scan: list[str]) -> None:
    for file_path in files_to_scan:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()

            for line_idx, line in enumerate(lines):
                stripped = line.strip()
                # Skip comment lines
                if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                    continue

                for desc, pattern, severity, lang_ext in DANGEROUS_PATTERNS:
                    # Only match patterns relevant to the file type
                    if lang_ext == ".py" and not file_path.endswith(".py"):
                        continue
                    if lang_ext == ".php" and not file_path.endswith(".php"):
                        continue
                    if lang_ext == ".js" and not file_path.endswith((".js", ".ts")):
                        continue

                    if re.search(pattern, line):
                        snippet = stripped
                        if len(snippet) > 80:
                            snippet = snippet[:80] + "..."

                        session.add_finding(Finding(
                            title=f"Insecure Function: {desc}",
                            severity=severity,
                            description=(
                                f"Usage of a dangerous function was detected. {desc} can lead to "
                                f"remote code execution, command injection, or deserialization attacks "
                                f"if user-controlled data reaches the function."
                            ),
                            evidence=(
                                f"File: {file_path}\n"
                                f"Line: {line_idx + 1}\n"
                                f"Snippet: {snippet}"
                            ),
                            remediation=(
                                "1. Replace dangerous functions with safe alternatives.\n"
                                "2. For eval/exec: use ast.literal_eval() or structured parsers.\n"
                                "3. For subprocess: avoid shell=True, use a list of arguments.\n"
                                "4. For deserialization: use safe formats (JSON) or validate input strictly."
                            ),
                            url="local://sast",
                            module="sast_insecure_functions",
                            cwe="CWE-78" if severity == Severity.HIGH else "CWE-94",
                            confirmed=True,
                            location=f"{file_path}:{line_idx + 1}",
                            parameter=desc,
                            payload="",
                            request_method="SAST",
                            response_status=0,
                            curl_command="",
                            reproduction_steps=f"Inspect line {line_idx + 1} of {file_path}",
                            developer_fix=(
                                "Replace the dangerous function with a safe alternative. "
                                "For command execution, use subprocess with a list of arguments and "
                                "shell=False. For eval/exec, use ast.literal_eval() or proper parsers."
                            ),
                            affected_component=f"File: {file_path}",
                            references="https://owasp.org/www-community/attacks/Code_Injection",
                            detection_method="SAST regex pattern matching on source files.",
                        ))
        except Exception:
            pass
