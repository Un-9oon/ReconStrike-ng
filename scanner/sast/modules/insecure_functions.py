import re
from scanner.core import Finding, Severity, ScanSession

DANGEROUS_PATTERNS = [
    # (description, regex, severity, language ext)
    ("os.system() call", r"\bos\.system\(", Severity.HIGH, ".py"),
    ("subprocess with shell=True", r"\bsubprocess\.call\(.*shell\s*=\s*True", Severity.HIGH, ".py"),
    ("eval() call (Python)", r"(?<!\w)eval\(", Severity.HIGH, ".py"),
    ("exec() call (Python)", r"(?<!\w)exec\(", Severity.HIGH, ".py"),
    ("pickle.loads() deserialization", r"\bpickle\.loads?\(", Severity.HIGH, ".py"),
    ("yaml.load() without SafeLoader", r"\byaml\.load\((?!.*SafeLoader)(?!.*safe_load)", Severity.MEDIUM, ".py"),
    ("eval() call (PHP)", r"\beval\s*\(", Severity.HIGH, ".php"),
    ("system() call (PHP)", r"\bsystem\s*\(", Severity.HIGH, ".php"),
    ("exec() call (PHP)", r"\bexec\s*\(", Severity.HIGH, ".php"),
    ("passthru() call (PHP)", r"\bpassthru\s*\(", Severity.HIGH, ".php"),
    ("shell_exec() call (PHP)", r"\bshell_exec\s*\(", Severity.HIGH, ".php"),
    ("unserialize() call (PHP)", r"\bunserialize\s*\(", Severity.HIGH, ".php"),
    ("eval() call (JS)", r"\beval\s*\(", Severity.HIGH, ".js"),
    ("Function() constructor (JS)", r"\bFunction\s*\(", Severity.MEDIUM, ".js"),
    ("setTimeout with string argument", r"\bsetTimeout\s*\(\s*['\"]", Severity.MEDIUM, ".js"),
    ("innerHTML assignment", r"\.innerHTML\s*=", Severity.MEDIUM, ".js"),
]


def run(session: ScanSession, files_to_scan: list[str]) -> None:
    from scanner.sast.sast_engine import _scan_lines
    _scan_lines(
        session, files_to_scan, DANGEROUS_PATTERNS,
        module="sast_insecure_functions",
        severity_col=2, cwe_col=None, lang_col=3,
        remediation=(
            "1. Replace dangerous functions with safe alternatives.\n"
            "2. For eval/exec: use ast.literal_eval() or structured parsers.\n"
            "3. For subprocess: avoid shell=True, use a list of arguments.\n"
            "4. For deserialization: use safe formats (JSON) or validate input strictly."
        ),
        dev_fix="Replace the dangerous function with a safe alternative. "
                "For command execution, use subprocess with list args and shell=False. "
                "For eval/exec, use ast.literal_eval() or proper parsers.",
        refs="https://owasp.org/www-community/attacks/Code_Injection",
    )
    # Patch CWE based on severity (HIGH = command injection, else code injection)
    # Already handled by the generic scanner's title generation
