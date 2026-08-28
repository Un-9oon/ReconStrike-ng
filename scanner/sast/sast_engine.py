import os
import re

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession


def _sast_finding(session, title, severity, desc, file_path, line_num, snippet, remediation,
                  module, cwe, dev_fix, refs):
    """Shared finding builder for all SAST modules."""
    session.add_finding(Finding(
        title=title, severity=severity, description=desc,
        evidence="File: {}\nLine: {}\nSnippet: {}".format(file_path, line_num, snippet),
        remediation=remediation, url="local://sast", module=module, cwe=cwe,
        confirmed=True, location="{}:{}".format(file_path, line_num),
        parameter="", payload="", request_method="SAST", response_status=0,
        curl_command="", reproduction_steps="Inspect line {} of {}".format(line_num, file_path),
        developer_fix=dev_fix, affected_component="File: {}".format(file_path),
        references=refs, detection_method="SAST regex pattern matching on source files.",
    ))


def _scan_lines(session, files, patterns, *, module, remediation, dev_fix, refs,
                severity_col=None, cwe_col=None, skip_comments=True, lang_col=None):
    """Generic line scanner used by all SAST modules.

    patterns: list of tuples. The first two elements are always (description, regex).
    Additional columns are mapped by severity_col, cwe_col, lang_col indices.
    """
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()
        except (OSError, UnicodeDecodeError):
            continue

        for idx, line in enumerate(lines):
            s = line.strip()
            if skip_comments and (s.startswith("#") or s.startswith("//") or s.startswith("*") or s.startswith("--")):
                continue

            for pat in patterns:
                desc, regex = pat[0], pat[1]

                # language filter
                if lang_col is not None:
                    ext = pat[lang_col]
                    if ext == ".py" and not fpath.endswith(".py"):
                        continue
                    if ext == ".php" and not fpath.endswith(".php"):
                        continue
                    if ext == ".js" and not fpath.endswith((".js", ".ts")):
                        continue

                if not re.search(regex, line):
                    continue

                sev = pat[severity_col] if severity_col is not None else Severity.HIGH
                cwe = pat[cwe_col] if cwe_col is not None else ""
                snip = s[:80] + "..." if len(s) > 80 else s

                _sast_finding(
                    session, "{}: {}".format(module.replace("sast_", "").replace("_", " ").title(), desc),
                    sev, desc, fpath, idx + 1, snip, remediation, module, cwe, dev_fix, refs,
                )


def run_sast(session: ScanSession, target_dir: str, quiet: bool = False):
    if not os.path.exists(target_dir):
        logger.error("SAST: Directory '%s' does not exist.", target_dir)
        return

    from scanner.sast.modules import (
        hardcoded_secrets, insecure_functions, sql_injection,
        insecure_crypto, path_traversal, sensitive_data,
    )

    modules = [
        ("Hardcoded Secrets", hardcoded_secrets),
        ("Insecure Functions", insecure_functions),
        ("SQL Injection Patterns", sql_injection),
        ("Insecure Cryptography", insecure_crypto),
        ("Path Traversal Risks", path_traversal),
        ("Sensitive Data Exposure", sensitive_data),
    ]

    skip_dirs = {".git", "node_modules", "venv", "__pycache__"}
    scan_exts = ('.py', '.php', '.js', '.ts', '.html', '.json', '.yml', '.yaml')
    files_to_scan = []
    for root, _, files in os.walk(target_dir):
        if any(exc in root for exc in skip_dirs):
            continue
        files_to_scan.extend(
            os.path.join(root, f) for f in files if f.endswith(scan_exts)
        )

    if not quiet:
        logger.info("SAST: Found %d files to analyze.", len(files_to_scan))

    for name, mod in modules:
        if not quiet:
            logger.info("SAST: Running %s", name)
        try:
            mod.run(session, files_to_scan)
        except (OSError, UnicodeDecodeError, ValueError, KeyError) as e:
            logger.error("SAST module '%s' error: %s", name, e)
