import os
import re

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession

def run_sast(session: ScanSession, target_dir: str, quiet: bool = False):
    """
    Core static analysis engine that walks the directory and runs SAST modules.
    """
    if not os.path.exists(target_dir):
        logger.error("SAST: Directory '%s' does not exist.", target_dir)
        return

    from scanner.sast.modules import (
        hardcoded_secrets,
        insecure_functions,
        sql_injection,
        insecure_crypto,
        path_traversal,
        sensitive_data,
    )

    modules = [
        ("Hardcoded Secrets", hardcoded_secrets),
        ("Insecure Functions", insecure_functions),
        ("SQL Injection Patterns", sql_injection),
        ("Insecure Cryptography", insecure_crypto),
        ("Path Traversal Risks", path_traversal),
        ("Sensitive Data Exposure", sensitive_data),
    ]

    files_to_scan = []
    for root, _, files in os.walk(target_dir):
        # Exclude common large/unnecessary directories
        if any(exc in root for exc in [".git", "node_modules", "venv", "__pycache__"]):
            continue
        for file in files:
            # Add more extensions as needed
            if file.endswith(('.py', '.php', '.js', '.ts', '.html', '.json', '.yml', '.yaml')):
                files_to_scan.append(os.path.join(root, file))

    if not quiet:
        logger.info("SAST: Found %d files to analyze.", len(files_to_scan))

    for name, module in modules:
        if not quiet:
            logger.info("SAST: Running %s", name)
        try:
            module.run(session, files_to_scan)
        except Exception as e:
            logger.error("SAST module '%s' error: %s", name, e)
