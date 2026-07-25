import os
import re
from colorama import Fore, Style

from scanner.core import Finding, Severity, ScanSession

def run_sast(session: ScanSession, target_dir: str, quiet: bool = False):
    """
    Core static analysis engine that walks the directory and runs SAST modules.
    """
    if not os.path.exists(target_dir):
        print(f"{Fore.RED}[!] SAST Error: Directory '{target_dir}' does not exist.{Style.RESET_ALL}")
        return

    from scanner.sast.modules import hardcoded_secrets

    modules = [
        ("Hardcoded Secrets", hardcoded_secrets),
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
        print(f"[*] Found {len(files_to_scan)} files to analyze for SAST.")

    for name, module in modules:
        if not quiet:
            print(f"\n  {Fore.CYAN}[>] Running SAST: {name}{Style.RESET_ALL}")
        try:
            module.run(session, files_to_scan)
        except Exception as e:
            print(f"\n  {Fore.RED}[!] SAST Module '{name}' error: {e}{Style.RESET_ALL}")
