#!/usr/bin/env python3
import argparse
import json
import os
import signal
import sys
import time
from urllib.parse import urlparse

from colorama import Fore, Style, init as colorama_init

from scanner.log import setup_logging, logger
from scanner.core import ScanConfig, ScanSession, Severity, Finding
from scanner.identity_manager import ANMConfig
from scanner.concurrent import ConcurrentCrawler
from scanner.reporter import generate_html_report, print_summary
from scanner.diff_scan import save_scan_results, load_previous_scan, compute_diff, print_diff
from scanner.compliance import generate_compliance_report, print_compliance_summary, generate_compliance_html
from scanner.api_scanner import scan_api_endpoints
from scanner.waf_detect import detect_waf
from scanner.tech_stack import analyze_tech_stack, print_tech_stack
from scanner.pdf_report import generate_pdf_report
from scanner import __version__ as VERSION
from scanner.modules import (
    headers, ssl_check, sqli, xss, csrf, directory, info_disclosure,
    auth, misconfig, lfi, cmd_injection, ssti, ssrf, xxe, idor,
    jwt, file_upload, portscan, fingerprint, subdomain, cors,
    session_security, cve_check, zero_day, nosql_injection,
    subdomain_takeover, hpp, graphql, deserialization,
    business_logic, cache_poisoning, dom_xss, host_header, http_method,
    ldap_injection, mass_assignment, oauth_misconfig, open_redirect,
    prototype_pollution, race_condition, request_smuggling, second_order,
    websocket_security,
)

colorama_init()

BANNER = f"""
{Fore.RED}██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗{Fore.YELLOW}███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
{Fore.RED}██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║{Fore.YELLOW}██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
{Fore.RED}██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║{Fore.YELLOW}███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
{Fore.RED}██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║{Fore.YELLOW}╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
{Fore.RED}██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║{Fore.YELLOW}███████║   ██║   ██║  ██║██║██║  ██╗███████╗
{Fore.RED}╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{Fore.YELLOW}╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝{Style.RESET_ALL}
{Fore.CYAN}    Advanced Web & Network Vulnerability Assessment Framework v{VERSION}{Style.RESET_ALL}
{Fore.WHITE}    43 Scan Modules | OWASP Top 10 + PCI DSS | Verified Findings{Style.RESET_ALL}
{Fore.WHITE}    WAF Detection | API Security | Compliance Mapping | Scan Diffing{Style.RESET_ALL}
{Fore.YELLOW}    ────────────────────────────────────────────────────────────────────{Style.RESET_ALL}
"""

ALL_MODULES = {
    "fingerprint": ("Technology Fingerprinting & WAF Detection", fingerprint),
    "portscan": ("Port Scanning", portscan),
    "subdomain": ("Subdomain Enumeration", subdomain),
    "headers": ("Security Headers", headers),
    "ssl": ("SSL/TLS Configuration", ssl_check),
    "sqli": ("SQL Injection", sqli),
    "xss": ("Cross-Site Scripting", xss),
    "ssti": ("Server-Side Template Injection", ssti),
    "csrf": ("CSRF", csrf),
    "ssrf": ("Server-Side Request Forgery", ssrf),
    "xxe": ("XML External Entity Injection", xxe),
    "lfi": ("Local File Inclusion / Path Traversal", lfi),
    "cmdi": ("OS Command Injection", cmd_injection),
    "idor": ("Insecure Direct Object Reference", idor),
    "jwt": ("JWT Vulnerabilities", jwt),
    "upload": ("File Upload Vulnerabilities", file_upload),
    "directory": ("Sensitive Files & Directories", directory),
    "info": ("Information Disclosure", info_disclosure),
    "auth": ("Authentication Security", auth),
    "misconfig": ("Security Misconfigurations", misconfig),
    "cors": ("CORS Misconfiguration", cors),
    "session_security": ("Session Security & Cookie Hardening", session_security),
    "cve_check": ("CVE Lookup & Vulnerability Correlation", cve_check),
    "zero_day": ("Zero-Day Heuristics & Fuzzing", zero_day),
    "nosql": ("NoSQL Injection", nosql_injection),
    "subdomain_takeover": ("Subdomain Takeover", subdomain_takeover),
    "hpp": ("HTTP Parameter Pollution", hpp),
    "graphql": ("GraphQL Vulnerability Scanner", graphql),
    "deserialization": ("Insecure Deserialization", deserialization),
    "business_logic": ("Business Logic Vulnerabilities", business_logic),
    "cache_poisoning": ("Web Cache Poisoning", cache_poisoning),
    "dom_xss": ("DOM-Based Cross-Site Scripting", dom_xss),
    "host_header": ("Host Header Injection", host_header),
    "http_method": ("HTTP Method Tampering & Verb Tampering", http_method),
    "ldap_injection": ("LDAP Injection", ldap_injection),
    "mass_assignment": ("Mass Assignment / HTTP Parameter Binding", mass_assignment),
    "oauth_misconfig": ("OAuth 2.0 / OpenID Connect Misconfigurations", oauth_misconfig),
    "open_redirect": ("Open Redirect Vulnerabilities", open_redirect),
    "prototype_pollution": ("Server-Side Prototype Pollution", prototype_pollution),
    "race_condition": ("HTTP Race Conditions & Concurrency Vulnerabilities", race_condition),
    "request_smuggling": ("HTTP Request Smuggling (CL.TE / TE.CL)", request_smuggling),
    "second_order": ("Second-Order Injection Vulnerabilities", second_order),
    "websocket_security": ("WebSocket Security & Hijacking", websocket_security),
}

SCAN_PROFILES = {
    "quick": {
        "modules": ["fingerprint", "headers", "ssl", "directory", "info"],
        "depth": 2,
        "description": "Fast reconnaissance scan (5 modules, depth 2)",
    },
    "standard": {
        "modules": list(ALL_MODULES.keys()),
        "depth": 3,
        "description": "Standard full scan (all modules, depth 3)",
    },
    "deep": {
        "modules": list(ALL_MODULES.keys()),
        "depth": 5,
        "description": "Deep scan (all modules, depth 5, extra checks)",
    },
    "aggressive": {
        "modules": list(ALL_MODULES.keys()),
        "depth": 7,
        "description": "Aggressive scan (all modules, depth 7, max coverage)",
    },
    "passive": {
        "modules": ["fingerprint", "headers", "ssl", "directory", "info", "subdomain"],
        "depth": 2,
        "description": "Passive scan (no injection tests, no active probing)",
    },
    "api": {
        "modules": ["fingerprint", "headers", "ssl", "sqli", "xss", "jwt", "idor", "auth", "misconfig"],
        "depth": 3,
        "description": "API-focused scan (injection + auth + JWT modules)",
    },
    "owasp": {
        "modules": ["sqli", "xss", "ssti", "csrf", "ssrf", "xxe", "lfi", "cmdi", "idor",
                     "jwt", "auth", "misconfig", "cors", "headers", "ssl", "fingerprint", "directory", "info"],
        "depth": 4,
        "description": "OWASP Top 10 coverage scan",
    },
    "full": {
        "modules": list(ALL_MODULES.keys()),
        "depth": 7,
        "description": "Maximum scan (all modules, depth 7, API scan, compliance, PDF report)",
    },
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="ReconStrike - Advanced Web & Network Vulnerability Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Scan Profiles:
{chr(10).join(f'  {k:12s} {v["description"]}' for k, v in SCAN_PROFILES.items())}

Examples:
  %(prog)s -t https://example.com
  %(prog)s -t https://example.com --profile deep
  %(prog)s -t https://example.com --profile api --json
  %(prog)s -t https://example.com --auth-url https://example.com/login -u admin --password-file pass.txt
  %(prog)s -t https://example.com --modules sqli,xss,headers
  %(prog)s -t https://example.com --diff --compliance
  %(prog)s -t https://example.com --proxy socks5://127.0.0.1:9050
  %(prog)s -t https://example.com --rate-limit 10 --ci
        """
    )
    parser.add_argument("-t", "--target", help="Target URL (Required for DAST)")
    parser.add_argument("--sast-dir", help="Local directory path for Static Application Security Testing (SAST)")
    parser.add_argument("-o", "--output", default="reconstrike_report.html", help="Output report file (default: reconstrike_report.html)")
    parser.add_argument("--depth", type=int, default=3, help="Crawl depth (default: 3)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--modules", help=f"Comma-separated list of modules (default: all). Available: {','.join(ALL_MODULES.keys())}")
    parser.add_argument("--exclude-modules", help="Comma-separated list of modules to exclude")
    parser.add_argument("--profile", choices=SCAN_PROFILES.keys(), help="Scan profile (overrides --modules and --depth)")
    parser.add_argument("--deep", action="store_true", help="Deep scan mode (shortcut for --profile deep)")
    parser.add_argument("--full", action="store_true", help="Full scan: all modules, max depth, API scan, compliance, PDF report")

    parser.add_argument("--auth-url", help="Login page URL for authenticated scanning")
    parser.add_argument("-u", "--username", help="Username for authenticated scanning")
    parser.add_argument("-p", "--password", help="Password for authenticated scanning (visible in process list; prefer --password-file)")
    parser.add_argument("--password-file", help="Read password from file (more secure than --password)")
    parser.add_argument("--cookie", help="Custom cookie (format: name=value; name2=value2)")
    parser.add_argument("--header", action="append", help="Custom header (format: Name: Value)")

    parser.add_argument("--proxy", help="HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080, socks5://127.0.0.1:9050)")
    parser.add_argument("--rate-limit", type=float, default=0, help="Max requests per second (0 = unlimited)")
    parser.add_argument("--scope-include", help="Regex pattern for URLs to include in scope")
    parser.add_argument("--scope-exclude", help="Regex pattern for URLs to exclude from scope")
    parser.add_argument("--no-ssl-verify", action="store_true", default=False, help="Skip SSL certificate verification")
    parser.add_argument("--user-agent", default=f"ReconStrike/{VERSION} (Security Audit)", help="Custom User-Agent")

    anm_group = parser.add_argument_group("Adaptive Network Masking (ANM)",
                                           "Runtime IP/MAC/UA rotation to evade blocking during scans")
    anm_group.add_argument("--anm", action="store_true", help="Enable Adaptive Network Masking (auto-rotate identity on block)")
    anm_group.add_argument("--tor", action="store_true", help="Route traffic through Tor SOCKS5 proxy (127.0.0.1:9050)")
    anm_group.add_argument("--tor-control-port", type=int, default=9051, help="Tor ControlPort for identity renewal (default: 9051)")
    anm_group.add_argument("--tor-password", default="", help="Tor ControlPort authentication password (visible in process list; prefer --tor-password-file)")
    anm_group.add_argument("--tor-password-file", help="Read Tor ControlPort password from file (more secure than --tor-password)")
    anm_group.add_argument("--proxy-pool", help="File with newline-delimited proxy list for round-robin rotation")
    anm_group.add_argument("--rotate-mac", action="store_true", help="Enable MAC address rotation (Linux, requires root)")
    anm_group.add_argument("--rotate-ua", action="store_true", default=False, help="Enable User-Agent fingerprint rotation")
    anm_group.add_argument("--anm-interface", default="", help="Network interface for MAC rotation (auto-detected if empty)")
    anm_group.add_argument("--anm-cooldown", type=float, default=3.0, help="Seconds to wait after identity rotation (default: 3)")
    anm_group.add_argument("--anm-max-rotations", type=int, default=50, help="Maximum identity rotations per scan (default: 50)")

    net_group = parser.add_argument_group("Network Scanning", "Internal network port scanning and service detection")
    net_group.add_argument("--network-scan", metavar="TARGET", help="Network scan target (IP, hostname, or CIDR range, e.g. 192.168.1.0/24)")
    net_group.add_argument("--ports", default="top-1000", help="Port specification: top-1000, 1-65535, 22,80,443, or mixed (default: top-1000)")
    net_group.add_argument("--scan-speed", type=int, choices=[1, 2, 3, 4, 5], default=3, help="Scan speed 1-5: 1=stealth, 3=normal, 5=insane (default: 3)")

    proxy_group = parser.add_argument_group("DAST Proxy", "Interception proxy for passive traffic analysis")
    proxy_group.add_argument("--dast-proxy", action="store_true", help="Start DAST interception proxy for passive analysis")
    proxy_group.add_argument("--proxy-port", type=int, default=8087, help="DAST proxy listen port (default: 8087)")
    proxy_group.add_argument("--proxy-bind", default="127.0.0.1",
                             help="DAST proxy bind address (default: 127.0.0.1). Use 0.0.0.0 for network access.")

    parser.add_argument("--pdf", help="Generate professional PDF report (e.g., --pdf report.pdf)")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Output results as JSON to stdout")
    parser.add_argument("--json-file", help="Save JSON results to file")
    parser.add_argument("--diff", action="store_true", help="Compare results with previous scan")
    parser.add_argument("--compliance", action="store_true", help="Include OWASP Top 10 & PCI DSS compliance report")
    parser.add_argument("--api-scan", action="store_true", help="Enable API endpoint discovery and testing")
    parser.add_argument("--nikto", action="store_true", help="Run Nikto-style misconfiguration and sensitive file scan")
    parser.add_argument("--ci", action="store_true", help="CI/CD mode: exit code reflects severity (1=critical, 2=high, 3=medium)")
    parser.add_argument("--severity-threshold", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        default="MEDIUM", help="Minimum severity to report in CI mode (default: MEDIUM)")
    stealth_group = parser.add_argument_group("Stealth Mode", "Make scan traffic indistinguishable from real browser sessions")
    stealth_group.add_argument("--stealth", action="store_true", help="Enable stealth mode (full browser emulation + human timing)")
    stealth_group.add_argument("--stealth-speed", choices=["slow", "normal", "fast"], default="normal",
                               help="Stealth timing: slow (3-12s gaps), normal (1-5s), fast (0.3-2s)")

    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output (findings only)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--log-file", help="Write log output to file")
    parser.add_argument("--list-modules", action="store_true", help="List all available scan modules and exit")
    parser.add_argument("--version", action="version", version=f"ReconStrike v{VERSION}")

    return parser.parse_args()


def _resolve_modules(args) -> list[str]:
    if args.full:
        profile = SCAN_PROFILES["full"]
        selected, depth_override = profile["modules"], profile["depth"]
    elif args.profile:
        profile = SCAN_PROFILES[args.profile]
        selected, depth_override = profile["modules"], profile["depth"]
    elif args.deep:
        selected, depth_override = list(ALL_MODULES.keys()), 5
    elif args.modules:
        selected, depth_override = [m.strip() for m in args.modules.split(",")], None
    else:
        selected, depth_override = list(ALL_MODULES.keys()), None

    if args.exclude_modules:
        excluded = {m.strip() for m in args.exclude_modules.split(",")}
        selected = [m for m in selected if m not in excluded]

    invalid = [m for m in selected if m not in ALL_MODULES]
    if invalid:
        logger.error("Unknown modules: %s", ", ".join(invalid))
        logger.error("Available: %s", ", ".join(ALL_MODULES.keys()))
        sys.exit(1)

    return selected, depth_override


def _build_json_output(session: ScanSession, duration: float, diff_data=None, compliance_data=None) -> dict:
    result = {
        "version": VERSION,
        "target": session.config.target,
        "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_seconds": round(duration, 1),
        "urls_scanned": len(session.crawled_urls),
        "forms_found": len(session.forms),
        "summary": {
            "total": len(session.findings),
            "confirmed": sum(1 for f in session.findings if f.confirmed),
            "critical": sum(1 for f in session.findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in session.findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in session.findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in session.findings if f.severity == Severity.LOW),
            "info": sum(1 for f in session.findings if f.severity == Severity.INFO),
        },
        "findings": [
            {
                "title": f.title, "severity": f.severity.value,
                "description": f.description, "evidence": f.evidence,
                "remediation": f.remediation, "url": f.url,
                "module": f.module, "cwe": f.cwe, "confirmed": f.confirmed,
                "location": f.location, "parameter": f.parameter,
                "payload": f.payload, "request_method": f.request_method,
                "request_body": f.request_body, "response_status": f.response_status,
                "curl_command": f.curl_command, "reproduction_steps": f.reproduction_steps,
                "developer_fix": f.developer_fix, "affected_component": f.affected_component,
                "references": f.references, "detection_method": f.detection_method,
            }
            for f in sorted(session.findings, key=lambda x: x.severity.score, reverse=True)
        ],
    }
    if diff_data:
        result["diff"] = {
            "new": len(diff_data["new"]),
            "fixed": len(diff_data["fixed"]),
            "persistent": len(diff_data["persistent"]),
            "previous_scan": diff_data["previous_timestamp"],
        }
    if compliance_data:
        result["compliance"] = {
            "owasp": {k: {"status": v["status"], "findings": v["finding_count"]}
                      for k, v in compliance_data["owasp"].items()},
            "pci_dss": {k: {"status": v["status"], "findings": v["finding_count"]}
                        for k, v in compliance_data["pci_dss"].items()},
        }
    return result


def _ci_exit_code(session: ScanSession, threshold: str) -> int:
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    exit_codes = {Severity.CRITICAL: 1, Severity.HIGH: 2, Severity.MEDIUM: 3}
    threshold_rank = severity_rank.get(threshold, 2)
    for f in session.findings:
        if severity_rank.get(f.severity.value, 0) >= threshold_rank:
            if f.severity in exit_codes:
                return exit_codes[f.severity]
    return 0


class ProgressTracker:
    def __init__(self, total_modules: int, quiet: bool = False):
        self.total = total_modules
        self.current = 0
        self.quiet = quiet
        self.start_time = time.time()

    def update(self, module_name: str):
        self.current += 1
        if self.quiet:
            return
        elapsed = time.time() - self.start_time
        avg = elapsed / self.current if self.current else 0
        remaining = avg * (self.total - self.current)
        filled = int(30 * self.current / self.total)
        bar = "█" * filled + "░" * (30 - filled)
        pct = self.current / self.total * 100
        print(
            f"\r  {Fore.CYAN}[{bar}] {pct:5.1f}% "
            f"({self.current}/{self.total}) "
            f"ETA: {remaining:.0f}s - {module_name}{Style.RESET_ALL}",
            end="", flush=True,
        )

    def finish(self):
        if not self.quiet:
            elapsed = time.time() - self.start_time
            print(f"\r  {Fore.GREEN}[{'█' * 30}] 100.0% complete in {elapsed:.1f}s{' ' * 30}{Style.RESET_ALL}")


# Global reference for SIGINT cleanup
_active_session = None


def _sigint_handler(signum, frame):
    """Gracefully shutdown on Ctrl+C, restoring MAC address if rotated."""
    if _active_session and _active_session.identity_manager:
        logger.warning("Interrupted -- restoring original identity...")
        _active_session.identity_manager.shutdown()
    sys.exit(130)


def main():
    signal.signal(signal.SIGINT, _sigint_handler)
    args = parse_args()

    setup_logging(verbose=args.verbose, quiet=args.quiet, no_color=args.no_color, log_file=args.log_file)

    if args.no_color:
        colorama_init(strip=True)
        os.environ["NO_COLOR"] = "1"

    if args.list_modules:
        print(f"ReconStrike v{VERSION} - Available Scan Modules:\n")
        for key, (desc, _) in ALL_MODULES.items():
            print(f"  {key:24s} {desc}")
        print(f"\nTotal: {len(ALL_MODULES)} modules")
        sys.exit(0)

    if args.password_file:
        with open(args.password_file) as f:
            args.password = f.read().strip()
    elif args.password:
        logger.warning("--password is visible in process list. Use --password-file or set RECONSTRIKE_PASSWORD env var.")
        for i, arg in enumerate(sys.argv):
            if arg in ("-p", "--password") and i + 1 < len(sys.argv):
                sys.argv[i + 1] = "********"
                break
    elif os.environ.get("RECONSTRIKE_PASSWORD"):
        args.password = os.environ["RECONSTRIKE_PASSWORD"]

    if args.tor_password_file:
        with open(args.tor_password_file) as f:
            args.tor_password = f.read().strip()
    elif args.tor_password:
        logger.warning("--tor-password is visible in process list. Use --tor-password-file or set RECONSTRIKE_TOR_PASSWORD env var.")
        for i, arg in enumerate(sys.argv):
            if arg == "--tor-password" and i + 1 < len(sys.argv):
                sys.argv[i + 1] = "********"
                break
    elif os.environ.get("RECONSTRIKE_TOR_PASSWORD"):
        args.tor_password = os.environ["RECONSTRIKE_TOR_PASSWORD"]

    original_stdout = sys.stdout
    if args.json_output:
        sys.stdout = sys.stderr

    if args.full:
        args.api_scan = True
        args.compliance = True
        args.diff = True
        args.nikto = True
        if not args.pdf:
            from urllib.parse import urlparse as _urlparse
            domain = _urlparse(args.target).netloc.replace(":", "_") or "target"
            args.pdf = f"reconstrike_{domain}_{time.strftime('%Y%m%d_%H%M%S')}.pdf"

    if not args.quiet:
        print(BANNER)

    dast_proxy = None
    if args.dast_proxy:
        try:
            from scanner.proxy.server import ProxyServer
            dast_proxy = ProxyServer(port=args.proxy_port, bind_addr=args.proxy_bind)
            dast_proxy.start()
            if not args.quiet:
                logger.info("DAST Proxy started on %s:%d", args.proxy_bind, args.proxy_port)
                logger.info("Configure your browser to use http://%s:%d as proxy", args.proxy_bind, args.proxy_port)
                logger.info("Import CA cert from: %s", dast_proxy.ca_cert)
        except ImportError:
            logger.error("DAST Proxy requires 'cryptography' package: pip install cryptography")

    if not args.target and not args.sast_dir:
        logger.error("You must provide either --target (DAST) or --sast-dir (SAST) or both.")
        sys.exit(1)

    if args.target:
        target = args.target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        if target.startswith("http://"):
            logger.warning("Target uses HTTP -- scan traffic (including credentials) will be unencrypted. "
                           "Use https:// if the target supports it.")
        if not urlparse(target).netloc:
            logger.error("Invalid target URL: %s", target)
            sys.exit(1)
    else:
        target = ""

    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(";"):
            if "=" in pair:
                k, v = pair.strip().split("=", 1)
                cookies[k.strip()] = v.strip()

    custom_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()

    selected_modules, depth_override = _resolve_modules(args)
    depth = depth_override if depth_override else args.depth

    anm_enabled = args.anm or args.tor or args.proxy_pool or args.rotate_mac or args.rotate_ua
    auto_scrape = not args.proxy_pool
    if auto_scrape and args.auth_url:
        auto_scrape = False
        if anm_enabled:
            logger.warning("ANM: Auto-scraped proxies disabled because authenticated scanning is active. "
                           "Untrusted proxies could intercept credentials. Use --proxy-pool with trusted proxies instead.")
    anm_cfg = ANMConfig(
        enabled=anm_enabled,
        use_tor=args.tor,
        tor_control_port=args.tor_control_port,
        tor_password=args.tor_password,
        proxy_pool_file=args.proxy_pool or "",
        rotate_mac=args.rotate_mac,
        network_interface=args.anm_interface,
        rotate_ua=args.rotate_ua or args.anm,
        cooldown_after_block=args.anm_cooldown,
        max_rotations_per_scan=args.anm_max_rotations,
        auto_scrape_proxies=auto_scrape,
    )

    config = ScanConfig(
        target=target, threads=args.threads, timeout=args.timeout, depth=depth,
        user_agent=args.user_agent,
        auth_url=args.auth_url or "", auth_username=args.username or "",
        auth_password=args.password or "",
        cookies=cookies, headers=custom_headers,
        verify_ssl=not args.no_ssl_verify, scan_modules=selected_modules,
        proxy=args.proxy or "", rate_limit=args.rate_limit,
        scope_include=args.scope_include or "", scope_exclude=args.scope_exclude or "",
        anm_config=anm_cfg,
    )

    session = ScanSession(config)
    global _active_session
    _active_session = session

    stealth_cfg = None
    if args.stealth:
        from scanner.stealth import StealthConfig, apply_stealth
        stealth_cfg = StealthConfig(speed=args.stealth_speed, rotate_profile=True)
        apply_stealth(session.session, stealth_cfg)
        session._stealth = stealth_cfg

    if args.proxy:
        session.session.proxies.update({"http": args.proxy, "https": args.proxy})

    if not args.quiet:
        profile_name = args.profile or ("deep" if args.deep else "standard")
        logger.info("Target     : %s", target)
        logger.info("Profile    : %s", profile_name)
        logger.info("Depth      : %s", depth)
        logger.info("Modules    : %d (%s%s)", len(selected_modules), ", ".join(selected_modules[:5]), "..." if len(selected_modules) > 5 else "")
        logger.info("Threads    : %s", args.threads)
        if args.proxy:
            logger.info("Proxy      : %s", args.proxy)
        if args.rate_limit:
            logger.info("Rate Limit : %s req/s", args.rate_limit)
        if anm_enabled:
            methods = []
            if args.tor: methods.append("Tor")
            if args.proxy_pool: methods.append("ProxyPool")
            if args.rotate_mac: methods.append("MAC")
            if anm_cfg.rotate_ua: methods.append("UA")
            logger.info("ANM        : ACTIVE [%s]", ", ".join(methods))
        if args.stealth:
            logger.info("Stealth    : ACTIVE [%s profile, %s timing]", stealth_cfg.profile_name, args.stealth_speed)

    if args.target:
        resp = session.get(target)
        if not resp:
            logger.error("Cannot reach target: %s", target)
            logger.warning("Check the URL and network connectivity.")
            sys.exit(1)

        if not args.quiet:
            logger.info("Target is reachable (HTTP %s)", resp.status_code)
            logger.info("Detecting WAF/CDN...")
            waf_list = detect_waf(session)
            if waf_list:
                logger.warning("WAF Detected: %s", ", ".join(waf_list))
            else:
                logger.info("No WAF detected")

            logger.info("Analyzing technology stack...")
            print_tech_stack(analyze_tech_stack(session))

        if config.auth_url:
            if not args.quiet:
                logger.info("Authenticating...")
            if not session.authenticate():
                logger.warning("Proceeding without authentication")

        session.start_time = time.time()

        crawler = ConcurrentCrawler(session)
        crawler.crawl()

        if not args.quiet:
            logger.info("=" * 60)
            logger.info("RUNNING DAST MODULES (%d modules)", len(selected_modules))
            logger.info("=" * 60)

        progress = ProgressTracker(len(selected_modules), quiet=args.quiet)
        for mod_key in selected_modules:
            if mod_key in ALL_MODULES:
                name, module = ALL_MODULES[mod_key]
                if stealth_cfg:
                    stealth_cfg.wait()
                try:
                    if args.verbose:
                        logger.debug("Running DAST: %s", name)
                    module.run(session)
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Module '%s' error: %s", name, e)
                progress.update(name)
        progress.finish()

        if args.nikto:
            from scanner.nikto.scanner import run as nikto_run
            if not args.quiet:
                logger.info("Running Nikto-style misconfiguration scan...")
            try:
                nikto_run(session)
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Nikto scan error: %s", e)

        if args.api_scan:
            scan_api_endpoints(session)
    else:
        session.start_time = time.time()

    if args.sast_dir:
        from scanner.sast.sast_engine import run_sast
        if not args.quiet:
            logger.info("=" * 60)
            logger.info("RUNNING SAST MODULES on %s", args.sast_dir)
            logger.info("=" * 60)
        run_sast(session, args.sast_dir, quiet=args.quiet)

    if args.network_scan:
        from scanner.network.port_scanner import scan_host, scan_network, parse_port_range, SERVICE_NAMES
        if not args.quiet:
            logger.info("=" * 60)
            logger.info("NETWORK SCAN: %s", args.network_scan)
            logger.info("=" * 60)

        ports = parse_port_range(args.ports)
        if "/" in args.network_scan:
            results = scan_network(args.network_scan, ports=ports, speed=args.scan_speed)
        else:
            result = scan_host(args.network_scan, ports=ports, speed=args.scan_speed)
            results = [result] if result.is_alive else []

        if not args.quiet:
            for hr in results:
                logger.info("Host: %s%s — %d open ports (%.1fs)",
                            hr.ip,
                            f" ({hr.hostname})" if hr.hostname else "",
                            len(hr.open_ports), hr.scan_time)
                for pr in hr.open_ports:
                    logger.info("  %5d/tcp  %-6s  %s", pr.port, pr.state, pr.service or "unknown")

        HIGH_RISK_PORTS = {21, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 2375}
        for hr in results:
            for pr in hr.open_ports:
                if pr.port in HIGH_RISK_PORTS:
                    svc = pr.service or "unknown"
                    session.add_finding(Finding(
                        title=f"High-Risk Service Exposed: {svc} on port {pr.port}",
                        severity=Severity.HIGH,
                        description="Port {} ({}) is open on {}. This service is commonly targeted by attackers.".format(pr.port, svc, hr.ip),
                        evidence="Host: {}, Port: {}/tcp, State: {}, Service: {}".format(hr.ip, pr.port, pr.state, pr.service),
                        remediation="1. Verify this service needs to be exposed\n"
                                    "2. Restrict access via firewall rules\n"
                                    "3. Ensure the service is patched and hardened",
                        url="tcp://{}:{}".format(hr.ip, pr.port),
                        module="network_scan",
                        confirmed=True,
                        detection_method="TCP connect scan with service identification",
                    ))

        if not results:
            logger.info("Network scan: No alive hosts found.")

    if dast_proxy:
        for pf in dast_proxy.get_findings():
            session.add_finding(Finding(
                title=pf.title, severity=pf.severity,
                description=pf.description, evidence=pf.evidence,
                url=pf.url, module="dast_proxy",
                remediation=pf.remediation, cwe=pf.cwe,
                confirmed=True,
                detection_method="DAST proxy passive traffic analysis",
            ))
        if not args.quiet:
            logger.info("DAST Proxy: %d transactions captured, %d passive findings",
                        dast_proxy.history.get_count(), len(dast_proxy.get_findings()))
        dast_proxy.stop()

    session.end_time = time.time()
    duration = session.end_time - session.start_time

    scan_file = save_scan_results(session)
    if args.verbose:
        logger.debug("Scan results saved to: %s", scan_file)

    diff_data = None
    if args.diff:
        previous = load_previous_scan(target)
        if previous:
            diff_data = compute_diff(previous, session)
            if not args.quiet and not args.json_output:
                print_diff(diff_data)
        elif not args.quiet:
            logger.warning("No previous scan found for comparison.")

    compliance_data = None
    if args.compliance:
        compliance_data = generate_compliance_report(session)
        if not args.quiet and not args.json_output:
            print_compliance_summary(compliance_data)

    if not args.quiet and not args.json_output:
        logger.info("=" * 60)
        logger.info("RESULTS")
        logger.info("=" * 60)
        print_summary(session)

    from scanner.core import _sanitize_path

    if args.json_output or args.json_file:
        json_data = _build_json_output(session, duration, diff_data, compliance_data)
        if args.json_output:
            original_stdout.write(json.dumps(json_data, indent=2) + "\n")
            original_stdout.flush()
        if args.json_file:
            json_path = _sanitize_path(args.json_file)
            fd = os.open(json_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as jf:
                json.dump(json_data, jf, indent=2)
            if not args.quiet:
                logger.info("JSON report saved to: %s", json_path)

    html_path = _sanitize_path(args.output)
    report_path = generate_html_report(session, html_path, compliance_data)
    if not args.quiet:
        logger.info("HTML report saved to: %s", report_path)

    if args.pdf:
        pdf_path = generate_pdf_report(session, _sanitize_path(args.pdf), compliance_data)
        if not args.quiet:
            logger.info("PDF report saved to: %s", pdf_path)

    if not args.quiet:
        logger.info("Scan completed in %.1f seconds", duration)

    if session.identity_manager:
        summary = session.identity_manager.get_summary()
        if summary["total_rotations"] > 0 and not args.quiet:
            logger.info("ANM: Total identity rotations: %d", summary["total_rotations"])
            for entry in summary["history"]:
                logger.info("  ├─ %s | trigger=%s | actions=[%s]",
                            entry["timestamp"], entry["trigger"], ", ".join(entry["actions"]))
        session.identity_manager.shutdown()

    if args.ci:
        sys.exit(_ci_exit_code(session, args.severity_threshold))


if __name__ == "__main__":
    main()
