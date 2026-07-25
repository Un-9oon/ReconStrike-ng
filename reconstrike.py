#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
from urllib.parse import urlparse

from colorama import Fore, Style, init as colorama_init

from scanner.core import ScanConfig, ScanSession, Severity
from scanner.concurrent import ConcurrentCrawler
from scanner.reporter import generate_html_report, print_summary
from scanner.diff_scan import save_scan_results, load_previous_scan, compute_diff, print_diff
from scanner.compliance import generate_compliance_report, print_compliance_summary, generate_compliance_html
from scanner.api_scanner import scan_api_endpoints
from scanner.waf_detect import detect_waf
from scanner.tech_stack import analyze_tech_stack, print_tech_stack
from scanner.pdf_report import generate_pdf_report
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

VERSION = "3.0"

BANNER = f"""
{Fore.RED}██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗{Fore.YELLOW}███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
{Fore.RED}██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║{Fore.YELLOW}██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
{Fore.RED}██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║{Fore.YELLOW}███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
{Fore.RED}██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║{Fore.YELLOW}╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
{Fore.RED}██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║{Fore.YELLOW}███████║   ██║   ██║  ██║██║██║  ██╗███████╗
{Fore.RED}╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{Fore.YELLOW}╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝{Style.RESET_ALL}
{Fore.CYAN}    Advanced Web & Network Vulnerability Assessment Framework v{VERSION}{Style.RESET_ALL}
{Fore.WHITE}    43 Scan Modules | OWASP Top 10 + PCI DSS | Zero False Positives{Style.RESET_ALL}
{Fore.WHITE}    WAF Detection | API Security | Compliance Mapping | Scan Diffing{Style.RESET_ALL}
{Fore.YELLOW}    ────────────────────────────────────────────────────────────────{Style.RESET_ALL}
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
  %(prog)s -t https://example.com --auth-url https://example.com/login -u admin -p secret
  %(prog)s -t https://example.com --modules sqli,xss,headers
  %(prog)s -t https://example.com --diff --compliance
  %(prog)s -t https://example.com --proxy socks5://127.0.0.1:9050
  %(prog)s -t https://example.com --rate-limit 10 --ci
        """
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
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
    parser.add_argument("-p", "--password", help="Password for authenticated scanning")
    parser.add_argument("--cookie", help="Custom cookie (format: name=value; name2=value2)")
    parser.add_argument("--header", action="append", help="Custom header (format: Name: Value)")

    parser.add_argument("--proxy", help="HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080, socks5://127.0.0.1:9050)")
    parser.add_argument("--rate-limit", type=float, default=0, help="Max requests per second (0 = unlimited)")
    parser.add_argument("--scope-include", help="Regex pattern for URLs to include in scope")
    parser.add_argument("--scope-exclude", help="Regex pattern for URLs to exclude from scope")
    parser.add_argument("--no-ssl-verify", action="store_true", default=False, help="Skip SSL certificate verification")
    parser.add_argument("--user-agent", default="ReconStrike/3.0 (Security Audit)", help="Custom User-Agent")

    parser.add_argument("--pdf", help="Generate professional PDF report (e.g., --pdf report.pdf)")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Output results as JSON to stdout")
    parser.add_argument("--json-file", help="Save JSON results to file")
    parser.add_argument("--diff", action="store_true", help="Compare results with previous scan")
    parser.add_argument("--compliance", action="store_true", help="Include OWASP Top 10 & PCI DSS compliance report")
    parser.add_argument("--api-scan", action="store_true", help="Enable API endpoint discovery and testing")
    parser.add_argument("--ci", action="store_true", help="CI/CD mode: exit code reflects severity (1=critical, 2=high, 3=medium)")
    parser.add_argument("--severity-threshold", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        default="MEDIUM", help="Minimum severity to report in CI mode (default: MEDIUM)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output (findings only)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"ReconStrike v{VERSION}")

    return parser.parse_args()


def _resolve_modules(args) -> list[str]:
    if args.full:
        profile = SCAN_PROFILES["full"]
        selected = profile["modules"]
        depth_override = profile["depth"]
    elif args.profile:
        profile = SCAN_PROFILES[args.profile]
        selected = profile["modules"]
        depth_override = profile["depth"]
    elif args.deep:
        selected = list(ALL_MODULES.keys())
        depth_override = 5
    elif args.modules:
        selected = [m.strip() for m in args.modules.split(",")]
        depth_override = None
    else:
        selected = list(ALL_MODULES.keys())
        depth_override = None

    if args.exclude_modules:
        excluded = {m.strip() for m in args.exclude_modules.split(",")}
        selected = [m for m in selected if m not in excluded]

    invalid = [m for m in selected if m not in ALL_MODULES]
    if invalid:
        print(f"{Fore.RED}[!] Unknown modules: {', '.join(invalid)}{Style.RESET_ALL}")
        print(f"    Available: {', '.join(ALL_MODULES.keys())}")
        sys.exit(1)

    return selected, depth_override


def _build_json_output(session: ScanSession, duration: float, diff_data=None, compliance_data=None) -> dict:
    return {
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
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "url": f.url,
                "module": f.module,
                "cwe": f.cwe,
                "confirmed": f.confirmed,
                "location": f.location,
                "parameter": f.parameter,
                "payload": f.payload,
                "request_method": f.request_method,
                "request_body": f.request_body,
                "response_status": f.response_status,
                "curl_command": f.curl_command,
                "reproduction_steps": f.reproduction_steps,
                "developer_fix": f.developer_fix,
                "affected_component": f.affected_component,
                "references": f.references,
                "detection_method": f.detection_method,
            }
            for f in sorted(session.findings, key=lambda x: x.severity.score, reverse=True)
        ],
        **({"diff": {
            "new": len(diff_data["new"]),
            "fixed": len(diff_data["fixed"]),
            "persistent": len(diff_data["persistent"]),
            "previous_scan": diff_data["previous_timestamp"],
        }} if diff_data else {}),
        **({"compliance": {
            "owasp": {k: {"status": v["status"], "findings": v["finding_count"]}
                      for k, v in compliance_data["owasp"].items()},
            "pci_dss": {k: {"status": v["status"], "findings": v["finding_count"]}
                        for k, v in compliance_data["pci_dss"].items()},
        }} if compliance_data else {}),
    }


def _ci_exit_code(session: ScanSession, threshold: str) -> int:
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    threshold_rank = severity_rank.get(threshold, 2)

    for f in session.findings:
        rank = severity_rank.get(f.severity.value, 0)
        if rank >= threshold_rank:
            if f.severity == Severity.CRITICAL:
                return 1
            elif f.severity == Severity.HIGH:
                return 2
            elif f.severity == Severity.MEDIUM:
                return 3
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
        avg_per_module = elapsed / self.current if self.current else 0
        remaining = avg_per_module * (self.total - self.current)
        bar_width = 30
        filled = int(bar_width * self.current / self.total)
        bar = "█" * filled + "░" * (bar_width - filled)
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


def main():
    args = parse_args()

    original_stdout = sys.stdout
    if args.json_output:
        sys.stdout = sys.stderr

    if args.full:
        args.api_scan = True
        args.compliance = True
        args.diff = True
        if not args.pdf:
            from urllib.parse import urlparse as _urlparse
            domain = _urlparse(args.target).netloc.replace(":", "_") or "target"
            args.pdf = f"reconstrike_{domain}_{time.strftime('%Y%m%d_%H%M%S')}.pdf"

    if not args.quiet:
        print(BANNER)

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    parsed = urlparse(target)
    if not parsed.netloc:
        print(f"{Fore.RED}[!] Invalid target URL: {target}{Style.RESET_ALL}")
        sys.exit(1)

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

    config = ScanConfig(
        target=target,
        threads=args.threads,
        timeout=args.timeout,
        depth=depth,
        user_agent=args.user_agent,
        auth_url=args.auth_url or "",
        auth_username=args.username or "",
        auth_password=args.password or "",
        cookies=cookies,
        headers=custom_headers,
        verify_ssl=not args.no_ssl_verify,
        scan_modules=selected_modules,
        proxy=args.proxy or "",
        rate_limit=args.rate_limit,
        scope_include=args.scope_include or "",
        scope_exclude=args.scope_exclude or "",
    )

    session = ScanSession(config)

    if args.proxy:
        proxy_dict = {"http": args.proxy, "https": args.proxy}
        session.session.proxies.update(proxy_dict)

    if not args.quiet:
        profile_name = args.profile or ("deep" if args.deep else "standard")
        print(f"{Fore.CYAN}[*] Target     : {target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Profile    : {profile_name}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Depth      : {depth}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Modules    : {len(selected_modules)} ({', '.join(selected_modules[:5])}{'...' if len(selected_modules) > 5 else ''}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Threads    : {args.threads}{Style.RESET_ALL}")
        if args.proxy:
            print(f"{Fore.CYAN}[*] Proxy      : {args.proxy}{Style.RESET_ALL}")
        if args.rate_limit:
            print(f"{Fore.CYAN}[*] Rate Limit : {args.rate_limit} req/s{Style.RESET_ALL}")

    resp = session.get(target)
    if not resp:
        print(f"\n{Fore.RED}[!] Cannot reach target: {target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Check the URL and network connectivity.{Style.RESET_ALL}")
        sys.exit(1)

    if not args.quiet:
        print(f"{Fore.GREEN}[+] Target is reachable (HTTP {resp.status_code}){Style.RESET_ALL}")

    if not args.quiet:
        print(f"\n{Fore.CYAN}[*] Detecting WAF/CDN...{Style.RESET_ALL}")
        waf_list = detect_waf(session)
        if waf_list:
            print(f"  {Fore.YELLOW}[!] WAF Detected: {', '.join(waf_list)}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}[+] No WAF detected{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[*] Analyzing technology stack...{Style.RESET_ALL}")
        tech_stack = analyze_tech_stack(session)
        print_tech_stack(tech_stack)

    if config.auth_url:
        if not args.quiet:
            print(f"\n{Fore.CYAN}[*] Authenticating...{Style.RESET_ALL}")
        if not session.authenticate():
            print(f"{Fore.YELLOW}[!] Proceeding without authentication{Style.RESET_ALL}")

    session.start_time = time.time()

    crawler = ConcurrentCrawler(session)
    crawler.crawl()

    if not args.quiet:
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  RUNNING VULNERABILITY SCANS ({len(selected_modules)} modules){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    progress = ProgressTracker(len(selected_modules), quiet=args.quiet)

    for mod_key in selected_modules:
        if mod_key in ALL_MODULES:
            name, module = ALL_MODULES[mod_key]
            try:
                if args.verbose:
                    print(f"\n  {Fore.CYAN}[>] Running: {name}{Style.RESET_ALL}")
                module.run(session)
            except Exception as e:
                print(f"\n  {Fore.RED}[!] Module '{name}' error: {e}{Style.RESET_ALL}")
            progress.update(name)

    progress.finish()

    if args.api_scan:
        scan_api_endpoints(session)

    session.end_time = time.time()
    duration = session.end_time - session.start_time

    scan_file = save_scan_results(session)
    if args.verbose:
        print(f"\n{Fore.CYAN}[*] Scan results saved to: {scan_file}{Style.RESET_ALL}")

    diff_data = None
    if args.diff:
        previous = load_previous_scan(target)
        if previous:
            diff_data = compute_diff(previous, session)
            if not args.quiet and not args.json_output:
                print_diff(diff_data)
        elif not args.quiet:
            print(f"\n{Fore.YELLOW}[*] No previous scan found for comparison.{Style.RESET_ALL}")

    compliance_data = None
    if args.compliance:
        compliance_data = generate_compliance_report(session)
        if not args.quiet and not args.json_output:
            print_compliance_summary(compliance_data)

    if not args.quiet and not args.json_output:
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print_summary(session)

    from scanner.core import _sanitize_path

    if args.json_output or args.json_file:
        json_data = _build_json_output(session, duration, diff_data, compliance_data)
        if args.json_output:
            original_stdout.write(json.dumps(json_data, indent=2) + "\n")
            original_stdout.flush()
        if args.json_file:
            json_path = _sanitize_path(args.json_file)
            with open(json_path, "w") as jf:
                json.dump(json_data, jf, indent=2)
            if not args.quiet:
                print(f"{Fore.GREEN}[+] JSON report saved to: {json_path}{Style.RESET_ALL}")

    html_path = _sanitize_path(args.output)
    report_path = generate_html_report(session, html_path, compliance_data)
    if not args.quiet:
        print(f"\n{Fore.GREEN}[+] HTML report saved to: {report_path}{Style.RESET_ALL}")

    if args.pdf:
        pdf_out = _sanitize_path(args.pdf)
        pdf_path = generate_pdf_report(session, pdf_out, compliance_data)
        if not args.quiet:
            print(f"{Fore.GREEN}[+] PDF report saved to: {pdf_path}{Style.RESET_ALL}")

    if not args.quiet:
        print(f"{Fore.CYAN}[*] Scan completed in {duration:.1f} seconds{Style.RESET_ALL}\n")

    if args.ci:
        code = _ci_exit_code(session, args.severity_threshold)
        sys.exit(code)


if __name__ == "__main__":
    main()
