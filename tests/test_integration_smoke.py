"""
Integration smoke test: full scan against vulnapp fixture.

This test validates the entire pipeline works end-to-end:
1. Start vulnapp.py fixture
2. Run a full scan with all modules
3. Assert minimum expected findings across categories
"""

import os
import socket
import subprocess
import sys
import time
import unittest

from scanner.core import ScanConfig, ScanSession
from scanner.concurrent import ConcurrentCrawler
# Import modules directly
from scanner.modules import (
    xss, sqli, ssti, cmd_injection, nosql_injection, ldap_injection, lfi,
    idor, cors, csrf, open_redirect, ssrf, xxe, second_order, jwt,
    prototype_pollution, http_method, zero_day, directory, headers,
    cache_poisoning, hpp, websocket_security, graphql,
    mass_assignment, race_condition, request_smuggling, business_logic,
    host_header, deserialization, file_upload, fingerprint, dom_xss,
    subdomain, subdomain_takeover, portscan, ssl_check, cve_check,
    oauth_misconfig, auth, misconfig, session_security, info_disclosure,
)


VULNAPP_PORT = 15791  # Different port to avoid conflicts with other tests
VULNAPP_URL = f"http://127.0.0.1:{VULNAPP_PORT}"
VULNAPP_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "vulnapp.py")


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Poll host:port until it accepts connections or timeout elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


class VulnAppFixture(unittest.TestCase):
    """Base class that starts/stops vulnapp.py as a subprocess."""

    _proc = None

    @classmethod
    def setUpClass(cls):
        cls._proc = subprocess.Popen(
            [sys.executable, VULNAPP_PATH, str(VULNAPP_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if not _wait_for_port("127.0.0.1", VULNAPP_PORT, timeout=10):
            cls._proc.kill()
            raise RuntimeError(
                f"vulnapp did not start on port {VULNAPP_PORT} within 10s"
            )

    @classmethod
    def tearDownClass(cls):
        if cls._proc:
            cls._proc.terminate()
            try:
                cls._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls._proc.kill()


class TestFullScanSmoke(VulnAppFixture):
    """Full scan smoke test against vulnapp fixture."""

    def test_full_scan_finds_expected_vulnerabilities(self):
        """Run full scan and assert we find vulnerabilities across multiple categories."""
        config = ScanConfig(
            target=VULNAPP_URL,
            threads=10,
            timeout=10,
            depth=3,
            user_agent='ReconStrike-SmokeTest/1.0',
            extra_urls=[],
            scan_modules=[],  # Run all modules
        )
        session = ScanSession(config)
        crawler = ConcurrentCrawler(session)
        crawler.crawl()

        # Run all available modules
        module_list = [
            xss, sqli, ssti, cmd_injection, nosql_injection, ldap_injection, lfi,
            idor, cors, csrf, open_redirect, ssrf, xxe, second_order, jwt,
            prototype_pollution, http_method, zero_day, directory, headers,
            cache_poisoning, hpp, websocket_security, graphql,
            mass_assignment, race_condition, request_smuggling, business_logic,
            host_header, deserialization, file_upload, fingerprint, dom_xss,
            subdomain, subdomain_takeover, portscan, ssl_check, cve_check,
            oauth_misconfig, auth, misconfig, session_security, info_disclosure,
        ]

        for module in module_list:
            try:
                module.run(session)
            except Exception as e:
                # Log but don't fail - we're testing the pipeline, not every module
                print(f"Module {module.__name__} raised: {e}")

        # Assert minimum findings across categories
        findings_by_module = {}
        for f in session.findings:
            findings_by_module.setdefault(f.module, 0)
            findings_by_module[f.module] += 1

        print("\n=== Smoke Test Findings Summary ===")
        for module, count in sorted(findings_by_module.items()):
            print(f"  {module}: {count}")
        print(f"  Total: {len(session.findings)}")

        # Critical: at least some findings overall
        assert len(session.findings) >= 20, f"Expected >=20 total findings, got {len(session.findings)}"

        # Injection category (should find XSS, SQLi, NoSQL at minimum)
        injection_modules = ['xss', 'sqli', 'nosql_injection', 'ldap_injection', 'lfi']
        injection_findings = sum(findings_by_module.get(m, 0) for m in injection_modules)
        assert injection_findings >= 3, f"Expected >=3 injection findings, got {injection_findings}"

        # Auth/Access Control (IDOR, CORS, CSRF, Open Redirect, JWT)
        auth_modules = ['idor', 'cors', 'csrf', 'open_redirect', 'jwt']
        auth_findings = sum(findings_by_module.get(m, 0) for m in auth_modules)
        assert auth_findings >= 1, f"Expected >=1 auth findings, got {auth_findings}"

        # Server-side (SSRF, XXE, Second Order, Prototype Pollution, HTTP Methods)
        server_modules = ['ssrf', 'xxe', 'second_order', 'prototype_pollution', 'http_method']
        server_findings = sum(findings_by_module.get(m, 0) for m in server_modules)
        assert server_findings >= 2, f"Expected >=2 server-side findings, got {server_findings}"

        # Discovery (Directory, Headers, Cache Poisoning, HPP, WebSocket, GraphQL, Mass Assignment, Race Condition, Request Smuggling, Business Logic, Host Header, Deserialization, File Upload, Fingerprint, DOM XSS, Subdomain, Subdomain Takeover, Portscan, SSL Check, CVE Check, OAuth Misconfig, Auth, Misconfig, Session Security, Info Disclosure)
        discovery_modules = ['directory', 'headers', 'cache_poisoning', 'hpp', 'websocket_security', 'graphql', 'mass_assignment', 'race_condition', 'request_smuggling', 'business_logic', 'host_header', 'deserialization', 'file_upload', 'fingerprint', 'dom_xss', 'subdomain', 'subdomain_takeover', 'portscan', 'ssl_check', 'cve_check', 'oauth_misconfig', 'auth', 'misconfig', 'session_security', 'info_disclosure']
        discovery_findings = sum(findings_by_module.get(m, 0) for m in discovery_modules)
        assert discovery_findings >= 5, f"Expected >=5 discovery findings, got {discovery_findings}"

        # No module errors
        error_findings = [f for f in session.findings if "Module Error" in f.title]
        assert len(error_findings) == 0, f"Module errors detected: {[f.evidence for f in error_findings]}"


if __name__ == "__main__":
    unittest.main()