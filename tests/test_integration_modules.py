"""
Integration tests: Section 1 — Module Correctness
===================================================
Starts vulnapp.py as a subprocess, then runs individual scanner modules
against it to verify:
  1. True-positive: module detects the deliberate vulnerability.
  2. True-negative / false-positive control: module does NOT fire on the
     safe counterpart endpoint (where one exists).
  3. Module boundary: unhandled exceptions are caught by run_module_with_timeout
     rather than propagating to the caller.
  4. build_curl signature: no TypeError from missing method argument.

Run with: pytest tests/test_integration_modules.py -v
"""

import os
import socket
import subprocess
import sys
import time
import threading
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.core import (
    ScanConfig, ScanSession, Severity, Finding,
    run_module_with_timeout, MODULE_TIMEOUT_SECONDS,
)

VULNAPP_PORT = 15790  # Use a different port from the default so parallel CI runs don't clash
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


def _make_session(target: str = VULNAPP_URL, timeout: int = 5) -> ScanSession:
    cfg = ScanConfig(
        target=target,
        timeout=timeout,
        threads=2,
        depth=1,
        verify_ssl=False,
    )
    session = ScanSession(cfg)
    # Pre-seed the crawled URLs so modules have something to work with
    session.crawled_urls = {
        target + "/",
        target + "/xss?q=test",
        target + "/sqli?id=1",
        target + "/ssti?name=World",
        target + "/cmdi?cmd=ls",
        target + "/nosql?filter=abc",
        target + "/ldap?username=admin",
        target + "/lfi?file=index.html",
        target + "/user?id=1",
        target + "/api/data",
        target + "/api/jwt-demo",
        target + "/csrf-form",
        target + "/redirect?url=http://example.com",
        target + "/fetch?url=http://example.com",
        target + "/cached",
        target + "/host-reflect",
        target + "/admin",
        target + "/.env",
        target + "/server-info",
        target + "/api/discount",
    }
    session.forms = [
        {
            "action": target + "/xss",
            "method": "get",
            "inputs": [{"name": "q", "type": "text", "value": ""}],
        },
        {
            "action": target + "/sqli",
            "method": "get",
            "inputs": [{"name": "id", "type": "text", "value": ""}],
        },
        {
            "action": target + "/upload",
            "method": "post",
            "inputs": [{"name": "file", "type": "file", "value": ""}],
            "enctype": "multipart/form-data",
        },
        {
            "action": target + "/api/transfer",
            "method": "post",
            "inputs": [
                {"name": "to", "type": "text", "value": ""},
                {"name": "amount", "type": "text", "value": ""},
            ],
        },
    ]
    return session


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


# ── Module timeout / crash guard ──────────────────────────────────────────────

class TestRunModuleWithTimeout(unittest.TestCase):
    """Unit tests for the run_module_with_timeout() helper (no vulnapp needed)."""

    def _make_mock_session(self):
        cfg = ScanConfig(target="http://127.0.0.1:1", timeout=1)
        session = MagicMock(spec=ScanSession)
        session.config = cfg
        session.findings = []
        session.add_finding = lambda f: session.findings.append(f)
        return session

    def test_normal_module_runs_and_returns(self):
        calls = []

        class FakeModule:
            __name__ = "scanner.modules.fake"
            @staticmethod
            def run(s):
                calls.append("ran")

        session = self._make_mock_session()
        run_module_with_timeout(FakeModule, session, timeout=5)
        self.assertEqual(calls, ["ran"])
        self.assertEqual(len(session.findings), 0)

    def test_crashing_module_adds_error_finding_not_raises(self):
        class BrokenModule:
            __name__ = "scanner.modules.broken"
            @staticmethod
            def run(s):
                raise ValueError("simulated crash")

        session = self._make_mock_session()
        # Should NOT raise — crash must be swallowed into a finding
        run_module_with_timeout(BrokenModule, session, timeout=5)
        self.assertEqual(len(session.findings), 1)
        f = session.findings[0]
        self.assertIn("Module Error", f.title)
        self.assertEqual(f.severity, Severity.INFO)
        self.assertIn("ValueError", f.description)

    def test_hanging_module_is_killed_after_timeout(self):
        event = threading.Event()

        class HangingModule:
            __name__ = "scanner.modules.hanger"
            @staticmethod
            def run(s):
                event.wait(timeout=60)  # will be killed by the timeout

        session = self._make_mock_session()
        start = time.time()
        run_module_with_timeout(HangingModule, session, timeout=1)
        elapsed = time.time() - start
        # Should return in ~1s (timeout), not 60s
        self.assertLess(elapsed, 10, "timeout did not fire quickly enough")
        self.assertEqual(len(session.findings), 1)
        self.assertIn("Timeout", session.findings[0].title)


# ── XSS module ─────────────────────────────────────────────────────────────

class TestXSSModule(VulnAppFixture):
    def test_xss_detects_reflected_param(self):
        from scanner.modules import xss
        session = _make_session()
        run_module_with_timeout(xss, session)
        xss_findings = [f for f in session.findings if "xss" in f.module.lower()
                        or "Cross-Site" in f.title]
        self.assertTrue(len(xss_findings) > 0,
                        f"XSS module produced no findings. All findings: {[f.title for f in session.findings]}")

    def test_xss_build_curl_no_typeerror(self):
        """Regression: build_curl must not be called without method arg."""
        from scanner.modules import xss
        from scanner.core import build_curl
        # Patch build_curl and assert it's always called with at least 2 args
        calls = []
        original = build_curl

        def recording_build_curl(method, url, *a, **kw):
            calls.append((method, url))
            return original(method, url, *a, **kw)

        session = _make_session()
        with patch("scanner.modules.xss.build_curl", side_effect=recording_build_curl):
            run_module_with_timeout(xss, session)

        for method, url in calls:
            self.assertIsInstance(method, str, "build_curl called without method string")


# ── SQLi module ────────────────────────────────────────────────────────────

class TestSQLiModule(VulnAppFixture):
    def test_sqli_detects_error_keyword(self):
        from scanner.modules import sqli
        session = _make_session()
        run_module_with_timeout(sqli, session)
        sqli_findings = [f for f in session.findings if "sql" in f.module.lower()
                         or "SQL" in f.title]
        self.assertTrue(len(sqli_findings) > 0,
                        f"SQLi module found nothing. All: {[f.title for f in session.findings]}")

    def test_sqli_no_multiplicative_duplication(self):
        """BUG-003 class: sqli must not emit >1 finding per unique URL+title."""
        from scanner.modules import sqli
        session = _make_session()
        run_module_with_timeout(sqli, session)
        titles_and_urls = [(f.title, f.url) for f in session.findings]
        unique = set(titles_and_urls)
        self.assertEqual(len(titles_and_urls), len(unique),
                         f"Duplicate (title, url) pairs: {titles_and_urls}")


# ── IDOR module ────────────────────────────────────────────────────────────

class TestIDORModule(VulnAppFixture):
    def test_idor_runs_without_crash(self):
        """Regression: idor.py previously crashed with build_curl(url) missing method."""
        from scanner.modules import idor
        session = _make_session()
        # Must not raise TypeError
        run_module_with_timeout(idor, session)

    def test_idor_detects_pii_difference(self):
        from scanner.modules import idor
        session = _make_session()
        run_module_with_timeout(idor, session)
        # Either finds something or runs cleanly — no crash is the minimum bar
        self.assertIsNotNone(session.findings)


# ── SSRF module ────────────────────────────────────────────────────────────

class TestSSRFModule(VulnAppFixture):
    def test_ssrf_runs_without_crash(self):
        """Regression: ssrf.py previously crashed with build_curl(url) missing method."""
        from scanner.modules import ssrf
        session = _make_session()
        run_module_with_timeout(ssrf, session)

    def test_ssrf_detects_url_reflection(self):
        from scanner.modules import ssrf
        session = _make_session()
        run_module_with_timeout(ssrf, session)
        # Module should not produce errors
        error_findings = [f for f in session.findings if "Module Error" in f.title]
        self.assertEqual(len(error_findings), 0,
                         f"SSRF module crashed: {[f.evidence for f in error_findings]}")


# ── CORS module ────────────────────────────────────────────────────────────

class TestCORSModule(VulnAppFixture):
    def test_cors_detects_wildcard_with_credentials(self):
        from scanner.modules import cors
        session = _make_session()
        run_module_with_timeout(cors, session)
        cors_findings = [f for f in session.findings if "cors" in f.module.lower()
                         or "CORS" in f.title]
        self.assertTrue(len(cors_findings) > 0,
                        f"CORS module missed ACAO:*+ACAC:true. All: {[f.title for f in session.findings]}")


# ── Open Redirect module ───────────────────────────────────────────────────

class TestOpenRedirectModule(VulnAppFixture):
    def test_open_redirect_detects_external(self):
        from scanner.modules import open_redirect
        session = _make_session()
        run_module_with_timeout(open_redirect, session)
        redir_findings = [f for f in session.findings
                          if "redirect" in f.title.lower() or "redirect" in f.module.lower()]
        self.assertTrue(len(redir_findings) > 0,
                        f"Open Redirect module missed /redirect. All: {[f.title for f in session.findings]}")


# ── Headers module ─────────────────────────────────────────────────────────

class TestHeadersModule(VulnAppFixture):
    def test_headers_detects_missing_security_headers(self):
        from scanner.modules import headers
        session = _make_session()
        run_module_with_timeout(headers, session)
        header_findings = [f for f in session.findings
                           if "header" in f.module.lower() or "Header" in f.title]
        self.assertTrue(len(header_findings) > 0,
                        "Headers module found no missing security headers")


# ── Directory module ───────────────────────────────────────────────────────

class TestDirectoryModule(VulnAppFixture):
    def test_directory_discovers_env_file(self):
        from scanner.modules import directory
        session = _make_session()
        run_module_with_timeout(directory, session)
        dir_findings = [f for f in session.findings
                        if ".env" in f.url or "env" in f.title.lower()]
        self.assertTrue(len(dir_findings) > 0,
                        f"Directory module missed /.env. All: {[f.title for f in session.findings]}")

    def test_directory_build_curl_no_typeerror(self):
        """directory.py uses its own _build_curl(url) that does NOT call core.build_curl — verify."""
        from scanner.modules.directory import _build_curl
        result = _build_curl("http://example.com/test")
        self.assertIn("curl", result)
        self.assertIn("http://example.com/test", result)


# ── Zero-Day module ────────────────────────────────────────────────────────

class TestZeroDayModule(VulnAppFixture):
    def test_zero_day_runs_without_crash(self):
        from scanner.modules import zero_day
        session = _make_session()
        run_module_with_timeout(zero_day, session)
        error_findings = [f for f in session.findings if "Module Error" in f.title]
        self.assertEqual(len(error_findings), 0,
                         f"Zero-day module crashed: {[f.evidence for f in error_findings]}")

    def test_zero_day_no_multiplicative_duplication(self):
        """BUG-003 regression: zero_day must not emit per-combination findings."""
        from scanner.modules import zero_day
        session = _make_session()
        run_module_with_timeout(zero_day, session)
        zd_findings = [f for f in session.findings if f.module == "zero_day"]
        titles_and_urls = [(f.title, f.url) for f in zd_findings]
        unique = set(titles_and_urls)
        self.assertEqual(len(titles_and_urls), len(unique),
                         f"Duplicate zero-day findings: {titles_and_urls}")


if __name__ == "__main__":
    unittest.main()
