"""
Determinism tests for ReconStrike modules.

These tests ensure that the same module run against the same target
produces identical finding counts across multiple runs, preventing
regression of non-deterministic detection logic.
"""

import os
import socket
import subprocess
import sys
import time
import unittest
import pytest

from scanner.core import ScanConfig, ScanSession
from scanner.concurrent import ConcurrentCrawler
from scanner.modules import idor, cors, hpp, cache_poisoning

VULNAPP_PORT = 15789
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


class TestModuleDeterminism(VulnAppFixture):
    """Test that modules produce deterministic results across repeated runs."""

    def _run_module(self, module_func, extra_urls):
        """Run a single module and return finding count."""
        config = ScanConfig(
            target=VULNAPP_URL,
            threads=10,
            timeout=10,
            depth=3,
            user_agent='Test',
            extra_urls=extra_urls,
            scan_modules=[],
        )
        session = ScanSession(config)
        crawler = ConcurrentCrawler(session)
        crawler.crawl()
        module_func(session)
        return len(session.findings)

    def test_idor_deterministic(self):
        """IDOR module should return consistent finding counts."""
        extra_urls = [
            f"{VULNAPP_URL}/user?id=1",
            f"{VULNAPP_URL}/user?id=2",
        ]
        counts = []
        for _ in range(3):
            count = self._run_module(idor.run, extra_urls)
            counts.append(count)
        # All runs should return the same count
        assert len(set(counts)) == 1, f"IDOR finding counts varied: {counts}"
        # Should find at least 1 IDOR
        assert counts[0] >= 1, f"IDOR should find at least 1 vulnerability, got {counts}"

    def test_cors_deterministic(self):
        """CORS module should return consistent finding counts."""
        extra_urls = [f"{VULNAPP_URL}/api/data"]
        counts = []
        for _ in range(3):
            count = self._run_module(cors.run, extra_urls)
            counts.append(count)
        assert len(set(counts)) == 1, f"CORS finding counts varied: {counts}"
        assert counts[0] >= 1, f"CORS should find at least 1 vulnerability, got {counts}"

    def test_hpp_deterministic(self):
        """HPP module should return consistent finding counts."""
        extra_urls = [f"{VULNAPP_URL}/xss?q=test"]
        counts = []
        for _ in range(3):
            count = self._run_module(hpp.run, extra_urls)
            counts.append(count)
        assert len(set(counts)) == 1, f"HPP finding counts varied: {counts}"
        assert counts[0] >= 1, f"HPP should find at least 1 vulnerability, got {counts}"

    def test_cache_poisoning_deterministic(self):
        """Cache poisoning module should return consistent finding counts."""
        extra_urls = [f"{VULNAPP_URL}/cached"]
        counts = []
        for _ in range(3):
            count = self._run_module(cache_poisoning.run, extra_urls)
            counts.append(count)
        assert len(set(counts)) == 1, f"Cache poisoning finding counts varied: {counts}"
        assert counts[0] >= 1, f"Cache poisoning should find at least 1 vulnerability, got {counts}"