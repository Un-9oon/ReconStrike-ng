"""
Determinism tests for ReconStrike modules.

These tests ensure that the same module run against the same target
produces identical finding counts across multiple runs, preventing
regression of non-deterministic detection logic.
"""

import pytest
import json
import os
from scanner.core import ScanConfig, ScanSession
from scanner.concurrent import ConcurrentCrawler
from scanner.modules import idor, cors, hpp, cache_poisoning


class TestModuleDeterminism:
    """Test that modules produce deterministic results across repeated runs."""

    @pytest.fixture(scope="class")
    def test_server(self):
        """The vulnapp.py fixture runs on port 15789."""
        return "http://127.0.0.1:15789"

    def _run_module(self, test_server, module_func, extra_urls):
        """Run a single module and return finding count."""
        config = ScanConfig(
            target=test_server,
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

    def test_idor_deterministic(self, test_server):
        """IDOR module should return consistent finding counts."""
        extra_urls = [
            f"{test_server}/user?id=1",
            f"{test_server}/user?id=2",
        ]
        counts = []
        for _ in range(3):
            count = self._run_module(test_server, idor.run, extra_urls)
            counts.append(count)
        # All runs should return the same count
        assert len(set(counts)) == 1, f"IDOR finding counts varied: {counts}"
        # Should find at least 1 IDOR
        assert counts[0] >= 1, f"IDOR should find at least 1 vulnerability, got {counts}"

    def test_cors_deterministic(self, test_server):
        """CORS module should return consistent finding counts."""
        extra_urls = [f"{test_server}/api/data"]
        counts = []
        for _ in range(3):
            count = self._run_module(test_server, cors.run, extra_urls)
            counts.append(count)
        assert len(set(counts)) == 1, f"CORS finding counts varied: {counts}"
        assert counts[0] >= 1, f"CORS should find at least 1 vulnerability, got {counts}"

    def test_hpp_deterministic(self, test_server):
        """HPP module should return consistent finding counts."""
        extra_urls = [f"{test_server}/xss?q=test"]
        counts = []
        for _ in range(3):
            count = self._run_module(test_server, hpp.run, extra_urls)
            counts.append(count)
        assert len(set(counts)) == 1, f"HPP finding counts varied: {counts}"
        assert counts[0] >= 1, f"HPP should find at least 1 vulnerability, got {counts}"

    def test_cache_poisoning_deterministic(self, test_server):
        """Cache poisoning module should return consistent finding counts."""
        extra_urls = [f"{test_server}/cached"]
        counts = []
        for _ in range(3):
            count = self._run_module(test_server, cache_poisoning.run, extra_urls)
            counts.append(count)
        assert len(set(counts)) == 1, f"Cache poisoning finding counts varied: {counts}"
        assert counts[0] >= 1, f"Cache poisoning should find at least 1 vulnerability, got {counts}"