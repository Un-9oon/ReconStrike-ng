"""Tests for scanner.diff_scan module."""

import json
import os
import time

import pytest

from scanner.core import Finding, Severity, ScanConfig, ScanSession
from scanner.diff_scan import _safe_domain, save_scan_results, load_previous_scan, compute_diff


class TestSafeDomain:
    def test_basic_url(self):
        assert _safe_domain("http://example.com") == "example.com"

    def test_url_with_port(self):
        assert _safe_domain("http://example.com:8080") == "example.com_8080"

    def test_url_with_path(self):
        result = _safe_domain("http://example.com/path/to/page")
        assert result == "example.com"

    def test_empty_string(self):
        result = _safe_domain("")
        assert result == "unknown"

    def test_special_chars_stripped(self):
        result = _safe_domain("http://ex@mple.com")
        # @ should be in netloc for http://ex@mple.com => netloc is "ex@mple.com"
        # The regex strips @, so we just verify it doesn't crash and returns valid chars
        assert all(c.isalnum() or c in "._-" for c in result)


class TestSaveAndLoadScan:
    def test_round_trip(self, tmp_path, monkeypatch):
        # Override the history dir to use tmp_path
        monkeypatch.setattr("scanner.diff_scan.SCAN_HISTORY_DIR", str(tmp_path))

        config = ScanConfig(target="http://roundtrip-test.com")
        session = ScanSession(config)
        session.start_time = time.time() - 5
        session.end_time = time.time()
        session.crawled_urls = {"http://roundtrip-test.com/", "http://roundtrip-test.com/page"}
        session.findings.append(Finding(
            title="Test Finding",
            severity=Severity.LOW,
            description="desc",
            evidence="ev",
            remediation="rem",
            url="http://roundtrip-test.com/",
            module="test",
        ))

        filepath = save_scan_results(session)
        assert os.path.exists(filepath)

        loaded = load_previous_scan("http://roundtrip-test.com")
        assert loaded is not None
        assert loaded["target"] == "http://roundtrip-test.com"
        assert len(loaded["findings"]) == 1
        assert loaded["findings"][0]["title"] == "Test Finding"

    def test_load_nonexistent(self, tmp_path, monkeypatch):
        monkeypatch.setattr("scanner.diff_scan.SCAN_HISTORY_DIR", str(tmp_path))
        result = load_previous_scan("http://does-not-exist.com")
        assert result is None


class TestComputeDiff:
    def test_new_findings(self):
        previous = {
            "findings": [
                {"title": "Old Bug", "url": "http://x.com", "module": "m", "severity": "LOW"},
            ]
        }
        config = ScanConfig(target="http://x.com")
        session = ScanSession(config)
        session.findings.append(Finding(
            title="Old Bug", severity=Severity.LOW, description="d",
            evidence="e", remediation="r", url="http://x.com", module="m",
        ))
        session.findings.append(Finding(
            title="New Bug", severity=Severity.HIGH, description="d",
            evidence="e", remediation="r", url="http://x.com", module="m",
        ))

        diff = compute_diff(previous, session)
        assert len(diff["new"]) == 1
        assert len(diff["fixed"]) == 0
        assert len(diff["persistent"]) == 1

    def test_fixed_findings(self):
        previous = {
            "findings": [
                {"title": "Was Fixed", "url": "http://x.com", "module": "m", "severity": "HIGH"},
                {"title": "Still There", "url": "http://x.com", "module": "m", "severity": "LOW"},
            ]
        }
        config = ScanConfig(target="http://x.com")
        session = ScanSession(config)
        session.findings.append(Finding(
            title="Still There", severity=Severity.LOW, description="d",
            evidence="e", remediation="r", url="http://x.com", module="m",
        ))

        diff = compute_diff(previous, session)
        assert len(diff["new"]) == 0
        assert len(diff["fixed"]) == 1
        assert diff["fixed"][0]["title"] == "Was Fixed"
        assert len(diff["persistent"]) == 1

    def test_empty_scans(self):
        previous = {"findings": []}
        config = ScanConfig(target="http://x.com")
        session = ScanSession(config)

        diff = compute_diff(previous, session)
        assert len(diff["new"]) == 0
        assert len(diff["fixed"]) == 0
        assert len(diff["persistent"]) == 0
        assert diff["current_total"] == 0
        assert diff["previous_total"] == 0
