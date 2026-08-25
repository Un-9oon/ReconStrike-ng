"""Tests for scanner.reporter module."""

import os
import tempfile
import time

import pytest

from scanner.core import Finding, Severity, ScanConfig, ScanSession
from scanner.reporter import generate_html_report, print_summary


@pytest.fixture
def session_with_findings():
    """Create a ScanSession with some sample findings."""
    config = ScanConfig(target="http://example.com", scan_modules=["headers", "xss"])
    session = ScanSession(config)
    session.start_time = time.time() - 10
    session.end_time = time.time()
    session.crawled_urls = {"http://example.com/", "http://example.com/page1"}

    session.findings.append(Finding(
        title="Missing CSP",
        severity=Severity.MEDIUM,
        description="Content-Security-Policy is missing",
        evidence="No CSP header",
        remediation="Add CSP header",
        url="http://example.com",
        module="headers",
        cwe="CWE-16",
        confirmed=True,
    ))
    session.findings.append(Finding(
        title="Reflected XSS",
        severity=Severity.HIGH,
        description="XSS in search param",
        evidence="<script>alert(1)</script> reflected",
        remediation="Encode output",
        url="http://example.com/search?q=test",
        module="xss",
        cwe="CWE-79",
        confirmed=True,
        parameter="q",
        payload="<script>alert(1)</script>",
    ))
    return session


@pytest.fixture
def empty_session():
    config = ScanConfig(target="http://example.com", scan_modules=[])
    session = ScanSession(config)
    session.start_time = time.time() - 1
    session.end_time = time.time()
    return session


class TestGenerateHtmlReport:
    def test_produces_html_file(self, session_with_findings, tmp_path):
        output = str(tmp_path / "report.html")
        result = generate_html_report(session_with_findings, output)
        assert os.path.exists(result)
        with open(result) as f:
            html = f.read()
        assert "<!DOCTYPE html>" in html
        assert "ReconStrike-ng" in html

    def test_report_contains_findings(self, session_with_findings, tmp_path):
        output = str(tmp_path / "report.html")
        generate_html_report(session_with_findings, output)
        with open(output) as f:
            html = f.read()
        assert "Missing CSP" in html
        assert "Reflected XSS" in html
        assert "CWE-79" in html

    def test_report_with_no_findings(self, empty_session, tmp_path):
        output = str(tmp_path / "report.html")
        generate_html_report(empty_session, output)
        with open(output) as f:
            html = f.read()
        assert "No vulnerabilities found" in html

    def test_report_has_valid_html_structure(self, session_with_findings, tmp_path):
        output = str(tmp_path / "report.html")
        generate_html_report(session_with_findings, output)
        with open(output) as f:
            html = f.read()
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html


class TestPrintSummary:
    def test_no_crash_empty_findings(self, empty_session, capsys):
        print_summary(empty_session)
        captured = capsys.readouterr()
        assert "No vulnerabilities found" in captured.out

    def test_no_crash_with_findings(self, session_with_findings, capsys):
        print_summary(session_with_findings)
        captured = capsys.readouterr()
        assert "SCAN SUMMARY" in captured.out
        assert "Total:" in captured.out

    def test_shows_severity_counts(self, session_with_findings, capsys):
        print_summary(session_with_findings)
        captured = capsys.readouterr()
        assert "HIGH" in captured.out
        assert "MEDIUM" in captured.out
