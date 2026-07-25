"""Tests for scanner.core module."""

import os

import pytest

from scanner.core import (
    Finding,
    Severity,
    ScanConfig,
    ScanSession,
    _redact_sensitive,
    shell_quote,
    build_curl,
    _is_private_ip,
    _domain_matches,
    _sanitize_path,
)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class TestSeverity:
    def test_enum_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.INFO.value == "INFO"

    def test_score_ordering(self):
        assert Severity.CRITICAL.score > Severity.HIGH.score
        assert Severity.HIGH.score > Severity.MEDIUM.score
        assert Severity.MEDIUM.score > Severity.LOW.score
        assert Severity.LOW.score > Severity.INFO.score

    def test_colors_are_strings(self):
        for s in Severity:
            assert isinstance(s.color, str)
            assert len(s.color) > 0


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class TestFinding:
    def test_creation_minimal(self):
        f = Finding(
            title="Test",
            severity=Severity.LOW,
            description="desc",
            evidence="ev",
            remediation="rem",
            url="http://example.com",
            module="test",
        )
        assert f.title == "Test"
        assert f.severity == Severity.LOW
        assert f.confirmed is False
        assert f.confidence == "Tentative"

    def test_confirmed_finding(self):
        f = Finding(
            title="Confirmed",
            severity=Severity.HIGH,
            description="d",
            evidence="e",
            remediation="r",
            url="http://x.com",
            module="m",
            confirmed=True,
        )
        assert f.confirmed is True
        assert f.confidence == "Confirmed"


# ---------------------------------------------------------------------------
# _redact_sensitive
# ---------------------------------------------------------------------------

class TestRedactSensitive:
    def test_empty_string(self):
        assert _redact_sensitive("") == ""

    def test_none_returns_empty(self):
        assert _redact_sensitive(None) == ""

    def test_password_param(self):
        result = _redact_sensitive("user=admin&password=secret123")
        assert "secret123" not in result
        assert "[REDACTED]" in result

    def test_token_param(self):
        result = _redact_sensitive("token=abc123def")
        assert "abc123def" not in result

    def test_api_key_param(self):
        result = _redact_sensitive("api_key=mysecretkey")
        assert "mysecretkey" not in result

    def test_authorization_header(self):
        result = _redact_sensitive("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9")
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert "[REDACTED]" in result

    def test_non_sensitive_unchanged(self):
        text = "page=1&sort=name"
        assert _redact_sensitive(text) == text


# ---------------------------------------------------------------------------
# shell_quote
# ---------------------------------------------------------------------------

class TestShellQuote:
    def test_simple_string(self):
        assert shell_quote("hello") == "'hello'"

    def test_string_with_spaces(self):
        assert shell_quote("hello world") == "'hello world'"

    def test_string_with_single_quote(self):
        result = shell_quote("it's")
        # The result should safely handle the single quote
        assert "it" in result
        assert "s" in result

    def test_string_with_semicolon(self):
        result = shell_quote("test;rm -rf /")
        assert result.startswith("'")
        assert result.endswith("'")

    def test_empty_string(self):
        assert shell_quote("") == "''"


# ---------------------------------------------------------------------------
# build_curl
# ---------------------------------------------------------------------------

class TestBuildCurl:
    def test_basic_get(self):
        result = build_curl("GET", "http://example.com")
        assert "curl" in result
        assert "-X GET" in result
        assert "example.com" in result

    def test_with_headers(self):
        result = build_curl("GET", "http://example.com", headers={"Accept": "text/html"})
        assert "-H" in result
        assert "Accept: text/html" in result

    def test_authorization_header_redacted(self):
        result = build_curl("GET", "http://example.com", headers={"Authorization": "Bearer secret"})
        assert "secret" not in result
        assert "[REDACTED]" in result

    def test_cookie_header_redacted(self):
        result = build_curl("GET", "http://example.com", headers={"Cookie": "session=abc123"})
        assert "abc123" not in result
        assert "[REDACTED]" in result

    def test_with_data(self):
        result = build_curl("POST", "http://example.com", data="key=value")
        assert "-d" in result
        assert "key=value" in result

    def test_sensitive_url_redacted(self):
        result = build_curl("GET", "http://example.com?password=hunter2")
        assert "hunter2" not in result


# ---------------------------------------------------------------------------
# ScanConfig
# ---------------------------------------------------------------------------

class TestScanConfig:
    def test_defaults(self):
        config = ScanConfig(target="http://example.com")
        assert config.threads == 10
        assert config.timeout == 10
        assert config.depth == 3
        assert config.verify_ssl is True
        assert config.follow_redirects is True
        assert config.cookies == {}
        assert config.headers == {}
        assert config.scan_modules == []
        assert config.proxy == ""
        assert config.rate_limit == 0

    def test_custom_values(self):
        config = ScanConfig(
            target="http://test.com",
            threads=5,
            timeout=30,
            depth=7,
        )
        assert config.threads == 5
        assert config.timeout == 30
        assert config.depth == 7


# ---------------------------------------------------------------------------
# ScanSession.add_finding deduplication
# ---------------------------------------------------------------------------

class TestScanSessionAddFinding:
    def test_add_finding(self, scan_session):
        f = Finding(
            title="Test Finding",
            severity=Severity.LOW,
            description="desc",
            evidence="ev",
            remediation="rem",
            url=scan_session.config.target,
            module="test",
        )
        scan_session.add_finding(f)
        assert len(scan_session.findings) == 1

    def test_deduplication(self, scan_session):
        f1 = Finding(
            title="Duplicate",
            severity=Severity.LOW,
            description="desc1",
            evidence="ev1",
            remediation="rem1",
            url=scan_session.config.target,
            module="test",
        )
        f2 = Finding(
            title="Duplicate",
            severity=Severity.HIGH,
            description="desc2",
            evidence="ev2",
            remediation="rem2",
            url=scan_session.config.target,
            module="test",
        )
        scan_session.add_finding(f1)
        scan_session.add_finding(f2)
        assert len(scan_session.findings) == 1

    def test_different_titles_not_deduplicated(self, scan_session):
        f1 = Finding(
            title="Finding A",
            severity=Severity.LOW,
            description="d",
            evidence="e",
            remediation="r",
            url=scan_session.config.target,
            module="test",
        )
        f2 = Finding(
            title="Finding B",
            severity=Severity.LOW,
            description="d",
            evidence="e",
            remediation="r",
            url=scan_session.config.target,
            module="test",
        )
        scan_session.add_finding(f1)
        scan_session.add_finding(f2)
        assert len(scan_session.findings) == 2


# ---------------------------------------------------------------------------
# _is_private_ip
# ---------------------------------------------------------------------------

class TestIsPrivateIp:
    def test_localhost(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_private_10(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_private_192(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_private_172(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_invalid_hostname(self):
        result = _is_private_ip("this.host.does.not.exist.invalid")
        assert result is False


# ---------------------------------------------------------------------------
# _domain_matches
# ---------------------------------------------------------------------------

class TestDomainMatches:
    def test_same_domain(self):
        assert _domain_matches("http://example.com/path", "http://example.com/other") is True

    def test_different_domain(self):
        assert _domain_matches("http://a.com/path", "http://b.com/path") is False

    def test_case_insensitive(self):
        assert _domain_matches("http://Example.COM/path", "http://example.com/path") is True

    def test_with_port(self):
        assert _domain_matches("http://example.com:8080/p", "http://example.com:8080/q") is True

    def test_different_port(self):
        assert _domain_matches("http://example.com:8080/p", "http://example.com:9090/p") is False


# ---------------------------------------------------------------------------
# _sanitize_path
# ---------------------------------------------------------------------------

class TestSanitizePath:
    def test_normal_path(self):
        result = _sanitize_path("report.html")
        assert os.path.isabs(result)
        assert result.endswith("report.html")

    def test_traversal_blocked(self):
        result = _sanitize_path("../../../../etc/passwd")
        # Should not resolve to /etc/passwd; should stay in cwd
        assert not result.startswith("/etc")
        assert "passwd" in result
