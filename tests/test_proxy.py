"""Tests for the DAST proxy components (CA manager, history, passive analyzer)."""

import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner.core import Severity
from scanner.proxy.history import HistoryDB, HttpTransaction
from scanner.proxy.passive_analyzer import (
    analyze_transaction, PassiveFinding,
    REQUIRED_SECURITY_HEADERS, SENSITIVE_PATTERNS, ERROR_PATTERNS,
)


class TestHistoryDB(unittest.TestCase):
    """Tests for the request/response history database."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_history.db")
        self.db = HistoryDB(db_path=self.db_path)

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.tmpdir)

    def test_log_and_retrieve(self):
        txn = HttpTransaction(
            method="GET",
            url="https://example.com/api/test",
            host="example.com",
            path="/api/test",
            request_headers={"User-Agent": "TestBot"},
            status_code=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"status": "ok"}',
            content_type="application/json",
            content_length=16,
            latency_ms=42.0,
        )
        txn_id = self.db.log_transaction(txn)
        self.assertGreater(txn_id, 0)

        retrieved = self.db.get_transaction(txn_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.method, "GET")
        self.assertEqual(retrieved.url, "https://example.com/api/test")
        self.assertEqual(retrieved.status_code, 200)

    def test_search_by_url(self):
        for i in range(5):
            self.db.log_transaction(HttpTransaction(
                method="GET", url=f"https://example.com/page{i}",
                host="example.com", status_code=200,
            ))
        results = self.db.search(url_pattern="page3")
        self.assertEqual(len(results), 1)
        self.assertIn("page3", results[0].url)

    def test_search_by_status(self):
        self.db.log_transaction(HttpTransaction(
            method="GET", url="https://example.com/ok", status_code=200,
        ))
        self.db.log_transaction(HttpTransaction(
            method="GET", url="https://example.com/err", status_code=500,
        ))
        results = self.db.search(status_code=500)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status_code, 500)

    def test_get_count(self):
        for i in range(3):
            self.db.log_transaction(HttpTransaction(
                method="GET", url=f"https://ex.com/{i}", status_code=200,
            ))
        self.assertEqual(self.db.get_count(), 3)

    def test_clear(self):
        self.db.log_transaction(HttpTransaction(
            method="GET", url="https://ex.com", status_code=200,
        ))
        self.db.clear()
        self.assertEqual(self.db.get_count(), 0)

    def test_export_har(self):
        self.db.log_transaction(HttpTransaction(
            method="GET", url="https://example.com/test",
            host="example.com", status_code=200,
            response_body="hello", content_type="text/plain",
            timestamp=time.time(),
        ))
        har_path = os.path.join(self.tmpdir, "export.har")
        self.db.export_har(har_path)

        with open(har_path) as f:
            har = json.load(f)

        self.assertIn("log", har)
        self.assertEqual(har["log"]["creator"]["name"], "ReconStrike DAST Proxy")
        self.assertEqual(len(har["log"]["entries"]), 1)
        self.assertEqual(har["log"]["entries"][0]["request"]["url"],
                         "https://example.com/test")

    def test_nonexistent_transaction(self):
        result = self.db.get_transaction(99999)
        self.assertIsNone(result)


class TestPassiveAnalyzer(unittest.TestCase):
    """Tests for the passive traffic analyzer."""

    def _make_txn(self, **kwargs) -> HttpTransaction:
        defaults = {
            "method": "GET",
            "url": "https://example.com/",
            "host": "example.com",
            "status_code": 200,
            "content_type": "text/html",
            "request_headers": {},
            "response_headers": {},
            "response_body": "<html><body>Hello</body></html>",
        }
        defaults.update(kwargs)
        return HttpTransaction(**defaults)

    def test_missing_security_headers(self):
        txn = self._make_txn(response_headers={})
        findings = analyze_transaction(txn)
        header_findings = [f for f in findings if f.category == "missing_header"]
        self.assertGreater(len(header_findings), 0)

        header_names = {f.title.split(": ")[1] for f in header_findings}
        self.assertIn("Strict-Transport-Security", header_names)
        self.assertIn("Content-Security-Policy", header_names)

    def test_no_header_findings_when_all_present(self):
        headers = {h: "value" for h in REQUIRED_SECURITY_HEADERS}
        txn = self._make_txn(response_headers=headers)
        findings = analyze_transaction(txn)
        header_findings = [f for f in findings if f.category == "missing_header"]
        self.assertEqual(len(header_findings), 0)

    def test_insecure_cookie_no_secure_flag(self):
        txn = self._make_txn(
            response_headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly"},
        )
        findings = analyze_transaction(txn)
        cookie_findings = [f for f in findings if f.category == "insecure_cookie"]
        titles = [f.title for f in cookie_findings]
        self.assertTrue(any("Secure" in t for t in titles))

    def test_insecure_cookie_no_httponly(self):
        txn = self._make_txn(
            response_headers={"Set-Cookie": "session=abc123; Path=/; Secure"},
        )
        findings = analyze_transaction(txn)
        cookie_findings = [f for f in findings if f.category == "insecure_cookie"]
        titles = [f.title for f in cookie_findings]
        self.assertTrue(any("HttpOnly" in t for t in titles))

    def test_sensitive_data_aws_key(self):
        txn = self._make_txn(
            content_type="application/json",
            response_body='{"key": "AKIAIOSFODNN7EXAMPLE", "secret": "test"}',
        )
        findings = analyze_transaction(txn)
        data_findings = [f for f in findings if f.category == "data_leakage"]
        self.assertTrue(any("AWS" in f.title for f in data_findings))

    def test_sensitive_data_private_key(self):
        txn = self._make_txn(
            response_body="-----BEGIN RSA PRIVATE KEY-----\nMIIEow...",
        )
        findings = analyze_transaction(txn)
        data_findings = [f for f in findings if f.category == "data_leakage"]
        self.assertTrue(any("Private Key" in f.title for f in data_findings))

    def test_stack_trace_detection(self):
        txn = self._make_txn(
            response_body='<html>Traceback (most recent call last):\n  File "app.py"</html>',
        )
        findings = analyze_transaction(txn)
        disclosure = [f for f in findings if f.category == "info_disclosure"]
        self.assertTrue(any("Python" in f.title for f in disclosure))

    def test_cors_wildcard(self):
        txn = self._make_txn(
            response_headers={"Access-Control-Allow-Origin": "*"},
        )
        findings = analyze_transaction(txn)
        cors = [f for f in findings if f.category == "cors"]
        self.assertTrue(len(cors) > 0)

    def test_cors_wildcard_with_credentials_is_critical(self):
        txn = self._make_txn(
            response_headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        findings = analyze_transaction(txn)
        cors = [f for f in findings if f.category == "cors"]
        self.assertTrue(any(f.severity == Severity.HIGH for f in cors))

    def test_server_version_disclosure(self):
        txn = self._make_txn(
            response_headers={"Server": "Apache/2.4.49 (Ubuntu)"},
        )
        findings = analyze_transaction(txn)
        version_findings = [f for f in findings if f.category == "version_disclosure"]
        self.assertTrue(len(version_findings) > 0)

    def test_jwt_in_url(self):
        txn = self._make_txn(
            url="https://example.com/api?token=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature",
        )
        findings = analyze_transaction(txn)
        token_findings = [f for f in findings if f.category == "token_leakage"]
        self.assertTrue(len(token_findings) > 0)

    def test_no_findings_for_clean_response(self):
        txn = self._make_txn(
            content_type="image/png",
            response_headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin",
                "Permissions-Policy": "camera=()",
                "X-XSS-Protection": "0",
            },
            response_body="",
        )
        findings = analyze_transaction(txn)
        # Image response shouldn't trigger header or body checks
        self.assertEqual(len(findings), 0)


class TestCAManager(unittest.TestCase):
    """Tests for the CA certificate manager."""

    def test_ca_generation(self):
        try:
            from scanner.proxy.ca_manager import generate_root_ca, generate_domain_cert
        except ImportError:
            self.skipTest("cryptography library not installed")

        tmpdir = tempfile.mkdtemp()
        try:
            key_path, cert_path = generate_root_ca(ca_dir=tmpdir)
            self.assertTrue(key_path.exists())
            self.assertTrue(cert_path.exists())

            # Should not regenerate on second call
            key_path2, cert_path2 = generate_root_ca(ca_dir=tmpdir)
            self.assertEqual(key_path, key_path2)

            # Generate a domain cert
            cert_pem, key_pem = generate_domain_cert(
                "example.com", key_path, cert_path,
                cache_dir=os.path.join(tmpdir, "domains"),
            )
            self.assertIn(b"BEGIN CERTIFICATE", cert_pem)
            self.assertIn(b"BEGIN", key_pem)

            # Cached domain cert
            cert_pem2, key_pem2 = generate_domain_cert(
                "example.com", key_path, cert_path,
                cache_dir=os.path.join(tmpdir, "domains"),
            )
            self.assertEqual(cert_pem, cert_pem2)
        finally:
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    unittest.main()
