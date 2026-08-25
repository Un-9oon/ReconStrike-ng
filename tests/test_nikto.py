"""Tests for the Nikto-style misconfiguration scanner."""

import re
import unittest
from unittest.mock import MagicMock, patch

from scanner.core import Severity
from scanner.nikto.signatures import (
    SIGNATURES, get_all_signatures, get_signatures_by_category,
    get_signatures_by_severity, get_signature_count,
    CAT_GIT, CAT_CONFIG, CAT_DEBUG, CAT_ADMIN, CAT_BACKUP,
)
from scanner.nikto.scanner import FPFingerprint, _check_signature


class TestSignatureDatabase(unittest.TestCase):
    """Tests for the signature database."""

    def test_signatures_not_empty(self):
        sigs = get_all_signatures()
        self.assertGreater(len(sigs), 50, "Should have 50+ signatures")

    def test_all_signatures_have_required_fields(self):
        for sig in SIGNATURES:
            self.assertIn("path", sig)
            self.assertIn("method", sig)
            self.assertIn("status", sig)
            self.assertIn("severity", sig)
            self.assertIn("category", sig)
            self.assertIn("description", sig)
            self.assertTrue(sig["path"].startswith("/"),
                            f"Path should start with /: {sig['path']}")
            self.assertIsInstance(sig["status"], list)
            self.assertIn(sig["method"], ("GET", "HEAD", "POST"))
            self.assertIsInstance(sig["severity"], Severity)

    def test_signature_count(self):
        self.assertEqual(get_signature_count(), len(SIGNATURES))

    def test_filter_by_category(self):
        git_sigs = get_signatures_by_category(CAT_GIT)
        self.assertTrue(len(git_sigs) > 0)
        for sig in git_sigs:
            self.assertEqual(sig["category"], CAT_GIT)

    def test_filter_by_severity(self):
        critical = get_signatures_by_severity(Severity.CRITICAL)
        self.assertTrue(len(critical) > 0)
        for sig in critical:
            self.assertEqual(sig["severity"], Severity.CRITICAL)

    def test_all_match_patterns_are_valid_regex(self):
        for sig in SIGNATURES:
            if sig["match"]:
                try:
                    re.compile(sig["match"])
                except re.error as e:
                    self.fail(f"Invalid regex in {sig['path']}: {e}")

    def test_known_critical_paths_present(self):
        paths = {s["path"] for s in SIGNATURES}
        self.assertIn("/.git/config", paths)
        self.assertIn("/.env", paths)
        self.assertIn("/phpinfo.php", paths)
        self.assertIn("/phpmyadmin/", paths)


class TestFPFingerprint(unittest.TestCase):
    """Tests for the false-positive fingerprint system."""

    def test_uncalibrated_returns_false(self):
        fp = FPFingerprint()
        mock_resp = MagicMock()
        mock_resp.text = "some content"
        self.assertFalse(fp.is_false_positive(mock_resp, {}))

    def test_body_hash_match_is_fp(self):
        import hashlib
        body = "<html><body>Page Not Found</body></html>"
        body_hash = hashlib.md5(body.encode()).hexdigest()

        fp = FPFingerprint()
        fp.calibrated = True
        fp.fp_body_hashes.add(body_hash)

        mock_resp = MagicMock()
        mock_resp.text = body
        mock_resp.status_code = 200

        self.assertTrue(fp.is_false_positive(mock_resp, {}))

    def test_content_match_overrides_fp(self):
        """If body matches signature pattern, it's NOT an FP even with soft-404."""
        import hashlib

        fp = FPFingerprint()
        fp.calibrated = True
        fp.fp_status_codes.add(200)
        fp.fp_body_lengths.add(100)

        mock_resp = MagicMock()
        mock_resp.text = "[core] repositoryformatversion = 0"
        mock_resp.status_code = 200

        sig = {"match": r"\[core\]"}
        self.assertFalse(fp.is_false_positive(mock_resp, sig))

    def test_soft_404_title_detected(self):
        fp = FPFingerprint()
        fp.calibrated = True
        fp.fp_status_codes.add(200)

        mock_resp = MagicMock()
        mock_resp.text = "<html><title>Page Not Found</title><body>Oops</body></html>"
        mock_resp.status_code = 200

        self.assertTrue(fp.is_false_positive(mock_resp, {}))


class TestCheckSignature(unittest.TestCase):
    """Tests for individual signature checking."""

    def test_hit_with_matching_status_and_content(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "[core]\n\trepositoryformatversion = 0"
        mock_session.get.return_value = mock_resp

        sig = {
            "path": "/.git/config", "method": "GET", "status": [200],
            "match": r"\[core\]", "severity": Severity.CRITICAL,
            "category": "source_control", "description": "Git config exposed",
            "cwe": "CWE-538",
        }
        fp = FPFingerprint()

        result = _check_signature(mock_session, "http://example.com", sig, fp)
        self.assertIsNotNone(result)
        self.assertEqual(result["path"], "/.git/config")
        self.assertEqual(result["severity"], Severity.CRITICAL)

    def test_miss_when_status_doesnt_match(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_session.get.return_value = mock_resp

        sig = {
            "path": "/.git/config", "method": "GET", "status": [200],
            "match": r"\[core\]", "severity": Severity.CRITICAL,
            "category": "source_control", "description": "test",
            "cwe": "CWE-538",
        }
        fp = FPFingerprint()

        result = _check_signature(mock_session, "http://example.com", sig, fp)
        self.assertIsNone(result)

    def test_miss_when_content_doesnt_match(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html>Welcome to our website</html>"
        mock_session.get.return_value = mock_resp

        sig = {
            "path": "/.git/config", "method": "GET", "status": [200],
            "match": r"\[core\]", "severity": Severity.CRITICAL,
            "category": "source_control", "description": "test",
            "cwe": "CWE-538",
        }
        fp = FPFingerprint()

        result = _check_signature(mock_session, "http://example.com", sig, fp)
        self.assertIsNone(result)

    def test_head_method_used(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_session.head.return_value = mock_resp

        sig = {
            "path": "/backup.zip", "method": "HEAD", "status": [200],
            "match": None, "severity": Severity.CRITICAL,
            "category": "backup_file", "description": "test",
            "cwe": "CWE-538",
        }
        fp = FPFingerprint()

        result = _check_signature(mock_session, "http://example.com", sig, fp)
        self.assertIsNotNone(result)
        mock_session.head.assert_called_once()


if __name__ == "__main__":
    unittest.main()
