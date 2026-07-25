"""Tests for scanner modules: importability, interface, and functional checks."""

import importlib
import os

import pytest

MODULE_FILES = [
    f[:-3]
    for f in os.listdir(os.path.join(os.path.dirname(__file__), "..", "scanner", "modules"))
    if f.endswith(".py") and f != "__init__.py"
]


class TestModuleImport:
    """Verify that every module file can be imported and has the expected interface."""

    @pytest.mark.parametrize("module_name", MODULE_FILES)
    def test_module_importable(self, module_name):
        mod = importlib.import_module(f"scanner.modules.{module_name}")
        assert mod is not None

    @pytest.mark.parametrize("module_name", MODULE_FILES)
    def test_module_has_run(self, module_name):
        mod = importlib.import_module(f"scanner.modules.{module_name}")
        assert hasattr(mod, "run"), f"scanner.modules.{module_name} is missing a run() function"
        assert callable(mod.run)

    @pytest.mark.parametrize("module_name", MODULE_FILES)
    def test_run_accepts_session(self, module_name):
        import inspect
        mod = importlib.import_module(f"scanner.modules.{module_name}")
        sig = inspect.signature(mod.run)
        params = list(sig.parameters.keys())
        assert len(params) >= 1, f"run() in {module_name} should accept at least one parameter (ScanSession)"

    def test_total_module_count(self):
        assert len(MODULE_FILES) == 43, f"Expected 43 modules, found {len(MODULE_FILES)}"


class TestHeadersModule:
    """Run the headers module against the test server and verify findings."""

    def test_finds_missing_headers(self, scan_session):
        from scanner.modules.headers import run
        run(scan_session)

        titles = [f.title for f in scan_session.findings]
        # The test server deliberately omits these headers
        assert any("Content-Security-Policy" in t for t in titles), (
            "headers module should detect missing Content-Security-Policy"
        )
        assert any("X-Frame-Options" in t for t in titles), (
            "headers module should detect missing X-Frame-Options"
        )
        assert any("X-Content-Type-Options" in t for t in titles), (
            "headers module should detect missing X-Content-Type-Options"
        )


class TestXssModule:
    """Run the XSS module against the test server and verify detection."""

    def test_finds_reflected_xss(self, scan_session_with_crawl):
        from scanner.modules.xss import run
        run(scan_session_with_crawl)

        xss_findings = [f for f in scan_session_with_crawl.findings if f.module == "xss"]
        assert len(xss_findings) > 0, "XSS module should detect reflected XSS on /xss?q= endpoint"
        assert any("XSS" in f.title for f in xss_findings)
        assert all(f.severity.value in ("HIGH", "CRITICAL") for f in xss_findings)
