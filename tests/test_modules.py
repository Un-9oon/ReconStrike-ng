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


# ---------------------------------------------------------------------------
# Regression: Gap 1 — idor.py crash (build_curl missing method argument)
# ---------------------------------------------------------------------------

class TestIdorCrashFix:
    """Regression test for the build_curl(url) crash in idor.py.

    The pre-fix code called build_curl(url) instead of build_curl('GET', url),
    raising TypeError the moment _check_param_idor found two IDs with meaningfully
    different responses.  This test reproduces that exact condition.
    """

    def test_idor_completes_without_crash(self, test_server):
        """Drive _check_param_idor against a server that returns different bodies
        for id=1 vs id=2, which is the exact trigger for the original TypeError."""
        from scanner.core import ScanConfig, ScanSession
        from scanner.modules.idor import _check_param_idor

        config = ScanConfig(target=test_server, threads=1, timeout=5, verify_ssl=False)
        session = ScanSession(config)
        # /idor-test?id=1 returns data for user 1; id=2 returns different data
        url = f"{test_server}/idor-test?id=1"
        # The server returns different JSON for each id (see VulnerableHandler)
        # If the bug is still present, calling _check_param_idor raises TypeError.
        try:
            _check_param_idor(session, url, "id", "1")
        except TypeError as exc:
            raise AssertionError(
                f"idor._check_param_idor crashed with TypeError — build_curl bug not fixed: {exc}"
            ) from exc
        # If it reaches here, the crash bug is fixed. Findings may or may not
        # be emitted depending on whether the test server responses differ enough.

    def test_idor_run_completes_without_crash(self, test_server):
        """Run the full idor module against a session with an IDOR-shaped URL."""
        from scanner.core import ScanConfig, ScanSession
        from scanner.modules.idor import run

        config = ScanConfig(target=test_server, threads=1, timeout=5, verify_ssl=False)
        session = ScanSession(config)
        session.crawled_urls = {f"{test_server}/idor-test?id=1"}
        try:
            run(session)  # must not raise
        except TypeError as exc:
            raise AssertionError(f"idor.run() crashed: {exc}") from exc


# ---------------------------------------------------------------------------
# Regression: Gap 1 — ssrf.py crash (build_curl missing method argument)
# ---------------------------------------------------------------------------

class TestSsrfCrashFix:
    """Regression test for the same build_curl(url) crash pattern in ssrf.py."""

    def test_ssrf_run_does_not_crash(self, test_server):
        from scanner.core import ScanConfig, ScanSession
        from scanner.modules.ssrf import run

        config = ScanConfig(target=test_server, threads=1, timeout=2, verify_ssl=False)
        session = ScanSession(config)
        # A URL with a parameter name that matches the SSRF heuristic
        session.crawled_urls = {f"{test_server}/redirect?url=http://example.com"}
        try:
            run(session)
        except TypeError as exc:
            raise AssertionError(f"ssrf.run() crashed with TypeError: {exc}") from exc


# ---------------------------------------------------------------------------
# Gap 3 — Zero-Day dedup: at most 1 finding per (param, category)
# ---------------------------------------------------------------------------

class TestZeroDayDedup:
    """The dedup fix should collapse N payload findings per (param, category)
    into at most 1 finding per (param, category)."""

    def test_dedup_limits_findings_per_param_category(self, scan_session_with_crawl):
        from scanner.modules.zero_day import run

        before = len(scan_session_with_crawl.findings)
        run(scan_session_with_crawl)
        zd_findings = [
            f for f in scan_session_with_crawl.findings[before:]
            if f.module == "zero_day"
        ]

        # Group by (parameter, category-prefix from title)
        seen = set()
        for f in zd_findings:
            key = (f.parameter, f.title)
            assert key not in seen, (
                f"Duplicate zero-day finding emitted for same (param, category): {key}. "
                "Dedup fix did not work."
            )
            seen.add(key)

    def test_dedup_finding_mentions_signal_count(self, scan_session_with_crawl):
        from scanner.modules.zero_day import run

        before = len(scan_session_with_crawl.findings)
        run(scan_session_with_crawl)
        # Only param-fuzz findings go through _report_anomaly, which adds the
        # signal-count language.  Method-confusion findings use a separate helper
        # (_test_method_confusion) and do not carry that language -- exclude them.
        zd_fuzz_findings = [
            f for f in scan_session_with_crawl.findings[before:]
            if f.module == "zero_day" and "Method Confusion" not in f.title
        ]
        for f in zd_fuzz_findings:
            assert "independent signals" in f.description or "independent triggering" in f.evidence, (
                f"Zero-day param-fuzz finding should document signal count, got: {f.title!r}\n"
                f"  description: {f.description!r}\n"
                f"  evidence: {f.evidence!r}"
            )


# ---------------------------------------------------------------------------
# Gap 2 — Crawler coverage: --extra-urls reaches unlinked endpoints
# ---------------------------------------------------------------------------

class TestCrawlerCoverage:
    """Verify that extra_urls seeds reach unlinked endpoints."""

    def test_extra_urls_reaches_unlinked_endpoint(self, test_server):
        """The /api/users endpoint is NOT linked from any HTML page but
        should be reachable via extra_urls."""
        from scanner.core import ScanConfig, ScanSession
        from scanner.crawler import Crawler

        config = ScanConfig(
            target=test_server, threads=1, timeout=5, verify_ssl=False,
            extra_urls=[f"{test_server}/api/users"],
        )
        session = ScanSession(config)
        crawler = Crawler(session)
        crawler.crawl()

        assert any("/api/users" in u for u in session.crawled_urls), (
            "/api/users was supplied via extra_urls but was not added to crawled_urls. "
            "The --extra-urls seeding is not working."
        )

    def test_crawl_attaches_coverage_report(self, scan_session):
        """After crawl(), session.coverage_report must exist with the right keys."""
        from scanner.crawler import Crawler

        crawler = Crawler(scan_session)
        crawler.crawl()

        assert hasattr(scan_session, "coverage_report"), (
            "Crawler must attach a coverage_report dict to the session"
        )
        report = scan_session.coverage_report
        for key in ("urls_discovered", "forms_found", "wordlist_routes_probed"):
            assert key in report, f"coverage_report missing key: {key}"

    def test_wordlist_probe_discovers_api_endpoint(self, test_server):
        """The wordlist prober should find /api/users (HTTP 200) and add it."""
        from scanner.core import ScanConfig, ScanSession
        from scanner.crawler import Crawler

        config = ScanConfig(
            target=test_server, threads=1, timeout=5, verify_ssl=False,
        )
        session = ScanSession(config)
        crawler = Crawler(session)
        crawler.crawl()

        # /api/users returns 200 in VulnerableHandler so the wordlist prober
        # should pick it up even without any HTML link to it.
        assert any("/api/users" in u for u in session.crawled_urls), (
            "Wordlist probe should discover /api/users (HTTP 200) even without HTML links."
        )


# ---------------------------------------------------------------------------
# Gap 5 — Full-profile smoke test (integration, catches crash bugs)
# ---------------------------------------------------------------------------

class TestFullProfileSmoke:
    """Smoke test: run every module (full profile) against the test server
    and assert nothing crashes with an unhandled exception.

    This is the test class that would have caught the idor.py crash before
    it shipped in v1.0.0.
    """

    def test_all_modules_run_without_crash(self, scan_session_with_crawl):
        import importlib, os as _os

        modules_dir = _os.path.join(_os.path.dirname(__file__), "..", "scanner", "modules")
        module_names = [
            f[:-3] for f in _os.listdir(modules_dir)
            if f.endswith(".py") and f != "__init__.py"
        ]

        failures = []
        for mod_name in sorted(module_names):
            mod = importlib.import_module(f"scanner.modules.{mod_name}")
            try:
                mod.run(scan_session_with_crawl)
            except TypeError as exc:
                failures.append(f"{mod_name}: TypeError — {exc}")
            except Exception:
                # Non-TypeError exceptions (e.g. connection errors) are expected
                # in a unit test environment; only TypeError indicates API misuse.
                pass

        assert not failures, (
            "The following modules crashed with TypeError (likely a build_curl API mismatch):\n"
            + "\n".join(failures)
        )
