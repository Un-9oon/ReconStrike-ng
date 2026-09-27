"""
Regression tests for scanner/modules/host_header.py:
  1. Deduplication key verification (iteration order dependency).
  2. String interpolation verification (real host/url values vs {placeholder} text).
"""

import os
import socket
import subprocess
import sys
import time

import pytest

from scanner.core import ScanConfig, ScanSession
from scanner.modules import host_header

VULNAPP_PORT = 15798
VULNAPP_URL = f"http://127.0.0.1:{VULNAPP_PORT}"
VULNAPP_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "vulnapp.py")


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def vulnapp_server():
    proc = subprocess.Popen(
        [sys.executable, VULNAPP_PATH, str(VULNAPP_PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if not _wait_for_port("127.0.0.1", VULNAPP_PORT, timeout=10.0):
        proc.kill()
        proc.wait()
        pytest.fail(f"vulnapp.py failed to start on port {VULNAPP_PORT}")

    yield VULNAPP_URL

    proc.terminate()
    try:
        proc.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def test_host_header_dedup_key_and_iteration_order(vulnapp_server):
    """
    Regression test for host_header.py dedup-key bug:
    Ensures host_header scans all crawled URLs even when the vulnerable URL is placed LAST
    in iteration order, and attributes findings to the exact vulnerable URL.
    """
    config = ScanConfig(target=vulnapp_server, timeout=5, verify_ssl=False)
    session = ScanSession(config)

    # 3 URLs with the vulnerable /host-reflect deliberately placed LAST
    clean_url_1 = f"{vulnapp_server}/"
    clean_url_2 = f"{vulnapp_server}/server-info"
    vuln_url = f"{vulnapp_server}/host-reflect"

    # Use a list/tuple to guarantee iteration order has vuln_url last
    session.crawled_urls = [clean_url_1, clean_url_2, vuln_url]

    host_header.run(session)

    assert len(session.findings) > 0, "host_header module failed to detect host header injection"

    # Verify that a finding is specifically attributed to vuln_url (/host-reflect)
    vuln_findings = [f for f in session.findings if vuln_url in f.url]
    assert len(vuln_findings) > 0, (
        f"Finding was not attributed to {vuln_url}. Findings found: {[f.url for f in session.findings]}"
    )

    # Ensure clean URLs were not false-positively marked as host header injection source
    for finding in session.findings:
        assert clean_url_1 not in finding.url or vuln_url in finding.url
        assert clean_url_2 not in finding.url or vuln_url in finding.url


def test_host_header_string_interpolation(vulnapp_server):
    """
    Regression test for host_header.py string interpolation bug:
    Ensures Finding.description and Finding.evidence contain real host/URL values
    and NEVER contain literal '{original_host}', '{url}', '{EVIL_HOST}', '{header_name}', etc.
    """
    config = ScanConfig(target=vulnapp_server, timeout=5, verify_ssl=False)
    session = ScanSession(config)
    session.crawled_urls = [f"{vulnapp_server}/host-reflect"]

    host_header.run(session)

    assert len(session.findings) > 0, "No findings generated for /host-reflect"

    for finding in session.findings:
        desc = finding.description
        evidence = finding.evidence

        # Check real values are present
        assert f"127.0.0.1:{VULNAPP_PORT}" in evidence or f"127.0.0.1:{VULNAPP_PORT}" in desc or "evil-host-header-test.com" in evidence or "evil-host-header-test.com" in desc, (
            f"Real host/port not found in finding evidence or description. Evidence: {evidence}, Desc: {desc}"
        )

        # Assert absence of literal placeholders
        forbidden_placeholders = [
            "{original_host}",
            "{url}",
            "{EVIL_HOST}",
            "{header_name}",
            "{reflection[",
            "{host}",
            "{parsed.path}",
        ]
        for ph in forbidden_placeholders:
            assert ph not in desc, f"Literal placeholder '{ph}' found in finding description: {desc}"
            assert ph not in evidence, f"Literal placeholder '{ph}' found in finding evidence: {evidence}"
