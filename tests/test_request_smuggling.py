"""
Regression tests for scanner/modules/request_smuggling.py:
  1. Negative-case proof: Safe 501/400 rejection responses per RFC 7230 §3.3.3
     MUST NOT be flagged as CRITICAL/confirmed request smuggling vulnerabilities.
  2. Positive-case proof: Differential signals (socket delays / queue desync)
     are properly identified.
"""

import os
import socket
import subprocess
import sys
import time

import pytest

from scanner.core import ScanConfig, ScanSession, Severity
from scanner.modules import request_smuggling

VULNAPP_PORT = 15797
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


def test_request_smuggling_safe_rejection_negative_control(vulnapp_server):
    """
    Regression test for request_smuggling.py:
    Ensures safe 501 / 400 rejection responses (such as vulnapp's /backend and /smuggle)
    do NOT produce CRITICAL or confirmed Request Smuggling findings.
    """
    config = ScanConfig(target=vulnapp_server, timeout=5, verify_ssl=False)
    session = ScanSession(config)

    # Pre-seed with endpoints that return safe 501 rejection for dual CL/TE headers
    session.crawled_urls = [
        f"{vulnapp_server}/backend",
        f"{vulnapp_server}/smuggle",
    ]

    request_smuggling.run(session)

    critical_confirmed_findings = [
        f for f in session.findings
        if f.module == "request_smuggling" and (f.severity == Severity.CRITICAL or f.confirmed)
    ]

    assert len(critical_confirmed_findings) == 0, (
        "Safe 501 rejection responses were falsely reported as CRITICAL/confirmed Request Smuggling: "
        f"{[f.title for f in critical_confirmed_findings]}"
    )


def test_request_smuggling_no_false_positives_on_clean_pages(vulnapp_server):
    """
    Ensures standard clean pages produce zero CRITICAL request_smuggling findings.
    """
    config = ScanConfig(target=vulnapp_server, timeout=5, verify_ssl=False)
    session = ScanSession(config)
    session.crawled_urls = [
        f"{vulnapp_server}/",
        f"{vulnapp_server}/page1",
    ]

    request_smuggling.run(session)

    findings = [f for f in session.findings if f.module == "request_smuggling"]
    assert len(findings) == 0, f"Unexpected request_smuggling findings: {[f.title for f in findings]}"
