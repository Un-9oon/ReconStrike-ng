"""
HTTP Request Smuggling Scanner Module for ReconStrike-ng

Tests for CL.TE and TE.CL Request Smuggling, Transfer-Encoding obfuscation,
and HTTP version mismatches in proxy chains.

Per RFC 7230 §3.3.3:
Rejecting dual Content-Length / Transfer-Encoding requests with a 4xx or 5xx
error (such as 400 Bad Request or 501 Not Implemented) is SAFE, RECOMMENDED behavior.
This module relies strictly on differential timing signals (socket hangs) or
response desynchronization (queue poisoning) to identify true vulnerabilities.
"""

import re
import time
from urllib.parse import urlparse

import requests

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession, build_curl

CLTE_PAYLOADS = [
    {
        "name": "CL.TE basic",
        "headers": {"Content-Length": "6", "Transfer-Encoding": "chunked"},
        "body": "0\r\n\r\nX",
        "description": (
            "CL header (6) covers the trailing 'X', but chunked TE sees "
            "'0\\r\\n\\r\\n' as terminator. If frontend uses CL and backend "
            "uses TE, the 'X' becomes a smuggled prefix."
        ),
    },
    {
        "name": "CL.TE with smuggled GET",
        "headers": {"Content-Length": "30", "Transfer-Encoding": "chunked"},
        "body": "0\r\n\r\nGET /404-smuggled-probe HTTP/1.1\r\n\r\n",
        "description": (
            "Smuggles a partial GET after the chunked terminator. Backend "
            "may route 'GET /404-smuggled-probe' and return 404 instead of the expected response."
        ),
    },
]

TECL_PAYLOADS = [
    {
        "name": "TE.CL basic",
        "headers": {"Transfer-Encoding": "chunked", "Content-Length": "3"},
        "body": "1\r\nZ\r\n0\r\n\r\n",
        "description": (
            "Chunked body with CL set to 3. Frontend (TE) reads full body, "
            "backend (CL) reads only 3 bytes -- remainder is smuggled."
        ),
    },
]

TE_OBFUSCATION_HEADERS = [
    {"Transfer-Encoding": "xchunked"},
    {"Transfer-Encoding": " chunked"},
    {"Transfer-Encoding": "chunked", "Transfer-encoding": "x"},
    {"Transfer-Encoding": "chunked\r\nX: "},
    {"Transfer-Encoding": "chunks"},
    {"Transfer-Encoding": "chunked\x00"},
]

SAFE_REJECTION_CODES = (400, 403, 405, 501, 502, 503)


def _build_curl_smuggle(method, url, headers, body):
    cmd = "curl -k -X {} '{}'".format(method, url)
    for k, v in headers.items():
        cmd += " -H '{}: {}'".format(k, v)
    if body:
        escaped = body.replace("'", "'\\''").replace("\r", "\\r").replace("\n", "\\n")
        cmd += " --data-binary $'{}'".format(escaped)
    return cmd


def _smuggle_test(session: ScanSession, url: str, payloads: list, technique_label: str) -> None:
    """Common differential logic for CL.TE and TE.CL smuggling tests."""
    parsed = urlparse(url)

    for payload in payloads:
        try:
            headers = dict(payload["headers"])
            body = payload["body"]

            # Measure baseline response time & status
            start_base = time.time()
            baseline = session.get(url)
            base_time = time.time() - start_base

            if not baseline or baseline.status_code in SAFE_REJECTION_CODES:
                continue

            # Send probe request and measure elapsed time
            start_probe = time.time()
            timed_out = False
            resp = None
            try:
                resp = session.post(url, headers=headers, data=body.encode("latin-1"), timeout=5.0)
            except (requests.Timeout, requests.RequestException, OSError):
                timed_out = True
            probe_time = time.time() - start_probe

            # 1. Safe Rejection Check per RFC 7230 §3.3.3:
            # If server returns a 4xx/5xx rejection (400 Bad Request, 501 Not Implemented, etc.),
            # it is correctly rejecting dual CL/TE headers. THIS IS NOT A VULNERABILITY.
            if resp and resp.status_code in SAFE_REJECTION_CODES:
                continue

            smuggling_detected = False
            evidence_details = []

            # 2. Timing Differential Signal (Socket Hang):
            # If backend parses chunked TE while frontend uses CL (or vice versa), the backend
            # hangs waiting for chunk terminator, causing a significant delay vs baseline.
            if (probe_time >= base_time + 3.0) or (timed_out and base_time < 2.0):
                smuggling_detected = True
                evidence_details.append(
                    "Probe request delayed by {:.2f}s (baseline: {:.2f}s), indicating backend socket hang due to desynchronized header parsing".format(
                        probe_time, base_time
                    )
                )

            # 3. Follow-up Queue Poisoning Signal (Response Desynchronization):
            # Send follow-up request to check if the smuggled request payload was processed
            followup = session.get(url)
            if followup and baseline.status_code == 200:
                # If smuggled request was 'GET /404-smuggled-probe' and follow-up returns 404
                if followup.status_code == 404 and "GET /404-smuggled-probe" in body:
                    smuggling_detected = True
                    evidence_details.append(
                        "Follow-up request returned 404 Not Found matching smuggled probe URL 'GET /404-smuggled-probe' (baseline was 200 OK), confirming queue desynchronization"
                    )

            if not smuggling_detected or not evidence_details:
                continue

            curl_cmd = _build_curl_smuggle("POST", url, headers, body)
            header_lines = "\n".join("  {}: {}".format(k, v) for k, v in headers.items())
            indicator_lines = "\n".join("  - {}".format(d) for d in evidence_details)
            resp_status = resp.status_code if resp else "TIMED_OUT"

            session.add_finding(Finding(
                title="HTTP Request Smuggling ({})".format(payload["name"]),
                severity=Severity.CRITICAL,
                description=(
                    "The server at '{}' appears vulnerable to HTTP Request Smuggling "
                    "via {}. {} Empirical differential signals confirmed desynchronization. "
                    "This allows smuggling a second request inside the first, "
                    "potentially bypassing security controls, poisoning caches, or "
                    "hijacking other users' requests.".format(
                        parsed.netloc, payload["name"], payload["description"])
                ),
                evidence=(
                    "Target URL: {}\nTechnique: {}\nHeaders Sent:\n{}\n"
                    "Body (escaped): {}\nBaseline Status: {}\n"
                    "Smuggle Status: {}\nIndicators:\n{}".format(
                        url, payload["name"], header_lines, repr(body),
                        baseline.status_code, resp_status, indicator_lines)
                ),
                remediation=(
                    "1. Reject requests with both Content-Length and Transfer-Encoding.\n"
                    "2. Normalize requests in the frontend proxy before forwarding.\n"
                    "3. Use HTTP/2 end-to-end (binary framing eliminates this class).\n"
                    "4. Ensure all servers agree on request boundaries.\n"
                    "5. Disable connection reuse between frontend/backend as a stopgap."
                ),
                url=url,
                module="request_smuggling",
                cwe="CWE-444",
                confirmed=True,
                location="HTTP endpoint at {}".format(parsed.path or "/"),
                payload=repr(body),
                request_method="POST",
                request_headers=str(headers),
                request_body=repr(body),
                response_status=resp.status_code if resp else 0,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. POST to {} with conflicting CL/TE headers.\n"
                    "2. Headers: {}\n"
                    "3. Body (raw): {}\n"
                    "4. Measure differential response time or follow-up status.\n"
                    "5. Run: {}".format(url, headers, repr(body), curl_cmd)
                ),
                developer_fix=(
                    "Server/Proxy configuration for {}:\n\n"
                    "Reject ambiguous requests at the edge:\n"
                    "  Nginx: proxy_request_buffering on;\n"
                    "  HAProxy: option http-use-htx;\n"
                    "  Apache: block dual CL/TE headers via mod_security\n\n"
                    "Or upgrade to HTTP/2 end-to-end.".format(parsed.netloc)
                ),
                affected_component="HTTP request parsing at {}".format(parsed.netloc),
                references=(
                    "https://portswigger.net/web-security/request-smuggling | "
                    "https://cwe.mitre.org/data/definitions/444.html | "
                    "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn"
                ),
                detection_method=(
                    "Sent ambiguous CL/TE headers ({}) and detected differential signal: {}".format(
                        payload["name"], "; ".join(evidence_details))
                ),
            ))
            return
        except (requests.RequestException, OSError, ConnectionError) as e:
            logger.debug("request_smuggling %s: %s", technique_label, e)
            continue


def _test_te_obfuscation(session: ScanSession, url: str) -> None:
    """Test for Transfer-Encoding obfuscation bypasses."""
    parsed = urlparse(url)
    start_base = time.time()
    baseline = session.get(url)
    base_time = time.time() - start_base

    if not baseline or baseline.status_code in SAFE_REJECTION_CODES:
        return

    for te_headers in TE_OBFUSCATION_HEADERS:
        try:
            headers = dict(te_headers)
            headers["Content-Length"] = "5"
            body = "0\r\n\r\n"

            start_probe = time.time()
            resp = session.post(url, headers=headers, data=body.encode("latin-1"), timeout=5.0)
            probe_time = time.time() - start_probe

            if not resp:
                continue

            # Safe rejection check: 4xx/5xx rejection of malformed TE is SAFE behavior.
            if resp.status_code in SAFE_REJECTION_CODES:
                continue

            # Check for differential timing or desync signal
            te_value = list(te_headers.values())[0]
            desync_detected = False
            evidence_details = []

            if probe_time >= base_time + 3.0:
                desync_detected = True
                evidence_details.append(
                    "Obfuscated TE probe caused {:.2f}s delay vs baseline {:.2f}s, suggesting frontend/backend parsing divergence".format(
                        probe_time, base_time
                    )
                )

            if not desync_detected or not evidence_details:
                continue

            curl_cmd = _build_curl_smuggle("POST", url, headers, body)
            session.add_finding(Finding(
                title="HTTP Request Smuggling (TE Obfuscation: {})".format(repr(te_value)),
                severity=Severity.HIGH,
                description=(
                    "The server at '{}' exhibits differential parsing delay when sent an "
                    "obfuscated TE header value ({}). Frontend and backend may parse TE differently, "
                    "enabling request smuggling.".format(parsed.netloc, repr(te_value))
                ),
                evidence=(
                    "Target URL: {}\nObfuscated TE Value: {}\nHeaders Sent: {}\n"
                    "Baseline Status: {}\nObfuscated TE Status: {}\nIndicators:\n{}".format(
                        url, repr(te_value), headers, baseline.status_code, resp.status_code,
                        "\n".join("  - {}".format(d) for d in evidence_details))
                ),
                remediation=(
                    "1. Normalize or reject malformed Transfer-Encoding headers at the frontend.\n"
                    "2. Strip requests with unrecognized TE values.\n"
                    "3. Ensure consistent header parsing across all layers.\n"
                    "4. Use HTTP/2 end-to-end to avoid TE ambiguity."
                ),
                url=url,
                module="request_smuggling",
                cwe="CWE-444",
                confirmed=False,
                location="HTTP endpoint at {}".format(parsed.path or "/"),
                payload=repr(te_value),
                request_method="POST",
                request_headers=str(headers),
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. POST to {} with obfuscated TE header.\n"
                    "2. Transfer-Encoding value: {}\n"
                    "3. Compare response timing vs baseline ({:.2f}s).\n"
                    "4. Run: {}".format(url, repr(te_value), base_time, curl_cmd)
                ),
                developer_fix=(
                    "Server/Proxy configuration for {}:\n\n"
                    "Normalize Transfer-Encoding at the edge:\n"
                    "  - Accept only exactly 'chunked' as valid TE.\n"
                    "  - Reject or strip any non-matching TE header.\n"
                    "  - Enable strict HTTP parsing in proxy/load balancer.".format(parsed.netloc)
                ),
                affected_component="Transfer-Encoding header parsing at {}".format(parsed.netloc),
                references=(
                    "https://portswigger.net/web-security/request-smuggling | "
                    "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn"
                ),
                detection_method=(
                    "Sent obfuscated TE header ({}) and detected differential signal: {}".format(
                        repr(te_value), "; ".join(evidence_details))
                ),
            ))
        except (requests.RequestException, OSError, ConnectionError) as e:
            logger.debug("request_smuggling te_obfuscation: %s", e)
            continue


def _test_http_version_downgrade(session: ScanSession, url: str) -> None:
    parsed = urlparse(url)
    try:
        resp = session.get(url)
        if not resp:
            return

        via_header = resp.headers.get("Via", "")
        if not via_header:
            return

        versions = set(re.findall(r"HTTP/(\d\.\d)", via_header, re.IGNORECASE))
        if len(versions) <= 1:
            return

        curl_cmd = build_curl("GET", url)
        sorted_versions = ", ".join(sorted(versions))
        session.add_finding(Finding(
            title="HTTP Version Mismatch in Proxy Chain",
            severity=Severity.MEDIUM,
            description=(
                "The Via header at '{}' reveals multiple HTTP versions ({}) across the "
                "proxy chain. Version mismatches can enable smuggling, especially "
                "HTTP/2-to-HTTP/1.1 downgrade.".format(url, sorted_versions)
            ),
            evidence=(
                "Target URL: {}\nVia Header: {}\nHTTP Versions: {}\n"
                "Server: {}".format(
                    url, via_header, sorted_versions, resp.headers.get("Server", ""))
            ),
            remediation=(
                "1. Use the same HTTP version across all proxy layers.\n"
                "2. If downgrade is necessary, fully normalize requests during conversion.\n"
                "3. Enable HTTP/2 end-to-end where possible.\n"
                "4. Remove or sanitize the Via header to limit info disclosure."
            ),
            url=url,
            module="request_smuggling",
            cwe="CWE-444",
            confirmed=False,
            location="Proxy chain for {}".format(parsed.netloc),
            request_method="GET",
            response_status=resp.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. GET {}\n"
                "2. Inspect the Via response header.\n"
                "3. Note different HTTP versions in the proxy chain.\n"
                "4. Run: {}".format(url, curl_cmd)
            ),
            developer_fix=(
                "Ensure consistent HTTP versions across the proxy chain:\n\n"
                "  Nginx: proxy_http_version 1.1;\n"
                "  HAProxy: option http-use-htx"
            ),
            affected_component="Proxy chain HTTP version handling at {}".format(parsed.netloc),
            references=(
                "https://portswigger.net/research/http2 | "
                "https://cwe.mitre.org/data/definitions/444.html"
            ),
            detection_method=(
                "Detected multiple HTTP versions ({}) in Via header, indicating "
                "potential protocol downgrade.".format(sorted_versions)
            ),
        ))
    except (requests.RequestException, OSError, ConnectionError) as e:
        logger.debug("request_smuggling version_downgrade: %s", e)


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for HTTP Request Smuggling...")

    tested_hosts = set()
    for url in session.crawled_urls:
        host_key = urlparse(url).netloc
        if host_key in tested_hosts:
            continue
        tested_hosts.add(host_key)

        _smuggle_test(session, url, CLTE_PAYLOADS, "clte")
        _smuggle_test(session, url, TECL_PAYLOADS, "tecl")
        _test_te_obfuscation(session, url)
        _test_http_version_downgrade(session, url)
