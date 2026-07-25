import re
from urllib.parse import urlparse

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession, build_curl


# CL.TE: Frontend uses Content-Length, backend uses Transfer-Encoding
# TE.CL: Frontend uses Transfer-Encoding, backend uses Content-Length
# TE.TE: Both use Transfer-Encoding but one can be tricked with obfuscation

CLTE_PAYLOADS = [
    {
        "name": "CL.TE basic",
        "headers": {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\n\r\nX",
        "description": (
            "Sends a request where Content-Length (6) covers the full body including "
            "the trailing 'X', but Transfer-Encoding: chunked sees '0\\r\\n\\r\\n' as "
            "the end. If the frontend uses CL and the backend uses TE, the 'X' is "
            "treated as the start of the next request (smuggled prefix)."
        ),
    },
    {
        "name": "CL.TE with smuggled GET",
        "headers": {
            "Content-Length": "30",
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\n\r\nGET /404-test HTTP/1.1\r\n\r\n",
        "description": (
            "Attempts to smuggle a partial GET request after the chunked terminator. "
            "If the backend treats the trailing data as a new request, it will attempt "
            "to route 'GET /404-test', which may return a 404 instead of the expected response."
        ),
    },
]

TECL_PAYLOADS = [
    {
        "name": "TE.CL basic",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "3",
        },
        "body": "1\r\nZ\r\n0\r\n\r\n",
        "description": (
            "Sends a chunked body ('1\\r\\nZ\\r\\n0\\r\\n\\r\\n') but sets Content-Length "
            "to 3. If the frontend uses TE (reads full chunked body) but the backend "
            "uses CL (reads only 3 bytes), the remainder is smuggled."
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

DOWNGRADE_INDICATORS = [
    "HTTP/1.0",
    "HTTP/1.1",
    "Connection: keep-alive",
    "Connection: close",
]


def _build_curl_smuggle(method, url, headers, body):
    """Build a curl command that represents the smuggling request."""
    cmd = f"curl -k -X {method} '{url}'"
    for k, v in headers.items():
        cmd += f" -H '{k}: {v}'"
    if body:
        escaped = body.replace("'", "'\\''").replace("\r", "\\r").replace("\n", "\\n")
        cmd += f" --data-binary $'{escaped}'"
    return cmd


def _test_clte(session, url):
    """Test for CL.TE request smuggling."""
    parsed = urlparse(url)

    for payload in CLTE_PAYLOADS:
        try:
            headers = dict(payload["headers"])
            body = payload["body"]

            # First, get a baseline response
            baseline = session.get(url)
            if not baseline:
                continue

            # Send the ambiguous request via POST
            resp = session.post(
                url,
                headers=headers,
                data=body.encode("latin-1"),
            )
            if not resp:
                continue

            # Indicators of smuggling success:
            # 1. Timeout or connection reset (backend confused)
            # 2. Different status code than baseline
            # 3. Response contains evidence of a second request being processed
            # 4. Server error (400, 500) indicating parsing confusion

            smuggling_detected = False
            evidence_details = []

            if resp.status_code in (400, 500, 501, 502, 503):
                if baseline.status_code not in (400, 500, 501, 502, 503):
                    smuggling_detected = True
                    evidence_details.append(
                        f"Server returned {resp.status_code} (baseline was {baseline.status_code}), "
                        f"indicating header parsing confusion"
                    )

            # Check if the server echoes back desync indicators
            if resp.status_code != baseline.status_code:
                evidence_details.append(
                    f"Status code changed from {baseline.status_code} to {resp.status_code}"
                )

            # Send a follow-up request to see if it was poisoned
            followup = session.get(url)
            if followup and followup.status_code != baseline.status_code:
                smuggling_detected = True
                evidence_details.append(
                    f"Follow-up request returned {followup.status_code} instead of "
                    f"expected {baseline.status_code}, suggesting request queue poisoning"
                )

            if smuggling_detected and evidence_details:
                curl_cmd = _build_curl_smuggle("POST", url, headers, body)
                session.add_finding(Finding(
                    title=f"HTTP Request Smuggling ({payload['name']})",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The server at '{parsed.netloc}' appears vulnerable to HTTP Request "
                        f"Smuggling via {payload['name']}. {payload['description']} "
                        f"This allows an attacker to smuggle a second request inside the first, "
                        f"potentially bypassing security controls, poisoning caches, or hijacking "
                        f"other users' requests."
                    ),
                    evidence=(
                        f"Target URL: {url}\n"
                        f"Technique: {payload['name']}\n"
                        f"Headers Sent:\n"
                        + "\n".join(f"  {k}: {v}" for k, v in headers.items())
                        + f"\nBody (escaped): {repr(body)}\n"
                        f"Baseline Status: {baseline.status_code}\n"
                        f"Smuggle Status: {resp.status_code}\n"
                        f"Indicators:\n"
                        + "\n".join(f"  - {d}" for d in evidence_details)
                    ),
                    remediation=(
                        "1. Normalize Transfer-Encoding handling: reject requests with both "
                        "Content-Length and Transfer-Encoding headers.\n"
                        "2. Configure the frontend proxy to always normalize requests before "
                        "forwarding to the backend.\n"
                        "3. Use HTTP/2 end-to-end where possible, as it uses a binary framing "
                        "layer that is not susceptible to this class of attack.\n"
                        "4. Ensure all servers in the chain agree on request boundaries.\n"
                        "5. Disable connection reuse between the frontend and backend if patching "
                        "is not immediately possible."
                    ),
                    url=url,
                    module="request_smuggling",
                    cwe="CWE-444",
                    confirmed=True,
                    location=f"HTTP endpoint at {parsed.path or '/'}",
                    payload=repr(body),
                    request_method="POST",
                    request_headers=str(headers),
                    request_body=repr(body),
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Send a POST request to {url} with both Content-Length and "
                        f"Transfer-Encoding headers.\n"
                        f"2. Headers: {headers}\n"
                        f"3. Body (raw): {repr(body)}\n"
                        f"4. Observe the response status and compare with a normal GET.\n"
                        f"5. Send a follow-up GET and check if the response is poisoned.\n"
                        f"6. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"Server/Proxy configuration for {parsed.netloc}:\n\n"
                        "Reject ambiguous requests at the edge:\n"
                        "  Nginx: proxy_request_buffering on; (default, ensures normalization)\n"
                        "  HAProxy: option http-use-htx; (enables strict HTTP parsing)\n"
                        "  Apache: reject requests with both CL and TE headers via mod_security\n\n"
                        "Or upgrade to HTTP/2 end-to-end to eliminate the attack surface entirely."
                    ),
                    affected_component=f"HTTP request parsing at {parsed.netloc}",
                    references=(
                        "https://portswigger.net/web-security/request-smuggling | "
                        "https://cwe.mitre.org/data/definitions/444.html | "
                        "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn"
                    ),
                    detection_method=(
                        f"Sent an HTTP request with ambiguous Content-Length and Transfer-Encoding "
                        f"headers ({payload['name']}) and detected desynchronization indicators: "
                        + "; ".join(evidence_details)
                    ),
                ))
                return
        except Exception as e:
            logger.debug("request_smuggling _test_clte: operation failed: %s", e)
            continue


def _test_tecl(session, url):
    """Test for TE.CL request smuggling."""
    parsed = urlparse(url)

    for payload in TECL_PAYLOADS:
        try:
            headers = dict(payload["headers"])
            body = payload["body"]

            baseline = session.get(url)
            if not baseline:
                continue

            resp = session.post(
                url,
                headers=headers,
                data=body.encode("latin-1"),
            )
            if not resp:
                continue

            smuggling_detected = False
            evidence_details = []

            if resp.status_code in (400, 500, 501, 502, 503):
                if baseline.status_code not in (400, 500, 501, 502, 503):
                    smuggling_detected = True
                    evidence_details.append(
                        f"Server returned {resp.status_code} (baseline was {baseline.status_code})"
                    )

            followup = session.get(url)
            if followup and followup.status_code != baseline.status_code:
                smuggling_detected = True
                evidence_details.append(
                    f"Follow-up request returned {followup.status_code} instead of "
                    f"expected {baseline.status_code}"
                )

            if smuggling_detected and evidence_details:
                curl_cmd = _build_curl_smuggle("POST", url, headers, body)
                session.add_finding(Finding(
                    title=f"HTTP Request Smuggling ({payload['name']})",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The server at '{parsed.netloc}' appears vulnerable to HTTP Request "
                        f"Smuggling via {payload['name']}. {payload['description']} "
                        f"This allows an attacker to smuggle requests past the frontend proxy."
                    ),
                    evidence=(
                        f"Target URL: {url}\n"
                        f"Technique: {payload['name']}\n"
                        f"Headers Sent:\n"
                        + "\n".join(f"  {k}: {v}" for k, v in headers.items())
                        + f"\nBody (escaped): {repr(body)}\n"
                        f"Baseline Status: {baseline.status_code}\n"
                        f"Smuggle Status: {resp.status_code}\n"
                        f"Indicators:\n"
                        + "\n".join(f"  - {d}" for d in evidence_details)
                    ),
                    remediation=(
                        "1. Reject requests with both Content-Length and Transfer-Encoding.\n"
                        "2. Use HTTP/2 end-to-end to eliminate ambiguity.\n"
                        "3. Configure all proxies and backends to use the same header priority.\n"
                        "4. Enable strict HTTP parsing in your reverse proxy.\n"
                        "5. Disable keep-alive between frontend and backend as a temporary fix."
                    ),
                    url=url,
                    module="request_smuggling",
                    cwe="CWE-444",
                    confirmed=True,
                    location=f"HTTP endpoint at {parsed.path or '/'}",
                    payload=repr(body),
                    request_method="POST",
                    request_headers=str(headers),
                    request_body=repr(body),
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Send a POST request to {url} with conflicting TE and CL headers.\n"
                        f"2. Headers: {headers}\n"
                        f"3. Body (raw): {repr(body)}\n"
                        f"4. Check response status vs. baseline.\n"
                        f"5. Send a follow-up request to detect queue poisoning.\n"
                        f"6. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"Server/Proxy configuration for {parsed.netloc}:\n\n"
                        "Reject ambiguous requests:\n"
                        "  Nginx: proxy_request_buffering on;\n"
                        "  HAProxy: option http-use-htx;\n"
                        "  Apache: use mod_security to block dual CL/TE headers\n\n"
                        "Best fix: upgrade to HTTP/2 end-to-end."
                    ),
                    affected_component=f"HTTP request parsing at {parsed.netloc}",
                    references=(
                        "https://portswigger.net/web-security/request-smuggling | "
                        "https://cwe.mitre.org/data/definitions/444.html"
                    ),
                    detection_method=(
                        f"Sent an HTTP request with conflicting Transfer-Encoding and "
                        f"Content-Length headers ({payload['name']}) and detected "
                        f"desynchronization: " + "; ".join(evidence_details)
                    ),
                ))
                return
        except Exception as e:
            logger.debug("request_smuggling _test_tecl: operation failed: %s", e)
            continue


def _test_te_obfuscation(session, url):
    """Test Transfer-Encoding obfuscation variants."""
    parsed = urlparse(url)

    baseline = session.get(url)
    if not baseline:
        return

    for te_headers in TE_OBFUSCATION_HEADERS:
        try:
            headers = dict(te_headers)
            headers["Content-Length"] = "5"
            body = "0\r\n\r\n"

            resp = session.post(
                url,
                headers=headers,
                data=body.encode("latin-1"),
            )
            if not resp:
                continue

            # If the server processes the obfuscated TE differently than expected
            if resp.status_code != baseline.status_code:
                te_value = list(te_headers.values())[0]
                if resp.status_code in (400, 500, 501, 502, 503):
                    curl_cmd = _build_curl_smuggle("POST", url, headers, body)
                    session.add_finding(Finding(
                        title=f"HTTP Request Smuggling (TE Obfuscation: {repr(te_value)})",
                        severity=Severity.HIGH,
                        description=(
                            f"The server at '{parsed.netloc}' responds differently to an obfuscated "
                            f"Transfer-Encoding header value ({repr(te_value)}). This suggests the "
                            f"frontend and backend may parse the TE header differently, which can be "
                            f"exploited for request smuggling by using a TE value that one layer "
                            f"recognizes and the other ignores."
                        ),
                        evidence=(
                            f"Target URL: {url}\n"
                            f"Obfuscated TE Value: {repr(te_value)}\n"
                            f"Headers Sent: {headers}\n"
                            f"Baseline Status: {baseline.status_code}\n"
                            f"Obfuscated TE Status: {resp.status_code}"
                        ),
                        remediation=(
                            "1. Configure the frontend to normalize or reject malformed "
                            "Transfer-Encoding headers.\n"
                            "2. Strip or reject requests with unrecognized TE values.\n"
                            "3. Ensure consistent header parsing across all layers.\n"
                            "4. Use HTTP/2 end-to-end to avoid TE ambiguity."
                        ),
                        url=url,
                        module="request_smuggling",
                        cwe="CWE-444",
                        confirmed=False,
                        location=f"HTTP endpoint at {parsed.path or '/'}",
                        payload=repr(te_value),
                        request_method="POST",
                        request_headers=str(headers),
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Send a POST request to {url} with an obfuscated TE header.\n"
                            f"2. Transfer-Encoding value: {repr(te_value)}\n"
                            f"3. Observe response status vs. baseline ({baseline.status_code}).\n"
                            f"4. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"Server/Proxy configuration for {parsed.netloc}:\n\n"
                            "Normalize Transfer-Encoding at the edge:\n"
                            "  - Accept only exactly 'chunked' as a valid TE value.\n"
                            "  - Reject or strip any TE header that doesn't match exactly.\n"
                            "  - Configure strict HTTP parsing in your proxy/load balancer."
                        ),
                        affected_component=f"Transfer-Encoding header parsing at {parsed.netloc}",
                        references=(
                            "https://portswigger.net/web-security/request-smuggling | "
                            "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn"
                        ),
                        detection_method=(
                            f"Sent an obfuscated Transfer-Encoding header ({repr(te_value)}) and "
                            f"observed a different response status ({resp.status_code}) compared to "
                            f"baseline ({baseline.status_code}), suggesting inconsistent TE parsing."
                        ),
                    ))
        except Exception as e:
            logger.debug("request_smuggling _test_te_obfuscation: operation failed: %s", e)
            continue


def _test_http_version_downgrade(session, url):
    """Check for HTTP version downgrade indicators in response headers."""
    parsed = urlparse(url)

    try:
        resp = session.get(url)
        if not resp:
            return

        # Check if the server advertises HTTP/1.0 behavior (connection: close)
        # or shows signs of protocol confusion
        via_header = resp.headers.get("Via", "")
        server_header = resp.headers.get("Server", "")

        # Look for multiple protocol versions in the Via header
        if via_header:
            versions = re.findall(r"HTTP/(\d\.\d)", via_header, re.IGNORECASE)
            unique_versions = set(versions)
            if len(unique_versions) > 1:
                curl_cmd = build_curl("GET", url)
                session.add_finding(Finding(
                    title="HTTP Version Mismatch in Proxy Chain",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The Via header at '{url}' reveals that multiple HTTP versions "
                        f"({', '.join(sorted(unique_versions))}) are used across the proxy chain. "
                        f"Protocol version mismatches between frontend and backend can enable "
                        f"request smuggling attacks, especially HTTP/2-to-HTTP/1.1 downgrade."
                    ),
                    evidence=(
                        f"Target URL: {url}\n"
                        f"Via Header: {via_header}\n"
                        f"HTTP Versions Detected: {', '.join(sorted(unique_versions))}\n"
                        f"Server Header: {server_header}"
                    ),
                    remediation=(
                        "1. Use the same HTTP version across all layers of the proxy chain.\n"
                        "2. If HTTP/2-to-HTTP/1.1 downgrade is necessary, ensure the proxy "
                        "fully normalizes requests during the conversion.\n"
                        "3. Enable HTTP/2 end-to-end where possible.\n"
                        "4. Remove or sanitize the Via header to avoid information disclosure."
                    ),
                    url=url,
                    module="request_smuggling",
                    cwe="CWE-444",
                    confirmed=False,
                    location=f"Proxy chain for {parsed.netloc}",
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Send a GET request to {url}.\n"
                        f"2. Inspect the Via response header.\n"
                        f"3. Note the different HTTP versions in the proxy chain.\n"
                        f"4. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        "Ensure consistent HTTP versions across the proxy chain:\n\n"
                        "  Nginx (as reverse proxy):\n"
                        "    proxy_http_version 1.1;  # Or use HTTP/2 to backend\n\n"
                        "  HAProxy:\n"
                        "    option http-use-htx\n"
                        "    # Ensure backend uses same version as frontend"
                    ),
                    affected_component=f"Proxy chain HTTP version handling at {parsed.netloc}",
                    references=(
                        "https://portswigger.net/research/http2 | "
                        "https://cwe.mitre.org/data/definitions/444.html"
                    ),
                    detection_method=(
                        "Analyzed the Via response header and detected multiple HTTP versions "
                        f"({', '.join(sorted(unique_versions))}) in the proxy chain, indicating "
                        "potential protocol downgrade."
                    ),
                ))
    except Exception as e:
        logger.debug("request_smuggling _test_http_version_downgrade: operation failed: %s", e)


def run(session: ScanSession) -> None:
    print("\n[*] Testing for HTTP Request Smuggling...")

    # Test a representative set of URLs (avoid excessive requests)
    tested_hosts = set()
    for url in session.crawled_urls:
        parsed = urlparse(url)
        host_key = parsed.netloc

        # Only test each host once for smuggling (it's a server-level issue)
        if host_key in tested_hosts:
            continue
        tested_hosts.add(host_key)

        _test_clte(session, url)
        _test_tecl(session, url)
        _test_te_obfuscation(session, url)
        _test_http_version_downgrade(session, url)
