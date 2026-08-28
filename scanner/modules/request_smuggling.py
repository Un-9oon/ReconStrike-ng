import re
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
        "body": "0\r\n\r\nGET /404-test HTTP/1.1\r\n\r\n",
        "description": (
            "Smuggles a partial GET after the chunked terminator. Backend "
            "may route 'GET /404-test' and return 404 instead of the expected response."
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

ERROR_CODES = (400, 500, 501, 502, 503)


def _build_curl_smuggle(method, url, headers, body):
    cmd = "curl -k -X {} '{}'".format(method, url)
    for k, v in headers.items():
        cmd += " -H '{}: {}'".format(k, v)
    if body:
        escaped = body.replace("'", "'\\''").replace("\r", "\\r").replace("\n", "\\n")
        cmd += " --data-binary $'{}'".format(escaped)
    return cmd


def _smuggle_test(session, url, payloads, technique_label):
    """Common logic for CL.TE and TE.CL smuggling tests."""
    parsed = urlparse(url)

    for payload in payloads:
        try:
            headers = dict(payload["headers"])
            body = payload["body"]

            baseline = session.get(url)
            if not baseline:
                continue

            resp = session.post(url, headers=headers, data=body.encode("latin-1"))
            if not resp:
                continue

            smuggling_detected = False
            evidence_details = []

            if resp.status_code in ERROR_CODES and baseline.status_code not in ERROR_CODES:
                smuggling_detected = True
                evidence_details.append(
                    "Server returned {} (baseline was {}), indicating header parsing confusion".format(
                        resp.status_code, baseline.status_code)
                )

            if resp.status_code != baseline.status_code:
                evidence_details.append(
                    "Status code changed from {} to {}".format(baseline.status_code, resp.status_code)
                )

            followup = session.get(url)
            if followup and followup.status_code != baseline.status_code:
                smuggling_detected = True
                evidence_details.append(
                    "Follow-up returned {} instead of {}, suggesting queue poisoning".format(
                        followup.status_code, baseline.status_code)
                )

            if not (smuggling_detected and evidence_details):
                continue

            curl_cmd = _build_curl_smuggle("POST", url, headers, body)
            header_lines = "\n".join("  {}: {}".format(k, v) for k, v in headers.items())
            indicator_lines = "\n".join("  - {}".format(d) for d in evidence_details)

            session.add_finding(Finding(
                title="HTTP Request Smuggling ({})".format(payload["name"]),
                severity=Severity.CRITICAL,
                description=(
                    "The server at '{}' appears vulnerable to HTTP Request Smuggling "
                    "via {}. {} This allows smuggling a second request inside the first, "
                    "potentially bypassing security controls, poisoning caches, or "
                    "hijacking other users' requests.".format(
                        parsed.netloc, payload["name"], payload["description"])
                ),
                evidence=(
                    "Target URL: {}\nTechnique: {}\nHeaders Sent:\n{}\n"
                    "Body (escaped): {}\nBaseline Status: {}\n"
                    "Smuggle Status: {}\nIndicators:\n{}".format(
                        url, payload["name"], header_lines, repr(body),
                        baseline.status_code, resp.status_code, indicator_lines)
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
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. POST to {} with conflicting CL/TE headers.\n"
                    "2. Headers: {}\n"
                    "3. Body (raw): {}\n"
                    "4. Compare response status with a normal GET.\n"
                    "5. Follow-up GET to detect queue poisoning.\n"
                    "6. Run: {}".format(url, headers, repr(body), curl_cmd)
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
                    "Sent ambiguous CL/TE headers ({}) and detected desync: {}".format(
                        payload["name"], "; ".join(evidence_details))
                ),
            ))
            return
        except (requests.RequestException, OSError, ConnectionError) as e:
            logger.debug("request_smuggling %s: %s", technique_label, e)
            continue


def _test_te_obfuscation(session, url):
    parsed = urlparse(url)
    baseline = session.get(url)
    if not baseline:
        return

    for te_headers in TE_OBFUSCATION_HEADERS:
        try:
            headers = dict(te_headers)
            headers["Content-Length"] = "5"
            body = "0\r\n\r\n"

            resp = session.post(url, headers=headers, data=body.encode("latin-1"))
            if not resp or resp.status_code == baseline.status_code:
                continue

            te_value = list(te_headers.values())[0]
            if resp.status_code not in ERROR_CODES:
                continue

            curl_cmd = _build_curl_smuggle("POST", url, headers, body)
            session.add_finding(Finding(
                title="HTTP Request Smuggling (TE Obfuscation: {})".format(repr(te_value)),
                severity=Severity.HIGH,
                description=(
                    "The server at '{}' responds differently to obfuscated TE header "
                    "value ({}). Frontend and backend may parse TE differently, enabling "
                    "smuggling via a value one layer recognizes and the other ignores.".format(
                        parsed.netloc, repr(te_value))
                ),
                evidence=(
                    "Target URL: {}\nObfuscated TE Value: {}\nHeaders Sent: {}\n"
                    "Baseline Status: {}\nObfuscated TE Status: {}".format(
                        url, repr(te_value), headers, baseline.status_code, resp.status_code)
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
                    "3. Compare response status vs baseline ({}).\n"
                    "4. Run: {}".format(url, repr(te_value), baseline.status_code, curl_cmd)
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
                    "Sent obfuscated TE header ({}) and observed status {} vs baseline {}, "
                    "suggesting inconsistent TE parsing.".format(
                        repr(te_value), resp.status_code, baseline.status_code)
                ),
            ))
        except (requests.RequestException, OSError, ConnectionError) as e:
            logger.debug("request_smuggling te_obfuscation: %s", e)
            continue


def _test_http_version_downgrade(session, url):
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
