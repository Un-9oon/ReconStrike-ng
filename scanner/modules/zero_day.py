import re
import json
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession

FUZZ_PAYLOADS = {
    "buffer_overflow": [
        "A" * 1000,
        "A" * 5000,
        "A" * 10000,
        "\x41" * 2048,
        "/" * 2048,
        "." * 2048,
    ],
    "format_string": [
        "%s%s%s%s%s%s%s%s%s%s",
        "%n%n%n%n%n%n%n%n%n%n",
        "%x" * 20,
        "%d" * 20,
        "%p" * 20,
        "AAAA%08x.%08x.%08x.%08x",
        "%s" * 50,
    ],
    "unicode_edge": [
        "\x00",
        "\x00" * 10,
        "\xc0\xaf",
        "\xc0\xae",
        "\xef\xbb\xbf",
        "\xfe\xff",
        "%ud800",
        "\x80" * 50,
        "test\x00admin",
        "\xff" * 100,
    ],
    "integer_overflow": [
        "2147483647",
        "2147483648",
        "-2147483648",
        "-2147483649",
        "4294967295",
        "4294967296",
        "9999999999999999999",
        "-1",
        "0",
        "99999999999999999999999999999999",
    ],
    "nested_structures": [
        '{"a":' * 50 + '"b"' + '}' * 50,
        "<a>" * 50 + "x" + "</a>" * 50,
        "[[[[[[[[[[" * 5 + "1" + "]]]]]]]]]]" * 5,
        '{"' + 'a":{"' * 30 + 'b":"c"' + '}' * 31,
    ],
    "special_chars": [
        "{{7*7}}",
        "${7*7}",
        "<!--",
        "<![CDATA[test]]>",
        "!@#$%^&*()_+-=[]{}|;':\",./<>?",
        "\r\n\r\n",
        "\t\t\t\t\t",
        "\\\\\\\\\\",
    ],
}

UNUSUAL_METHODS = ["PATCH", "PROPFIND", "TRACE", "OPTIONS", "CONNECT", "MOVE", "COPY", "LOCK"]

CRASH_INDICATORS = [
    (r'Segmentation fault', "segfault"),
    (r'stack smashing detected', "stack_overflow"),
    (r'buffer overflow', "buffer_overflow"),
    (r'core dump', "core_dump"),
    (r'panic:', "go_panic"),
    (r'SIGSEGV|SIGABRT|SIGBUS', "signal_crash"),
    (r'java\.lang\.(NullPointerException|StackOverflowError|OutOfMemoryError)', "java_crash"),
    (r'Traceback \(most recent call last\)', "python_traceback"),
    (r'Fatal error.*?Allowed memory size', "php_oom"),
    (r'System\.StackOverflowException|System\.OutOfMemoryException', "dotnet_crash"),
    (r'undefined method|NoMethodError', "ruby_error"),
    (r'at Object\.<anonymous>.*?\n.*?at Module', "node_crash"),
]

STACK_TRACE_PATTERNS = [
    r'at\s+[\w$.]+\([\w]+\.java:\d+\)',
    r'File\s+"[^"]+",\s+line\s+\d+',
    r'in\s+/[\w/]+\.(?:php|py|rb|js)(?:\s+on\s+line\s+\d+)?',
    r'#\d+\s+0x[0-9a-f]+\s+in\s+',
    r'\.cs:line\s+\d+',
]


# Minimum number of independently-triggering payloads required before a
# finding is emitted.  Keeps single-signal noise out of the main report.
# Overridable per scan via session.config._zero_day_min_signals (set by CLI).
_DEFAULT_MIN_SIGNALS = 2


def _build_curl(method: str, url: str, data: str = None, headers: dict = None) -> str:
    from scanner.core import build_curl
    return build_curl(method, url, headers=headers, data=data)


def _resp_text(resp) -> str:
    """Safely decode a response body, replacing un-decodable bytes.

    `resp.text` raises UnicodeDecodeError when the server returns binary
    content (e.g. a payload triggers a binary 500 error page on some stacks).
    This helper never raises.
    """
    if resp is None:
        return ""
    try:
        return resp.text
    except (UnicodeDecodeError, LookupError):
        try:
            return resp.content.decode("utf-8", errors="replace")
        except Exception:
            return ""


def _get_baseline(session: ScanSession, url: str) -> dict:
    start = time.time()
    resp = session.get(url, allow_redirects=False)
    elapsed = time.time() - start
    if resp is None:
        return {"status": None, "size": 0, "time": elapsed, "body": ""}
    body = _resp_text(resp)
    return {
        "status": resp.status_code,
        "size": len(body),
        "time": elapsed,
        "body": body,
    }


def _analyze_response(resp, elapsed: float, baseline: dict, payload: str, category: str) -> list:
    anomalies = []

    if resp is None:
        if baseline["status"] is not None:
            anomalies.append(f"Connection error/timeout (baseline returned {baseline['status']})")
        return anomalies

    if resp.status_code >= 500 and (baseline["status"] is None or baseline["status"] < 500):
        anomalies.append(f"Server error {resp.status_code} (baseline: {baseline['status']})")

    if baseline["time"] > 0 and elapsed > baseline["time"] * 3 and elapsed > 2.0:
        anomalies.append(
            f"Timing anomaly: {elapsed:.2f}s vs baseline {baseline['time']:.2f}s "
            f"({elapsed / baseline['time']:.1f}x slower)"
        )

    resp_text_safe = _resp_text(resp)
    resp_size = len(resp_text_safe)
    if baseline["size"] > 100:
        if resp_size > baseline["size"] * 3:
            anomalies.append(
                f"Response size anomaly: {resp_size} bytes vs baseline {baseline['size']} bytes "
                f"({resp_size / baseline['size']:.1f}x larger)"
            )
        elif resp_size < baseline["size"] // 3 and resp_size < baseline["size"] - 500:
            anomalies.append(
                f"Response size anomaly: {resp_size} bytes vs baseline {baseline['size']} bytes "
                f"(significantly smaller)"
            )

    for pattern, crash_type in CRASH_INDICATORS:
        if re.search(pattern, _resp_text(resp), re.IGNORECASE):
            anomalies.append(f"Crash indicator ({crash_type}): {_extract_snippet(_resp_text(resp), pattern)}")

    for pattern in STACK_TRACE_PATTERNS:
        if re.search(pattern, _resp_text(resp)):
            anomalies.append(f"Stack trace leaked: {_extract_snippet(_resp_text(resp), pattern)}")
            break

    return anomalies


def _extract_snippet(body: str, pattern: str, context: int = 80) -> str:
    match = re.search(pattern, body, re.IGNORECASE)
    if not match:
        return ""
    start = max(0, match.start() - context)
    end = min(len(body), match.end() + context)
    snippet = body[start:end].replace('\n', ' ').replace('\r', '').strip()
    return snippet[:200] + "..." if len(snippet) > 200 else snippet


def _fuzz_url_params(session: ScanSession, url: str, baseline: dict, min_signals: int = _DEFAULT_MIN_SIGNALS) -> None:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    for param_name, original_values in params.items():
        # Accumulate anomalies per category before deciding to emit a finding.
        # Key: category str → list of (payload, anomalies, resp, elapsed)
        category_hits: dict = {}

        for category, payloads in FUZZ_PAYLOADS.items():
            hits_for_cat = []
            for payload in payloads:
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

                start = time.time()
                resp = session.get(test_url, allow_redirects=False)
                elapsed = time.time() - start

                anomalies = _analyze_response(resp, elapsed, baseline, payload, category)
                if anomalies:
                    hits_for_cat.append((test_url, payload, anomalies, resp, elapsed))

            if len(hits_for_cat) >= min_signals:
                category_hits[category] = hits_for_cat

        for category, hits in category_hits.items():
            # Emit one consolidated finding per (param, category)
            all_anomalies = [a for _, _, anoms, _, _ in hits for a in anoms]
            representative_url, representative_payload, _, representative_resp, representative_elapsed = hits[0]
            _report_anomaly(
                session=session,
                url=representative_url,
                param=param_name,
                payload=representative_payload,
                category=category,
                anomalies=all_anomalies,
                baseline=baseline,
                resp=representative_resp,
                elapsed=representative_elapsed,
                method="GET",
                triggering_count=len(hits),
            )


def _fuzz_form_fields(session: ScanSession, baseline: dict, min_signals: int = _DEFAULT_MIN_SIGNALS) -> None:
    if not session.forms:
        return

    for form in session.forms:
        action = form.get("action", session.config.target)
        method = form.get("method", "post").upper()
        inputs = form.get("inputs", [])

        for inp in inputs:
            field_name = inp.get("name", "")
            if not field_name:
                continue
            if inp.get("type", "text").lower() in ("submit", "button", "image", "hidden", "file"):
                continue

            for category, payloads in FUZZ_PAYLOADS.items():
                hits_for_cat = []
                for payload in payloads:
                    form_data = {}
                    for other_inp in inputs:
                        other_name = other_inp.get("name", "")
                        if not other_name:
                            continue
                        form_data[other_name] = payload if other_name == field_name else other_inp.get("value", "test")

                    start = time.time()
                    if method == "GET":
                        test_url = action + "?" + urlencode(form_data)
                        resp = session.get(test_url, allow_redirects=False)
                    else:
                        resp = session.post(action, data=form_data, allow_redirects=False)
                        test_url = action
                    elapsed = time.time() - start

                    anomalies = _analyze_response(resp, elapsed, baseline, payload, category)
                    if anomalies:
                        hits_for_cat.append((test_url, payload, form_data, anomalies, resp, elapsed))

                if len(hits_for_cat) >= min_signals:
                    test_url, payload, form_data, anoms, resp, elapsed = hits_for_cat[0]
                    all_anomalies = [a for _, _, _, a_list, _, _ in hits_for_cat for a in a_list]
                    _report_anomaly(
                        session=session,
                        url=test_url,
                        param=field_name,
                        payload=payload,
                        category=category,
                        anomalies=all_anomalies,
                        baseline=baseline,
                        resp=resp,
                        elapsed=elapsed,
                        method=method,
                        form_data=form_data,
                        triggering_count=len(hits_for_cat),
                    )


def _test_method_confusion(session: ScanSession, baseline: dict) -> None:
    target = session.config.target
    for method in UNUSUAL_METHODS:
        try:
            start = time.time()
            resp = session.session.request(
                method, target,
                timeout=session.config.timeout,
                verify=session.config.verify_ssl,
            )
            elapsed = time.time() - start
        except (OSError, ValueError) as e:
            logger.debug("zero_day _test_method_confusion: request failed: %s", e)
            continue

        anomalies = []
        if resp.status_code == 200 and method in ("TRACE", "PROPFIND", "MOVE", "COPY"):
            anomalies.append(f"Server accepted {method} method with 200 OK")
        if resp.status_code >= 500:
            anomalies.append(f"Server error {resp.status_code} on {method} method")

        if method == "TRACE" and resp.status_code == 200 and "TRACE" in _resp_text(resp):
            anomalies.append("TRACE method reflects request back (Cross-Site Tracing risk)")

        for pattern, crash_type in CRASH_INDICATORS:
            if re.search(pattern, _resp_text(resp), re.IGNORECASE):
                anomalies.append(f"Crash indicator on {method}: {crash_type}")

        if anomalies:
            session.add_finding(Finding(
                title=f"HTTP Method Confusion: Anomalous response to {method}",
                severity=Severity.MEDIUM,
                description=(
                    f"The server exhibited unexpected behavior when sent an HTTP {method} request. "
                    f"Anomalies detected: {'; '.join(anomalies)}. "
                    "This may indicate missing method validation or unexpected server behavior "
                    "that could be leveraged for further attacks."
                ),
                evidence=f"Response status: {resp.status_code}, anomalies: {'; '.join(anomalies)}",
                remediation=(
                    "Restrict allowed HTTP methods to only those required by the application "
                    "(typically GET, POST, HEAD). Return 405 Method Not Allowed for all others. "
                    "Disable TRACE method to prevent Cross-Site Tracing attacks."
                ),
                url=target,
                module="zero_day",
                cwe="CWE-749",
                confirmed=True,
                request_method=method,
                response_status=resp.status_code,
                detection_method=f"Sent HTTP {method} request and observed anomalous response vs standard GET baseline",
                curl_command=_build_curl(method, target),
                reproduction_steps=(
                    f"1. Send: curl -k -X {method} '{target}'\n"
                    f"2. Observe the {resp.status_code} response\n"
                    f"3. Anomalies: {'; '.join(anomalies)}\n"
                    "4. Investigate if the method exposes internal functionality or information"
                ),
                developer_fix=(
                    "1. Configure the web server/framework to only accept required HTTP methods\n"
                    "2. Add method validation middleware that returns 405 for unsupported methods\n"
                    "3. In Apache: use <LimitExcept GET POST HEAD> Deny from all </LimitExcept>\n"
                    "4. In Nginx: if ($request_method !~ ^(GET|POST|HEAD)$) { return 405; }\n"
                    "5. Disable TRACE in the web server configuration"
                ),
                references=(
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods, "
                    "https://cwe.mitre.org/data/definitions/749.html"
                ),
            ))


def _report_anomaly(
    session: ScanSession,
    url: str,
    param: str,
    payload: str,
    category: str,
    anomalies: list,
    baseline: dict,
    resp,
    elapsed: float,
    method: str = "GET",
    form_data: dict = None,
    triggering_count: int = 1,
) -> None:
    anomaly_str = "; ".join(dict.fromkeys(anomalies))  # deduplicate while preserving order
    payload_display = payload if len(payload) <= 100 else payload[:100] + f"... ({len(payload)} chars)"

    baseline_summary = (
        f"Status: {baseline['status']}, Size: {baseline['size']} bytes, "
        f"Time: {baseline['time']:.2f}s"
    )
    fuzzed_summary = (
        f"Status: {resp.status_code if resp else 'N/A'}, "
        f"Size: {len(_resp_text(resp)) if resp else 'N/A'} bytes, "
        f"Time: {elapsed:.2f}s"
    )

    data_arg = urlencode(form_data) if form_data else None

    session.add_finding(Finding(
        title=f"Zero-Day Heuristic: {category.replace('_', ' ').title()} anomaly in '{param}'",
        severity=Severity.MEDIUM,
        description=(
            f"Differential analysis detected anomalous behavior when fuzzing parameter '{param}' "
            f"with {category.replace('_', ' ')} payloads ({triggering_count} independent signals). "
            f"Anomalies: {anomaly_str}. "
            f"This may indicate an unpatched vulnerability, improper input validation, "
            f"or an exploitable edge case that warrants manual investigation."
        ),
        evidence=(
            f"Payload category: {category}\n"
            f"Representative payload: {payload_display}\n"
            f"Independent triggering payloads: {triggering_count}\n"
            f"Baseline: {baseline_summary}\n"
            f"Fuzzed:   {fuzzed_summary}\n"
            f"Anomalies: {anomaly_str}"
        ),
        remediation=(
            "1. Investigate the root cause of the anomalous behavior\n"
            "2. Implement strict input validation and sanitization for the affected parameter\n"
            "3. Add length limits, type checking, and character whitelisting\n"
            "4. Ensure error handling does not expose internal details\n"
            "5. Consider deploying a WAF to filter malicious payloads"
        ),
        url=url,
        module="zero_day",
        cwe="CWE-20",
        confirmed=False,
        parameter=param,
        payload=payload_display,
        request_method=method,
        response_status=resp.status_code if resp else 0,
        detection_method=(
            f"Intelligent fuzzing with {category} payloads and differential analysis "
            f"against baseline response; {triggering_count} of {len(FUZZ_PAYLOADS[category])} "
            f"payloads in this category triggered anomalies"
        ),
        curl_command=_build_curl(method, url, data=data_arg),
        reproduction_steps=(
            f"1. Get baseline: curl -k '{session.config.target}'\n"
            f"2. Send fuzzed request: {_build_curl(method, url, data=data_arg)}\n"
            f"3. Compare response status, size, and timing against baseline\n"
            f"4. Baseline: {baseline_summary}\n"
            f"5. Fuzzed result: {fuzzed_summary}\n"
            f"6. Look for: {anomaly_str}\n"
            "7. Manually investigate whether the anomaly is exploitable"
        ),
        developer_fix=(
            f"1. Add input validation for parameter '{param}' - reject inputs exceeding "
            f"expected length/format\n"
            "2. Implement proper error handling that returns generic error pages (no stack traces)\n"
            "3. Add request size limits at the web server and application level\n"
            "4. Use parameterized queries and type-safe APIs to prevent injection\n"
            "5. Set up monitoring/alerting for 500 errors and unusual response patterns\n"
            "6. Consider rate limiting to prevent automated fuzzing"
        ),
        references=(
            "https://owasp.org/www-community/Fuzzing, "
            "https://cwe.mitre.org/data/definitions/20.html, "
            "https://owasp.org/www-project-web-security-testing-guide/latest/6-Appendix/C-Fuzz_Vectors"
        ),
    ))


def run(session: ScanSession) -> None:
    logger.info(f"\n[⚡] Running Zero-Day Heuristics (Intelligent Fuzzing)...")

    # Respect --zero-day-sensitivity if the CLI set it on the session config
    min_signals = getattr(session.config, "_zero_day_min_signals", _DEFAULT_MIN_SIGNALS)

    target = session.config.target

    logger.info(f" ▸ Establishing baseline response...")
    baseline = _get_baseline(session, target)
    if baseline["status"] is None:
        logger.warning(f" ✗ Could not establish baseline, skipping zero-day heuristics.")
        return
    logger.info(
        "✓ Baseline established: status=%s, size=%d bytes, time=%.2fs "
        "(min_signals threshold: %d)",
        baseline['status'], baseline['size'], baseline['time'], min_signals
    )

    logger.info(f" ▸ Phase 1: Fuzzing URL parameters...")
    fuzzed_urls = set()
    for url in list(session.crawled_urls):
        parsed = urlparse(url)
        if parsed.query and url not in fuzzed_urls:
            fuzzed_urls.add(url)
            _fuzz_url_params(session, url, baseline, min_signals=min_signals)
            if len(fuzzed_urls) >= 10:
                break

    if not fuzzed_urls:
        logger.info(f" ℹ No parameterized URLs found, testing common parameters...")
        common_params = ["id", "page", "q", "search", "name", "user", "file", "path", "url", "callback"]
        for param in common_params:
            test_url = f"{target}?{param}=1"
            test_baseline = _get_baseline(session, test_url)
            if test_baseline["status"] and test_baseline["status"] < 404:
                _fuzz_url_params(session, test_url, test_baseline, min_signals=min_signals)
                break

    logger.info(f" ▸ Phase 2: Fuzzing form fields...")
    _fuzz_form_fields(session, baseline, min_signals=min_signals)

    logger.info(f" ▸ Phase 3: Testing HTTP method confusion...")
    _test_method_confusion(session, baseline)

    found_count = sum(1 for f in session.findings if f.module == "zero_day")
    if found_count > 0:
        logger.info(f" ★ Zero-day heuristic scan complete: {found_count} anomalies detected.")
    else:
        logger.info(f" ✓ Zero-day heuristic scan complete: No anomalies detected.")
