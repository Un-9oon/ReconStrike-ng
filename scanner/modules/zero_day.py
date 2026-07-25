import re
import json
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession

# Mutation payloads organized by category
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
        "\xc0\xaf",  # Overlong encoding of /
        "\xc0\xae",  # Overlong encoding of .
        "\xef\xbb\xbf",  # UTF-8 BOM
        "\xfe\xff",  # UTF-16 BE BOM
        "%ud800",  # Lone surrogate probe
        "\x80" * 50,
        "test\x00admin",
        "\xff" * 100,
    ],
    "integer_overflow": [
        "2147483647",   # INT32_MAX
        "2147483648",   # INT32_MAX + 1
        "-2147483648",  # INT32_MIN
        "-2147483649",  # INT32_MIN - 1
        "4294967295",   # UINT32_MAX
        "4294967296",   # UINT32_MAX + 1
        "9999999999999999999",
        "-1",
        "0",
        "99999999999999999999999999999999",
    ],
    "nested_structures": [
        '{"a":' * 50 + '"b"' + '}' * 50,  # Deeply nested JSON
        "<a>" * 50 + "x" + "</a>" * 50,   # Deeply nested XML
        "[[[[[[[[[[" * 5 + "1" + "]]]]]]]]]]" * 5,  # Nested arrays
        '{"' + 'a":{"' * 30 + 'b":"c"' + '}' * 31,
    ],
    "special_chars": [
        "{{7*7}}",       # SSTI probe
        "${7*7}",        # Expression language
        "<!--",          # HTML comment
        "<![CDATA[test]]>",
        "!@#$%^&*()_+-=[]{}|;':\",./<>?",
        "\r\n\r\n",      # CRLF
        "\t\t\t\t\t",
        "\\\\\\\\\\",
    ],
}

# HTTP methods for method confusion testing
UNUSUAL_METHODS = ["PATCH", "PROPFIND", "TRACE", "OPTIONS", "CONNECT", "MOVE", "COPY", "LOCK"]

# Patterns that indicate potential crashes or error information leakage
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

# Stack trace / debug info patterns
STACK_TRACE_PATTERNS = [
    r'at\s+[\w$.]+\([\w]+\.java:\d+\)',
    r'File\s+"[^"]+",\s+line\s+\d+',
    r'in\s+/[\w/]+\.(?:php|py|rb|js)(?:\s+on\s+line\s+\d+)?',
    r'#\d+\s+0x[0-9a-f]+\s+in\s+',
    r'\.cs:line\s+\d+',
]


def _build_curl(method: str, url: str, data: str = None, headers: dict = None) -> str:
    from scanner.core import build_curl
    return build_curl(method, url, headers=headers, data=data)


def _get_baseline(session: ScanSession, url: str) -> dict:
    """Get baseline response metrics for differential analysis."""
    start = time.time()
    resp = session.get(url)
    elapsed = time.time() - start
    if resp is None:
        return {"status": None, "size": 0, "time": elapsed, "body": ""}
    return {
        "status": resp.status_code,
        "size": len(resp.text),
        "time": elapsed,
        "body": resp.text,
    }


def _analyze_response(resp, elapsed: float, baseline: dict, payload: str, category: str) -> list:
    """Compare a fuzzed response against baseline. Returns list of anomaly descriptions."""
    anomalies = []

    if resp is None:
        if baseline["status"] is not None:
            anomalies.append(f"Connection error/timeout (baseline returned {baseline['status']})")
        return anomalies

    # Status code anomaly
    if resp.status_code >= 500 and (baseline["status"] is None or baseline["status"] < 500):
        anomalies.append(f"Server error {resp.status_code} (baseline: {baseline['status']})")

    # Timing anomaly (>3x baseline)
    if baseline["time"] > 0 and elapsed > baseline["time"] * 3 and elapsed > 2.0:
        anomalies.append(
            f"Timing anomaly: {elapsed:.2f}s vs baseline {baseline['time']:.2f}s "
            f"({elapsed / baseline['time']:.1f}x slower)"
        )

    # Size anomaly (>3x or <1/3 of baseline, if baseline had content)
    resp_size = len(resp.text)
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

    # Crash indicators in response body
    for pattern, crash_type in CRASH_INDICATORS:
        if re.search(pattern, resp.text, re.IGNORECASE):
            snippet = _extract_snippet(resp.text, pattern)
            anomalies.append(f"Crash indicator ({crash_type}): {snippet}")

    # Stack traces in response
    for pattern in STACK_TRACE_PATTERNS:
        if re.search(pattern, resp.text):
            snippet = _extract_snippet(resp.text, pattern)
            anomalies.append(f"Stack trace leaked: {snippet}")
            break  # One stack trace finding is enough

    return anomalies


def _extract_snippet(body: str, pattern: str, context: int = 80) -> str:
    """Extract a snippet around a regex match."""
    match = re.search(pattern, body, re.IGNORECASE)
    if match:
        start = max(0, match.start() - context)
        end = min(len(body), match.end() + context)
        snippet = body[start:end].replace('\n', ' ').replace('\r', '').strip()
        if len(snippet) > 200:
            snippet = snippet[:200] + "..."
        return snippet
    return ""


def _fuzz_url_params(session: ScanSession, url: str, baseline: dict) -> None:
    """Fuzz URL query parameters with mutation payloads."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    for param_name, original_values in params.items():
        original = original_values[0] if original_values else ""
        for category, payloads in FUZZ_PAYLOADS.items():
            for payload in payloads:
                test_params = dict(params)
                test_params[param_name] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                start = time.time()
                resp = session.get(test_url)
                elapsed = time.time() - start

                anomalies = _analyze_response(resp, elapsed, baseline, payload, category)
                if anomalies:
                    _report_anomaly(
                        session=session,
                        url=test_url,
                        param=param_name,
                        payload=payload,
                        category=category,
                        anomalies=anomalies,
                        baseline=baseline,
                        resp=resp,
                        elapsed=elapsed,
                        method="GET",
                    )


def _fuzz_form_fields(session: ScanSession, baseline: dict) -> None:
    """Fuzz discovered form fields with mutation payloads."""
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
            field_type = inp.get("type", "text").lower()
            if field_type in ("submit", "button", "image", "hidden", "file"):
                continue

            for category, payloads in FUZZ_PAYLOADS.items():
                for payload in payloads:
                    form_data = {}
                    for other_inp in inputs:
                        other_name = other_inp.get("name", "")
                        if not other_name:
                            continue
                        if other_name == field_name:
                            form_data[other_name] = payload
                        else:
                            form_data[other_name] = other_inp.get("value", "test")

                    start = time.time()
                    if method == "GET":
                        test_url = action + "?" + urlencode(form_data)
                        resp = session.get(test_url)
                    else:
                        resp = session.post(action, data=form_data)
                        test_url = action
                    elapsed = time.time() - start

                    anomalies = _analyze_response(resp, elapsed, baseline, payload, category)
                    if anomalies:
                        _report_anomaly(
                            session=session,
                            url=test_url,
                            param=field_name,
                            payload=payload,
                            category=category,
                            anomalies=anomalies,
                            baseline=baseline,
                            resp=resp,
                            elapsed=elapsed,
                            method=method,
                            form_data=form_data,
                        )


def _test_method_confusion(session: ScanSession, baseline: dict) -> None:
    """Test unusual HTTP methods for unexpected behavior."""
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
        except Exception as e:
            logger.debug("zero_day _test_method_confusion: request failed: %s", e)
            continue

        anomalies = []
        if resp.status_code == 200 and method in ("TRACE", "PROPFIND", "MOVE", "COPY"):
            anomalies.append(f"Server accepted {method} method with 200 OK")
        if resp.status_code >= 500:
            anomalies.append(f"Server error {resp.status_code} on {method} method")

        # Check for TRACE reflection (XST)
        if method == "TRACE" and resp.status_code == 200 and "TRACE" in resp.text:
            anomalies.append("TRACE method reflects request back (Cross-Site Tracing risk)")

        # Check for stack traces or crash indicators
        for pattern, crash_type in CRASH_INDICATORS:
            if re.search(pattern, resp.text, re.IGNORECASE):
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
) -> None:
    """Create a finding for a detected anomaly."""
    anomaly_str = "; ".join(anomalies)
    payload_display = payload if len(payload) <= 100 else payload[:100] + f"... ({len(payload)} chars)"

    # Build before/after comparison
    baseline_summary = (
        f"Status: {baseline['status']}, Size: {baseline['size']} bytes, "
        f"Time: {baseline['time']:.2f}s"
    )
    fuzzed_summary = (
        f"Status: {resp.status_code if resp else 'N/A'}, "
        f"Size: {len(resp.text) if resp else 'N/A'} bytes, "
        f"Time: {elapsed:.2f}s"
    )

    data_arg = None
    if form_data:
        data_arg = urlencode(form_data)

    session.add_finding(Finding(
        title=f"Zero-Day Heuristic: {category.replace('_', ' ').title()} anomaly in '{param}'",
        severity=Severity.MEDIUM,
        description=(
            f"Differential analysis detected anomalous behavior when fuzzing parameter '{param}' "
            f"with {category.replace('_', ' ')} payload. "
            f"Anomalies: {anomaly_str}. "
            f"This may indicate an unpatched vulnerability, improper input validation, "
            f"or an exploitable edge case that warrants manual investigation."
        ),
        evidence=(
            f"Payload category: {category}\n"
            f"Payload: {payload_display}\n"
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
        cwe="CWE-20",  # Improper Input Validation
        confirmed=False,
        parameter=param,
        payload=payload_display,
        request_method=method,
        response_status=resp.status_code if resp else 0,
        detection_method=(
            f"Intelligent fuzzing with {category} payloads and differential analysis "
            f"against baseline response"
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
    print(f"\n{Fore.CYAN}[⚡] Running Zero-Day Heuristics (Intelligent Fuzzing)...{Style.RESET_ALL}")

    target = session.config.target

    # Get baseline response for differential analysis
    print(f"  {Fore.LIGHTBLACK_EX}▸ Establishing baseline response...{Style.RESET_ALL}")
    baseline = _get_baseline(session, target)
    if baseline["status"] is None:
        print(f"  {Fore.RED}✗ Could not establish baseline, skipping zero-day heuristics.{Style.RESET_ALL}")
        return
    print(
        f"  {Fore.GREEN}✓ Baseline established:{Style.RESET_ALL} status={baseline['status']}, "
        f"size={baseline['size']} bytes, time={baseline['time']:.2f}s"
    )

    # Phase 1: Fuzz URL parameters on crawled URLs
    print(f"  {Fore.LIGHTBLACK_EX}▸ Phase 1: Fuzzing URL parameters...{Style.RESET_ALL}")
    fuzzed_urls = set()
    for url in list(session.crawled_urls):
        parsed = urlparse(url)
        if parsed.query and url not in fuzzed_urls:
            fuzzed_urls.add(url)
            _fuzz_url_params(session, url, baseline)
            if len(fuzzed_urls) >= 10:  # Limit to avoid excessive scanning
                break

    if not fuzzed_urls:
        # If no parameterized URLs found, try common parameter names on the target
        print(f"  {Fore.YELLOW}ℹ No parameterized URLs found, testing common parameters...{Style.RESET_ALL}")
        common_params = ["id", "page", "q", "search", "name", "user", "file", "path", "url", "callback"]
        for param in common_params:
            test_url = f"{target}?{param}=1"
            test_baseline = _get_baseline(session, test_url)
            if test_baseline["status"] and test_baseline["status"] < 404:
                _fuzz_url_params(session, test_url, test_baseline)
                break  # Found a responsive parameter

    # Phase 2: Fuzz form fields
    print(f"  {Fore.LIGHTBLACK_EX}▸ Phase 2: Fuzzing form fields...{Style.RESET_ALL}")
    _fuzz_form_fields(session, baseline)

    # Phase 3: HTTP method confusion
    print(f"  {Fore.LIGHTBLACK_EX}▸ Phase 3: Testing HTTP method confusion...{Style.RESET_ALL}")
    _test_method_confusion(session, baseline)

    # Summary
    found_count = sum(1 for f in session.findings if f.module == "zero_day")
    if found_count > 0:
        print(f"  {Fore.MAGENTA}★ Zero-day heuristic scan complete: {found_count} anomalies detected.{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}✓ Zero-day heuristic scan complete: No anomalies detected.{Style.RESET_ALL}")
