import threading
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession, build_curl


CONCURRENT_REQUEST_COUNT = 10

# Paths that are commonly susceptible to race conditions
SENSITIVE_PATH_KEYWORDS = [
    "checkout", "purchase", "buy", "order", "pay", "payment",
    "transfer", "send", "withdraw", "deposit",
    "redeem", "coupon", "promo", "discount", "voucher",
    "vote", "like", "follow", "subscribe",
    "register", "signup", "invite",
    "confirm", "approve", "verify",
    "delete", "remove",
    "claim", "reward", "bonus",
]

SENSITIVE_FORM_KEYWORDS = [
    "submit", "confirm", "process", "execute", "apply",
    "transfer", "send", "pay", "checkout", "order",
    "redeem", "claim", "vote", "delete", "remove",
]


def _build_curl(method, url, data=None):
    cmd = f"curl -k -X {method} '{url}'"
    if data:
        cmd += f" -d '{data}'"
    return cmd


def _is_sensitive_endpoint(url, form=None):
    """Check if a URL or form appears to be a sensitive action endpoint."""
    path = urlparse(url).path.lower()
    for kw in SENSITIVE_PATH_KEYWORDS:
        if kw in path:
            return True

    if form:
        action = form.get("action", "").lower()
        for kw in SENSITIVE_FORM_KEYWORDS:
            if kw in action:
                return True

        # Check for submit button text
        for inp in form.get("inputs", []):
            val = str(inp.get("value", "")).lower()
            inp_type = inp.get("type", "").lower()
            if inp_type in ("submit", "button"):
                for kw in SENSITIVE_FORM_KEYWORDS:
                    if kw in val:
                        return True

    return False


def _send_concurrent_requests(session, method, url, data=None, count=CONCURRENT_REQUEST_COUNT):
    """Send multiple identical requests concurrently and collect responses."""
    results = []
    lock = threading.Lock()
    barrier = threading.Barrier(count, timeout=10)

    def _make_request():
        try:
            # Synchronize all threads to fire simultaneously
            barrier.wait()
            if method == "POST":
                resp = session.post(url, data=data)
            else:
                resp = session.get(url)

            with lock:
                if resp:
                    results.append({
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "body_hash": hash(resp.text[:500]),
                        "headers": dict(resp.headers),
                    })
        except Exception as e:
            logger.debug("race_condition _make_request: request failed: %s", e)

    threads = []
    for _ in range(count):
        t = threading.Thread(target=_make_request, daemon=True)
        threads.append(t)

    for t in threads:
        t.start()

    for t in threads:
        t.join(timeout=15)

    return results


def _analyze_race_results(results):
    """Analyze concurrent request results for race condition indicators."""
    if len(results) < 2:
        return None

    statuses = [r["status"] for r in results]
    lengths = [r["length"] for r in results]
    body_hashes = [r["body_hash"] for r in results]

    indicators = {}

    # Count how many requests succeeded (2xx)
    success_count = sum(1 for s in statuses if 200 <= s < 300)
    indicators["success_count"] = success_count
    indicators["total_count"] = len(results)

    # Check for mixed status codes (some succeed, some fail)
    unique_statuses = set(statuses)
    indicators["unique_statuses"] = unique_statuses
    indicators["mixed_statuses"] = len(unique_statuses) > 1

    # Check for inconsistent response bodies
    unique_hashes = set(body_hashes)
    indicators["unique_responses"] = len(unique_hashes)
    indicators["inconsistent_bodies"] = len(unique_hashes) > 1

    # Check if all succeeded (potential double-processing)
    indicators["all_succeeded"] = success_count == len(results)

    # Significant length variance
    if lengths:
        avg_len = sum(lengths) / len(lengths)
        max_deviation = max(abs(l - avg_len) for l in lengths)
        indicators["length_variance"] = max_deviation / max(avg_len, 1)
    else:
        indicators["length_variance"] = 0

    return indicators


def _test_url_race(session, url):
    """Test URL endpoints for race conditions."""
    if not _is_sensitive_endpoint(url):
        return

    parsed = urlparse(url)

    # Get baseline single request
    baseline = session.get(url)
    if not baseline or baseline.status_code not in (200, 201, 301, 302):
        return

    # Send concurrent requests
    results = _send_concurrent_requests(session, "GET", url)
    indicators = _analyze_race_results(results)
    if not indicators:
        return

    race_detected = False
    evidence_details = []

    # If all concurrent requests succeeded on an action endpoint, that's suspicious
    if indicators["all_succeeded"] and indicators["success_count"] >= CONCURRENT_REQUEST_COUNT - 1:
        race_detected = True
        evidence_details.append(
            f"All {indicators['success_count']}/{indicators['total_count']} concurrent "
            f"requests returned success status codes"
        )

    # Mixed statuses on identical requests suggest a race window
    if indicators["mixed_statuses"]:
        race_detected = True
        evidence_details.append(
            f"Mixed status codes returned: {indicators['unique_statuses']}"
        )

    # Inconsistent response bodies with high variance
    if indicators["inconsistent_bodies"] and indicators["length_variance"] > 0.2:
        race_detected = True
        evidence_details.append(
            f"Inconsistent response bodies: {indicators['unique_responses']} unique "
            f"responses with {indicators['length_variance']:.1%} length variance"
        )

    if race_detected and evidence_details:
        curl_cmd = _build_curl("GET", url)
        session.add_finding(Finding(
            title="Potential Race Condition (GET Endpoint)",
            severity=Severity.MEDIUM,
            description=(
                f"The endpoint '{parsed.path}' appears to be a sensitive action endpoint "
                f"that may be vulnerable to race conditions. When {CONCURRENT_REQUEST_COUNT} "
                f"identical requests were sent simultaneously, the responses showed indicators "
                f"of inconsistent state handling, suggesting the endpoint may process "
                f"duplicate requests without proper synchronization."
            ),
            evidence=(
                f"Target URL: {url}\n"
                f"Concurrent Requests: {indicators['total_count']}\n"
                f"Successful Responses: {indicators['success_count']}\n"
                f"Unique Status Codes: {indicators['unique_statuses']}\n"
                f"Unique Response Bodies: {indicators['unique_responses']}\n"
                f"Length Variance: {indicators['length_variance']:.1%}\n"
                f"Indicators:\n"
                + "\n".join(f"  - {d}" for d in evidence_details)
            ),
            remediation=(
                "1. Implement idempotency keys for state-changing operations.\n"
                "2. Use database-level locking (SELECT ... FOR UPDATE) or atomic operations.\n"
                "3. Implement distributed locks (Redis/mutex) for critical sections.\n"
                "4. Use unique constraints in the database to prevent duplicate records.\n"
                "5. Implement optimistic concurrency control with version fields."
            ),
            url=url,
            module="race_condition",
            cwe="CWE-362",
            confirmed=False,
            location=f"Endpoint at {parsed.path}",
            request_method="GET",
            response_status=baseline.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                f"1. Identify the sensitive endpoint: {url}\n"
                f"2. Use a tool like Turbo Intruder or a custom script to send "
                f"{CONCURRENT_REQUEST_COUNT}+ identical requests simultaneously.\n"
                f"3. Compare response statuses and bodies.\n"
                f"4. Check for duplicate processing in the application state.\n"
                f"5. Single request: {curl_cmd}\n"
                f"6. For concurrent testing, use:\n"
                f"   for i in $(seq 1 {CONCURRENT_REQUEST_COUNT}); do "
                f"curl -k -s '{url}' & done; wait"
            ),
            developer_fix=(
                f"Handler for {parsed.path}:\n\n"
                "Add idempotency and locking:\n\n"
                "  Python/Django:\n"
                "    from django.db import transaction\n"
                "    with transaction.atomic():\n"
                "        obj = Model.objects.select_for_update().get(pk=id)\n"
                "        # ... process ...\n\n"
                "  Node.js/SQL:\n"
                "    await db.query('SELECT * FROM table WHERE id = $1 FOR UPDATE', [id]);\n"
                "    // ... process within transaction ..."
            ),
            affected_component=f"State management at {parsed.path}",
            references=(
                "https://portswigger.net/research/smashing-the-state-machine | "
                "https://cwe.mitre.org/data/definitions/362.html | "
                "https://owasp.org/www-community/attacks/Testing_for_Race_Conditions"
            ),
            detection_method=(
                f"Sent {CONCURRENT_REQUEST_COUNT} concurrent identical GET requests to a "
                f"sensitive endpoint and analyzed response consistency: "
                + "; ".join(evidence_details)
            ),
        ))


def _test_form_race(session, form):
    """Test form submissions for race conditions (double-submit)."""
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)

    if not _is_sensitive_endpoint(action, form):
        return

    parsed = urlparse(action)

    # Build form data
    form_data = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            form_data[name] = inp.get("value", "test")

    # Get a baseline single submission
    if method == "post":
        baseline = session.post(action, data=form_data)
    else:
        baseline = session.get(action, params=form_data)

    if not baseline:
        return

    # Send concurrent form submissions
    results = _send_concurrent_requests(
        session,
        method.upper(),
        action,
        data=form_data if method == "post" else None,
        count=CONCURRENT_REQUEST_COUNT,
    )

    indicators = _analyze_race_results(results)
    if not indicators:
        return

    race_detected = False
    evidence_details = []

    # For POST forms: if all concurrent submissions succeed, there may be no
    # duplicate-submission protection
    if indicators["all_succeeded"] and method == "post":
        race_detected = True
        evidence_details.append(
            f"All {indicators['success_count']}/{indicators['total_count']} concurrent "
            f"POST submissions were accepted (no duplicate-submission protection)"
        )

    if indicators["mixed_statuses"]:
        # Some succeeded, some failed -- partial race window
        success = indicators["success_count"]
        if success > 1:
            race_detected = True
            evidence_details.append(
                f"{success} of {indicators['total_count']} concurrent submissions "
                f"succeeded with mixed statuses {indicators['unique_statuses']}"
            )

    if indicators["inconsistent_bodies"] and indicators["length_variance"] > 0.15:
        race_detected = True
        evidence_details.append(
            f"Inconsistent responses: {indicators['unique_responses']} unique bodies"
        )

    if race_detected and evidence_details:
        form_data_str = urlencode(form_data)
        curl_cmd = _build_curl(
            method.upper(),
            action,
            data=form_data_str if method == "post" else None,
        )

        field_names = [inp.get("name", "") for inp in inputs if inp.get("name")]

        session.add_finding(Finding(
            title=f"Potential Race Condition (Form: {parsed.path})",
            severity=Severity.HIGH,
            description=(
                f"The form at '{source_url}' submitting to '{action}' appears vulnerable "
                f"to race conditions. When {CONCURRENT_REQUEST_COUNT} identical form "
                f"submissions were sent simultaneously, multiple submissions were processed "
                f"successfully, indicating a lack of duplicate-submission protection or "
                f"proper synchronization."
            ),
            evidence=(
                f"Form Action: {action}\n"
                f"Form Method: {method.upper()}\n"
                f"Form Fields: {', '.join(field_names)}\n"
                f"Source URL: {source_url}\n"
                f"Concurrent Submissions: {indicators['total_count']}\n"
                f"Successful: {indicators['success_count']}\n"
                f"Unique Statuses: {indicators['unique_statuses']}\n"
                f"Unique Responses: {indicators['unique_responses']}\n"
                f"Indicators:\n"
                + "\n".join(f"  - {d}" for d in evidence_details)
            ),
            remediation=(
                "1. Implement anti-CSRF tokens that are consumed on use (one-time tokens).\n"
                "2. Use database-level unique constraints to prevent duplicate records.\n"
                "3. Implement idempotency keys for financial or state-changing operations.\n"
                "4. Use SELECT ... FOR UPDATE or advisory locks for critical sections.\n"
                "5. Implement client-side double-submit prevention (disable button on click).\n"
                "6. Use a distributed lock (Redis SETNX) for high-concurrency scenarios."
            ),
            url=source_url,
            module="race_condition",
            cwe="CWE-362",
            confirmed=False,
            location=f"Form submission to {action}",
            parameter=", ".join(field_names),
            request_method=method.upper(),
            request_body=form_data_str,
            response_status=baseline.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                f"1. Navigate to: {source_url}\n"
                f"2. Locate the form that submits to {action}.\n"
                f"3. Fill in the form fields: {form_data}\n"
                f"4. Use Turbo Intruder or a script to submit the form "
                f"{CONCURRENT_REQUEST_COUNT} times simultaneously.\n"
                f"5. Check if the action was performed multiple times "
                f"(e.g., duplicate records, multiple charges).\n"
                f"6. Single request: {curl_cmd}\n"
                f"7. Concurrent test:\n"
                f"   for i in $(seq 1 {CONCURRENT_REQUEST_COUNT}); do "
                f"{curl_cmd} & done; wait"
            ),
            developer_fix=(
                f"Handler for {method.upper()} {action}:\n\n"
                "Prevent duplicate processing:\n\n"
                "  Option 1 - Idempotency key:\n"
                "    const key = req.headers['idempotency-key'];\n"
                "    if (await redis.get(`idem:${key}`)) return res.status(409).json({error: 'Duplicate'});\n"
                "    await redis.set(`idem:${key}`, '1', 'EX', 3600);\n\n"
                "  Option 2 - Database lock:\n"
                "    BEGIN;\n"
                "    SELECT * FROM accounts WHERE id = $1 FOR UPDATE;\n"
                "    -- process --\n"
                "    COMMIT;\n\n"
                "  Option 3 - One-time CSRF token:\n"
                "    const token = req.body._csrf;\n"
                "    if (!consumeToken(token)) return res.status(403).json({error: 'Token already used'});"
            ),
            affected_component=f"Form submission handler at {action}",
            references=(
                "https://portswigger.net/research/smashing-the-state-machine | "
                "https://cwe.mitre.org/data/definitions/362.html | "
                "https://owasp.org/www-community/attacks/Testing_for_Race_Conditions"
            ),
            detection_method=(
                f"Sent {CONCURRENT_REQUEST_COUNT} concurrent identical form submissions "
                f"to a sensitive endpoint and observed: " + "; ".join(evidence_details)
            ),
        ))


def _test_limit_bypass(session, url):
    """Test if rate limits or resource limits can be bypassed via concurrent requests."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # Look for endpoints that might have limits (pagination, quantity, count)
    limit_params = {}
    for param in params:
        param_lower = param.lower()
        if any(kw in param_lower for kw in ("limit", "count", "quantity", "amount", "num", "max")):
            limit_params[param] = params[param][0] if params[param] else "1"

    if not limit_params:
        return

    for param, value in limit_params.items():
        try:
            # Get sequential baseline responses
            resp1 = session.get(url)
            resp2 = session.get(url)
            if not resp1 or not resp2:
                continue

            # If sequential requests show rate limiting or different behavior
            sequential_same = (
                resp1.status_code == resp2.status_code
                and abs(len(resp1.text) - len(resp2.text)) < 50
            )

            # Now test concurrent
            results = _send_concurrent_requests(session, "GET", url, count=5)
            indicators = _analyze_race_results(results)
            if not indicators:
                continue

            if indicators["mixed_statuses"] and sequential_same:
                # Concurrent requests produced different results than sequential,
                # suggesting a TOCTOU window in limit checking
                curl_cmd = _build_curl("GET", url)
                session.add_finding(Finding(
                    title=f"Potential Limit Bypass via Race Condition ({param})",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The parameter '{param}' at '{parsed.path}' may be vulnerable to "
                        f"a limit bypass via race condition. Sequential requests produce "
                        f"consistent results, but concurrent requests show inconsistent "
                        f"behavior, suggesting a TOCTOU (Time-of-Check-to-Time-of-Use) window "
                        f"in the limit enforcement logic."
                    ),
                    evidence=(
                        f"Target URL: {url}\n"
                        f"Limit Parameter: {param}={value}\n"
                        f"Sequential: Consistent (status {resp1.status_code})\n"
                        f"Concurrent: Mixed statuses {indicators['unique_statuses']}\n"
                        f"Success Count: {indicators['success_count']}/{indicators['total_count']}"
                    ),
                    remediation=(
                        "1. Use atomic database operations for limit checks and decrements.\n"
                        "2. Implement optimistic locking with version columns.\n"
                        "3. Use Redis atomic DECR for rate limit counters.\n"
                        "4. Ensure limit checks and state updates are in the same transaction."
                    ),
                    url=url,
                    module="race_condition",
                    cwe="CWE-362",
                    confirmed=False,
                    location=f"Limit enforcement for '{param}' at {parsed.path}",
                    parameter=param,
                    request_method="GET",
                    response_status=resp1.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Send sequential requests to {url} and confirm consistent behavior.\n"
                        f"2. Send 5+ concurrent requests using Turbo Intruder or:\n"
                        f"   for i in $(seq 1 5); do {curl_cmd} & done; wait\n"
                        f"3. Compare results: concurrent should show different behavior."
                    ),
                    developer_fix=(
                        f"Limit checking for '{param}' at {parsed.path}:\n\n"
                        "Use atomic operations:\n"
                        "  Redis: local count = redis.call('DECR', key)\n"
                        "         if count < 0 then redis.call('INCR', key); return error end\n\n"
                        "  SQL: UPDATE limits SET remaining = remaining - 1\n"
                        "       WHERE id = $1 AND remaining > 0\n"
                        "       RETURNING remaining;  -- Atomic check-and-decrement"
                    ),
                    affected_component=f"Limit enforcement at {parsed.path}",
                    references=(
                        "https://portswigger.net/research/smashing-the-state-machine | "
                        "https://cwe.mitre.org/data/definitions/362.html"
                    ),
                    detection_method=(
                        f"Compared sequential vs. concurrent requests to a limit-controlled "
                        f"endpoint. Sequential requests were consistent, but concurrent requests "
                        f"showed mixed status codes {indicators['unique_statuses']}, indicating "
                        f"a TOCTOU window."
                    ),
                ))
        except Exception as e:
            logger.debug("race_condition _test_limit_bypass: operation failed: %s", e)
            continue


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Race Conditions...")

    for url in session.crawled_urls:
        _test_url_race(session, url)
        _test_limit_bypass(session, url)

    for form in session.forms:
        _test_form_race(session, form)
