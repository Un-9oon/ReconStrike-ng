import threading
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession, build_curl


CONCURRENT_REQUEST_COUNT = 10

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
    cmd = "curl -k -X {} '{}'".format(method, url)
    if data:
        cmd += " -d '{}'".format(data)
    return cmd


def _is_sensitive_endpoint(url, form=None):
    path = urlparse(url).path.lower()
    if any(kw in path for kw in SENSITIVE_PATH_KEYWORDS):
        return True

    if form:
        action = form.get("action", "").lower()
        if any(kw in action for kw in SENSITIVE_FORM_KEYWORDS):
            return True

        for inp in form.get("inputs", []):
            val = str(inp.get("value", "")).lower()
            if inp.get("type", "").lower() in ("submit", "button"):
                if any(kw in val for kw in SENSITIVE_FORM_KEYWORDS):
                    return True

    return False


def _send_concurrent_requests(session, method, url, data=None, count=CONCURRENT_REQUEST_COUNT):
    results = []
    lock = threading.Lock()
    barrier = threading.Barrier(count, timeout=10)

    def _make_request():
        try:
            barrier.wait()
            resp = session.post(url, data=data) if method == "POST" else session.get(url)
            with lock:
                if resp:
                    results.append({
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "body_hash": hash(resp.text[:500]),
                        "headers": dict(resp.headers),
                    })
        except (requests.RequestException, ValueError) as e:
            logger.debug("race_condition _make_request: request failed: %s", e)

    threads = [threading.Thread(target=_make_request, daemon=True) for _ in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    return results


def _analyze_race_results(results):
    if len(results) < 2:
        return None

    statuses = [r["status"] for r in results]
    lengths = [r["length"] for r in results]
    body_hashes = [r["body_hash"] for r in results]

    success_count = sum(1 for s in statuses if 200 <= s < 300)
    unique_statuses = set(statuses)
    unique_hashes = set(body_hashes)

    avg_len = sum(lengths) / len(lengths) if lengths else 0
    max_dev = max(abs(l - avg_len) for l in lengths) if lengths else 0

    return {
        "success_count": success_count,
        "total_count": len(results),
        "unique_statuses": unique_statuses,
        "mixed_statuses": len(unique_statuses) > 1,
        "unique_responses": len(unique_hashes),
        "inconsistent_bodies": len(unique_hashes) > 1,
        "all_succeeded": success_count == len(results),
        "length_variance": max_dev / max(avg_len, 1) if lengths else 0,
    }


def _test_url_race(session, url):
    if not _is_sensitive_endpoint(url):
        return

    parsed = urlparse(url)

    baseline = session.get(url)
    if not baseline or baseline.status_code not in (200, 201, 301, 302):
        return

    results = _send_concurrent_requests(session, "GET", url)
    indicators = _analyze_race_results(results)
    if not indicators:
        return

    race_detected = False
    evidence_details = []

    if indicators["all_succeeded"] and indicators["success_count"] >= CONCURRENT_REQUEST_COUNT - 1:
        race_detected = True
        evidence_details.append(
            "All {}/{} concurrent requests returned success status codes".format(
                indicators['success_count'], indicators['total_count'])
        )

    if indicators["mixed_statuses"]:
        race_detected = True
        evidence_details.append(
            "Mixed status codes returned: {}".format(indicators['unique_statuses'])
        )

    if indicators["inconsistent_bodies"] and indicators["length_variance"] > 0.2:
        race_detected = True
        evidence_details.append(
            "Inconsistent response bodies: {} unique responses with {:.1%} length variance".format(
                indicators['unique_responses'], indicators['length_variance'])
        )

    if race_detected and evidence_details:
        curl_cmd = _build_curl("GET", url)
        session.add_finding(Finding(
            title="Potential Race Condition (GET Endpoint)",
            severity=Severity.MEDIUM,
            description=(
                "The endpoint '{}' appears to be a sensitive action endpoint "
                "that may be vulnerable to race conditions. When {} "
                "identical requests were sent simultaneously, the responses showed indicators "
                "of inconsistent state handling, suggesting the endpoint may process "
                "duplicate requests without proper synchronization.".format(
                    parsed.path, CONCURRENT_REQUEST_COUNT)
            ),
            evidence=(
                "Target URL: {}\n"
                "Concurrent Requests: {}\n"
                "Successful Responses: {}\n"
                "Unique Status Codes: {}\n"
                "Unique Response Bodies: {}\n"
                "Length Variance: {:.1%}\n"
                "Indicators:\n".format(
                    url, indicators['total_count'], indicators['success_count'],
                    indicators['unique_statuses'], indicators['unique_responses'],
                    indicators['length_variance'])
                + "\n".join("  - {}".format(d) for d in evidence_details)
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
            location="Endpoint at {}".format(parsed.path),
            request_method="GET",
            response_status=baseline.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Identify the sensitive endpoint: {}\n"
                "2. Use a tool like Turbo Intruder or a custom script to send "
                "{}+ identical requests simultaneously.\n"
                "3. Compare response statuses and bodies.\n"
                "4. Check for duplicate processing in the application state.\n"
                "5. Single request: {}\n"
                "6. For concurrent testing, use:\n"
                "   for i in $(seq 1 {}); do "
                "curl -k -s '{}' & done; wait".format(
                    url, CONCURRENT_REQUEST_COUNT, curl_cmd,
                    CONCURRENT_REQUEST_COUNT, url)
            ),
            developer_fix=(
                "Handler for {}:\n\n"
                "Add idempotency and locking:\n\n"
                "  Python/Django:\n"
                "    from django.db import transaction\n"
                "    with transaction.atomic():\n"
                "        obj = Model.objects.select_for_update().get(pk=id)\n"
                "        # ... process ...\n\n"
                "  Node.js/SQL:\n"
                "    await db.query('SELECT * FROM table WHERE id = $1 FOR UPDATE', [id]);\n"
                "    // ... process within transaction ...".format(parsed.path)
            ),
            affected_component="State management at {}".format(parsed.path),
            references=(
                "https://portswigger.net/research/smashing-the-state-machine | "
                "https://cwe.mitre.org/data/definitions/362.html | "
                "https://owasp.org/www-community/attacks/Testing_for_Race_Conditions"
            ),
            detection_method=(
                "Sent {} concurrent identical GET requests to a "
                "sensitive endpoint and analyzed response consistency: ".format(
                    CONCURRENT_REQUEST_COUNT)
                + "; ".join(evidence_details)
            ),
        ))


def _test_form_race(session, form):
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)

    if not _is_sensitive_endpoint(action, form):
        return

    parsed = urlparse(action)

    form_data = {inp.get("name"): inp.get("value", "test")
                 for inp in inputs if inp.get("name")}

    baseline = (session.post(action, data=form_data) if method == "post"
                else session.get(action, params=form_data))
    if not baseline:
        return

    results = _send_concurrent_requests(
        session, method.upper(), action,
        data=form_data if method == "post" else None,
        count=CONCURRENT_REQUEST_COUNT,
    )

    indicators = _analyze_race_results(results)
    if not indicators:
        return

    race_detected = False
    evidence_details = []

    if indicators["all_succeeded"] and method == "post":
        race_detected = True
        evidence_details.append(
            "All {}/{} concurrent POST submissions were accepted "
            "(no duplicate-submission protection)".format(
                indicators['success_count'], indicators['total_count'])
        )

    if indicators["mixed_statuses"]:
        success = indicators["success_count"]
        if success > 1:
            race_detected = True
            evidence_details.append(
                "{} of {} concurrent submissions succeeded with mixed statuses {}".format(
                    success, indicators['total_count'], indicators['unique_statuses'])
            )

    if indicators["inconsistent_bodies"] and indicators["length_variance"] > 0.15:
        race_detected = True
        evidence_details.append(
            "Inconsistent responses: {} unique bodies".format(indicators['unique_responses'])
        )

    if race_detected and evidence_details:
        form_data_str = urlencode(form_data)
        curl_cmd = _build_curl(
            method.upper(), action,
            data=form_data_str if method == "post" else None,
        )
        field_names = [inp.get("name", "") for inp in inputs if inp.get("name")]

        session.add_finding(Finding(
            title="Potential Race Condition (Form: {})".format(parsed.path),
            severity=Severity.HIGH,
            description=(
                "The form at '{}' submitting to '{}' appears vulnerable "
                "to race conditions. When {} identical form "
                "submissions were sent simultaneously, multiple submissions were processed "
                "successfully, indicating a lack of duplicate-submission protection or "
                "proper synchronization.".format(
                    source_url, action, CONCURRENT_REQUEST_COUNT)
            ),
            evidence=(
                "Form Action: {}\n"
                "Form Method: {}\n"
                "Form Fields: {}\n"
                "Source URL: {}\n"
                "Concurrent Submissions: {}\n"
                "Successful: {}\n"
                "Unique Statuses: {}\n"
                "Unique Responses: {}\n"
                "Indicators:\n".format(
                    action, method.upper(), ', '.join(field_names), source_url,
                    indicators['total_count'], indicators['success_count'],
                    indicators['unique_statuses'], indicators['unique_responses'])
                + "\n".join("  - {}".format(d) for d in evidence_details)
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
            location="Form submission to {}".format(action),
            parameter=", ".join(field_names),
            request_method=method.upper(),
            request_body=form_data_str,
            response_status=baseline.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Navigate to: {}\n"
                "2. Locate the form that submits to {}.\n"
                "3. Fill in the form fields: {}\n"
                "4. Use Turbo Intruder or a script to submit the form "
                "{} times simultaneously.\n"
                "5. Check if the action was performed multiple times "
                "(e.g., duplicate records, multiple charges).\n"
                "6. Single request: {}\n"
                "7. Concurrent test:\n"
                "   for i in $(seq 1 {}); do "
                "{} & done; wait".format(
                    source_url, action, form_data, CONCURRENT_REQUEST_COUNT,
                    curl_cmd, CONCURRENT_REQUEST_COUNT, curl_cmd)
            ),
            developer_fix=(
                "Handler for {} {}:\n\n"
                "Prevent duplicate processing:\n\n"
                "  Option 1 - Idempotency key:\n"
                "    const key = req.headers['idempotency-key'];\n"
                "    if (await redis.get(`idem:${{key}}`)) return res.status(409).json({{error: 'Duplicate'}});\n"
                "    await redis.set(`idem:${{key}}`, '1', 'EX', 3600);\n\n"
                "  Option 2 - Database lock:\n"
                "    BEGIN;\n"
                "    SELECT * FROM accounts WHERE id = $1 FOR UPDATE;\n"
                "    -- process --\n"
                "    COMMIT;\n\n"
                "  Option 3 - One-time CSRF token:\n"
                "    const token = req.body._csrf;\n"
                "    if (!consumeToken(token)) return res.status(403).json({{error: 'Token already used'}});".format(
                    method.upper(), action)
            ),
            affected_component="Form submission handler at {}".format(action),
            references=(
                "https://portswigger.net/research/smashing-the-state-machine | "
                "https://cwe.mitre.org/data/definitions/362.html | "
                "https://owasp.org/www-community/attacks/Testing_for_Race_Conditions"
            ),
            detection_method=(
                "Sent {} concurrent identical form submissions "
                "to a sensitive endpoint and observed: ".format(CONCURRENT_REQUEST_COUNT)
                + "; ".join(evidence_details)
            ),
        ))


def _test_limit_bypass(session, url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    limit_params = {p: (params[p][0] if params[p] else "1")
                    for p in params
                    if any(kw in p.lower() for kw in ("limit", "count", "quantity", "amount", "num", "max"))}

    if not limit_params:
        return

    for param, value in limit_params.items():
        try:
            resp1 = session.get(url)
            resp2 = session.get(url)
            if not resp1 or not resp2:
                continue

            sequential_same = (
                resp1.status_code == resp2.status_code
                and abs(len(resp1.text) - len(resp2.text)) < 50
            )

            results = _send_concurrent_requests(session, "GET", url, count=5)
            indicators = _analyze_race_results(results)
            if not indicators:
                continue

            # TOCTOU window: concurrent diverges from sequential
            if indicators["mixed_statuses"] and sequential_same:
                curl_cmd = _build_curl("GET", url)
                session.add_finding(Finding(
                    title="Potential Limit Bypass via Race Condition ({})".format(param),
                    severity=Severity.MEDIUM,
                    description=(
                        "The parameter '{}' at '{}' may be vulnerable to "
                        "a limit bypass via race condition. Sequential requests produce "
                        "consistent results, but concurrent requests show inconsistent "
                        "behavior, suggesting a TOCTOU (Time-of-Check-to-Time-of-Use) window "
                        "in the limit enforcement logic.".format(param, parsed.path)
                    ),
                    evidence=(
                        "Target URL: {}\n"
                        "Limit Parameter: {}={}\n"
                        "Sequential: Consistent (status {})\n"
                        "Concurrent: Mixed statuses {}\n"
                        "Success Count: {}/{}".format(
                            url, param, value, resp1.status_code,
                            indicators['unique_statuses'],
                            indicators['success_count'], indicators['total_count'])
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
                    location="Limit enforcement for '{}' at {}".format(param, parsed.path),
                    parameter=param,
                    request_method="GET",
                    response_status=resp1.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        "1. Send sequential requests to {} and confirm consistent behavior.\n"
                        "2. Send 5+ concurrent requests using Turbo Intruder or:\n"
                        "   for i in $(seq 1 5); do {} & done; wait\n"
                        "3. Compare results: concurrent should show different behavior.".format(
                            url, curl_cmd)
                    ),
                    developer_fix=(
                        "Limit checking for '{}' at {}:\n\n"
                        "Use atomic operations:\n"
                        "  Redis: local count = redis.call('DECR', key)\n"
                        "         if count < 0 then redis.call('INCR', key); return error end\n\n"
                        "  SQL: UPDATE limits SET remaining = remaining - 1\n"
                        "       WHERE id = $1 AND remaining > 0\n"
                        "       RETURNING remaining;  -- Atomic check-and-decrement".format(
                            param, parsed.path)
                    ),
                    affected_component="Limit enforcement at {}".format(parsed.path),
                    references=(
                        "https://portswigger.net/research/smashing-the-state-machine | "
                        "https://cwe.mitre.org/data/definitions/362.html"
                    ),
                    detection_method=(
                        "Compared sequential vs. concurrent requests to a limit-controlled "
                        "endpoint. Sequential requests were consistent, but concurrent requests "
                        "showed mixed status codes {}, indicating a TOCTOU window.".format(
                            indicators['unique_statuses'])
                    ),
                ))
        except (requests.RequestException, ValueError) as e:
            logger.debug("race_condition _test_limit_bypass: operation failed: %s", e)
            continue


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for Race Conditions...")

    for url in session.crawled_urls:
        _test_url_race(session, url)
        _test_limit_bypass(session, url)

    for form in session.forms:
        _test_form_race(session, form)
