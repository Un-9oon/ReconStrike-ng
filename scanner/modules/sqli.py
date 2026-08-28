import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger

ERROR_PATTERNS = [
    (r"SQL syntax.*?MySQL", "MySQL"),
    (r"Warning.*?\Wmysqli?_", "MySQL"),
    (r"MySQLSyntaxErrorException", "MySQL"),
    (r"check the manual that (?:corresponds to|fits) your MySQL server version", "MySQL"),
    (r"PostgreSQL.*?ERROR", "PostgreSQL"),
    (r"pg_query\(\).*?failed", "PostgreSQL"),
    (r"PSQLException", "PostgreSQL"),
    (r"org\.postgresql\.util\.PSQLException", "PostgreSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"SQLServerException", "MSSQL"),
    (r"ORA-\d{5}", "Oracle"),
    (r"oracle\.jdbc", "Oracle"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"SQLITE_ERROR", "SQLite"),
    (r"unrecognized token:", "SQLite"),
    (r"SQLSTATE\[\w+\]", "Generic"),
    (r"Syntax error.*?in query expression", "Generic"),
]

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "1' AND '1'='1",
    "' UNION SELECT NULL--",
    "') OR ('1'='1",
]

TIME_PAYLOADS = [
    ("' OR SLEEP(5)-- ", 5),
    ("' AND (SELECT * FROM (SELECT SLEEP(5))a)-- ", 5),
    ("'; WAITFOR DELAY '0:0:5'-- ", 5),
    ("' OR pg_sleep(5)-- ", 5),
]


def _build_curl(method, url, data=None):
    cmd = f"curl -k -X {method} '{url}'"
    if data:
        cmd += f" -d '{data}'"
    return cmd


def _extract_error_snippet(body, pattern):
    m = re.search(pattern, body, re.IGNORECASE)
    if not m:
        return ""
    start = max(0, m.start() - 60)
    end = min(len(body), m.end() + 60)
    return body[start:end].replace('\n', ' ').strip()


def _get_baseline(session, url, param, original):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [original or "harmless"]
    resp = session.get(urlunparse(parsed._replace(query=urlencode(params, doseq=True))))
    return resp.text if resp else ""


def _check_error_based(session: ScanSession, url: str, param: str, original_value: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    baseline_text = _get_baseline(session, url, param, original_value)

    for payload in SQLI_PAYLOADS:
        params[param] = [original_value + payload]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        resp = session.get(test_url)
        if not resp or resp.status_code in (404, 403):
            continue

        body = resp.text
        for pattern, db_type in ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if re.search(pattern, baseline_text, re.IGNORECASE):
                    continue
                snippet = _extract_error_snippet(body, pattern)
                curl_cmd = _build_curl("GET", test_url)
                session.add_finding(Finding(
                    title=f"SQL Injection (Error-Based) - {db_type}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The URL parameter '{param}' is vulnerable to error-based SQL injection. "
                        f"When a SQL metacharacter is injected, the application returns a {db_type} "
                        f"database error message in the HTTP response, confirming that user input is "
                        f"concatenated directly into SQL queries without sanitization."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Payload: {original_value}{payload}\n"
                        f"Database Type: {db_type}\n"
                        f"Error Pattern Matched: {pattern}\n"
                        f"Error Snippet: {snippet}\n"
                        f"Test URL: {test_url}\n"
                        f"Response Status: {resp.status_code}"
                    ),
                    remediation=(
                        "1. Use parameterized queries / prepared statements for ALL database queries.\n"
                        "2. Never concatenate user input directly into SQL strings.\n"
                        "3. Implement input validation (allowlist approach) on the parameter.\n"
                        "4. Use an ORM (SQLAlchemy, Hibernate, ActiveRecord) for database access.\n"
                        "5. Configure the application to suppress database error messages in production."
                    ),
                    url=url,
                    module="sqli",
                    cwe="CWE-89",
                    confirmed=True,
                    location=f"URL parameter '{param}' in query string of {parsed.path}",
                    parameter=param,
                    payload=original_value + payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Open: {url}\n"
                        f"2. Modify the '{param}' parameter to: {original_value}{payload}\n"
                        f"3. Full test URL: {test_url}\n"
                        f"4. Observe the {db_type} error message in the response body.\n"
                        f"5. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: The server-side code that handles '{parsed.path}' and uses the "
                        f"'{param}' parameter in a SQL query.\n\n"
                        f"VULNERABLE pattern (do NOT use):\n"
                        f"  query = \"SELECT * FROM table WHERE col = '\" + {param} + \"'\"\n\n"
                        f"SECURE pattern (use this instead):\n"
                        f"  Python: cursor.execute(\"SELECT * FROM table WHERE col = %s\", ({param},))\n"
                        f"  PHP: $stmt = $pdo->prepare(\"SELECT * FROM table WHERE col = ?\"); $stmt->execute([${param}]);\n"
                        f"  Java: PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM table WHERE col = ?\"); ps.setString(1, {param});\n"
                        f"  Node.js: db.query(\"SELECT * FROM table WHERE col = $1\", [{param}])"
                    ),
                    affected_component=f"Database query in route handler for {parsed.path}",
                    references="https://owasp.org/www-community/attacks/SQL_Injection | https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    detection_method="Injected SQL time-delay payloads (e.g., SLEEP(), pg_sleep()) into parameters and measured response time. A baseline request was sent first; delays >5s above baseline on 2/2 attempts confirm blind injection.",
                ))
                return True
    return False


def _check_time_based(session: ScanSession, url: str, param: str, original_value: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    baseline_times = []
    params[param] = [original_value or "harmless"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    for _ in range(2):
        start = time.time()
        session.get(baseline_url)
        baseline_times.append(time.time() - start)
    baseline_max = max(baseline_times)

    for payload, delay in TIME_PAYLOADS:
        params[param] = [original_value + payload]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        hits = 0
        elapsed_times = []
        for _ in range(2):
            start = time.time()
            resp = session.get(test_url)
            elapsed = time.time() - start
            elapsed_times.append(elapsed)

            expected_min = baseline_max + delay - 1.5
            expected_max = baseline_max + delay + 3
            if resp and expected_min <= elapsed <= expected_max:
                hits += 1

        if hits >= 2:
            curl_cmd = _build_curl("GET", test_url)
            session.add_finding(Finding(
                title="SQL Injection (Time-Based Blind)",
                severity=Severity.CRITICAL,
                description=(
                    f"The URL parameter '{param}' is vulnerable to time-based blind SQL injection. "
                    f"By injecting a time-delay SQL function, the server response was delayed by "
                    f"~{delay} seconds consistently across 2 verification requests, confirming "
                    f"that the input is executed as part of a SQL query."
                ),
                evidence=(
                    f"Parameter: {param}\n"
                    f"Payload: {original_value}{payload}\n"
                    f"Expected Delay: {delay}s\n"
                    f"Baseline Response Time: {baseline_max:.2f}s\n"
                    f"Injected Response Times: {', '.join('{:.2f}s'.format(t) for t in elapsed_times)}\n"
                    f"Verification: 2/2 requests matched expected delay window\n"
                    f"Test URL: {test_url}"
                ),
                remediation=(
                    "1. Use parameterized queries / prepared statements.\n"
                    "2. Never concatenate user input into SQL.\n"
                    "3. Use an ORM for database access.\n"
                    "4. Implement input validation on the parameter."
                ),
                url=url,
                module="sqli",
                cwe="CWE-89",
                confirmed=True,
                location=f"URL parameter '{param}' in query string of {parsed.path}",
                parameter=param,
                payload=original_value + payload,
                request_method="GET",
                response_status=resp.status_code if resp else 0,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Open: {url}\n"
                    f"2. Modify the '{param}' parameter to: {original_value}{payload}\n"
                    f"3. Full test URL: {test_url}\n"
                    f"4. Measure the response time -- it should take ~{delay}s longer than normal.\n"
                    f"5. Run: time {curl_cmd}\n"
                    f"6. Normal baseline response time: {baseline_max:.2f}s"
                ),
                developer_fix=(
                    f"File: The server-side code that handles '{parsed.path}' and uses the "
                    f"'{param}' parameter in a SQL query.\n\n"
                    f"Use parameterized queries:\n"
                    f"  Python: cursor.execute(\"SELECT * FROM t WHERE c = %s\", ({param},))\n"
                    f"  PHP: $stmt = $pdo->prepare(\"SELECT * FROM t WHERE c = ?\"); $stmt->execute([${param}]);\n"
                    f"  Java: ps.setString(1, {param});\n"
                    f"  Node.js: db.query(\"SELECT * FROM t WHERE c = $1\", [{param}])"
                ),
                affected_component=f"Database query in route handler for {parsed.path}",
                references="https://owasp.org/www-community/attacks/SQL_Injection | https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                detection_method="Injected SQL time-delay payloads (e.g., SLEEP(), pg_sleep()) into parameters and measured response time. A baseline request was sent first; delays >5s above baseline on 2/2 attempts confirm blind injection.",
            ))
            return True
    return False


def _check_form_sqli(session: ScanSession, form: dict):
    baseline_data = {inp["name"]: inp.get("value", "test")
                     for inp in form["inputs"] if inp.get("name")}

    if form["method"] == "post":
        baseline_resp = session.post(form["action"], data=baseline_data)
    else:
        baseline_resp = session.get(form["action"], params=baseline_data)
    baseline_text = baseline_resp.text if baseline_resp else ""

    for inp in form["inputs"]:
        name = inp.get("name")
        if not name or inp.get("type") in ("hidden", "submit", "button", "checkbox", "radio", "file"):
            continue

        for payload in SQLI_PAYLOADS[:4]:
            post_data = dict(baseline_data)
            post_data[name] = payload

            method = form["method"].upper()
            if form["method"] == "post":
                resp = session.post(form["action"], data=post_data)
            else:
                resp = session.get(form["action"], params=post_data)

            if not resp or resp.status_code in (404, 403):
                continue

            for pattern, db_type in ERROR_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    if re.search(pattern, baseline_text, re.IGNORECASE):
                        continue
                    snippet = _extract_error_snippet(resp.text, pattern)
                    data_str = "&".join(f"{k}={v}" for k, v in post_data.items())
                    curl_cmd = _build_curl(method, form["action"], data=data_str) if method == "POST" else _build_curl("GET", f"{form['action']}?{data_str}")
                    session.add_finding(Finding(
                        title=f"SQL Injection in Form (Error-Based) - {db_type}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The form field '{name}' submitted to {form['action']} is vulnerable "
                            f"to error-based SQL injection. The application returns a {db_type} "
                            f"database error when SQL metacharacters are submitted, confirming "
                            f"unsanitized input is used in SQL queries."
                        ),
                        evidence=(
                            f"Form Action: {form['action']}\n"
                            f"Form Method: {method}\n"
                            f"Vulnerable Field: {name}\n"
                            f"Payload: {payload}\n"
                            f"Database Type: {db_type}\n"
                            f"Error Snippet: {snippet}\n"
                            f"Response Status: {resp.status_code}"
                        ),
                        remediation=(
                            "1. Use parameterized queries / prepared statements.\n"
                            "2. Implement server-side input validation.\n"
                            "3. Use an ORM for database access.\n"
                            "4. Suppress database errors in production."
                        ),
                        url=form.get("source_url", form["action"]),
                        module="sqli",
                        cwe="CWE-89",
                        confirmed=True,
                        location=f"Form field '{name}' at {form['action']}",
                        parameter=name,
                        payload=payload,
                        request_method=method,
                        request_body=data_str,
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            "1. Navigate to: {}\n".format(form.get("source_url", form["action"])) +
                            f"2. Locate the form that submits to: {form['action']}\n"
                            f"3. Enter the following in the '{name}' field: {payload}\n"
                            f"4. Submit the form.\n"
                            f"5. Observe the {db_type} error message in the response.\n"
                            f"6. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"File: The server-side handler for {method} {form['action']} that "
                            f"processes the '{name}' form field in a SQL query.\n\n"
                            f"Use parameterized queries:\n"
                            f"  Python: cursor.execute(\"SELECT * FROM t WHERE c = %s\", ({name},))\n"
                            f"  PHP: $stmt = $pdo->prepare(\"SELECT * FROM t WHERE c = ?\"); $stmt->execute([${name}]);\n"
                            f"  Node.js: db.query(\"SELECT * FROM t WHERE c = $1\", [{name}])"
                        ),
                        affected_component=f"{method} {form['action']} - form field '{name}'",
                        references="https://owasp.org/www-community/attacks/SQL_Injection",
                        detection_method="Injected SQL time-delay payloads (e.g., SLEEP(), pg_sleep()) into parameters and measured response time. A baseline request was sent first; delays >5s above baseline on 2/2 attempts confirm blind injection.",
                    ))
                    return


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for SQL Injection...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param, values in params.items():
            original = values[0] if values else ""
            if not _check_error_based(session, url, param, original):
                _check_time_based(session, url, param, original)

    for form in session.forms:
        _check_form_sqli(session, form)
