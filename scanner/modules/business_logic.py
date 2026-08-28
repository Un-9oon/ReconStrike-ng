import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession, build_curl
from scanner.log import logger


NUMERIC_PARAM_PATTERNS = re.compile(
    r"(qty|quantity|amount|price|cost|total|count|num|number|size|limit|"
    r"offset|page|id|item|product|order|discount|tax|shipping|fee|rate|"
    r"balance|credit|debit|value|weight|stock|units|max|min)",
    re.IGNORECASE,
)

NEGATIVE_PAYLOADS = [
    ("-1", "Negative value"),
    ("-100", "Large negative value"),
    ("-0.01", "Negative fractional value"),
    ("-999999", "Extreme negative value"),
]

OVERFLOW_PAYLOADS = [
    ("2147483647", "32-bit integer max (INT_MAX)"),
    ("2147483648", "32-bit integer overflow (INT_MAX + 1)"),
    ("9999999999", "Large integer value"),
    ("99999999999999999999", "Extreme large integer"),
    ("0", "Zero value"),
    ("0.001", "Very small fractional value"),
    ("1e308", "Scientific notation (near float max)"),
    ("NaN", "Not-a-Number"),
    ("Infinity", "Infinity value"),
]

PRICE_MANIPULATION_INDICATORS = [
    re.compile(r"(\$|USD|EUR|GBP|price|total|amount|cost)\s*:?\s*-", re.IGNORECASE),
    re.compile(r"negative.*?(balance|total|amount|price)", re.IGNORECASE),
    re.compile(r"(balance|total|amount|price).*?negative", re.IGNORECASE),
]

ERROR_PATTERNS = [
    re.compile(r"(overflow|underflow|out of range|too (large|small))", re.IGNORECASE),
    re.compile(r"(integer|numeric|number|arithmetic)\s*(error|exception|overflow)", re.IGNORECASE),
    re.compile(r"(cannot|can't|unable to)\s*(convert|parse|cast)", re.IGNORECASE),
    re.compile(r"(NaN|Infinity|infinite)\b", re.IGNORECASE),
    re.compile(r"stack\s*overflow", re.IGNORECASE),
]


def _is_numeric_value(value):
    if not value:
        return False
    try:
        float(value.strip())
        return True
    except (ValueError, TypeError):
        return False


def _is_numeric_param(name):
    return bool(NUMERIC_PARAM_PATTERNS.search(name))


def _snippet_around(body, match):
    start = max(0, match.start() - 50)
    end = min(len(body), match.end() + 50)
    return body[start:end].replace('\n', ' ').strip()


def _check_negative_in_response(body):
    for pattern in PRICE_MANIPULATION_INDICATORS:
        match = pattern.search(body)
        if match:
            return match.group(0), _snippet_around(body, match)
    return None, None


def _check_error_in_response(body, baseline_body):
    for pattern in ERROR_PATTERNS:
        if pattern.search(body) and not pattern.search(baseline_body):
            match = pattern.search(body)
            return match.group(0), _snippet_around(body, match)
    return None, None


def _make_test_url(parsed, params, param, payload):
    test_params = dict(params)
    test_params[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))


def _get_url_baseline(session, parsed, params, param, original):
    baseline_params = dict(params)
    baseline_params[param] = [original or "1"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(baseline_params, doseq=True)))
    return session.get(baseline_url)


def _send_form(session, method, action, data):
    if method == "post":
        return session.post(action, data=data)
    return session.get(action, params=data)


def _test_negative_values_url(session, url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    for param, values in params.items():
        original = values[0] if values else ""
        if not _is_numeric_value(original) and not _is_numeric_param(param):
            continue

        baseline_resp = _get_url_baseline(session, parsed, params, param, original)
        if not baseline_resp:
            continue

        for payload, description in NEGATIVE_PAYLOADS:
            test_url = _make_test_url(parsed, params, param, payload)
            resp = session.get(test_url)
            if not resp or resp.status_code in (404, 500):
                continue

            if resp.status_code != 200:
                continue
            neg_indicator, snippet = _check_negative_in_response(resp.text)
            if not neg_indicator:
                continue

            curl_cmd = build_curl("GET", test_url)
            session.add_finding(Finding(
                title="Negative Value Accepted in '{}' (Price/Quantity Manipulation)".format(param),
                severity=Severity.HIGH,
                description=(
                    "The URL parameter '{}' accepts negative values ({}). "
                    "The response indicates the application processed the negative value "
                    "in a financial or quantity context ('{}'). This could "
                    "allow an attacker to manipulate prices, get refunds, add credits, "
                    "or bypass business logic constraints."
                ).format(param, payload, neg_indicator),
                evidence=(
                    "Parameter: {}\n"
                    "Original Value: {}\n"
                    "Payload: {}\n"
                    "Technique: {}\n"
                    "Negative Indicator: {}\n"
                    "Context: {}\n"
                    "Test URL: {}\n"
                    "Response Status: {}"
                ).format(param, original, payload, description,
                         neg_indicator, snippet, test_url, resp.status_code),
                remediation=(
                    "1. Validate all numeric inputs server-side with minimum value constraints.\n"
                    "2. Reject negative values for quantities, prices, and amounts.\n"
                    "3. Use unsigned integer types in the database for non-negative fields.\n"
                    "4. Implement business logic validation layer separate from input validation.\n"
                    "5. Add server-side recalculation of totals; never trust client-submitted prices."
                ),
                url=url,
                module="business_logic",
                cwe="CWE-840",
                confirmed=True,
                location="URL parameter '{}' in {}".format(param, parsed.path),
                parameter=param,
                payload=payload,
                request_method="GET",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Open: {}\n"
                    "2. Change the '{}' parameter to: {}\n"
                    "3. Full test URL: {}\n"
                    "4. Observe that the negative value is processed in the response.\n"
                    "5. Run: {}"
                ).format(url, param, payload, test_url, curl_cmd),
                developer_fix=(
                    "File: Server-side handler for {}.\n\n"
                    "Add server-side validation:\n\n"
                    "  Python:\n"
                    "    {p} = int(request.args.get('{p}', 0))\n"
                    "    if {p} < 0:\n"
                    "        abort(400, 'Invalid value')\n\n"
                    "  Node.js:\n"
                    "    const {p} = parseInt(req.query.{p}, 10);\n"
                    "    if (isNaN({p}) || {p} < 0) {{\n"
                    "      return res.status(400).json({{ error: 'Invalid value' }});\n"
                    "    }}"
                ).format(parsed.path, p=param),
                affected_component="Business logic validation for {}".format(parsed.path),
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
                detection_method="Submitted negative value ({}) for parameter '{}' and detected financial/quantity context in the response indicating the value was processed.".format(payload, param),
            ))
            return


def _test_overflow_values_url(session, url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    for param, values in params.items():
        original = values[0] if values else ""
        if not _is_numeric_value(original) and not _is_numeric_param(param):
            continue

        baseline_resp = _get_url_baseline(session, parsed, params, param, original)
        if not baseline_resp:
            continue
        baseline_text = baseline_resp.text

        for payload, description in OVERFLOW_PAYLOADS:
            test_url = _make_test_url(parsed, params, param, payload)
            resp = session.get(test_url)
            if not resp:
                continue

            error_msg, snippet = _check_error_in_response(resp.text, baseline_text)
            if not error_msg:
                continue

            curl_cmd = build_curl("GET", test_url)
            session.add_finding(Finding(
                title="Integer Overflow / Numeric Error in '{}'".format(param),
                severity=Severity.MEDIUM,
                description=(
                    "The URL parameter '{}' triggers a numeric error when given the "
                    "value '{}' ({}). The application returned an error "
                    "message ('{}') that was absent from the baseline response. "
                    "This indicates insufficient numeric input validation and may lead to "
                    "integer overflow, unexpected behavior, or application crashes."
                ).format(param, payload, description, error_msg),
                evidence=(
                    "Parameter: {}\n"
                    "Original Value: {}\n"
                    "Payload: {}\n"
                    "Technique: {}\n"
                    "Error Message: {}\n"
                    "Context: {}\n"
                    "Test URL: {}\n"
                    "Response Status: {}"
                ).format(param, original, payload, description,
                         error_msg, snippet, test_url, resp.status_code),
                remediation=(
                    "1. Validate numeric inputs against expected ranges on the server side.\n"
                    "2. Use appropriate data types (e.g., BigInteger for large values).\n"
                    "3. Implement input length limits for numeric fields.\n"
                    "4. Handle numeric parsing errors gracefully without exposing internals.\n"
                    "5. Use parameterized queries to prevent overflow in SQL contexts."
                ),
                url=url,
                module="business_logic",
                cwe="CWE-840",
                confirmed=True,
                location="URL parameter '{}' in {}".format(param, parsed.path),
                parameter=param,
                payload=payload,
                request_method="GET",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Open: {}\n"
                    "2. Set the '{}' parameter to: {}\n"
                    "3. Full test URL: {}\n"
                    "4. Observe the error message in the response.\n"
                    "5. Run: {}"
                ).format(url, param, payload, test_url, curl_cmd),
                developer_fix=(
                    "File: Server-side handler for {}.\n\n"
                    "Add bounds checking:\n\n"
                    "  Python:\n"
                    "    try:\n"
                    "        val = int(request.args['{p}'])\n"
                    "        if not (0 <= val <= 2147483647):\n"
                    "            abort(400, 'Value out of range')\n"
                    "    except (ValueError, OverflowError):\n"
                    "        abort(400, 'Invalid numeric input')\n\n"
                    "  Node.js:\n"
                    "    const val = Number(req.query.{p});\n"
                    "    if (!Number.isSafeInteger(val) || val < 0 || val > MAX_ALLOWED) {{\n"
                    "      return res.status(400).json({{ error: 'Value out of range' }});\n"
                    "    }}"
                ).format(parsed.path, p=param),
                affected_component="Numeric input handling in {}".format(parsed.path),
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/ | https://cwe.mitre.org/data/definitions/190.html",
                detection_method="Submitted overflow value ({} - {}) for parameter '{}' and detected numeric error in response absent from baseline.".format(payload, description, param),
            ))
            return


def _test_negative_values_form(session, form):
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)

    baseline_data = {
        inp.get("name"): inp.get("value", "1")
        for inp in inputs if inp.get("name")
    }

    baseline_resp = _send_form(session, method, action, baseline_data)
    if not baseline_resp:
        return
    baseline_text = baseline_resp.text

    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue

        original = inp.get("value", "")
        inp_type = inp.get("type", "").lower()

        if not _is_numeric_value(original) and not _is_numeric_param(name) and inp_type != "number":
            continue

        # Test negatives
        for payload, description in NEGATIVE_PAYLOADS:
            test_data = dict(baseline_data)
            test_data[name] = payload

            resp = _send_form(session, method, action, test_data)
            if not resp or resp.status_code in (404, 500):
                continue

            if resp.status_code != 200:
                continue
            neg_indicator, snippet = _check_negative_in_response(resp.text)
            if not neg_indicator:
                continue

            data_str = urlencode(test_data)
            curl_cmd = build_curl(method.upper(), action, data=data_str)
            session.add_finding(Finding(
                title="Negative Value Accepted in Form Field '{}'".format(name),
                severity=Severity.HIGH,
                description=(
                    "The form field '{}' at '{}' accepts negative values "
                    "({}). The response indicates the negative value was processed "
                    "in a financial or quantity context ('{}'). This could "
                    "enable price manipulation, unauthorized refunds, or credit inflation."
                ).format(name, action, payload, neg_indicator),
                evidence=(
                    "Form Action: {}\n"
                    "Form Method: {}\n"
                    "Field: {}\n"
                    "Original Value: {}\n"
                    "Payload: {}\n"
                    "Negative Indicator: {}\n"
                    "Context: {}\n"
                    "Response Status: {}"
                ).format(action, method.upper(), name, original,
                         payload, neg_indicator, snippet, resp.status_code),
                remediation=(
                    "1. Validate all numeric form inputs server-side before processing.\n"
                    "2. Enforce minimum value of 0 for quantities, prices, and amounts.\n"
                    "3. Recalculate totals server-side; never trust client-submitted values.\n"
                    "4. Add business rule validation in the service layer.\n"
                    "5. Log and alert on negative value submission attempts."
                ),
                url=source_url,
                module="business_logic",
                cwe="CWE-840",
                confirmed=True,
                location="Form field '{}' in form at {}".format(name, action),
                parameter=name,
                payload=payload,
                request_method=method.upper(),
                request_body=data_str,
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Navigate to: {}\n"
                    "2. Locate the form that submits to {}\n"
                    "3. Set the '{}' field to: {}\n"
                    "4. Submit the form and observe the response.\n"
                    "5. Run: {}"
                ).format(source_url, action, name, payload, curl_cmd),
                developer_fix=(
                    "File: Server-side handler for {} {}.\n\n"
                    "Add validation before processing:\n\n"
                    "  Python/Flask:\n"
                    "    {n} = float(request.form.get('{n}', 0))\n"
                    "    if {n} < 0:\n"
                    "        abort(400, '{n} must be non-negative')\n\n"
                    "  Node.js:\n"
                    "    const {n} = parseFloat(req.body.{n});\n"
                    "    if (isNaN({n}) || {n} < 0) {{\n"
                    "      return res.status(400).json({{ error: 'Invalid {n}' }});\n"
                    "    }}"
                ).format(method.upper(), action, n=name),
                affected_component="Form processing logic at {}".format(action),
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
                detection_method="Submitted negative value ({}) in form field '{}' and detected financial/quantity indicator in the response.".format(payload, name),
            ))
            return

        # Test overflow
        for payload, description in OVERFLOW_PAYLOADS:
            test_data = dict(baseline_data)
            test_data[name] = payload

            resp = _send_form(session, method, action, test_data)
            if not resp:
                continue

            error_msg, snippet = _check_error_in_response(resp.text, baseline_text)
            if not error_msg:
                continue

            data_str = urlencode(test_data)
            curl_cmd = build_curl(method.upper(), action, data=data_str)
            session.add_finding(Finding(
                title="Integer Overflow in Form Field '{}'".format(name),
                severity=Severity.MEDIUM,
                description=(
                    "The form field '{}' at '{}' triggers a numeric error "
                    "when submitted with the value '{}' ({}). "
                    "The error message ('{}') was not present in the baseline "
                    "response, indicating insufficient numeric validation."
                ).format(name, action, payload, description, error_msg),
                evidence=(
                    "Form Action: {}\n"
                    "Field: {}\n"
                    "Payload: {}\n"
                    "Technique: {}\n"
                    "Error Message: {}\n"
                    "Context: {}\n"
                    "Response Status: {}"
                ).format(action, name, payload, description,
                         error_msg, snippet, resp.status_code),
                remediation=(
                    "1. Validate numeric inputs against defined ranges server-side.\n"
                    "2. Use try/catch for numeric parsing and return generic errors.\n"
                    "3. Set appropriate min/max attributes on HTML number inputs as a first layer.\n"
                    "4. Never rely on client-side validation alone."
                ),
                url=source_url,
                module="business_logic",
                cwe="CWE-840",
                confirmed=True,
                location="Form field '{}' in form at {}".format(name, action),
                parameter=name,
                payload=payload,
                request_method=method.upper(),
                request_body=urlencode(test_data),
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Navigate to: {}\n"
                    "2. Set the '{}' field to: {}\n"
                    "3. Submit the form and observe the error.\n"
                    "4. Run: {}"
                ).format(source_url, name, payload, curl_cmd),
                developer_fix=(
                    "File: Server-side handler for {} {}.\n\n"
                    "Validate numeric bounds:\n"
                    "  val = int(request.form['{n}'])\n"
                    "  if not (MIN_VALUE <= val <= MAX_VALUE):\n"
                    "      abort(400, 'Value out of acceptable range')"
                ).format(method.upper(), action, n=name),
                affected_component="Numeric processing in form handler for {}".format(action),
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/ | https://cwe.mitre.org/data/definitions/190.html",
                detection_method="Submitted overflow value ({}) in form field '{}' and detected numeric error in response absent from baseline.".format(payload, name),
            ))
            return


def _test_parameter_removal(session, form):
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)

    if len(inputs) < 2:
        return

    baseline_data = {
        inp.get("name"): inp.get("value", "test")
        for inp in inputs if inp.get("name")
    }

    baseline_resp = _send_form(session, method, action, baseline_data)
    if not baseline_resp:
        return

    security_keywords = (
        "token", "csrf", "nonce", "verify", "captcha", "confirm",
        "check", "validate", "auth", "role", "permission", "admin",
        "approved", "status", "active", "enabled", "hidden",
    )
    security_params = [
        inp.get("name") for inp in inputs
        if inp.get("name") and any(kw in inp["name"].lower() for kw in security_keywords)
    ]

    for param_to_remove in security_params:
        reduced_data = {k: v for k, v in baseline_data.items() if k != param_to_remove}
        resp = _send_form(session, method, action, reduced_data)
        if not resp:
            continue

        bypassed = False
        if baseline_resp.status_code in (400, 403, 422) and resp.status_code == 200:
            bypassed = True
        elif resp.status_code == 200 and baseline_resp.status_code == 200:
            if abs(len(resp.text) - len(baseline_resp.text)) > 200:
                success_terms = ["success", "created", "updated", "approved", "granted"]
                bypassed = any(
                    t in resp.text.lower() and t not in baseline_resp.text.lower()
                    for t in success_terms
                )

        if not bypassed:
            continue

        data_str = urlencode(reduced_data)
        curl_cmd = build_curl(method.upper(), action, data=data_str)
        session.add_finding(Finding(
            title="Parameter Removal Bypass (Removed '{}')".format(param_to_remove),
            severity=Severity.MEDIUM,
            description=(
                "Removing the security-relevant parameter '{}' from the "
                "form submission to '{}' produced a different (potentially successful) "
                "response. The application may not properly validate the presence of required "
                "security parameters, allowing an attacker to bypass validation checks."
            ).format(param_to_remove, action),
            evidence=(
                "Form Action: {}\n"
                "Removed Parameter: {}\n"
                "Baseline Status: {}\n"
                "Without Parameter Status: {}\n"
                "Baseline Response Length: {}\n"
                "Modified Response Length: {}"
            ).format(action, param_to_remove, baseline_resp.status_code,
                     resp.status_code, len(baseline_resp.text), len(resp.text)),
            remediation=(
                "1. Validate the presence of all required security parameters server-side.\n"
                "2. Reject requests missing required fields with a clear error.\n"
                "3. Do not rely on hidden form fields for security decisions.\n"
                "4. Implement server-side session-based validation for security-critical operations.\n"
                "5. Use allowlist validation: explicitly require expected parameters."
            ),
            url=source_url,
            module="business_logic",
            cwe="CWE-840",
            confirmed=False,
            location="Parameter '{}' in form at {}".format(param_to_remove, action),
            parameter=param_to_remove,
            payload="(parameter removed from submission)",
            request_method=method.upper(),
            request_body=data_str,
            response_status=resp.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Navigate to: {}\n"
                "2. Locate the form that submits to {}\n"
                "3. Using an intercepting proxy, remove the '{}' parameter.\n"
                "4. Submit the modified request and observe the response.\n"
                "5. Run: {}"
            ).format(source_url, action, param_to_remove, curl_cmd),
            developer_fix=(
                "File: Server-side handler for {} {}.\n\n"
                "Explicitly validate required parameters:\n\n"
                "  Python/Flask:\n"
                "    {p} = request.form.get('{p}')\n"
                "    if not {p}:\n"
                "        abort(400, 'Missing required field: {p}')\n\n"
                "  Node.js:\n"
                "    if (!req.body.{p}) {{\n"
                "      return res.status(400).json({{ error: 'Missing {p}' }});\n"
                "    }}"
            ).format(method.upper(), action, p=param_to_remove),
            affected_component="Input validation in form handler for {}".format(action),
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
            detection_method="Removed the security-relevant parameter '{}' from the form submission and observed a different (potentially bypassed) response.".format(param_to_remove),
        ))


def _test_sequential_ids(session):
    id_pattern = re.compile(
        r"[?&](id|uid|user_id|item_id|order_id|account_id|doc_id|record_id)=(\d+)",
        re.IGNORECASE,
    )
    tested_params = set()

    for url in session.crawled_urls:
        for match in id_pattern.finditer(url):
            param_name = match.group(1)
            original_id = match.group(2)
            param_key = "{}:{}".format(param_name, urlparse(url).path)

            if param_key in tested_params:
                continue
            tested_params.add(param_key)

            original_int = int(original_id)
            baseline_resp = session.get(url)
            if not baseline_resp or baseline_resp.status_code != 200:
                continue

            adjacent_ids = [
                str(v) for v in (original_int - 1, original_int + 1,
                                 original_int - 10, original_int + 10)
                if v >= 0
            ]

            for adj_id in adjacent_ids:
                test_url = re.sub(
                    r"([?&]{p})={orig}".format(p=re.escape(param_name), orig=re.escape(original_id)),
                    r"\g<1>={}".format(adj_id),
                    url,
                )
                resp = session.get(test_url)
                if not resp or resp.status_code != 200 or len(resp.text) <= 100:
                    continue

                if resp.text == baseline_resp.text:
                    continue
                if len(resp.text) <= len(baseline_resp.text) * 0.5:
                    continue

                parsed = urlparse(url)
                curl_cmd = build_curl("GET", test_url)
                session.add_finding(Finding(
                    title="Sequential ID Accessible ('{}' = {})".format(param_name, adj_id),
                    severity=Severity.MEDIUM,
                    description=(
                        "The endpoint '{}' uses sequential numeric IDs for the "
                        "'{}' parameter (original: {}). Adjacent IDs "
                        "(e.g., {}) return valid 200 responses with different content. "
                        "If no authorization checks are performed, this could allow an attacker "
                        "to enumerate and access other users' resources (IDOR)."
                    ).format(parsed.path, param_name, original_id, adj_id),
                    evidence=(
                        "URL: {}\n"
                        "Parameter: {}\n"
                        "Original ID: {}\n"
                        "Adjacent ID Tested: {}\n"
                        "Test URL: {}\n"
                        "Original Response Length: {}\n"
                        "Adjacent Response Length: {}\n"
                        "Response Status: {}"
                    ).format(url, param_name, original_id, adj_id,
                             test_url, len(baseline_resp.text), len(resp.text), resp.status_code),
                    remediation=(
                        "1. Use non-sequential, unpredictable identifiers (UUIDs/GUIDs).\n"
                        "2. Implement server-side authorization checks for every resource access.\n"
                        "3. Verify that the authenticated user owns the requested resource.\n"
                        "4. Return 403/404 for resources the user is not authorized to access.\n"
                        "5. Implement rate limiting on resource enumeration endpoints."
                    ),
                    url=url,
                    module="business_logic",
                    cwe="CWE-840",
                    confirmed=False,
                    location="Parameter '{}' in {}".format(param_name, parsed.path),
                    parameter=param_name,
                    payload=adj_id,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        "1. Access the original URL: {}\n"
                        "2. Change '{}' from {} to {}.\n"
                        "3. Full test URL: {}\n"
                        "4. Observe that the adjacent resource is accessible.\n"
                        "5. Run: {}\n"
                        "6. Compare the content with the original response."
                    ).format(url, param_name, original_id, adj_id, test_url, curl_cmd),
                    developer_fix=(
                        "File: Server-side handler for {}.\n\n"
                        "Add authorization check:\n\n"
                        "  Python/Flask:\n"
                        "    resource = db.get({p}=request.args['{p}'])\n"
                        "    if resource.owner_id != current_user.id:\n"
                        "        abort(403)\n\n"
                        "  Node.js:\n"
                        "    const resource = await Resource.findById(req.query.{p});\n"
                        "    if (resource.ownerId !== req.user.id) {{\n"
                        "      return res.status(403).json({{ error: 'Forbidden' }});\n"
                        "    }}\n\n"
                        "  Better: Use UUIDs instead of sequential IDs:\n"
                        "    id = uuid.uuid4()  # Python\n"
                        "    const id = crypto.randomUUID();  // Node.js"
                    ).format(parsed.path, p=param_name),
                    affected_component="Access control for {}".format(parsed.path),
                    references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/ | https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                    detection_method="Detected sequential numeric ID in parameter '{}' (value: {}), tested adjacent ID ({}), and received a valid response with different content.".format(param_name, original_id, adj_id),
                ))
                break


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for Business Logic Vulnerabilities...")

    for url in session.crawled_urls:
        _test_negative_values_url(session, url)
        _test_overflow_values_url(session, url)

    for form in session.forms:
        _test_negative_values_form(session, form)
        _test_parameter_removal(session, form)

    _test_sequential_ids(session)
