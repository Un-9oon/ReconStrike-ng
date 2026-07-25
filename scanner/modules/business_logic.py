import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession, build_curl


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
    """Check if a value looks numeric."""
    if not value:
        return False
    try:
        float(value.strip())
        return True
    except (ValueError, TypeError):
        return False


def _is_numeric_param(name):
    """Check if a parameter name suggests a numeric field."""
    return bool(NUMERIC_PARAM_PATTERNS.search(name))


def _check_negative_in_response(body):
    """Check if the response indicates negative value processing."""
    for pattern in PRICE_MANIPULATION_INDICATORS:
        match = pattern.search(body)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(body), match.end() + 50)
            return match.group(0), body[start:end].replace('\n', ' ').strip()
    return None, None


def _check_error_in_response(body, baseline_body):
    """Check for error messages that weren't in the baseline."""
    for pattern in ERROR_PATTERNS:
        if pattern.search(body) and not pattern.search(baseline_body):
            match = pattern.search(body)
            start = max(0, match.start() - 50)
            end = min(len(body), match.end() + 50)
            return match.group(0), body[start:end].replace('\n', ' ').strip()
    return None, None


def _test_negative_values_url(session, url):
    """Test URL parameters for negative value manipulation."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    for param, values in params.items():
        original = values[0] if values else ""
        if not _is_numeric_value(original) and not _is_numeric_param(param):
            continue

        # Get baseline
        baseline_params = dict(params)
        baseline_params[param] = [original or "1"]
        baseline_url = urlunparse(parsed._replace(
            query=urlencode(baseline_params, doseq=True)
        ))
        baseline_resp = session.get(baseline_url)
        if not baseline_resp:
            continue
        baseline_text = baseline_resp.text

        for payload, description in NEGATIVE_PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            test_url = urlunparse(parsed._replace(
                query=urlencode(test_params, doseq=True)
            ))
            resp = session.get(test_url)
            if not resp or resp.status_code in (404, 500):
                continue

            # Check if negative value was accepted (200 OK and content suggests processing)
            if resp.status_code == 200:
                neg_indicator, snippet = _check_negative_in_response(resp.text)
                if neg_indicator:
                    curl_cmd = build_curl("GET", test_url)
                    session.add_finding(Finding(
                        title=f"Negative Value Accepted in '{param}' (Price/Quantity Manipulation)",
                        severity=Severity.HIGH,
                        description=(
                            f"The URL parameter '{param}' accepts negative values ({payload}). "
                            f"The response indicates the application processed the negative value "
                            f"in a financial or quantity context ('{neg_indicator}'). This could "
                            f"allow an attacker to manipulate prices, get refunds, add credits, "
                            f"or bypass business logic constraints."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Original Value: {original}\n"
                            f"Payload: {payload}\n"
                            f"Technique: {description}\n"
                            f"Negative Indicator: {neg_indicator}\n"
                            f"Context: {snippet}\n"
                            f"Test URL: {test_url}\n"
                            f"Response Status: {resp.status_code}"
                        ),
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
                        location=f"URL parameter '{param}' in {parsed.path}",
                        parameter=param,
                        payload=payload,
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Open: {url}\n"
                            f"2. Change the '{param}' parameter to: {payload}\n"
                            f"3. Full test URL: {test_url}\n"
                            f"4. Observe that the negative value is processed in the response.\n"
                            f"5. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"File: Server-side handler for {parsed.path}.\n\n"
                            f"Add server-side validation:\n\n"
                            f"  Python:\n"
                            f"    {param} = int(request.args.get('{param}', 0))\n"
                            f"    if {param} < 0:\n"
                            f"        abort(400, 'Invalid value')\n\n"
                            f"  Node.js:\n"
                            f"    const {param} = parseInt(req.query.{param}, 10);\n"
                            f"    if (isNaN({param}) || {param} < 0) {{\n"
                            f"      return res.status(400).json({{ error: 'Invalid value' }});\n"
                            f"    }}"
                        ),
                        affected_component=f"Business logic validation for {parsed.path}",
                        references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
                        detection_method=f"Submitted negative value ({payload}) for parameter '{param}' and detected financial/quantity context in the response indicating the value was processed.",
                    ))
                    return


def _test_overflow_values_url(session, url):
    """Test URL parameters for integer overflow vulnerabilities."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    for param, values in params.items():
        original = values[0] if values else ""
        if not _is_numeric_value(original) and not _is_numeric_param(param):
            continue

        baseline_params = dict(params)
        baseline_params[param] = [original or "1"]
        baseline_url = urlunparse(parsed._replace(
            query=urlencode(baseline_params, doseq=True)
        ))
        baseline_resp = session.get(baseline_url)
        if not baseline_resp:
            continue
        baseline_text = baseline_resp.text

        for payload, description in OVERFLOW_PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            test_url = urlunparse(parsed._replace(
                query=urlencode(test_params, doseq=True)
            ))
            resp = session.get(test_url)
            if not resp:
                continue

            # Check for overflow errors
            error_msg, snippet = _check_error_in_response(
                resp.text, baseline_text
            )
            if error_msg:
                curl_cmd = build_curl("GET", test_url)
                session.add_finding(Finding(
                    title=f"Integer Overflow / Numeric Error in '{param}'",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The URL parameter '{param}' triggers a numeric error when given the "
                        f"value '{payload}' ({description}). The application returned an error "
                        f"message ('{error_msg}') that was absent from the baseline response. "
                        f"This indicates insufficient numeric input validation and may lead to "
                        f"integer overflow, unexpected behavior, or application crashes."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Original Value: {original}\n"
                        f"Payload: {payload}\n"
                        f"Technique: {description}\n"
                        f"Error Message: {error_msg}\n"
                        f"Context: {snippet}\n"
                        f"Test URL: {test_url}\n"
                        f"Response Status: {resp.status_code}"
                    ),
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
                    location=f"URL parameter '{param}' in {parsed.path}",
                    parameter=param,
                    payload=payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Open: {url}\n"
                        f"2. Set the '{param}' parameter to: {payload}\n"
                        f"3. Full test URL: {test_url}\n"
                        f"4. Observe the error message in the response.\n"
                        f"5. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: Server-side handler for {parsed.path}.\n\n"
                        f"Add bounds checking:\n\n"
                        f"  Python:\n"
                        f"    try:\n"
                        f"        val = int(request.args['{param}'])\n"
                        f"        if not (0 <= val <= 2147483647):\n"
                        f"            abort(400, 'Value out of range')\n"
                        f"    except (ValueError, OverflowError):\n"
                        f"        abort(400, 'Invalid numeric input')\n\n"
                        f"  Node.js:\n"
                        f"    const val = Number(req.query.{param});\n"
                        f"    if (!Number.isSafeInteger(val) || val < 0 || val > MAX_ALLOWED) {{\n"
                        f"      return res.status(400).json({{ error: 'Value out of range' }});\n"
                        f"    }}"
                    ),
                    affected_component=f"Numeric input handling in {parsed.path}",
                    references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/ | https://cwe.mitre.org/data/definitions/190.html",
                    detection_method=f"Submitted overflow value ({payload} - {description}) for parameter '{param}' and detected numeric error in response absent from baseline.",
                ))
                return


def _test_negative_values_form(session, form):
    """Test form fields for negative value manipulation."""
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)

    baseline_data = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            baseline_data[name] = inp.get("value", "1")

    if method == "post":
        baseline_resp = session.post(action, data=baseline_data)
    else:
        baseline_resp = session.get(action, params=baseline_data)
    if not baseline_resp:
        return
    baseline_text = baseline_resp.text

    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue

        original = inp.get("value", "")
        inp_type = inp.get("type", "").lower()

        # Focus on numeric-looking fields
        if not _is_numeric_value(original) and not _is_numeric_param(name) and inp_type != "number":
            continue

        # Test negative values
        for payload, description in NEGATIVE_PAYLOADS:
            test_data = dict(baseline_data)
            test_data[name] = payload

            if method == "post":
                resp = session.post(action, data=test_data)
            else:
                resp = session.get(action, params=test_data)

            if not resp or resp.status_code in (404, 500):
                continue

            if resp.status_code == 200:
                neg_indicator, snippet = _check_negative_in_response(resp.text)
                if neg_indicator:
                    data_str = urlencode(test_data)
                    curl_cmd = build_curl(method.upper(), action, data=data_str)
                    session.add_finding(Finding(
                        title=f"Negative Value Accepted in Form Field '{name}'",
                        severity=Severity.HIGH,
                        description=(
                            f"The form field '{name}' at '{action}' accepts negative values "
                            f"({payload}). The response indicates the negative value was processed "
                            f"in a financial or quantity context ('{neg_indicator}'). This could "
                            f"enable price manipulation, unauthorized refunds, or credit inflation."
                        ),
                        evidence=(
                            f"Form Action: {action}\n"
                            f"Form Method: {method.upper()}\n"
                            f"Field: {name}\n"
                            f"Original Value: {original}\n"
                            f"Payload: {payload}\n"
                            f"Negative Indicator: {neg_indicator}\n"
                            f"Context: {snippet}\n"
                            f"Response Status: {resp.status_code}"
                        ),
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
                            f"4. Submit the form and observe the response.\n"
                            f"5. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"File: Server-side handler for {method.upper()} {action}.\n\n"
                            f"Add validation before processing:\n\n"
                            f"  Python/Flask:\n"
                            f"    {name} = float(request.form.get('{name}', 0))\n"
                            f"    if {name} < 0:\n"
                            f"        abort(400, '{name} must be non-negative')\n\n"
                            f"  Node.js:\n"
                            f"    const {name} = parseFloat(req.body.{name});\n"
                            f"    if (isNaN({name}) || {name} < 0) {{\n"
                            f"      return res.status(400).json({{ error: 'Invalid {name}' }});\n"
                            f"    }}"
                        ),
                        affected_component=f"Form processing logic at {action}",
                        references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
                        detection_method=f"Submitted negative value ({payload}) in form field '{name}' and detected financial/quantity indicator in the response.",
                    ))
                    return

        # Test overflow values
        for payload, description in OVERFLOW_PAYLOADS:
            test_data = dict(baseline_data)
            test_data[name] = payload

            if method == "post":
                resp = session.post(action, data=test_data)
            else:
                resp = session.get(action, params=test_data)

            if not resp:
                continue

            error_msg, snippet = _check_error_in_response(resp.text, baseline_text)
            if error_msg:
                data_str = urlencode(test_data)
                curl_cmd = build_curl(method.upper(), action, data=data_str)
                session.add_finding(Finding(
                    title=f"Integer Overflow in Form Field '{name}'",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The form field '{name}' at '{action}' triggers a numeric error "
                        f"when submitted with the value '{payload}' ({description}). "
                        f"The error message ('{error_msg}') was not present in the baseline "
                        f"response, indicating insufficient numeric validation."
                    ),
                    evidence=(
                        f"Form Action: {action}\n"
                        f"Field: {name}\n"
                        f"Payload: {payload}\n"
                        f"Technique: {description}\n"
                        f"Error Message: {error_msg}\n"
                        f"Context: {snippet}\n"
                        f"Response Status: {resp.status_code}"
                    ),
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
                    location=f"Form field '{name}' in form at {action}",
                    parameter=name,
                    payload=payload,
                    request_method=method.upper(),
                    request_body=urlencode(test_data),
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Navigate to: {source_url}\n"
                        f"2. Set the '{name}' field to: {payload}\n"
                        f"3. Submit the form and observe the error.\n"
                        f"4. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: Server-side handler for {method.upper()} {action}.\n\n"
                        f"Validate numeric bounds:\n"
                        f"  val = int(request.form['{name}'])\n"
                        f"  if not (MIN_VALUE <= val <= MAX_VALUE):\n"
                        f"      abort(400, 'Value out of acceptable range')"
                    ),
                    affected_component=f"Numeric processing in form handler for {action}",
                    references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/ | https://cwe.mitre.org/data/definitions/190.html",
                    detection_method=f"Submitted overflow value ({payload}) in form field '{name}' and detected numeric error in response absent from baseline.",
                ))
                return


def _test_parameter_removal(session, form):
    """Test if removing required form parameters leads to bypass."""
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)

    if len(inputs) < 2:
        return

    baseline_data = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            baseline_data[name] = inp.get("value", "test")

    if method == "post":
        baseline_resp = session.post(action, data=baseline_data)
    else:
        baseline_resp = session.get(action, params=baseline_data)
    if not baseline_resp:
        return

    # Focus on parameters that look security-relevant
    security_params = []
    for inp in inputs:
        name = inp.get("name", "").lower()
        if not name:
            continue
        if any(kw in name for kw in (
            "token", "csrf", "nonce", "verify", "captcha", "confirm",
            "check", "validate", "auth", "role", "permission", "admin",
            "approved", "status", "active", "enabled", "hidden",
        )):
            security_params.append(inp.get("name"))

    for param_to_remove in security_params:
        reduced_data = {k: v for k, v in baseline_data.items() if k != param_to_remove}

        if method == "post":
            resp = session.post(action, data=reduced_data)
        else:
            resp = session.get(action, params=reduced_data)

        if not resp:
            continue

        # Check if removal led to a successful response where baseline had an error,
        # or a significantly different response
        bypassed = False
        if baseline_resp.status_code in (400, 403, 422) and resp.status_code == 200:
            bypassed = True
        elif resp.status_code == 200 and baseline_resp.status_code == 200:
            # Check if response content differs significantly (e.g., bypassed validation)
            if abs(len(resp.text) - len(baseline_resp.text)) > 200:
                # Look for success indicators not in baseline
                success_terms = ["success", "created", "updated", "approved", "granted"]
                for term in success_terms:
                    if term in resp.text.lower() and term not in baseline_resp.text.lower():
                        bypassed = True
                        break

        if bypassed:
            data_str = urlencode(reduced_data)
            curl_cmd = build_curl(method.upper(), action, data=data_str)
            session.add_finding(Finding(
                title=f"Parameter Removal Bypass (Removed '{param_to_remove}')",
                severity=Severity.MEDIUM,
                description=(
                    f"Removing the security-relevant parameter '{param_to_remove}' from the "
                    f"form submission to '{action}' produced a different (potentially successful) "
                    f"response. The application may not properly validate the presence of required "
                    f"security parameters, allowing an attacker to bypass validation checks."
                ),
                evidence=(
                    f"Form Action: {action}\n"
                    f"Removed Parameter: {param_to_remove}\n"
                    f"Baseline Status: {baseline_resp.status_code}\n"
                    f"Without Parameter Status: {resp.status_code}\n"
                    f"Baseline Response Length: {len(baseline_resp.text)}\n"
                    f"Modified Response Length: {len(resp.text)}"
                ),
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
                location=f"Parameter '{param_to_remove}' in form at {action}",
                parameter=param_to_remove,
                payload=f"(parameter removed from submission)",
                request_method=method.upper(),
                request_body=data_str,
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Navigate to: {source_url}\n"
                    f"2. Locate the form that submits to {action}\n"
                    f"3. Using an intercepting proxy, remove the '{param_to_remove}' parameter.\n"
                    f"4. Submit the modified request and observe the response.\n"
                    f"5. Run: {curl_cmd}"
                ),
                developer_fix=(
                    f"File: Server-side handler for {method.upper()} {action}.\n\n"
                    f"Explicitly validate required parameters:\n\n"
                    f"  Python/Flask:\n"
                    f"    {param_to_remove} = request.form.get('{param_to_remove}')\n"
                    f"    if not {param_to_remove}:\n"
                    f"        abort(400, 'Missing required field: {param_to_remove}')\n\n"
                    f"  Node.js:\n"
                    f"    if (!req.body.{param_to_remove}) {{\n"
                    f"      return res.status(400).json({{ error: 'Missing {param_to_remove}' }});\n"
                    f"    }}"
                ),
                affected_component=f"Input validation in form handler for {action}",
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
                detection_method=f"Removed the security-relevant parameter '{param_to_remove}' from the form submission and observed a different (potentially bypassed) response.",
            ))


def _test_sequential_ids(session):
    """Detect and test sequential/predictable IDs for access control issues."""
    id_pattern = re.compile(r"[?&](id|uid|user_id|item_id|order_id|account_id|doc_id|record_id)=(\d+)", re.IGNORECASE)

    tested_params = set()

    for url in session.crawled_urls:
        matches = id_pattern.finditer(url)
        for match in matches:
            param_name = match.group(1)
            original_id = match.group(2)
            param_key = f"{param_name}:{urlparse(url).path}"

            if param_key in tested_params:
                continue
            tested_params.add(param_key)

            original_int = int(original_id)
            # Get baseline response
            baseline_resp = session.get(url)
            if not baseline_resp or baseline_resp.status_code != 200:
                continue

            # Try adjacent IDs
            adjacent_ids = [
                str(original_int - 1),
                str(original_int + 1),
                str(original_int - 10),
                str(original_int + 10),
            ]

            for adj_id in adjacent_ids:
                if int(adj_id) < 0:
                    continue

                test_url = re.sub(
                    rf"([?&]{re.escape(param_name)})={re.escape(original_id)}",
                    rf"\g<1>={adj_id}",
                    url,
                )
                resp = session.get(test_url)
                if not resp:
                    continue

                # If we can access adjacent resources with 200, it might be IDOR
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Check that response content actually differs (not just the same page)
                    if resp.text != baseline_resp.text and len(resp.text) > len(baseline_resp.text) * 0.5:
                        parsed = urlparse(url)
                        curl_cmd = build_curl("GET", test_url)
                        session.add_finding(Finding(
                            title=f"Sequential ID Accessible ('{param_name}' = {adj_id})",
                            severity=Severity.MEDIUM,
                            description=(
                                f"The endpoint '{parsed.path}' uses sequential numeric IDs for the "
                                f"'{param_name}' parameter (original: {original_id}). Adjacent IDs "
                                f"(e.g., {adj_id}) return valid 200 responses with different content. "
                                f"If no authorization checks are performed, this could allow an attacker "
                                f"to enumerate and access other users' resources (IDOR)."
                            ),
                            evidence=(
                                f"URL: {url}\n"
                                f"Parameter: {param_name}\n"
                                f"Original ID: {original_id}\n"
                                f"Adjacent ID Tested: {adj_id}\n"
                                f"Test URL: {test_url}\n"
                                f"Original Response Length: {len(baseline_resp.text)}\n"
                                f"Adjacent Response Length: {len(resp.text)}\n"
                                f"Response Status: {resp.status_code}"
                            ),
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
                            location=f"Parameter '{param_name}' in {parsed.path}",
                            parameter=param_name,
                            payload=adj_id,
                            request_method="GET",
                            response_status=resp.status_code,
                            curl_command=curl_cmd,
                            reproduction_steps=(
                                f"1. Access the original URL: {url}\n"
                                f"2. Change '{param_name}' from {original_id} to {adj_id}.\n"
                                f"3. Full test URL: {test_url}\n"
                                f"4. Observe that the adjacent resource is accessible.\n"
                                f"5. Run: {curl_cmd}\n"
                                f"6. Compare the content with the original response."
                            ),
                            developer_fix=(
                                f"File: Server-side handler for {parsed.path}.\n\n"
                                f"Add authorization check:\n\n"
                                f"  Python/Flask:\n"
                                f"    resource = db.get({param_name}=request.args['{param_name}'])\n"
                                f"    if resource.owner_id != current_user.id:\n"
                                f"        abort(403)\n\n"
                                f"  Node.js:\n"
                                f"    const resource = await Resource.findById(req.query.{param_name});\n"
                                f"    if (resource.ownerId !== req.user.id) {{\n"
                                f"      return res.status(403).json({{ error: 'Forbidden' }});\n"
                                f"    }}\n\n"
                                f"  Better: Use UUIDs instead of sequential IDs:\n"
                                f"    id = uuid.uuid4()  # Python\n"
                                f"    const id = crypto.randomUUID();  // Node.js"
                            ),
                            affected_component=f"Access control for {parsed.path}",
                            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/ | https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                            detection_method=f"Detected sequential numeric ID in parameter '{param_name}' (value: {original_id}), tested adjacent ID ({adj_id}), and received a valid response with different content.",
                        ))
                        break  # One finding per param is enough


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Business Logic Vulnerabilities...")

    for url in session.crawled_urls:
        _test_negative_values_url(session, url)
        _test_overflow_values_url(session, url)

    for form in session.forms:
        _test_negative_values_form(session, form)
        _test_parameter_removal(session, form)

    _test_sequential_ids(session)
