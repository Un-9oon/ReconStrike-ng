import json
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession


PROTO_PAYLOADS_URL = [
    ("__proto__[polluted]=true", "__proto__ bracket injection"),
    ("__proto__.polluted=true", "__proto__ dot injection"),
    ("constructor[prototype][polluted]=true", "constructor.prototype bracket injection"),
    ("constructor.prototype.polluted=true", "constructor.prototype dot injection"),
    ("__proto__[isAdmin]=true", "__proto__ privilege escalation (isAdmin)"),
    ("__proto__[role]=admin", "__proto__ privilege escalation (role)"),
    ("__proto__[debug]=true", "__proto__ debug mode activation"),
    ("__proto__[status]=admin", "__proto__ status override"),
]

PROTO_PAYLOADS_JSON = [
    ({"__proto__": {"polluted": "true"}}, "__proto__ object injection"),
    ({"__proto__": {"isAdmin": True}}, "__proto__ isAdmin gadget"),
    ({"__proto__": {"role": "admin"}}, "__proto__ role gadget"),
    ({"__proto__": {"debug": True}}, "__proto__ debug gadget"),
    ({"__proto__": {"status": 1}}, "__proto__ status gadget"),
    ({"constructor": {"prototype": {"polluted": "true"}}}, "constructor.prototype injection"),
]

POLLUTION_INDICATORS = [
    (r'"polluted"\s*:\s*"?true"?', "polluted property reflected"),
    (r'"isAdmin"\s*:\s*true', "isAdmin property reflected as true"),
    (r'"role"\s*:\s*"admin"', "role property reflected as admin"),
    (r'"debug"\s*:\s*true', "debug property reflected as true"),
    (r'"status"\s*:\s*("admin"|1)', "status property reflected"),
]

ERROR_PATTERNS = [
    (r"Cannot read propert(?:y|ies) of", "JS property access error"),
    (r"Object\.prototype", "Object.prototype reference leaked"),
    (r"prototype pollution", "Prototype pollution keyword"),
    (r"\[object Object\]", "Object coercion indicator"),
]


def _build_curl(method, url, data=None, content_type=None):
    cmd = f"curl -k -X {method} '{url}'"
    if content_type:
        cmd += f" -H 'Content-Type: {content_type}'"
    if data:
        cmd += f" -d '{data}'"
    return cmd


def _check_pollution_reflected(body, baseline_body):
    """Check if any prototype pollution indicators appear in response but not baseline."""
    for pattern, description in POLLUTION_INDICATORS:
        if re.search(pattern, body, re.IGNORECASE):
            if not baseline_body or not re.search(pattern, baseline_body, re.IGNORECASE):
                return pattern, description
    return None, None


def _check_error_indicators(body, baseline_body):
    """Check for error messages indicating prototype chain interaction."""
    for pattern, description in ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            if not baseline_body or not re.search(pattern, baseline_body, re.IGNORECASE):
                return pattern, description
    return None, None


def _extract_snippet(body, pattern):
    match = re.search(pattern, body, re.IGNORECASE)
    if match:
        start = max(0, match.start() - 80)
        end = min(len(body), match.end() + 80)
        return body[start:end].replace('\n', ' ').strip()
    return ""


def _response_differs(baseline_resp, test_resp):
    if not baseline_resp or not test_resp:
        return False
    if baseline_resp.status_code != test_resp.status_code:
        return True
    bl = len(baseline_resp.text)
    tl = len(test_resp.text)
    if bl == 0:
        return tl > 0
    return abs(tl - bl) / max(bl, 1) > 0.15


def _test_url_params(session, url):
    """Test URL parameters for prototype pollution via query string injection."""
    parsed = urlparse(url)

    # Test appending __proto__ payloads to existing query strings
    for payload, description in PROTO_PAYLOADS_URL:
        if parsed.query:
            test_query = parsed.query + "&" + payload
        else:
            test_query = payload
        test_url = urlunparse(parsed._replace(query=test_query))

        # Get baseline without pollution payload
        baseline_resp = session.get(url)
        baseline_text = baseline_resp.text if baseline_resp else ""

        resp = session.get(test_url)
        if not resp or resp.status_code in (404, 403):
            continue

        # Check for reflected pollution properties
        pattern, indicator = _check_pollution_reflected(resp.text, baseline_text)
        if pattern:
            snippet = _extract_snippet(resp.text, pattern)
            curl_cmd = _build_curl("GET", test_url)
            session.add_finding(Finding(
                title=f"Prototype Pollution (Reflected) - {indicator}",
                severity=Severity.HIGH,
                description=(
                    f"The application is vulnerable to JavaScript Prototype Pollution via URL "
                    f"parameters. When '{description}' was injected via the query string, the "
                    f"polluted property appeared in the server response, confirming that the "
                    f"injected prototype properties are merged into application objects."
                ),
                evidence=(
                    f"Payload: {payload}\n"
                    f"Technique: {description}\n"
                    f"Indicator: {indicator}\n"
                    f"Reflected Pattern: {pattern}\n"
                    f"Snippet: {snippet}\n"
                    f"Test URL: {test_url}\n"
                    f"Response Status: {resp.status_code}"
                ),
                remediation=(
                    "1. Freeze Object.prototype using Object.freeze(Object.prototype).\n"
                    "2. Use Object.create(null) for dictionary-like objects.\n"
                    "3. Validate and sanitize all keys in user input; reject '__proto__' and 'constructor'.\n"
                    "4. Use a safe merge/deep-copy library that filters prototype keys.\n"
                    "5. Apply schema validation on all incoming JSON and query parameters."
                ),
                url=url,
                module="prototype_pollution",
                cwe="CWE-1321",
                confirmed=True,
                location=f"Query string of {parsed.path}",
                parameter="__proto__",
                payload=payload,
                request_method="GET",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Open: {url}\n"
                    f"2. Append the following to the query string: {payload}\n"
                    f"3. Full test URL: {test_url}\n"
                    f"4. Observe the polluted property in the response ({indicator}).\n"
                    f"5. Run: {curl_cmd}"
                ),
                developer_fix=(
                    f"File: The server-side code handling '{parsed.path}'.\n\n"
                    f"VULNERABLE pattern (do NOT use):\n"
                    f"  function merge(target, source) {{\n"
                    f"    for (let key in source) {{ target[key] = source[key]; }}\n"
                    f"  }}\n\n"
                    f"SECURE pattern:\n"
                    f"  function safeMerge(target, source) {{\n"
                    f"    for (let key of Object.keys(source)) {{\n"
                    f"      if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;\n"
                    f"      target[key] = source[key];\n"
                    f"    }}\n"
                    f"  }}"
                ),
                affected_component=f"Object merge/assignment in route handler for {parsed.path}",
                references="https://portswigger.net/web-security/prototype-pollution | https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution",
                detection_method=f"Injected prototype pollution payload ({description}) via URL query string and detected polluted property reflected in server response.",
            ))
            return

        # Check for error-based detection
        err_pattern, err_desc = _check_error_indicators(resp.text, baseline_text)
        if err_pattern:
            snippet = _extract_snippet(resp.text, err_pattern)
            curl_cmd = _build_curl("GET", test_url)
            session.add_finding(Finding(
                title=f"Potential Prototype Pollution (Error-Based) - {err_desc}",
                severity=Severity.MEDIUM,
                description=(
                    f"The application may be vulnerable to Prototype Pollution. When "
                    f"'{description}' was injected via the query string, the server returned "
                    f"an error message ({err_desc}) that was not present in the baseline, "
                    f"suggesting the injected key interacted with the prototype chain."
                ),
                evidence=(
                    f"Payload: {payload}\n"
                    f"Technique: {description}\n"
                    f"Error Indicator: {err_desc}\n"
                    f"Error Snippet: {snippet}\n"
                    f"Test URL: {test_url}\n"
                    f"Response Status: {resp.status_code}"
                ),
                remediation=(
                    "1. Sanitize all user-supplied object keys; reject '__proto__' and 'constructor'.\n"
                    "2. Use Object.create(null) for config/options objects.\n"
                    "3. Freeze prototypes: Object.freeze(Object.prototype).\n"
                    "4. Use Map instead of plain objects for dynamic key-value storage."
                ),
                url=url,
                module="prototype_pollution",
                cwe="CWE-1321",
                confirmed=False,
                location=f"Query string of {parsed.path}",
                parameter="__proto__",
                payload=payload,
                request_method="GET",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Open: {url}\n"
                    f"2. Append: {payload}\n"
                    f"3. Full URL: {test_url}\n"
                    f"4. Observe the error message in the response.\n"
                    f"5. Run: {curl_cmd}"
                ),
                developer_fix=(
                    f"File: The server-side code handling '{parsed.path}'.\n\n"
                    f"Filter dangerous keys before any object merge:\n"
                    f"  const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);\n"
                    f"  function safeAssign(target, source) {{\n"
                    f"    for (const [key, val] of Object.entries(source)) {{\n"
                    f"      if (BLOCKED_KEYS.has(key)) continue;\n"
                    f"      target[key] = val;\n"
                    f"    }}\n"
                    f"  }}"
                ),
                affected_component=f"Object processing in route handler for {parsed.path}",
                references="https://portswigger.net/web-security/prototype-pollution | https://owasp.org/www-community/vulnerabilities/Prototype_Pollution",
                detection_method=f"Injected prototype pollution payload ({description}) and detected error message ({err_desc}) in response absent from baseline.",
            ))
            return


def _test_forms_json(session, form):
    """Test form submissions with JSON bodies for prototype pollution."""
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)

    if method != "post":
        return

    # Build baseline JSON body
    baseline_json = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            baseline_json[name] = inp.get("value", "test")

    baseline_resp = session.post(action, json=baseline_json)
    if not baseline_resp:
        return
    baseline_text = baseline_resp.text

    for proto_obj, description in PROTO_PAYLOADS_JSON:
        test_json = dict(baseline_json)
        test_json.update(proto_obj)

        try:
            resp = session.post(action, json=test_json)
        except Exception:
            continue

        if not resp or resp.status_code in (404, 403):
            continue

        # Check for reflected pollution
        pattern, indicator = _check_pollution_reflected(resp.text, baseline_text)
        if pattern:
            snippet = _extract_snippet(resp.text, pattern)
            data_str = json.dumps(test_json)
            curl_cmd = _build_curl("POST", action, data=data_str, content_type="application/json")
            session.add_finding(Finding(
                title=f"Prototype Pollution via JSON Body - {indicator}",
                severity=Severity.HIGH,
                description=(
                    f"The form endpoint '{action}' is vulnerable to Prototype Pollution via "
                    f"JSON body. When a '{description}' payload was submitted in the JSON body, "
                    f"the polluted property was reflected in the server response, confirming "
                    f"that the injected prototype properties are merged into application objects."
                ),
                evidence=(
                    f"Form Action: {action}\n"
                    f"Technique: {description}\n"
                    f"Indicator: {indicator}\n"
                    f"Reflected Pattern: {pattern}\n"
                    f"Snippet: {snippet}\n"
                    f"Payload JSON: {data_str}\n"
                    f"Response Status: {resp.status_code}"
                ),
                remediation=(
                    "1. Strip '__proto__' and 'constructor' keys from parsed JSON before processing.\n"
                    "2. Use JSON.parse with a reviver that rejects dangerous keys.\n"
                    "3. Use Object.create(null) for merge targets.\n"
                    "4. Freeze Object.prototype in your application startup.\n"
                    "5. Use a schema validator (ajv, Joi) that only allows expected keys."
                ),
                url=source_url,
                module="prototype_pollution",
                cwe="CWE-1321",
                confirmed=True,
                location=f"JSON body submitted to {action}",
                parameter="__proto__",
                payload=data_str,
                request_method="POST",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Navigate to: {source_url}\n"
                    f"2. Submit a POST request to {action} with JSON body:\n"
                    f"   {data_str}\n"
                    f"3. Observe the polluted property in the response ({indicator}).\n"
                    f"4. Run: {curl_cmd}"
                ),
                developer_fix=(
                    f"File: The handler for POST {action}.\n\n"
                    f"Sanitize JSON input before merge:\n"
                    f"  function sanitizeInput(obj) {{\n"
                    f"    if (typeof obj !== 'object' || obj === null) return obj;\n"
                    f"    const clean = Object.create(null);\n"
                    f"    for (const [key, val] of Object.entries(obj)) {{\n"
                    f"      if (key === '__proto__' || key === 'constructor') continue;\n"
                    f"      clean[key] = sanitizeInput(val);\n"
                    f"    }}\n"
                    f"    return clean;\n"
                    f"  }}\n"
                    f"  const data = sanitizeInput(req.body);"
                ),
                affected_component=f"JSON body parsing / object merge in handler for {action}",
                references="https://portswigger.net/web-security/prototype-pollution/server-side | https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution",
                detection_method=f"Injected prototype pollution payload ({description}) via JSON POST body and detected polluted property reflected in server response.",
            ))
            return

        # Check for error-based indicators
        err_pattern, err_desc = _check_error_indicators(resp.text, baseline_text)
        if err_pattern:
            snippet = _extract_snippet(resp.text, err_pattern)
            data_str = json.dumps(test_json)
            curl_cmd = _build_curl("POST", action, data=data_str, content_type="application/json")
            session.add_finding(Finding(
                title=f"Potential Prototype Pollution via JSON (Error-Based) - {err_desc}",
                severity=Severity.MEDIUM,
                description=(
                    f"The endpoint '{action}' may be vulnerable to Prototype Pollution via "
                    f"JSON body. When a '{description}' payload was submitted, the server "
                    f"returned an error ({err_desc}) not present in the baseline response."
                ),
                evidence=(
                    f"Form Action: {action}\n"
                    f"Technique: {description}\n"
                    f"Error Indicator: {err_desc}\n"
                    f"Error Snippet: {snippet}\n"
                    f"Payload JSON: {data_str}\n"
                    f"Response Status: {resp.status_code}"
                ),
                remediation=(
                    "1. Sanitize all JSON keys; reject '__proto__' and 'constructor'.\n"
                    "2. Use schema validation to reject unexpected properties.\n"
                    "3. Use a safe deep-merge library (e.g., lodash >= 4.17.12).\n"
                    "4. Freeze Object.prototype at application startup."
                ),
                url=source_url,
                module="prototype_pollution",
                cwe="CWE-1321",
                confirmed=False,
                location=f"JSON body submitted to {action}",
                parameter="__proto__",
                payload=data_str,
                request_method="POST",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Navigate to: {source_url}\n"
                    f"2. Submit JSON to {action}: {data_str}\n"
                    f"3. Observe the error in the response.\n"
                    f"4. Run: {curl_cmd}"
                ),
                developer_fix=(
                    f"File: The handler for POST {action}.\n\n"
                    f"Use JSON.parse with a reviver to strip dangerous keys:\n"
                    f"  JSON.parse(body, (key, value) => {{\n"
                    f"    if (key === '__proto__' || key === 'constructor') return undefined;\n"
                    f"    return value;\n"
                    f"  }});"
                ),
                affected_component=f"JSON parsing in handler for {action}",
                references="https://portswigger.net/web-security/prototype-pollution/server-side",
                detection_method=f"Injected prototype pollution payload ({description}) via JSON body and detected error ({err_desc}) in response absent from baseline.",
            ))
            return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Prototype Pollution...")

    for url in session.crawled_urls:
        _test_url_params(session, url)

    for form in session.forms:
        _test_forms_json(session, form)
