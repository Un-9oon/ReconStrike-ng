import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger


def _build_curl(method, url, data=None):
    cmd = "curl -k -X {} '{}'".format(method, url)
    if data:
        cmd += " -d '{}'".format(data)
    return cmd


def _get_baseline(session, url, param, value):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value or "1"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    return session.get(baseline_url)


HANDLING_LABELS = {
    "first": "uses the FIRST occurrence",
    "last": "uses the LAST occurrence",
    "both": "uses BOTH values",
    "concatenated": "CONCATENATES the values",
}


def _detect_handling(baseline_text, test_text, val1, val2):
    if not baseline_text or not test_text:
        return None

    has_val1 = val1 in test_text
    has_val2 = val2 in test_text

    if "{}{}".format(val1, val2) in test_text or "{},{}".format(val1, val2) in test_text:
        return "concatenated"
    if has_val1 and has_val2:
        return "both"
    if has_val2 and not has_val1:
        return "last"
    if has_val1 and not has_val2:
        return "first"
    return None


def _response_differs_significantly(baseline_resp, test_resp):
    if not baseline_resp or not test_resp:
        return False
    if baseline_resp.status_code != test_resp.status_code:
        return True
    baseline_len = len(baseline_resp.text)
    test_len = len(test_resp.text)
    if baseline_len == 0:
        return test_len > 50
    return abs(test_len - baseline_len) / max(baseline_len, 1) > 0.1


MARKER_VAL1 = "hpp_first_7291"
MARKER_VAL2 = "hpp_second_3847"


def _test_url_params(session, url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    for param, values in params.items():
        original = values[0] if values else ""

        baseline_resp = _get_baseline(session, url, param, original or "1")
        if not baseline_resp:
            continue

        val1 = original or MARKER_VAL1
        val2 = MARKER_VAL2

        other_params = [
            "{}={}".format(p, v)
            for p, vs in params.items() if p != param for v in vs
        ]
        dup_query = "&".join(other_params + ["{}={}".format(param, val1), "{}={}".format(param, val2)])
        test_url = urlunparse(parsed._replace(query=dup_query))

        resp = session.get(test_url)
        if not resp or resp.status_code in (404, 500):
            continue

        handling = _detect_handling(baseline_resp.text, resp.text, val1, val2)
        differs = _response_differs_significantly(baseline_resp, resp)

        if not handling and not differs:
            continue

        # Test WAF bypass with a duplicate carrying a malicious value
        attack_val1 = original or "1"
        attack_val2 = "1 OR 1=1"
        attack_query = "&".join(
            other_params + ["{}={}".format(param, attack_val1), "{}={}".format(param, attack_val2)]
        )
        attack_url = urlunparse(parsed._replace(query=attack_query))
        attack_resp = session.get(attack_url)

        waf_bypass_indicator = False
        if attack_resp and attack_resp.status_code == 200:
            single_params = dict(params)
            single_params[param] = [attack_val2]
            single_url = urlunparse(parsed._replace(query=urlencode(single_params, doseq=True)))
            single_resp = session.get(single_url)
            if single_resp and single_resp.status_code in (403, 406, 429):
                waf_bypass_indicator = True

        handling_desc = HANDLING_LABELS.get(handling, "produces different behavior")
        severity = Severity.MEDIUM if waf_bypass_indicator else Severity.LOW

        curl_cmd = _build_curl("GET", test_url)
        session.add_finding(Finding(
            title="HTTP Parameter Pollution (GET) - Server {}".format(handling_desc),
            severity=severity,
            description=(
                "The URL parameter '{}' is susceptible to HTTP Parameter Pollution. "
                "When duplicate parameters are supplied, the server {}. {}"
            ).format(
                param, handling_desc,
                "Additionally, a WAF bypass was detected: a single malicious parameter "
                "was blocked, but the same payload passed through when duplicated."
                if waf_bypass_indicator else
                "This behavior inconsistency can be exploited for WAF bypass, "
                "logic flaws, or parameter precedence attacks."
            ),
            evidence=(
                "Parameter: {}\n"
                "Test URL: {}\n"
                "Server Handling: {}\n"
                "Baseline Status: {}\n"
                "Duplicate Param Status: {}\n"
                "Response Differs: {}\n"
                "WAF Bypass Detected: {}{}"
            ).format(param, test_url, handling_desc,
                     baseline_resp.status_code, resp.status_code, differs,
                     waf_bypass_indicator,
                     "\n  Single malicious param blocked, duplicate allowed" if waf_bypass_indicator else ""),
            remediation=(
                "1. Explicitly handle duplicate parameters in server-side code:\n"
                "   - Accept only the first value or reject the request entirely.\n"
                "2. Ensure WAF/proxy and application see the same parameter value.\n"
                "3. Use a framework that rejects duplicate parameters by default.\n"
                "4. Validate parameters after any proxying/load-balancing layer.\n"
                "5. If using multiple layers, ensure both use the same parameter."
            ),
            url=url,
            module="hpp",
            cwe="CWE-235",
            confirmed=waf_bypass_indicator,
            location="URL parameter '{}' in query string of {}".format(param, parsed.path),
            parameter=param,
            payload="{}={}&{}={}".format(param, val1, param, val2),
            request_method="GET",
            response_status=resp.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Open: {}\n"
                "2. Add a duplicate parameter: {}\n"
                "3. Observe which value the server uses ({}).\n"
                "4. Run: {}\n"
                "5. Compare the response with the baseline (single param) response.{}"
            ).format(url, test_url, handling_desc, curl_cmd,
                     "\n6. WAF bypass: single malicious value was blocked, duplicate was allowed."
                     if waf_bypass_indicator else ""),
            developer_fix=(
                "File: Server-side code handling '{path}'.\n\n"
                "Explicitly extract only a single value per parameter:\n\n"
                "  Python/Flask:\n"
                "    value = request.args.get('{p}')  # Gets first value only\n\n"
                "  Node.js/Express:\n"
                "    const value = Array.isArray(req.query.{p})\n"
                "      ? req.query.{p}[0]\n"
                "      : req.query.{p};\n\n"
                "  PHP:\n"
                "    // PHP natively uses last value; be aware of param[] array syntax"
            ).format(path=parsed.path, p=param),
            affected_component="Parameter handling in route for {}".format(parsed.path),
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution | https://book.hacktricks.xyz/pentesting-web/parameter-pollution",
            detection_method="Sent duplicate URL parameters ('{}' appearing twice with different values) and analyzed which value the server used. Server {}.".format(param, handling_desc),
        ))


def _test_form_params(session, form):
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)

    if method != "post":
        return

    baseline_data = {
        inp.get("name"): inp.get("value", "test")
        for inp in inputs if inp.get("name")
    }

    baseline_resp = session.post(action, data=baseline_data)
    if not baseline_resp:
        return

    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue

        val1 = inp.get("value", "test")
        val2 = MARKER_VAL2

        dup_data = [(k, v) for k, v in baseline_data.items() if k != name]
        dup_data.extend([(name, val1), (name, val2)])

        resp = session.post(action, data=dup_data)
        if not resp or resp.status_code in (404, 500):
            continue

        handling = _detect_handling(baseline_resp.text, resp.text, val1, val2)
        differs = _response_differs_significantly(baseline_resp, resp)

        if not handling and not differs:
            continue

        handling_desc = HANDLING_LABELS.get(handling, "produces different behavior")
        post_body = "&".join("{}={}".format(k, v) for k, v in dup_data)
        curl_cmd = _build_curl("POST", action, data=post_body)

        session.add_finding(Finding(
            title="HTTP Parameter Pollution (POST Form) - Server {}".format(handling_desc),
            severity=Severity.LOW,
            description=(
                "The form field '{}' at '{}' is susceptible to HTTP Parameter "
                "Pollution via POST. When the field appears twice with "
                "different values, the server {}. This can lead to logic "
                "flaws, WAF bypass, or parameter precedence attacks."
            ).format(name, action, handling_desc),
            evidence=(
                "Form Action: {}\nForm Method: POST\nField: {}\n"
                "Duplicate Values: {}, {}\nServer Handling: {}\n"
                "Baseline Status: {}\nDuplicate Param Status: {}\n"
                "Response Differs: {}"
            ).format(action, name, val1, val2, handling_desc,
                     baseline_resp.status_code, resp.status_code, differs),
            remediation=(
                "1. Explicitly handle duplicate POST parameters on the server side.\n"
                "2. Reject requests with duplicate parameter names.\n"
                "3. Ensure WAF and application agree on which value to use.\n"
                "4. Use a strict parameter parser that does not silently merge values."
            ),
            url=source_url,
            module="hpp",
            cwe="CWE-235",
            confirmed=False,
            location="Form field '{}' in form at {}".format(name, action),
            parameter=name,
            payload="{}={}&{}={}".format(name, val1, name, val2),
            request_method="POST",
            request_body=post_body,
            response_status=resp.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Navigate to: {}\n"
                "2. Locate the form that submits to {}\n"
                "3. Using an intercepting proxy, duplicate the '{}' field:\n"
                "   {}={}&{}={}\n"
                "4. Submit and observe which value the server uses.\n"
                "5. Run: {}"
            ).format(source_url, action, name, name, val1, name, val2, curl_cmd),
            developer_fix=(
                "File: Server-side handler for POST {}.\n\n"
                "Explicitly extract a single value:\n\n"
                "  Python/Flask:\n"
                "    value = request.form.get('{n}')  # First value only\n\n"
                "  Node.js/Express:\n"
                "    const value = Array.isArray(req.body.{n})\n"
                "      ? req.body.{n}[0]\n"
                "      : req.body.{n};\n\n"
                "  Or reject duplicates:\n"
                "    if (Array.isArray(req.body.{n})) return res.status(400).json({{error: 'Invalid input'}});"
            ).format(action, n=name),
            affected_component="POST parameter handling in form handler for {}".format(action),
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution",
            detection_method="Submitted duplicate POST form parameters ('{}' appearing twice) and detected the server {} based on response content comparison.".format(name, handling_desc),
        ))


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for HTTP Parameter Pollution...")

    for url in session.crawled_urls:
        _test_url_params(session, url)

    for form in session.forms:
        _test_form_params(session, form)
