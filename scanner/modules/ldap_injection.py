import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession

LDAP_PAYLOADS = [
    ("*", "Wildcard injection"),
    (")(cn=*)", "Filter closure + wildcard"),
    ("*(|(mail=*))", "OR filter injection"),
    (")(&)", "Boolean filter injection (AND)"),
    (")(|(uid=*))", "OR uid enumeration"),
    ("*)(objectClass=*)", "Object class enumeration"),
    (")(sn=*", "Surname wildcard injection"),
    ("admin)(|(password=*))", "Password filter injection"),
    ("*)(uid=*))(|(uid=*", "Nested filter injection"),
    ("\\28", "Encoded parenthesis injection"),
    ("\\2a", "Encoded wildcard injection"),
    (")(cn=admin)(&(1=1", "Tautology injection"),
    ("x)(|(cn=*)(cn=x", "Double condition injection"),
]

LDAP_ERROR_PATTERNS = [
    (r"LDAP.*?error", "LDAP error"),
    (r"ldap_search", "LDAP search function"),
    (r"ldap_bind", "LDAP bind function"),
    (r"ldap_connect", "LDAP connection function"),
    (r"Invalid DN", "Invalid Distinguished Name"),
    (r"Bad search filter", "Bad LDAP filter"),
    (r"invalid filter", "Invalid LDAP filter"),
    (r"Filter Error", "LDAP filter error"),
    (r"javax\.naming\.directory", "Java LDAP exception"),
    (r"javax\.naming\.NamingException", "Java Naming exception"),
    (r"LDAPException", "LDAP exception"),
    (r"DSMLv2", "DSML error"),
    (r"ldap://", "LDAP URL leaked"),
    (r"ldaps://", "LDAPS URL leaked"),
    (r"cn=.*?,\s*dc=", "Distinguished Name leaked"),
    (r"ou=.*?,\s*dc=", "Organizational Unit leaked"),
    (r"Active Directory", "Active Directory reference"),
    (r"LDAP server", "LDAP server reference"),
    (r"directory service", "Directory service reference"),
    (r"unbalanced.*?parenthes[ie]s", "Unbalanced parentheses in filter"),
    (r"filter.*?syntax", "Filter syntax error"),
]

AUTH_BYPASS_INDICATORS = [
    (r"(?i)welcome|dashboard|profile|account|admin|logout|sign.?out", "Authenticated content indicators"),
    (r"(?i)session.*?created|logged.?in|login.?success", "Login success indicators"),
]


def _build_curl(method, url, data=None):
    cmd = "curl -k -X {} '{}'".format(method, url)
    if data:
        cmd += " -d '{}'".format(data)
    return cmd


def _check_ldap_errors(body):
    for pattern, description in LDAP_ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            return pattern, description
    return None, None


def _extract_snippet(body, pattern):
    match = re.search(pattern, body, re.IGNORECASE)
    if not match:
        return ""
    start = max(0, match.start() - 60)
    end = min(len(body), match.end() + 60)
    return body[start:end].replace('\n', ' ').strip()


def _response_differs(baseline_resp, test_resp):
    if not baseline_resp or not test_resp:
        return False
    if baseline_resp.status_code != test_resp.status_code:
        return True
    bl = len(baseline_resp.text)
    tl = len(test_resp.text)
    return tl > 0 if bl == 0 else abs(tl - bl) / max(bl, 1) > 0.15


def _get_baseline(session, url, param, original):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [original or "harmless"]
    return session.get(urlunparse(parsed._replace(query=urlencode(params, doseq=True))))


def _check_auth_bypass(baseline_text, test_text):
    for pattern, description in AUTH_BYPASS_INDICATORS:
        if re.search(pattern, test_text, re.IGNORECASE):
            if not baseline_text or not re.search(pattern, baseline_text, re.IGNORECASE):
                return pattern, description
    return None, None


def _test_url_params(session, url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    for param, values in params.items():
        original = values[0] if values else ""
        baseline_resp = _get_baseline(session, url, param, original)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for payload, description in LDAP_PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

            resp = session.get(test_url)
            if not resp or resp.status_code in (404, 403):
                continue

            error_pattern, error_desc = _check_ldap_errors(resp.text)
            if error_pattern and not re.search(error_pattern, baseline_text, re.IGNORECASE):
                snippet = _extract_snippet(resp.text, error_pattern)
                curl_cmd = _build_curl("GET", test_url)
                session.add_finding(Finding(
                    title="LDAP Injection (Error-Based) - {}".format(error_desc),
                    severity=Severity.HIGH,
                    description=(
                        "The URL parameter '{param}' is vulnerable to LDAP injection. "
                        "When LDAP metacharacters ({desc}) were injected, the application "
                        "returned an LDAP-specific error ({edesc}), confirming that user "
                        "input reaches the LDAP query filter unsanitized. This can allow "
                        "authentication bypass, data exfiltration, or directory enumeration."
                    ).format(param=param, desc=description, edesc=error_desc),
                    evidence=(
                        "Parameter: {param}\nPayload: {pay}\nTechnique: {desc}\n"
                        "Error Type: {edesc}\nError Pattern: {epat}\n"
                        "Error Snippet: {snip}\nTest URL: {turl}\nResponse Status: {status}"
                    ).format(param=param, pay=payload, desc=description, edesc=error_desc,
                             epat=error_pattern, snip=snippet, turl=test_url, status=resp.status_code),
                    remediation=(
                        "1. Escape all LDAP special characters in user input before query construction:\n"
                        "   Characters to escape: \\ * ( ) / NUL\n"
                        "2. Use parameterized LDAP queries where supported.\n"
                        "3. Validate input against a strict allowlist (alphanumeric only for usernames).\n"
                        "4. Use LDAP framework functions for escaping (e.g., ldap.filter.escape_filter_chars).\n"
                        "5. Apply least privilege to the LDAP bind account."
                    ),
                    url=url,
                    module="ldap_injection",
                    cwe="CWE-90",
                    confirmed=True,
                    location="URL parameter '{}' in query string of {}".format(param, parsed.path),
                    parameter=param,
                    payload=payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        "1. Open: {url}\n"
                        "2. Set the '{param}' parameter to: {pay}\n"
                        "3. Full test URL: {turl}\n"
                        "4. Observe the LDAP error ({edesc}) in the response.\n"
                        "5. Run: {cmd}"
                    ).format(url=url, param=param, pay=payload, turl=test_url,
                             edesc=error_desc, cmd=curl_cmd),
                    developer_fix=(
                        "File: The server-side code handling '{path}'.\n\n"
                        "VULNERABLE pattern (do NOT use):\n"
                        "  filter = '(uid=' + user_input + ')'\n"
                        "  ldap_conn.search(base_dn, filter)\n\n"
                        "SECURE pattern (Python):\n"
                        "  from ldap3.utils.conv import escape_filter_chars\n"
                        "  safe_input = escape_filter_chars(user_input)\n"
                        "  filter = '(uid=' + safe_input + ')'\n"
                        "  ldap_conn.search(base_dn, filter)\n\n"
                        "SECURE pattern (Java):\n"
                        "  String safe = LdapEncoder.filterEncode(userInput);\n"
                        "  String filter = \"(uid=\" + safe + \")\";"
                    ).format(path=parsed.path),
                    affected_component="LDAP query construction in route handler for {}".format(parsed.path),
                    references="https://owasp.org/www-community/attacks/LDAP_Injection | https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
                    detection_method="Injected LDAP metacharacters ({}) into URL parameter and detected LDAP-specific error message ({}) in response absent from baseline.".format(description, error_desc),
                ))
                return

            # Wildcard returning more data than baseline
            if payload == "*" and _response_differs(baseline_resp, resp):
                if resp.status_code == 200 and len(resp.text) > len(baseline_text) * 1.3:
                    curl_cmd = _build_curl("GET", test_url)
                    session.add_finding(Finding(
                        title="Potential LDAP Injection (Wildcard Data Leak)",
                        severity=Severity.HIGH,
                        description=(
                            "The URL parameter '{param}' may be vulnerable to LDAP injection. "
                            "When a wildcard character (*) was injected, the response was "
                            "significantly larger than the baseline, suggesting the wildcard "
                            "matched multiple LDAP entries and returned additional data."
                        ).format(param=param),
                        evidence=(
                            "Parameter: {param}\nPayload: *\n"
                            "Baseline Response Length: {blen}\nWildcard Response Length: {tlen}\n"
                            "Length Ratio: {ratio:.2f}x\nTest URL: {turl}\nResponse Status: {status}"
                        ).format(param=param, blen=len(baseline_text), tlen=len(resp.text),
                                 ratio=len(resp.text) / max(len(baseline_text), 1),
                                 turl=test_url, status=resp.status_code),
                        remediation=(
                            "1. Escape LDAP special characters (* \\ ( ) / NUL) in all user input.\n"
                            "2. Validate input format (e.g., alphanumeric only for usernames).\n"
                            "3. Limit LDAP search result count with size limits.\n"
                            "4. Use parameterized LDAP searches."
                        ),
                        url=url,
                        module="ldap_injection",
                        cwe="CWE-90",
                        confirmed=False,
                        location="URL parameter '{}' in query string of {}".format(param, parsed.path),
                        parameter=param,
                        payload="*",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            "1. Open: {url}\n"
                            "2. Set '{param}' to: *\n"
                            "3. Compare the response with the original page.\n"
                            "4. Run: {cmd}"
                        ).format(url=url, param=param, cmd=curl_cmd),
                        developer_fix=(
                            "File: Code handling '{path}'.\n\n"
                            "Escape wildcards before LDAP query:\n"
                            "  safe = user_input.replace('*', '\\\\2a').replace('(', '\\\\28')"
                        ).format(path=parsed.path),
                        affected_component="LDAP query in route handler for {}".format(parsed.path),
                        references="https://owasp.org/www-community/attacks/LDAP_Injection",
                        detection_method="Injected LDAP wildcard (*) into URL parameter and observed significantly larger response, suggesting multiple directory entries were returned.",
                    ))
                    return


def _test_forms(session, form):
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)
    parsed = urlparse(action)

    baseline_data = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            baseline_data[name] = inp.get("value", "test")

    baseline_resp = session.post(action, data=baseline_data) if method == "post" \
        else session.get(action, params=baseline_data)
    if not baseline_resp:
        return
    baseline_text = baseline_resp.text

    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue

        for payload, description in LDAP_PAYLOADS:
            test_data = dict(baseline_data)
            test_data[name] = payload

            try:
                resp = session.post(action, data=test_data) if method == "post" \
                    else session.get(action, params=test_data)
            except (OSError, ValueError) as e:
                logger.debug("ldap_injection _test_forms: request failed: %s", e)
                continue

            if not resp or resp.status_code in (404, 403):
                continue

            # Error-based detection
            error_pattern, error_desc = _check_ldap_errors(resp.text)
            if error_pattern and not re.search(error_pattern, baseline_text, re.IGNORECASE):
                snippet = _extract_snippet(resp.text, error_pattern)
                data_str = "&".join("{}={}".format(k, v) for k, v in test_data.items())
                curl_cmd = _build_curl(method.upper(), action, data=data_str)
                session.add_finding(Finding(
                    title="LDAP Injection in Form (Error-Based) - {}".format(error_desc),
                    severity=Severity.HIGH,
                    description=(
                        "The form field '{name}' at '{action}' is vulnerable to LDAP injection. "
                        "When LDAP metacharacters ({desc}) were injected into the field, "
                        "the application returned an LDAP error ({edesc}), confirming that "
                        "user input is used directly in LDAP filter construction."
                    ).format(name=name, action=action, desc=description, edesc=error_desc),
                    evidence=(
                        "Form Action: {action}\nForm Method: {method}\nField: {name}\n"
                        "Payload: {pay}\nTechnique: {desc}\nError Type: {edesc}\n"
                        "Error Snippet: {snip}\nResponse Status: {status}"
                    ).format(action=action, method=method.upper(), name=name, pay=payload,
                             desc=description, edesc=error_desc, snip=snippet, status=resp.status_code),
                    remediation=(
                        "1. Escape all LDAP special characters in user input:\n"
                        "   * \\ ( ) / NUL -> \\2a \\5c \\28 \\29 \\2f \\00\n"
                        "2. Use parameterized LDAP queries.\n"
                        "3. Validate usernames/input against a strict allowlist.\n"
                        "4. Use LDAP framework escaping functions.\n"
                        "5. Implement rate limiting on authentication endpoints."
                    ),
                    url=source_url,
                    module="ldap_injection",
                    cwe="CWE-90",
                    confirmed=True,
                    location="Form field '{}' in form at {}".format(name, action),
                    parameter=name,
                    payload=payload,
                    request_method=method.upper(),
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        "1. Navigate to: {src}\n"
                        "2. In the form submitting to {action}, set '{name}' to: {pay}\n"
                        "3. Submit and observe the LDAP error in the response.\n"
                        "4. Run: {cmd}"
                    ).format(src=source_url, action=action, name=name, pay=payload, cmd=curl_cmd),
                    developer_fix=(
                        "File: The handler for {method} {action}.\n\n"
                        "VULNERABLE:\n"
                        "  filter = '(&(uid=' + username + ')(userPassword=' + password + '))'\n\n"
                        "SECURE (Python/ldap3):\n"
                        "  from ldap3.utils.conv import escape_filter_chars\n"
                        "  safe_user = escape_filter_chars(username)\n"
                        "  safe_pass = escape_filter_chars(password)\n"
                        "  filter = '(&(uid=' + safe_user + ')(userPassword=' + safe_pass + '))'\n\n"
                        "SECURE (PHP):\n"
                        "  $safe = ldap_escape($input, '', LDAP_ESCAPE_FILTER);"
                    ).format(method=method.upper(), action=action),
                    affected_component="LDAP authentication/query in form handler for {}".format(action),
                    references="https://owasp.org/www-community/attacks/LDAP_Injection | https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
                    detection_method="Injected LDAP metacharacters ({}) into form field and detected LDAP error message ({}) in response absent from baseline.".format(description, error_desc),
                ))
                return

            # Auth bypass check
            auth_pattern, auth_desc = _check_auth_bypass(baseline_text, resp.text)
            if auth_pattern and payload in ("*", ")(cn=*)", "*(|(mail=*))"):
                data_str = "&".join("{}={}".format(k, v) for k, v in test_data.items())
                curl_cmd = _build_curl(method.upper(), action, data=data_str)
                session.add_finding(Finding(
                    title="Potential LDAP Authentication Bypass",
                    severity=Severity.CRITICAL,
                    description=(
                        "The form field '{name}' at '{action}' may allow LDAP authentication "
                        "bypass. When LDAP metacharacters ({desc}) were injected, the "
                        "response contained indicators of successful authentication "
                        "({adesc}) that were absent from the baseline response."
                    ).format(name=name, action=action, desc=description, adesc=auth_desc),
                    evidence=(
                        "Form Action: {action}\nField: {name}\nPayload: {pay}\n"
                        "Technique: {desc}\nAuth Indicator: {adesc}\nResponse Status: {status}"
                    ).format(action=action, name=name, pay=payload, desc=description,
                             adesc=auth_desc, status=resp.status_code),
                    remediation=(
                        "1. Escape all LDAP special characters before query construction.\n"
                        "2. Use LDAP bind authentication instead of search-based authentication.\n"
                        "3. Validate input format strictly (alphanumeric only).\n"
                        "4. Implement multi-factor authentication.\n"
                        "5. Monitor and alert on failed LDAP authentication attempts."
                    ),
                    url=source_url,
                    module="ldap_injection",
                    cwe="CWE-90",
                    confirmed=False,
                    location="Form field '{}' in form at {}".format(name, action),
                    parameter=name,
                    payload=payload,
                    request_method=method.upper(),
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        "1. Navigate to: {src}\n"
                        "2. Set '{name}' to: {pay}\n"
                        "3. Submit and check for authenticated content.\n"
                        "4. Run: {cmd}"
                    ).format(src=source_url, name=name, pay=payload, cmd=curl_cmd),
                    developer_fix=(
                        "File: The authentication handler for {action}.\n\n"
                        "Use LDAP bind for authentication instead of search:\n"
                        "  # Instead of searching with user-supplied credentials in the filter,\n"
                        "  # use ldap_bind with the user's DN and password:\n"
                        "  user_dn = 'uid=' + escape(username) + ',ou=users,dc=example,dc=com'\n"
                        "  conn.simple_bind_s(user_dn, password)"
                    ).format(action=action),
                    affected_component="LDAP authentication in form handler for {}".format(action),
                    references="https://owasp.org/www-community/attacks/LDAP_Injection | https://book.hacktricks.xyz/pentesting-web/ldap-injection",
                    detection_method="Injected LDAP metacharacters ({}) into login form and detected authentication success indicators ({}) absent from baseline.".format(description, auth_desc),
                ))
                return


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for LDAP Injection...")

    for url in session.crawled_urls:
        _test_url_params(session, url)

    for form in session.forms:
        _test_forms(session, form)
