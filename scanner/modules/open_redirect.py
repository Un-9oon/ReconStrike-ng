import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession


REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "goto", "dest", "destination",
    "target", "rurl", "return_to", "returnTo", "redirect_uri", "redirect_url",
    "continue", "forward", "out", "view", "login_url", "logout_url",
    "callback", "return_url", "returnUrl", "go", "to", "link", "ref",
    "jump", "redir", "ReturnUrl", "return_path", "redirect_to", "redirectTo",
]

REDIRECT_PAYLOADS = [
    ("https://evil.com", "Direct external URL", "basic"),
    ("//evil.com", "Protocol-relative URL", "basic"),
    ("/\\evil.com", "Backslash after path separator", "bypass"),
    ("///evil.com", "Triple-slash redirect", "bypass"),
    ("////evil.com", "Quadruple-slash redirect", "bypass"),
    ("/\\/evil.com", "Mixed slash bypass", "bypass"),
    ("https://evil.com%23.legitimate.com", "Fragment anchor bypass", "bypass"),
    ("https://legitimate.com@evil.com", "Userinfo at-sign bypass", "bypass"),
    ("https://evil.com?.legitimate.com", "Query string bypass", "bypass"),
    ("https://evil.com#.legitimate.com", "Fragment bypass", "bypass"),
    ("https://evil.com\\@legitimate.com", "Backslash-at bypass", "bypass"),
    ("%0d%0aLocation:%20https://evil.com", "CRLF header injection", "header_injection"),
    ("%0aLocation:%20https://evil.com", "LF header injection", "header_injection"),
    ("java%0d%0ascript:alert(1)", "CRLF + JavaScript protocol", "header_injection"),
    ("https:evil.com", "Missing slashes bypass", "bypass"),
    ("https:/evil.com", "Single slash bypass", "bypass"),
    ("HtTpS://evil.com", "Mixed case protocol", "bypass"),
    (".evil.com", "Dot-prefix bypass", "bypass"),
    ("evil%E3%80%82com", "Fullwidth dot bypass", "bypass"),
]

META_REFRESH_PATTERNS = [
    (r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\d+;\s*url=([^"\'>\s]+)', "Meta refresh redirect"),
    (r'window\.location\s*=\s*["\']([^"\']+)["\']', "JavaScript window.location redirect"),
    (r'window\.location\.href\s*=\s*["\']([^"\']+)["\']', "JavaScript location.href redirect"),
    (r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']', "JavaScript location.replace redirect"),
    (r'document\.location\s*=\s*["\']([^"\']+)["\']', "JavaScript document.location redirect"),
]


def _build_curl(method, url, data=None):
    cmd = f"curl -k -v -X {method} '{url}'"
    if data:
        cmd += f" -d '{data}'"
    return cmd


def _is_external_redirect(location, payload):
    """Check if the Location header or redirect target points to an external domain."""
    if not location:
        return False
    # Check for evil.com in the redirect target
    location_lower = location.lower()
    return "evil.com" in location_lower or "evil%2e" in location_lower


def _check_meta_redirect(body, payload):
    """Check if the response body contains a meta refresh or JS redirect to the payload domain."""
    for pattern, _ in META_REFRESH_PATTERNS:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            target = match.group(1)
            if "evil.com" in target.lower():
                return True, pattern, target
    return False, None, None


def _test_url_params(session, url):
    """Test URL parameters for open redirect vulnerabilities."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    # Identify potential redirect parameters
    redirect_params = []
    for param in params:
        if param.lower() in [rp.lower() for rp in REDIRECT_PARAMS]:
            redirect_params.append(param)

    if not redirect_params:
        return

    for param in redirect_params:
        for payload, description, technique in REDIRECT_PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))

            try:
                # Use allow_redirects=False to catch 3xx redirects
                resp = session.get(test_url)
            except Exception as e:
                logger.debug("open_redirect _test_url_params: request failed: %s", e)
                continue

            if not resp:
                continue

            # Check for 3xx redirect with external Location
            location = resp.headers.get("Location", "")
            is_redirect = resp.status_code in (301, 302, 303, 307, 308)

            if is_redirect and _is_external_redirect(location, payload):
                severity = Severity.HIGH if technique == "basic" else Severity.MEDIUM
                curl_cmd = _build_curl("GET", test_url)
                session.add_finding(Finding(
                    title=f"Open Redirect ({resp.status_code}) - {description}",
                    severity=severity,
                    description=(
                        f"The URL parameter '{param}' is vulnerable to open redirect. "
                        f"When the value was set to '{payload}' ({description}), the server "
                        f"responded with a {resp.status_code} redirect to the attacker-controlled "
                        f"URL '{location}'. This allows phishing attacks where victims are "
                        f"redirected from a trusted domain to a malicious site."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Payload: {payload}\n"
                        f"Technique: {description}\n"
                        f"Response Status: {resp.status_code}\n"
                        f"Location Header: {location}\n"
                        f"Test URL: {test_url}"
                    ),
                    remediation=(
                        "1. Validate redirect targets against a strict allowlist of permitted domains.\n"
                        "2. Use relative paths only for redirects; reject any absolute URL input.\n"
                        "3. Map redirect targets to indices/tokens rather than accepting raw URLs.\n"
                        "4. If external redirects are needed, use an interstitial warning page.\n"
                        "5. Validate the parsed URL scheme (allow only http/https) and host."
                    ),
                    url=url,
                    module="open_redirect",
                    cwe="CWE-601",
                    confirmed=True,
                    location=f"URL parameter '{param}' in {parsed.path}",
                    parameter=param,
                    payload=payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Open: {test_url}\n"
                        f"2. Observe the {resp.status_code} redirect to: {location}\n"
                        f"3. The browser follows the redirect to the attacker's site.\n"
                        f"4. Run: {curl_cmd}\n"
                        f"5. Check the Location header in the response."
                    ),
                    developer_fix=(
                        f"File: The server-side code handling '{parsed.path}'.\n\n"
                        f"VULNERABLE pattern (do NOT use):\n"
                        f"  redirect_url = request.args.get('{param}')\n"
                        f"  return redirect(redirect_url)\n\n"
                        f"SECURE pattern:\n"
                        f"  ALLOWED_HOSTS = {{'example.com', 'app.example.com'}}\n"
                        f"  redirect_url = request.args.get('{param}', '/')\n"
                        f"  parsed = urlparse(redirect_url)\n"
                        f"  if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n"
                        f"      redirect_url = '/'\n"
                        f"  return redirect(redirect_url)"
                    ),
                    affected_component=f"Redirect handler for parameter '{param}' in {parsed.path}",
                    references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html | https://portswigger.net/web-security/ssrf#ssrf-with-whitelist-based-input-filters",
                    detection_method=f"Injected external URL ({description}) into redirect parameter '{param}' and confirmed the server issued a {resp.status_code} redirect to the attacker-controlled domain.",
                ))
                return

            # Check for meta refresh or JavaScript redirect in body
            if resp.status_code == 200:
                is_meta, meta_pattern, meta_target = _check_meta_redirect(resp.text, payload)
                if is_meta:
                    curl_cmd = _build_curl("GET", test_url)
                    session.add_finding(Finding(
                        title=f"Open Redirect (Client-Side) - {description}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The URL parameter '{param}' is vulnerable to client-side open "
                            f"redirect. When set to '{payload}' ({description}), the response "
                            f"body contains a client-side redirect mechanism (meta refresh or "
                            f"JavaScript) pointing to the attacker-controlled domain."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Technique: {description}\n"
                            f"Redirect Target: {meta_target}\n"
                            f"Redirect Pattern: {meta_pattern}\n"
                            f"Response Status: {resp.status_code}\n"
                            f"Test URL: {test_url}"
                        ),
                        remediation=(
                            "1. Sanitize redirect targets before embedding in HTML or JavaScript.\n"
                            "2. Use a server-side allowlist for redirect destinations.\n"
                            "3. Never reflect user input directly into meta refresh or location assignments.\n"
                            "4. Use Content-Security-Policy to restrict navigation targets."
                        ),
                        url=url,
                        module="open_redirect",
                        cwe="CWE-601",
                        confirmed=True,
                        location=f"URL parameter '{param}' reflected in response body at {parsed.path}",
                        parameter=param,
                        payload=payload,
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Open: {test_url}\n"
                            f"2. View the page source.\n"
                            f"3. Find the client-side redirect to: {meta_target}\n"
                            f"4. The browser will redirect to the attacker's site.\n"
                            f"5. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"File: Template/view rendering for {parsed.path}.\n\n"
                            f"Do not embed user input in redirect targets:\n"
                            f"  <!-- VULNERABLE -->\n"
                            f"  <meta http-equiv=\"refresh\" content=\"0;url={{{{ redirect_url }}}}\">\n\n"
                            f"  <!-- SECURE -->\n"
                            f"  Validate on the server before rendering:\n"
                            f"  if is_safe_url(redirect_url, allowed_hosts):\n"
                            f"      render('redirect.html', url=redirect_url)\n"
                            f"  else:\n"
                            f"      redirect('/')"
                        ),
                        affected_component=f"Client-side redirect in template for {parsed.path}",
                        references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                        detection_method=f"Injected external URL ({description}) into parameter '{param}' and detected client-side redirect (meta refresh/JavaScript) to attacker domain in response body.",
                    ))
                    return

            # Check for CRLF header injection
            if technique == "header_injection" and resp.status_code in (301, 302, 303, 307, 308):
                # Check all headers for injected Location
                for header_name, header_value in resp.headers.items():
                    if header_name.lower() == "location" and "evil.com" in header_value.lower():
                        curl_cmd = _build_curl("GET", test_url)
                        session.add_finding(Finding(
                            title="Open Redirect via CRLF Header Injection",
                            severity=Severity.HIGH,
                            description=(
                                f"The URL parameter '{param}' is vulnerable to CRLF header "
                                f"injection, allowing an attacker to inject a Location header "
                                f"and redirect users to an external domain. The payload "
                                f"'{payload}' successfully injected a redirect header."
                            ),
                            evidence=(
                                f"Parameter: {param}\n"
                                f"Payload: {payload}\n"
                                f"Technique: {description}\n"
                                f"Injected Header: Location: {header_value}\n"
                                f"Response Status: {resp.status_code}\n"
                                f"Test URL: {test_url}"
                            ),
                            remediation=(
                                "1. Strip or reject CRLF characters (\\r\\n, %0d%0a) from all user input.\n"
                                "2. Use framework-provided redirect functions that sanitize headers.\n"
                                "3. Encode special characters before including in HTTP headers.\n"
                                "4. Validate redirect URLs against an allowlist."
                            ),
                            url=url,
                            module="open_redirect",
                            cwe="CWE-601",
                            confirmed=True,
                            location=f"URL parameter '{param}' in {parsed.path}",
                            parameter=param,
                            payload=payload,
                            request_method="GET",
                            response_status=resp.status_code,
                            curl_command=curl_cmd,
                            reproduction_steps=(
                                f"1. Open: {test_url}\n"
                                f"2. Observe the injected Location header.\n"
                                f"3. The browser follows the redirect.\n"
                                f"4. Run: {curl_cmd}"
                            ),
                            developer_fix=(
                                f"File: The handler for {parsed.path}.\n\n"
                                f"Strip CRLF from all input before using in headers:\n"
                                f"  import re\n"
                                f"  safe_value = re.sub(r'[\\r\\n]', '', user_input)\n"
                                f"  # Or use framework redirect which handles this:\n"
                                f"  return redirect(safe_value)  # Framework sanitizes"
                            ),
                            affected_component=f"Header construction in {parsed.path}",
                            references="https://owasp.org/www-community/attacks/HTTP_Response_Splitting | https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                            detection_method=f"Injected CRLF characters with Location header ({description}) and confirmed a redirect to attacker domain via injected header.",
                        ))
                        return


def _test_path_based(session, url):
    """Test for open redirects by probing common redirect parameter names not in the current URL."""
    parsed = urlparse(url)
    existing_params = set(parse_qs(parsed.query, keep_blank_values=True).keys())

    # Only test a subset of redirect params that are not already in the URL
    test_params = [p for p in REDIRECT_PARAMS[:10] if p not in existing_params]

    for param in test_params:
        # Test with basic external URL
        payload = "https://evil.com"
        if parsed.query:
            test_query = parsed.query + f"&{param}={payload}"
        else:
            test_query = f"{param}={payload}"
        test_url = urlunparse(parsed._replace(query=test_query))

        try:
            resp = session.get(test_url)
        except Exception as e:
            logger.debug("open_redirect _test_path_based: request failed: %s", e)
            continue

        if not resp:
            continue

        location = resp.headers.get("Location", "")
        is_redirect = resp.status_code in (301, 302, 303, 307, 308)

        if is_redirect and _is_external_redirect(location, payload):
            curl_cmd = _build_curl("GET", test_url)
            session.add_finding(Finding(
                title=f"Open Redirect via Injected Parameter '{param}'",
                severity=Severity.HIGH,
                description=(
                    f"The application at '{parsed.path}' accepts a redirect parameter '{param}' "
                    f"that is not part of the original URL. When '{param}=https://evil.com' was "
                    f"appended, the server responded with a {resp.status_code} redirect to the "
                    f"external domain. This hidden redirect parameter can be exploited for phishing."
                ),
                evidence=(
                    f"Parameter: {param} (injected, not originally present)\n"
                    f"Payload: {payload}\n"
                    f"Response Status: {resp.status_code}\n"
                    f"Location Header: {location}\n"
                    f"Test URL: {test_url}"
                ),
                remediation=(
                    "1. Do not accept redirect parameters that are not explicitly expected.\n"
                    "2. Validate all redirect targets against a strict domain allowlist.\n"
                    "3. Use a lookup table (redirect IDs) instead of accepting raw URLs.\n"
                    "4. Remove unused redirect parameter handling from the codebase."
                ),
                url=url,
                module="open_redirect",
                cwe="CWE-601",
                confirmed=True,
                location=f"Injected parameter '{param}' at {parsed.path}",
                parameter=param,
                payload=payload,
                request_method="GET",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Take the URL: {url}\n"
                    f"2. Append: ?{param}=https://evil.com (or &{param}=...)\n"
                    f"3. Open: {test_url}\n"
                    f"4. Observe the redirect to evil.com.\n"
                    f"5. Run: {curl_cmd}"
                ),
                developer_fix=(
                    f"File: The handler for {parsed.path}.\n\n"
                    f"Remove or restrict the '{param}' redirect parameter:\n"
                    f"  # If not needed, remove the redirect logic entirely\n"
                    f"  # If needed, validate strictly:\n"
                    f"  SAFE_PATHS = {{'/dashboard', '/home', '/profile'}}\n"
                    f"  target = request.args.get('{param}', '/')\n"
                    f"  if target not in SAFE_PATHS:\n"
                    f"      target = '/'"
                ),
                affected_component=f"Hidden redirect parameter handling in {parsed.path}",
                references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                detection_method=f"Injected redirect parameter '{param}' (not originally in the URL) with external URL and confirmed the server issued a redirect to the attacker domain.",
            ))
            return

        # Also check for client-side redirects
        if resp.status_code == 200:
            is_meta, _, meta_target = _check_meta_redirect(resp.text, payload)
            if is_meta:
                curl_cmd = _build_curl("GET", test_url)
                session.add_finding(Finding(
                    title=f"Open Redirect (Client-Side) via Injected Parameter '{param}'",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The application accepts a hidden redirect parameter '{param}' "
                        f"and embeds it in a client-side redirect (meta refresh or JavaScript). "
                        f"When '{param}=https://evil.com' was injected, the response body "
                        f"contained a redirect to the external domain."
                    ),
                    evidence=(
                        f"Parameter: {param} (injected)\n"
                        f"Payload: {payload}\n"
                        f"Redirect Target: {meta_target}\n"
                        f"Response Status: {resp.status_code}\n"
                        f"Test URL: {test_url}"
                    ),
                    remediation=(
                        "1. Validate redirect targets on the server before embedding in HTML.\n"
                        "2. Use an allowlist of safe redirect destinations.\n"
                        "3. Do not reflect user input into meta refresh or JavaScript redirects."
                    ),
                    url=url,
                    module="open_redirect",
                    cwe="CWE-601",
                    confirmed=True,
                    location=f"Injected parameter '{param}' reflected in body at {parsed.path}",
                    parameter=param,
                    payload=payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Open: {test_url}\n"
                        f"2. View page source for the redirect mechanism.\n"
                        f"3. The browser will redirect to evil.com.\n"
                        f"4. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: Template for {parsed.path}.\n\n"
                        f"Validate before rendering:\n"
                        f"  if not is_safe_url(redirect_target):\n"
                        f"      redirect_target = '/'"
                    ),
                    affected_component=f"Client-side redirect via '{param}' in {parsed.path}",
                    references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                    detection_method=f"Injected redirect parameter '{param}' with external URL and detected client-side redirect to attacker domain in response body.",
                ))
                return


def _test_forms(session, form):
    """Test form fields for open redirect vulnerabilities."""
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)
    parsed = urlparse(action)

    # Look for redirect-related form fields
    redirect_fields = []
    for inp in inputs:
        name = inp.get("name", "")
        if name and name.lower() in [rp.lower() for rp in REDIRECT_PARAMS]:
            redirect_fields.append(inp)

    if not redirect_fields:
        return

    baseline_data = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            baseline_data[name] = inp.get("value", "test")

    for field in redirect_fields:
        name = field.get("name")
        if not name:
            continue

        for payload, description, technique in REDIRECT_PAYLOADS[:5]:  # Test basic payloads on forms
            test_data = dict(baseline_data)
            test_data[name] = payload

            try:
                if method == "post":
                    resp = session.post(action, data=test_data)
                else:
                    resp = session.get(action, params=test_data)
            except Exception as e:
                logger.debug("open_redirect _test_forms: request failed: %s", e)
                continue

            if not resp:
                continue

            location = resp.headers.get("Location", "")
            is_redirect = resp.status_code in (301, 302, 303, 307, 308)

            if is_redirect and _is_external_redirect(location, payload):
                data_str = "&".join(f"{k}={v}" for k, v in test_data.items())
                curl_cmd = _build_curl(method.upper(), action, data=data_str if method == "post" else None)
                session.add_finding(Finding(
                    title=f"Open Redirect in Form Field '{name}' - {description}",
                    severity=Severity.HIGH,
                    description=(
                        f"The form field '{name}' at '{action}' is vulnerable to open redirect. "
                        f"When set to '{payload}' ({description}), the server redirected to the "
                        f"attacker-controlled domain. This is commonly exploited in login forms "
                        f"where a 'return_to' or 'next' field controls post-authentication redirect."
                    ),
                    evidence=(
                        f"Form Action: {action}\n"
                        f"Form Method: {method.upper()}\n"
                        f"Field: {name}\n"
                        f"Payload: {payload}\n"
                        f"Technique: {description}\n"
                        f"Response Status: {resp.status_code}\n"
                        f"Location Header: {location}"
                    ),
                    remediation=(
                        "1. Validate the redirect field value against a domain allowlist.\n"
                        "2. Only allow relative paths in the redirect field.\n"
                        "3. Use a hidden token mapping instead of a raw URL field.\n"
                        "4. Strip or reject URLs with external hosts."
                    ),
                    url=source_url,
                    module="open_redirect",
                    cwe="CWE-601",
                    confirmed=True,
                    location=f"Form field '{name}' in form at {action}",
                    parameter=name,
                    payload=payload,
                    request_method=method.upper(),
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Navigate to: {source_url}\n"
                        f"2. Set the '{name}' field to: {payload}\n"
                        f"3. Submit the form.\n"
                        f"4. Observe the redirect to: {location}\n"
                        f"5. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: The handler for {method.upper()} {action}.\n\n"
                        f"Validate the '{name}' field:\n"
                        f"  from urllib.parse import urlparse\n"
                        f"  target = request.form.get('{name}', '/')\n"
                        f"  parsed = urlparse(target)\n"
                        f"  if parsed.netloc:  # Has a host = external URL\n"
                        f"      target = '/'  # Default to safe path\n"
                        f"  return redirect(target)"
                    ),
                    affected_component=f"Redirect handling via form field '{name}' in {action}",
                    references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html | https://portswigger.net/kb/issues/00500100_open-redirection-reflected",
                    detection_method=f"Set form field '{name}' to external URL ({description}) and confirmed the server issued a redirect to the attacker domain.",
                ))
                return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Open Redirects...")

    for url in session.crawled_urls:
        _test_url_params(session, url)
        _test_path_based(session, url)

    for form in session.forms:
        _test_forms(session, form)
