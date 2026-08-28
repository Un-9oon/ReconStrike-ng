import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

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
    cmd = "curl -k -v -X {} '{}'".format(method, url)
    if data:
        cmd += " -d '{}'".format(data)
    return cmd


def _is_external_redirect(location, payload):
    if not location:
        return False
    loc = location.lower()
    return "evil.com" in loc or "evil%2e" in loc


def _check_meta_redirect(body, payload):
    for pattern, _ in META_REFRESH_PATTERNS:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            target = match.group(1)
            if "evil.com" in target.lower():
                return True, pattern, target
    return False, None, None


def _test_url_params(session, url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    rp_lower = {rp.lower() for rp in REDIRECT_PARAMS}
    redirect_params = [p for p in params if p.lower() in rp_lower]
    if not redirect_params:
        return

    for param in redirect_params:
        for payload, description, technique in REDIRECT_PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            test_url = urlunparse(parsed._replace(
                query=urlencode(test_params, doseq=True)
            ))

            try:
                resp = session.get(test_url)
            except (requests.RequestException, ValueError) as e:
                logger.debug("open_redirect _test_url_params: request failed: %s", e)
                continue

            if not resp:
                continue

            location = resp.headers.get("Location", "")
            is_redirect = resp.status_code in (301, 302, 303, 307, 308)

            if is_redirect and _is_external_redirect(location, payload):
                severity = Severity.HIGH if technique == "basic" else Severity.MEDIUM
                curl_cmd = _build_curl("GET", test_url)
                session.add_finding(Finding(
                    title="Open Redirect ({}) - {}".format(resp.status_code, description),
                    severity=severity,
                    description=(
                        "The URL parameter '{}' is vulnerable to open redirect. "
                        "When the value was set to '{}' ({}), the server "
                        "responded with a {} redirect to the attacker-controlled "
                        "URL '{}'. This allows phishing attacks where victims are "
                        "redirected from a trusted domain to a malicious site."
                    ).format(param, payload, description, resp.status_code, location),
                    evidence=(
                        "Parameter: {}\n"
                        "Payload: {}\n"
                        "Technique: {}\n"
                        "Response Status: {}\n"
                        "Location Header: {}\n"
                        "Test URL: {}"
                    ).format(param, payload, description, resp.status_code, location, test_url),
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
                    location="URL parameter '{}' in {}".format(param, parsed.path),
                    parameter=param,
                    payload=payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        "1. Open: {}\n"
                        "2. Observe the {} redirect to: {}\n"
                        "3. The browser follows the redirect to the attacker's site.\n"
                        "4. Run: {}\n"
                        "5. Check the Location header in the response."
                    ).format(test_url, resp.status_code, location, curl_cmd),
                    developer_fix=(
                        "File: The server-side code handling '{path}'.\n\n"
                        "VULNERABLE pattern (do NOT use):\n"
                        "  redirect_url = request.args.get('{param}')\n"
                        "  return redirect(redirect_url)\n\n"
                        "SECURE pattern:\n"
                        "  ALLOWED_HOSTS = {{'example.com', 'app.example.com'}}\n"
                        "  redirect_url = request.args.get('{param}', '/')\n"
                        "  parsed = urlparse(redirect_url)\n"
                        "  if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n"
                        "      redirect_url = '/'\n"
                        "  return redirect(redirect_url)"
                    ).format(path=parsed.path, param=param),
                    affected_component="Redirect handler for parameter '{}' in {}".format(param, parsed.path),
                    references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html | https://portswigger.net/web-security/ssrf#ssrf-with-whitelist-based-input-filters",
                    detection_method="Injected external URL ({}) into redirect parameter '{}' and confirmed the server issued a {} redirect to the attacker-controlled domain.".format(description, param, resp.status_code),
                ))
                return

            # meta refresh / JS redirect in body
            if resp.status_code == 200:
                is_meta, meta_pattern, meta_target = _check_meta_redirect(resp.text, payload)
                if is_meta:
                    curl_cmd = _build_curl("GET", test_url)
                    session.add_finding(Finding(
                        title="Open Redirect (Client-Side) - {}".format(description),
                        severity=Severity.MEDIUM,
                        description=(
                            "The URL parameter '{}' is vulnerable to client-side open "
                            "redirect. When set to '{}' ({}), the response "
                            "body contains a client-side redirect mechanism (meta refresh or "
                            "JavaScript) pointing to the attacker-controlled domain."
                        ).format(param, payload, description),
                        evidence=(
                            "Parameter: {}\n"
                            "Payload: {}\n"
                            "Technique: {}\n"
                            "Redirect Target: {}\n"
                            "Redirect Pattern: {}\n"
                            "Response Status: {}\n"
                            "Test URL: {}"
                        ).format(param, payload, description, meta_target, meta_pattern, resp.status_code, test_url),
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
                        location="URL parameter '{}' reflected in response body at {}".format(param, parsed.path),
                        parameter=param,
                        payload=payload,
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            "1. Open: {}\n"
                            "2. View the page source.\n"
                            "3. Find the client-side redirect to: {}\n"
                            "4. The browser will redirect to the attacker's site.\n"
                            "5. Run: {}"
                        ).format(test_url, meta_target, curl_cmd),
                        developer_fix=(
                            "File: Template/view rendering for {path}.\n\n"
                            "Do not embed user input in redirect targets:\n"
                            "  <!-- VULNERABLE -->\n"
                            "  <meta http-equiv=\"refresh\" content=\"0;url={{{{ redirect_url }}}}\">\n\n"
                            "  <!-- SECURE -->\n"
                            "  Validate on the server before rendering:\n"
                            "  if is_safe_url(redirect_url, allowed_hosts):\n"
                            "      render('redirect.html', url=redirect_url)\n"
                            "  else:\n"
                            "      redirect('/')"
                        ).format(path=parsed.path),
                        affected_component="Client-side redirect in template for {}".format(parsed.path),
                        references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                        detection_method="Injected external URL ({}) into parameter '{}' and detected client-side redirect (meta refresh/JavaScript) to attacker domain in response body.".format(description, param),
                    ))
                    return

            # CRLF injection check
            if technique == "header_injection" and resp.status_code in (301, 302, 303, 307, 308):
                for hdr_name, hdr_val in resp.headers.items():
                    if hdr_name.lower() == "location" and "evil.com" in hdr_val.lower():
                        curl_cmd = _build_curl("GET", test_url)
                        session.add_finding(Finding(
                            title="Open Redirect via CRLF Header Injection",
                            severity=Severity.HIGH,
                            description=(
                                "The URL parameter '{}' is vulnerable to CRLF header "
                                "injection, allowing an attacker to inject a Location header "
                                "and redirect users to an external domain. The payload "
                                "'{}' successfully injected a redirect header."
                            ).format(param, payload),
                            evidence=(
                                "Parameter: {}\n"
                                "Payload: {}\n"
                                "Technique: {}\n"
                                "Injected Header: Location: {}\n"
                                "Response Status: {}\n"
                                "Test URL: {}"
                            ).format(param, payload, description, hdr_val, resp.status_code, test_url),
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
                            location="URL parameter '{}' in {}".format(param, parsed.path),
                            parameter=param,
                            payload=payload,
                            request_method="GET",
                            response_status=resp.status_code,
                            curl_command=curl_cmd,
                            reproduction_steps=(
                                "1. Open: {}\n"
                                "2. Observe the injected Location header.\n"
                                "3. The browser follows the redirect.\n"
                                "4. Run: {}"
                            ).format(test_url, curl_cmd),
                            developer_fix=(
                                "File: The handler for {path}.\n\n"
                                "Strip CRLF from all input before using in headers:\n"
                                "  import re\n"
                                "  safe_value = re.sub(r'[\\r\\n]', '', user_input)\n"
                                "  # Or use framework redirect which handles this:\n"
                                "  return redirect(safe_value)  # Framework sanitizes"
                            ).format(path=parsed.path),
                            affected_component="Header construction in {}".format(parsed.path),
                            references="https://owasp.org/www-community/attacks/HTTP_Response_Splitting | https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                            detection_method="Injected CRLF characters with Location header ({}) and confirmed a redirect to attacker domain via injected header.".format(description),
                        ))
                        return


def _test_path_based(session, url):
    parsed = urlparse(url)
    existing_params = set(parse_qs(parsed.query, keep_blank_values=True).keys())
    test_params = [p for p in REDIRECT_PARAMS[:10] if p not in existing_params]

    for param in test_params:
        payload = "https://evil.com"
        test_query = parsed.query + "&{}={}".format(param, payload) if parsed.query else "{}={}".format(param, payload)
        test_url = urlunparse(parsed._replace(query=test_query))

        try:
            resp = session.get(test_url)
        except (requests.RequestException, ValueError) as e:
            logger.debug("open_redirect _test_path_based: request failed: %s", e)
            continue

        if not resp:
            continue

        location = resp.headers.get("Location", "")
        is_redirect = resp.status_code in (301, 302, 303, 307, 308)

        if is_redirect and _is_external_redirect(location, payload):
            curl_cmd = _build_curl("GET", test_url)
            session.add_finding(Finding(
                title="Open Redirect via Injected Parameter '{}'".format(param),
                severity=Severity.HIGH,
                description=(
                    "The application at '{}' accepts a redirect parameter '{}' "
                    "that is not part of the original URL. When '{}=https://evil.com' was "
                    "appended, the server responded with a {} redirect to the "
                    "external domain. This hidden redirect parameter can be exploited for phishing."
                ).format(parsed.path, param, param, resp.status_code),
                evidence=(
                    "Parameter: {} (injected, not originally present)\n"
                    "Payload: {}\n"
                    "Response Status: {}\n"
                    "Location Header: {}\n"
                    "Test URL: {}"
                ).format(param, payload, resp.status_code, location, test_url),
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
                location="Injected parameter '{}' at {}".format(param, parsed.path),
                parameter=param,
                payload=payload,
                request_method="GET",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Take the URL: {}\n"
                    "2. Append: ?{}=https://evil.com (or &{}=...)\n"
                    "3. Open: {}\n"
                    "4. Observe the redirect to evil.com.\n"
                    "5. Run: {}"
                ).format(url, param, param, test_url, curl_cmd),
                developer_fix=(
                    "File: The handler for {path}.\n\n"
                    "Remove or restrict the '{param}' redirect parameter:\n"
                    "  # If not needed, remove the redirect logic entirely\n"
                    "  # If needed, validate strictly:\n"
                    "  SAFE_PATHS = {{'/dashboard', '/home', '/profile'}}\n"
                    "  target = request.args.get('{param}', '/')\n"
                    "  if target not in SAFE_PATHS:\n"
                    "      target = '/'"
                ).format(path=parsed.path, param=param),
                affected_component="Hidden redirect parameter handling in {}".format(parsed.path),
                references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                detection_method="Injected redirect parameter '{}' (not originally in the URL) with external URL and confirmed the server issued a redirect to the attacker domain.".format(param),
            ))
            return

        if resp.status_code == 200:
            is_meta, _, meta_target = _check_meta_redirect(resp.text, payload)
            if is_meta:
                curl_cmd = _build_curl("GET", test_url)
                session.add_finding(Finding(
                    title="Open Redirect (Client-Side) via Injected Parameter '{}'".format(param),
                    severity=Severity.MEDIUM,
                    description=(
                        "The application accepts a hidden redirect parameter '{}' "
                        "and embeds it in a client-side redirect (meta refresh or JavaScript). "
                        "When '{}=https://evil.com' was injected, the response body "
                        "contained a redirect to the external domain."
                    ).format(param, param),
                    evidence=(
                        "Parameter: {} (injected)\n"
                        "Payload: {}\n"
                        "Redirect Target: {}\n"
                        "Response Status: {}\n"
                        "Test URL: {}"
                    ).format(param, payload, meta_target, resp.status_code, test_url),
                    remediation=(
                        "1. Validate redirect targets on the server before embedding in HTML.\n"
                        "2. Use an allowlist of safe redirect destinations.\n"
                        "3. Do not reflect user input into meta refresh or JavaScript redirects."
                    ),
                    url=url,
                    module="open_redirect",
                    cwe="CWE-601",
                    confirmed=True,
                    location="Injected parameter '{}' reflected in body at {}".format(param, parsed.path),
                    parameter=param,
                    payload=payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        "1. Open: {}\n"
                        "2. View page source for the redirect mechanism.\n"
                        "3. The browser will redirect to evil.com.\n"
                        "4. Run: {}"
                    ).format(test_url, curl_cmd),
                    developer_fix=(
                        "File: Template for {path}.\n\n"
                        "Validate before rendering:\n"
                        "  if not is_safe_url(redirect_target):\n"
                        "      redirect_target = '/'"
                    ).format(path=parsed.path),
                    affected_component="Client-side redirect via '{}' in {}".format(param, parsed.path),
                    references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                    detection_method="Injected redirect parameter '{}' with external URL and detected client-side redirect to attacker domain in response body.".format(param),
                ))
                return


def _test_forms(session, form):
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)
    parsed = urlparse(action)

    rp_lower = {rp.lower() for rp in REDIRECT_PARAMS}
    redirect_fields = [inp for inp in inputs if inp.get("name", "").lower() in rp_lower and inp.get("name")]
    if not redirect_fields:
        return

    baseline_data = {inp["name"]: inp.get("value", "test") for inp in inputs if inp.get("name")}

    for field in redirect_fields:
        name = field.get("name")
        if not name:
            continue

        for payload, description, technique in REDIRECT_PAYLOADS[:5]:
            test_data = dict(baseline_data)
            test_data[name] = payload

            try:
                resp = session.post(action, data=test_data) if method == "post" else session.get(action, params=test_data)
            except (requests.RequestException, ValueError) as e:
                logger.debug("open_redirect _test_forms: request failed: %s", e)
                continue

            if not resp:
                continue

            location = resp.headers.get("Location", "")
            if resp.status_code not in (301, 302, 303, 307, 308) or not _is_external_redirect(location, payload):
                continue

            data_str = "&".join("{}={}".format(k, v) for k, v in test_data.items())
            curl_cmd = _build_curl(method.upper(), action, data=data_str if method == "post" else None)
            session.add_finding(Finding(
                title="Open Redirect in Form Field '{}' - {}".format(name, description),
                severity=Severity.HIGH,
                description=(
                    "The form field '{}' at '{}' is vulnerable to open redirect. "
                    "When set to '{}' ({}), the server redirected to the "
                    "attacker-controlled domain. This is commonly exploited in login forms "
                    "where a 'return_to' or 'next' field controls post-authentication redirect."
                ).format(name, action, payload, description),
                evidence=(
                    "Form Action: {}\n"
                    "Form Method: {}\n"
                    "Field: {}\n"
                    "Payload: {}\n"
                    "Technique: {}\n"
                    "Response Status: {}\n"
                    "Location Header: {}"
                ).format(action, method.upper(), name, payload, description, resp.status_code, location),
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
                location="Form field '{}' in form at {}".format(name, action),
                parameter=name,
                payload=payload,
                request_method=method.upper(),
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Navigate to: {}\n"
                    "2. Set the '{}' field to: {}\n"
                    "3. Submit the form.\n"
                    "4. Observe the redirect to: {}\n"
                    "5. Run: {}"
                ).format(source_url, name, payload, location, curl_cmd),
                developer_fix=(
                    "File: The handler for {method} {action}.\n\n"
                    "Validate the '{name}' field:\n"
                    "  from urllib.parse import urlparse\n"
                    "  target = request.form.get('{name}', '/')\n"
                    "  parsed = urlparse(target)\n"
                    "  if parsed.netloc:  # Has a host = external URL\n"
                    "      target = '/'  # Default to safe path\n"
                    "  return redirect(target)"
                ).format(method=method.upper(), action=action, name=name),
                affected_component="Redirect handling via form field '{}' in {}".format(name, action),
                references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html | https://portswigger.net/kb/issues/00500100_open-redirection-reflected",
                detection_method="Set form field '{}' to external URL ({}) and confirmed the server issued a redirect to the attacker domain.".format(name, description),
            ))
            return


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for Open Redirects...")

    for url in session.crawled_urls:
        _test_url_params(session, url)
        _test_path_based(session, url)

    for form in session.forms:
        _test_forms(session, form)
