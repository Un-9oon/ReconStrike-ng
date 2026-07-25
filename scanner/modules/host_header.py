import re
from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession, build_curl


EVIL_HOST = "evil.attacker-controlled.com"
EVIL_HOST_FQDN = "attacker.example.com"

HOST_INJECTION_HEADERS = [
    ("X-Forwarded-Host", "X-Forwarded-Host header"),
    ("X-Host", "X-Host header"),
    ("X-Forwarded-Server", "X-Forwarded-Server header"),
    ("Forwarded", "Forwarded header (RFC 7239)"),
]

PASSWORD_RESET_PATTERNS = [
    re.compile(r"(password|reset|recover|forgot|restore)", re.IGNORECASE),
]

LINK_REFLECTION_PATTERNS = [
    re.compile(r'(href|src|action|url|link|redirect|location)\s*[=:]\s*["\']?https?://' + re.escape(EVIL_HOST), re.IGNORECASE),
    re.compile(re.escape(EVIL_HOST), re.IGNORECASE),
]

REDIRECT_HEADERS = ["Location", "Refresh", "Content-Location"]


def _is_password_reset_form(form):
    """Check if a form is likely a password reset / forgot password form."""
    action = form.get("action", "").lower()
    inputs = form.get("inputs", [])

    for pattern in PASSWORD_RESET_PATTERNS:
        if pattern.search(action):
            return True

    # Check form field names for email/password reset indicators
    field_names = [inp.get("name", "").lower() for inp in inputs]
    has_email = any("email" in n or "mail" in n for n in field_names)
    has_no_password = not any("password" in n or "passwd" in n for n in field_names)
    has_reset_indicator = any(
        "reset" in n or "forgot" in n or "recover" in n for n in field_names
    )

    if has_email and has_no_password and has_reset_indicator:
        return True
    if has_email and has_no_password and len(inputs) <= 3:
        # Simple email-only form, could be password reset
        return True

    return False


def _check_host_in_response(body, headers_dict, evil_host):
    """Check if the injected host appears in the response body or headers."""
    findings = []

    # Check response body for the evil host
    if evil_host.lower() in body.lower():
        # Find the context where it appears
        idx = body.lower().find(evil_host.lower())
        start = max(0, idx - 80)
        end = min(len(body), idx + len(evil_host) + 80)
        snippet = body[start:end].replace('\n', ' ').strip()

        # Check if it's in a link/URL context
        in_link = False
        for pattern in LINK_REFLECTION_PATTERNS:
            if pattern.search(body):
                in_link = True
                break

        findings.append({
            "location": "response body",
            "in_link": in_link,
            "snippet": snippet,
        })

    # Check response headers
    for header_name in REDIRECT_HEADERS:
        header_val = headers_dict.get(header_name, "")
        if evil_host.lower() in header_val.lower():
            findings.append({
                "location": f"response header ({header_name})",
                "in_link": True,
                "snippet": f"{header_name}: {header_val}",
            })

    return findings


def _test_host_header_direct(session, url):
    """Test direct Host header manipulation."""
    parsed = urlparse(url)
    original_host = parsed.netloc

    # Test 1: Replace Host header with evil host
    try:
        resp = session.session.get(
            url,
            headers={"Host": EVIL_HOST},
            timeout=session.config.timeout,
            verify=session.config.verify_ssl,
            allow_redirects=False,
        )
    except Exception:
        return

    if not resp:
        return

    body = resp.text if hasattr(resp, 'text') else ""
    headers_dict = dict(resp.headers)

    reflections = _check_host_in_response(body, headers_dict, EVIL_HOST)

    if reflections:
        reflection = reflections[0]
        curl_cmd = build_curl("GET", url, headers={"Host": EVIL_HOST})

        severity = Severity.HIGH if reflection["in_link"] else Severity.MEDIUM

        session.add_finding(Finding(
            title="Host Header Injection (Direct Host Override)",
            severity=severity,
            description=(
                f"The application at '{original_host}' reflects a manipulated Host header "
                f"value in its response. When the Host header was set to '{EVIL_HOST}', "
                f"the injected value appeared in the {reflection['location']}. "
                + (
                    "The injected host appears in a URL/link context, which could be "
                    "exploited for password reset poisoning, cache poisoning, or phishing."
                    if reflection["in_link"] else
                    "The injected host appears in the response content, indicating the "
                    "application uses the Host header to generate content without validation."
                )
            ),
            evidence=(
                f"URL: {url}\n"
                f"Original Host: {original_host}\n"
                f"Injected Host: {EVIL_HOST}\n"
                f"Reflection Location: {reflection['location']}\n"
                f"In Link/URL Context: {reflection['in_link']}\n"
                f"Response Status: {resp.status_code}\n"
                f"Context: {reflection['snippet']}"
            ),
            remediation=(
                "1. Never use the Host header to generate URLs, links, or redirects.\n"
                "2. Configure a server-side whitelist of allowed Host header values.\n"
                "3. Use a hardcoded or environment-variable-based base URL for link generation.\n"
                "4. Configure the web server to reject requests with unexpected Host headers:\n"
                "   - Nginx: Use a default server block that returns 444 for unknown hosts.\n"
                "   - Apache: Configure ServerName and reject unmatched requests.\n"
                "5. Validate the Host header against the expected domain before use."
            ),
            url=url,
            module="host_header",
            cwe="CWE-644",
            confirmed=True,
            location=f"Host header processing at {parsed.path}",
            parameter="Host",
            payload=f"Host: {EVIL_HOST}",
            request_method="GET",
            request_headers=f"Host: {EVIL_HOST}",
            response_status=resp.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                f"1. Send a GET request to {url} with a manipulated Host header.\n"
                f"2. Run: {curl_cmd}\n"
                f"3. Examine the response for the injected host '{EVIL_HOST}'.\n"
                f"4. Check the {reflection['location']} for the reflected value."
            ),
            developer_fix=(
                f"File: Application configuration or middleware.\n\n"
                f"VULNERABLE pattern:\n"
                f"  base_url = request.headers['Host']  # Attacker-controlled!\n"
                f"  link = f'https://{{base_url}}/reset?token={{token}}'\n\n"
                f"SECURE pattern:\n"
                f"  # Use a hardcoded or config-based base URL\n"
                f"  BASE_URL = os.environ.get('BASE_URL', 'https://{original_host}')\n"
                f"  link = f'{{BASE_URL}}/reset?token={{token}}'\n\n"
                f"  Nginx - reject unknown hosts:\n"
                f"  server {{\n"
                f"    listen 80 default_server;\n"
                f"    return 444;  # Drop connections with unknown Host\n"
                f"  }}\n"
                f"  server {{\n"
                f"    listen 80;\n"
                f"    server_name {original_host};\n"
                f"    ...\n"
                f"  }}"
            ),
            affected_component=f"Host header processing / URL generation at {parsed.netloc}",
            references="https://portswigger.net/web-security/host-header | https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection",
            detection_method=f"Sent a request with 'Host: {EVIL_HOST}' and detected the injected host in the {reflection['location']} of the response.",
        ))

    # Test 2: Host header with port injection
    injected_host = f"{original_host}@{EVIL_HOST}"
    try:
        resp = session.session.get(
            url,
            headers={"Host": injected_host},
            timeout=session.config.timeout,
            verify=session.config.verify_ssl,
            allow_redirects=False,
        )
    except Exception:
        return

    if resp:
        body = resp.text if hasattr(resp, 'text') else ""
        headers_dict = dict(resp.headers)
        reflections = _check_host_in_response(body, headers_dict, EVIL_HOST)

        if reflections:
            reflection = reflections[0]
            curl_cmd = build_curl("GET", url, headers={"Host": injected_host})
            session.add_finding(Finding(
                title="Host Header Injection (@ Character Bypass)",
                severity=Severity.HIGH,
                description=(
                    f"The application processes a Host header containing an '@' character "
                    f"('{injected_host}'), which can be used to bypass host validation. "
                    f"URL parsers may interpret the portion before '@' as credentials and "
                    f"the portion after as the actual host, leading to routing-based SSRF."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Injected Host: {injected_host}\n"
                    f"Reflection Location: {reflection['location']}\n"
                    f"Response Status: {resp.status_code}\n"
                    f"Context: {reflection['snippet']}"
                ),
                remediation=(
                    "1. Reject Host headers containing '@', ':', or other unexpected characters.\n"
                    "2. Parse and validate the Host header before any use.\n"
                    "3. Use a strict allowlist for valid Host header values.\n"
                    "4. Never use the Host header for routing decisions."
                ),
                url=url,
                module="host_header",
                cwe="CWE-644",
                confirmed=True,
                location=f"Host header parsing at {parsed.path}",
                parameter="Host",
                payload=f"Host: {injected_host}",
                request_method="GET",
                request_headers=f"Host: {injected_host}",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Send a request with Host: {injected_host}\n"
                    f"2. Run: {curl_cmd}\n"
                    f"3. Observe '{EVIL_HOST}' reflected in the response."
                ),
                developer_fix=(
                    f"Validate Host header strictly:\n"
                    f"  if '@' in request.headers.get('Host', ''):\n"
                    f"      abort(400, 'Invalid Host header')"
                ),
                affected_component=f"Host header parsing at {parsed.netloc}",
                references="https://portswigger.net/web-security/host-header/exploiting",
                detection_method=f"Injected Host header with '@' character ('{injected_host}') and detected the attacker-controlled portion reflected in the response.",
            ))


def _test_forwarded_headers(session, url):
    """Test X-Forwarded-Host and similar headers for host injection."""
    parsed = urlparse(url)

    for header_name, header_desc in HOST_INJECTION_HEADERS:
        if header_name == "Forwarded":
            header_value = f"host={EVIL_HOST_FQDN}"
        else:
            header_value = EVIL_HOST_FQDN

        try:
            resp = session.session.get(
                url,
                headers={header_name: header_value},
                timeout=session.config.timeout,
                verify=session.config.verify_ssl,
                allow_redirects=False,
            )
        except Exception:
            continue

        if not resp:
            continue

        body = resp.text if hasattr(resp, 'text') else ""
        headers_dict = dict(resp.headers)

        reflections = _check_host_in_response(body, headers_dict, EVIL_HOST_FQDN)

        if reflections:
            reflection = reflections[0]
            curl_cmd = build_curl("GET", url, headers={header_name: header_value})

            severity = Severity.HIGH if reflection["in_link"] else Severity.MEDIUM

            session.add_finding(Finding(
                title=f"Host Header Injection via {header_name}",
                severity=severity,
                description=(
                    f"The application at '{parsed.netloc}' reflects the value of the "
                    f"'{header_name}' header in its response. When set to '{EVIL_HOST_FQDN}', "
                    f"the injected value appeared in the {reflection['location']}. "
                    f"This header is often trusted by applications behind reverse proxies "
                    f"and can be exploited for password reset poisoning, web cache poisoning, "
                    f"or open redirect attacks."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Header: {header_name}: {header_value}\n"
                    f"Reflection Location: {reflection['location']}\n"
                    f"In Link/URL Context: {reflection['in_link']}\n"
                    f"Response Status: {resp.status_code}\n"
                    f"Context: {reflection['snippet']}"
                ),
                remediation=(
                    f"1. Do not trust the '{header_name}' header for generating URLs or links.\n"
                    "2. If behind a reverse proxy, configure it to strip or overwrite this header.\n"
                    "3. Use a hardcoded base URL from application configuration.\n"
                    "4. If the header is needed, validate it against an allowlist of known values.\n"
                    "5. Configure the reverse proxy to set the header and reject client-supplied values:\n"
                    "   - Nginx: proxy_set_header X-Forwarded-Host $host;\n"
                    "   - Apache: RequestHeader set X-Forwarded-Host \"expected.domain.com\""
                ),
                url=url,
                module="host_header",
                cwe="CWE-644",
                confirmed=True,
                location=f"{header_name} header processing at {parsed.path}",
                parameter=header_name,
                payload=f"{header_name}: {header_value}",
                request_method="GET",
                request_headers=f"{header_name}: {header_value}",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Send a GET request to {url} with the header: {header_name}: {header_value}\n"
                    f"2. Run: {curl_cmd}\n"
                    f"3. Examine the response for '{EVIL_HOST_FQDN}' in the {reflection['location']}."
                ),
                developer_fix=(
                    f"File: Application middleware or reverse proxy config.\n\n"
                    f"VULNERABLE pattern:\n"
                    f"  host = request.headers.get('{header_name}', request.host)\n"
                    f"  link = f'https://{{host}}/action'\n\n"
                    f"SECURE pattern:\n"
                    f"  # Ignore {header_name} for URL generation\n"
                    f"  BASE_URL = os.environ['BASE_URL']  # e.g., 'https://{parsed.netloc}'\n"
                    f"  link = f'{{BASE_URL}}/action'\n\n"
                    f"  Nginx - overwrite the header:\n"
                    f"  proxy_set_header {header_name} $host;\n\n"
                    f"  Apache - set a trusted value:\n"
                    f"  RequestHeader set {header_name} \"{parsed.netloc}\""
                ),
                affected_component=f"{header_name} handling in {parsed.netloc}",
                references="https://portswigger.net/web-security/host-header | https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection",
                detection_method=f"Sent '{header_name}: {header_value}' header and detected the injected host reflected in the {reflection['location']} of the response.",
            ))
            return  # One finding per URL is sufficient


def _test_password_reset_poisoning(session, form):
    """Test password reset forms for host header poisoning."""
    if not _is_password_reset_form(form):
        return

    action = form.get("action", "")
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)
    parsed = urlparse(action)

    # Build form data with a test email
    form_data = {}
    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue
        name_lower = name.lower()
        if "email" in name_lower or "mail" in name_lower:
            form_data[name] = "test@example.com"
        elif "user" in name_lower:
            form_data[name] = "testuser"
        elif inp.get("value"):
            form_data[name] = inp["value"]

    # Test with manipulated Host header
    headers_to_test = [
        ("Host", EVIL_HOST, "Direct Host header"),
    ] + [
        (h, EVIL_HOST_FQDN, desc) for h, desc in HOST_INJECTION_HEADERS
    ]

    for header_name, header_value, technique in headers_to_test:
        if header_name == "Forwarded":
            actual_value = f"host={header_value}"
        else:
            actual_value = header_value

        try:
            resp = session.session.post(
                action,
                data=form_data,
                headers={header_name: actual_value},
                timeout=session.config.timeout,
                verify=session.config.verify_ssl,
                allow_redirects=False,
            )
        except Exception:
            continue

        if not resp:
            continue

        # Check if the form submission was accepted (indicates the reset email was sent)
        if resp.status_code not in (200, 201, 302, 303):
            continue

        body = resp.text if hasattr(resp, 'text') else ""
        headers_dict = dict(resp.headers)

        # Check for the evil host in the response
        evil_host_for_check = header_value
        reflections = _check_host_in_response(body, headers_dict, evil_host_for_check)

        # Even without reflection, if the reset was accepted, it's noteworthy
        # because the reset email may contain the poisoned link
        if reflections:
            reflection = reflections[0]
            data_str = "&".join(f"{k}={v}" for k, v in form_data.items())
            curl_cmd = build_curl(
                "POST", action,
                headers={header_name: actual_value},
                data=data_str,
            )
            session.add_finding(Finding(
                title=f"Password Reset Poisoning via {header_name}",
                severity=Severity.HIGH,
                description=(
                    f"The password reset form at '{action}' is vulnerable to host header "
                    f"poisoning via the '{header_name}' header. When a password reset was "
                    f"submitted with '{header_name}: {actual_value}', the injected host "
                    f"appeared in the {reflection['location']}. This strongly suggests the "
                    f"password reset email will contain a link pointing to the attacker's "
                    f"domain, allowing token theft when the victim clicks it."
                ),
                evidence=(
                    f"Form Action: {action}\n"
                    f"Header: {header_name}: {actual_value}\n"
                    f"Technique: {technique}\n"
                    f"Form Data: {form_data}\n"
                    f"Response Status: {resp.status_code}\n"
                    f"Reflection Location: {reflection['location']}\n"
                    f"Context: {reflection['snippet']}"
                ),
                remediation=(
                    "1. NEVER use the Host header to construct password reset links.\n"
                    "2. Store the application base URL in server-side configuration.\n"
                    "3. Ignore X-Forwarded-Host and similar headers for security-critical operations.\n"
                    "4. Configure the reverse proxy to strip or overwrite forwarded host headers.\n"
                    "5. Validate the Host header against a whitelist before any use.\n"
                    "6. Generate reset tokens as one-time-use and time-limited."
                ),
                url=source_url,
                module="host_header",
                cwe="CWE-644",
                confirmed=True,
                location=f"Password reset form at {action}",
                parameter=header_name,
                payload=f"{header_name}: {actual_value}",
                request_method="POST",
                request_headers=f"{header_name}: {actual_value}",
                request_body=data_str,
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Navigate to the password reset page: {source_url}\n"
                    f"2. Enter a valid email address in the form.\n"
                    f"3. Intercept the request and add the header: {header_name}: {actual_value}\n"
                    f"4. Submit the form.\n"
                    f"5. Run: {curl_cmd}\n"
                    f"6. Check the password reset email for a link pointing to '{evil_host_for_check}'.\n"
                    f"7. The attacker's server at '{evil_host_for_check}' would receive the reset token."
                ),
                developer_fix=(
                    f"File: Password reset handler for POST {action}.\n\n"
                    f"VULNERABLE pattern:\n"
                    f"  host = request.headers.get('{header_name}', request.host)\n"
                    f"  reset_link = f'https://{{host}}/reset?token={{token}}'\n"
                    f"  send_email(user.email, reset_link)\n\n"
                    f"SECURE pattern:\n"
                    f"  # Use a hardcoded base URL from config\n"
                    f"  BASE_URL = os.environ['APP_BASE_URL']  # 'https://{parsed.netloc}'\n"
                    f"  reset_link = f'{{BASE_URL}}/reset?token={{token}}'\n"
                    f"  send_email(user.email, reset_link)"
                ),
                affected_component=f"Password reset functionality at {action}",
                references="https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning | https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html",
                detection_method=f"Submitted a password reset request with '{header_name}: {actual_value}' and detected the injected host reflected in the {reflection['location']}, indicating the reset link uses the attacker-controlled host.",
            ))
            return


def _test_routing_ssrf(session, url):
    """Test for routing-based SSRF via Host header."""
    parsed = urlparse(url)
    original_host = parsed.netloc

    # Test with an internal hostname to see if the server routes differently
    internal_targets = [
        ("localhost", "localhost routing"),
        ("127.0.0.1", "loopback routing"),
        ("0.0.0.0", "wildcard binding"),
        ("169.254.169.254", "cloud metadata endpoint"),
        (f"internal.{parsed.hostname}", "internal subdomain"),
    ]

    for internal_host, technique in internal_targets:
        try:
            resp = session.session.get(
                url,
                headers={"Host": internal_host},
                timeout=session.config.timeout,
                verify=session.config.verify_ssl,
                allow_redirects=False,
            )
        except Exception:
            continue

        if not resp:
            continue

        # Check for signs of internal routing
        # - Different response from baseline
        # - Cloud metadata patterns
        # - Internal error pages
        body = resp.text if hasattr(resp, 'text') else ""

        ssrf_indicators = [
            # AWS metadata
            re.search(r"ami-id|instance-id|iam/security-credentials", body, re.IGNORECASE),
            # GCP metadata
            re.search(r"computeMetadata|project-id", body, re.IGNORECASE),
            # Azure metadata
            re.search(r"azEnvironment|subscriptionId", body, re.IGNORECASE),
            # Internal services
            re.search(r"(internal server|admin panel|management console|debug mode)", body, re.IGNORECASE),
        ]

        if any(ssrf_indicators):
            indicator = next(m for m in ssrf_indicators if m)
            curl_cmd = build_curl("GET", url, headers={"Host": internal_host})
            session.add_finding(Finding(
                title=f"Routing-Based SSRF via Host Header ({internal_host})",
                severity=Severity.CRITICAL,
                description=(
                    f"The application routes requests based on the Host header. When the "
                    f"Host header was set to '{internal_host}' ({technique}), the server "
                    f"returned content from an internal service. This allows an attacker "
                    f"to access internal resources, cloud metadata, or admin panels by "
                    f"manipulating the Host header."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Original Host: {original_host}\n"
                    f"Injected Host: {internal_host}\n"
                    f"Technique: {technique}\n"
                    f"Response Status: {resp.status_code}\n"
                    f"SSRF Indicator: {indicator.group(0)}\n"
                    f"Response Snippet: {body[:500]}"
                ),
                remediation=(
                    "1. Never use the Host header for internal routing decisions.\n"
                    "2. Configure the web server to reject requests with unexpected Host values.\n"
                    "3. Implement a strict Host header whitelist at the reverse proxy level.\n"
                    "4. Ensure internal services are not accessible via Host header manipulation.\n"
                    "5. Use network-level segmentation to isolate internal services."
                ),
                url=url,
                module="host_header",
                cwe="CWE-644",
                confirmed=True,
                location=f"Host-based routing at {parsed.path}",
                parameter="Host",
                payload=f"Host: {internal_host}",
                request_method="GET",
                request_headers=f"Host: {internal_host}",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Send a GET request to {url} with Host: {internal_host}\n"
                    f"2. Run: {curl_cmd}\n"
                    f"3. Observe that the response contains internal service content.\n"
                    f"4. The indicator '{indicator.group(0)}' confirms internal routing."
                ),
                developer_fix=(
                    f"File: Reverse proxy / load balancer configuration.\n\n"
                    f"Nginx - strict host validation:\n"
                    f"  server {{\n"
                    f"    listen 80 default_server;\n"
                    f"    return 444;  # Reject unknown hosts\n"
                    f"  }}\n"
                    f"  server {{\n"
                    f"    listen 80;\n"
                    f"    server_name {original_host};  # Only accept valid host\n"
                    f"    ...\n"
                    f"  }}\n\n"
                    f"  Application level:\n"
                    f"  ALLOWED_HOSTS = ['{original_host}']\n"
                    f"  if request.host not in ALLOWED_HOSTS:\n"
                    f"      abort(400)"
                ),
                affected_component=f"Host-based routing at {parsed.netloc}",
                references="https://portswigger.net/web-security/host-header/exploiting | https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface",
                detection_method=f"Set Host header to '{internal_host}' ({technique}) and detected internal service content in the response, confirming host-based routing SSRF.",
            ))
            return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Host Header Injection...")

    tested_hosts = set()

    for url in session.crawled_urls:
        parsed = urlparse(url)
        host = parsed.netloc

        # Test direct host header and forwarded headers once per unique host+path
        host_path = f"{host}{parsed.path}"
        if host_path not in tested_hosts:
            tested_hosts.add(host_path)
            _test_host_header_direct(session, url)
            _test_forwarded_headers(session, url)

        # Test routing SSRF once per host
        if host not in tested_hosts:
            tested_hosts.add(host)
            _test_routing_ssrf(session, url)

    # Test password reset forms for host header poisoning
    for form in session.forms:
        _test_password_reset_poisoning(session, form)
