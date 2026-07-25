import re
from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession, build_curl


TAMPER_METHODS = ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]

METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
]

SENSITIVE_PATH_PATTERNS = [
    re.compile(r"/admin", re.IGNORECASE),
    re.compile(r"/user", re.IGNORECASE),
    re.compile(r"/account", re.IGNORECASE),
    re.compile(r"/profile", re.IGNORECASE),
    re.compile(r"/settings", re.IGNORECASE),
    re.compile(r"/dashboard", re.IGNORECASE),
    re.compile(r"/api/", re.IGNORECASE),
    re.compile(r"/manage", re.IGNORECASE),
    re.compile(r"/config", re.IGNORECASE),
    re.compile(r"/delete", re.IGNORECASE),
    re.compile(r"/edit", re.IGNORECASE),
    re.compile(r"/update", re.IGNORECASE),
]


def _is_sensitive_path(url):
    parsed = urlparse(url)
    path = parsed.path
    for pattern in SENSITIVE_PATH_PATTERNS:
        if pattern.search(path):
            return True
    return False


def _safe_request(session, method, url, **kwargs):
    """Send an arbitrary HTTP method request using the underlying session."""
    try:
        kwargs.setdefault("timeout", session.config.timeout)
        kwargs.setdefault("allow_redirects", session.config.follow_redirects)
        kwargs.setdefault("verify", session.config.verify_ssl)
        resp = session.session.request(method, url, **kwargs)
        return resp
    except Exception:
        return None


def _test_trace_method(session, url):
    """Check if TRACE method is enabled (Cross-Site Tracing risk)."""
    resp = _safe_request(session, "TRACE", url)
    if not resp:
        return

    body = resp.text if resp else ""

    # TRACE should echo back the request. If the server responds with 200
    # and the body contains the TRACE method or request headers, it's enabled.
    trace_indicators = [
        resp.status_code == 200 and "TRACE" in body.upper(),
        resp.status_code == 200 and "User-Agent" in body,
        resp.headers.get("Content-Type", "").startswith("message/http"),
    ]

    if any(trace_indicators):
        parsed = urlparse(url)
        curl_cmd = build_curl("TRACE", url)
        snippet = body[:500] if body else "(empty)"
        session.add_finding(Finding(
            title="TRACE Method Enabled (Cross-Site Tracing)",
            severity=Severity.MEDIUM,
            description=(
                f"The server at '{parsed.netloc}' accepts HTTP TRACE requests on "
                f"'{parsed.path}'. The TRACE method echoes back the full HTTP request, "
                f"including headers such as cookies and authorization tokens. An attacker "
                f"can exploit this via Cross-Site Tracing (XST) to steal credentials from "
                f"authenticated users, especially when combined with XSS vulnerabilities."
            ),
            evidence=(
                f"URL: {url}\n"
                f"Method: TRACE\n"
                f"Response Status: {resp.status_code}\n"
                f"Content-Type: {resp.headers.get('Content-Type', 'N/A')}\n"
                f"Response Body (first 500 chars): {snippet}"
            ),
            remediation=(
                "1. Disable the TRACE method on the web server:\n"
                "   - Apache: Add 'TraceEnable off' to httpd.conf.\n"
                "   - Nginx: TRACE is disabled by default; ensure no custom config re-enables it.\n"
                "   - IIS: Use URLScan or Request Filtering to block TRACE.\n"
                "2. Ensure the reverse proxy or load balancer also blocks TRACE.\n"
                "3. Set HttpOnly flag on session cookies to limit XST impact."
            ),
            url=url,
            module="http_method",
            cwe="CWE-650",
            confirmed=True,
            location=f"HTTP TRACE method on {parsed.netloc}{parsed.path}",
            parameter="",
            payload="TRACE / HTTP/1.1",
            request_method="TRACE",
            response_status=resp.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                f"1. Send an HTTP TRACE request to: {url}\n"
                f"2. Run: {curl_cmd}\n"
                f"3. Observe that the server echoes back the request including headers.\n"
                f"4. Note: cookies and auth headers are reflected, enabling credential theft."
            ),
            developer_fix=(
                f"File: Web server configuration for {parsed.netloc}.\n\n"
                f"Apache httpd.conf / .htaccess:\n"
                f"  TraceEnable off\n\n"
                f"Nginx (should already be default):\n"
                f"  if ($request_method = TRACE) {{\n"
                f"    return 405;\n"
                f"  }}\n\n"
                f"IIS web.config:\n"
                f"  <security><requestFiltering><verbs>"
                f"<add verb=\"TRACE\" allowed=\"false\" />"
                f"</verbs></requestFiltering></security>"
            ),
            affected_component=f"HTTP method handling on {parsed.netloc}",
            references="https://owasp.org/www-community/attacks/Cross_Site_Tracing | https://cwe.mitre.org/data/definitions/693.html",
            detection_method="Sent an HTTP TRACE request and confirmed the server echoed back the request body including headers, indicating TRACE method is enabled.",
        ))


def _test_options_disclosure(session, url):
    """Check OPTIONS response for allowed methods disclosure."""
    resp = _safe_request(session, "OPTIONS", url)
    if not resp:
        return

    allow_header = resp.headers.get("Allow", "")
    access_control = resp.headers.get("Access-Control-Allow-Methods", "")
    disclosed_methods = allow_header or access_control

    if not disclosed_methods:
        return

    dangerous_methods = []
    for method in ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]:
        if method in disclosed_methods.upper():
            dangerous_methods.append(method)

    if not dangerous_methods:
        return

    parsed = urlparse(url)
    curl_cmd = build_curl("OPTIONS", url)
    session.add_finding(Finding(
        title=f"Dangerous HTTP Methods Allowed ({', '.join(dangerous_methods)})",
        severity=Severity.LOW,
        description=(
            f"The server at '{parsed.netloc}' responds to an OPTIONS request on "
            f"'{parsed.path}' with an Allow header disclosing that the following "
            f"potentially dangerous HTTP methods are available: "
            f"{', '.join(dangerous_methods)}. If these methods are not properly "
            f"access-controlled, they could allow unauthorized data modification or "
            f"deletion."
        ),
        evidence=(
            f"URL: {url}\n"
            f"Method: OPTIONS\n"
            f"Response Status: {resp.status_code}\n"
            f"Allow Header: {allow_header}\n"
            f"Access-Control-Allow-Methods: {access_control}\n"
            f"Dangerous Methods Found: {', '.join(dangerous_methods)}"
        ),
        remediation=(
            "1. Disable HTTP methods that are not required by the application.\n"
            "2. Restrict PUT, DELETE, PATCH to authenticated and authorized users only.\n"
            "3. Configure the web server to return 405 for unused methods.\n"
            "4. Limit the Allow header in OPTIONS responses to only necessary methods."
        ),
        url=url,
        module="http_method",
        cwe="CWE-650",
        confirmed=True,
        location=f"OPTIONS response on {parsed.netloc}{parsed.path}",
        parameter="",
        payload="OPTIONS request",
        request_method="OPTIONS",
        response_status=resp.status_code,
        curl_command=curl_cmd,
        reproduction_steps=(
            f"1. Send an HTTP OPTIONS request to: {url}\n"
            f"2. Run: {curl_cmd}\n"
            f"3. Examine the Allow header in the response.\n"
            f"4. Note the dangerous methods listed: {', '.join(dangerous_methods)}."
        ),
        developer_fix=(
            f"File: Web server configuration or application route definitions.\n\n"
            f"Restrict allowed methods per endpoint:\n\n"
            f"  Python/Flask:\n"
            f"    @app.route('{parsed.path}', methods=['GET', 'POST'])\n\n"
            f"  Node.js/Express:\n"
            f"    app.route('{parsed.path}').get(handler).post(handler);\n"
            f"    // Do not define .put(), .delete() unless needed\n\n"
            f"  Apache .htaccess:\n"
            f"    <LimitExcept GET POST>\n"
            f"      Require all denied\n"
            f"    </LimitExcept>"
        ),
        affected_component=f"HTTP method configuration on {parsed.netloc}{parsed.path}",
        references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
        detection_method="Sent an OPTIONS request and parsed the Allow header to identify dangerous HTTP methods that the server accepts.",
    ))


def _test_method_tampering(session, url):
    """Test if restricted endpoints accept alternative HTTP methods."""
    # Get baseline with normal GET
    baseline_resp = session.get(url)
    if not baseline_resp:
        return

    baseline_status = baseline_resp.status_code
    # Focus on restricted endpoints (403, 401, 405)
    is_restricted = baseline_status in (401, 403, 405)
    is_sensitive = _is_sensitive_path(url)

    if not is_restricted and not is_sensitive:
        return

    parsed = urlparse(url)

    for method in TAMPER_METHODS:
        if method in ("TRACE", "OPTIONS"):
            continue  # Handled separately

        resp = _safe_request(session, method, url)
        if not resp:
            continue

        # Detect bypass: restricted endpoint now returns 200 or different content
        bypassed = False
        if is_restricted and resp.status_code == 200:
            bypassed = True
        elif is_restricted and resp.status_code not in (401, 403, 405, 501) and resp.status_code < 400:
            bypassed = True

        if bypassed:
            curl_cmd = build_curl(method, url)
            session.add_finding(Finding(
                title=f"HTTP Method Tampering Bypass ({method})",
                severity=Severity.HIGH,
                description=(
                    f"The endpoint '{parsed.path}' returned HTTP {baseline_status} for a "
                    f"standard GET request but returned HTTP {resp.status_code} when the "
                    f"{method} method was used. This indicates the access control mechanism "
                    f"only restricts specific HTTP methods, allowing an attacker to bypass "
                    f"authentication or authorization by using an alternative verb."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Original Method: GET -> Status {baseline_status}\n"
                    f"Tampered Method: {method} -> Status {resp.status_code}\n"
                    f"Response Length: {len(resp.text)}\n"
                    f"Response Snippet: {resp.text[:300]}"
                ),
                remediation=(
                    "1. Implement access controls that apply to ALL HTTP methods, not just GET/POST.\n"
                    "2. Use a whitelist approach: explicitly allow required methods and deny everything else.\n"
                    "3. Configure the framework to reject unexpected HTTP methods with 405.\n"
                    "4. Apply authentication and authorization checks at the route level, not the method level."
                ),
                url=url,
                module="http_method",
                cwe="CWE-650",
                confirmed=True,
                location=f"Access control on {parsed.path}",
                parameter="",
                payload=f"HTTP {method} request",
                request_method=method,
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Attempt to access: {url} via GET (observe {baseline_status} response).\n"
                    f"2. Send the same request using the {method} method.\n"
                    f"3. Run: {curl_cmd}\n"
                    f"4. Observe that the server responds with {resp.status_code} instead of {baseline_status}."
                ),
                developer_fix=(
                    f"File: The route definition / middleware for '{parsed.path}'.\n\n"
                    f"VULNERABLE pattern (method-specific restriction):\n"
                    f"  @app.route('{parsed.path}')\n"
                    f"  def handler():\n"
                    f"    if request.method == 'GET':\n"
                    f"      return abort(403)  # Only blocks GET!\n\n"
                    f"SECURE pattern (method-agnostic restriction):\n"
                    f"  @app.route('{parsed.path}', methods=['GET', 'POST'])\n"
                    f"  @login_required\n"
                    f"  def handler():\n"
                    f"    ...  # Auth check applies to all allowed methods\n\n"
                    f"  # Reject all other methods via 405 (framework default when methods= is set)"
                ),
                affected_component=f"Access control on {parsed.path}",
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods | https://cwe.mitre.org/data/definitions/650.html",
                detection_method=f"Sent HTTP {method} request to an endpoint that returned {baseline_status} for GET, and received a {resp.status_code} response indicating access control bypass.",
            ))
            return


def _test_method_override_headers(session, url):
    """Test if method override headers bypass access controls."""
    baseline_resp = session.get(url)
    if not baseline_resp:
        return

    baseline_status = baseline_resp.status_code
    is_restricted = baseline_status in (401, 403, 405)
    is_sensitive = _is_sensitive_path(url)

    if not is_restricted and not is_sensitive:
        return

    parsed = urlparse(url)

    override_methods = ["PUT", "DELETE", "PATCH", "ADMIN", "DEBUG"]

    for header_name in METHOD_OVERRIDE_HEADERS:
        for override_method in override_methods:
            try:
                resp = session.session.get(
                    url,
                    headers={header_name: override_method},
                    timeout=session.config.timeout,
                    verify=session.config.verify_ssl,
                )
            except Exception:
                continue

            if not resp:
                continue

            bypassed = False
            if is_restricted and resp.status_code == 200:
                bypassed = True
            elif is_restricted and resp.status_code not in (401, 403, 405, 501) and resp.status_code < 400:
                bypassed = True
            # Also check if the response differs significantly for sensitive paths
            elif is_sensitive and not is_restricted:
                if resp.status_code != baseline_status:
                    bypassed = True
                elif abs(len(resp.text) - len(baseline_resp.text)) > len(baseline_resp.text) * 0.3:
                    bypassed = True

            if bypassed:
                curl_cmd = build_curl(
                    "GET", url,
                    headers={header_name: override_method},
                )
                session.add_finding(Finding(
                    title=f"Method Override Header Bypass ({header_name}: {override_method})",
                    severity=Severity.HIGH,
                    description=(
                        f"The endpoint '{parsed.path}' accepts the '{header_name}' header "
                        f"to override the HTTP method. When a GET request was sent with "
                        f"'{header_name}: {override_method}', the server processed it as "
                        f"a {override_method} request, bypassing access controls that returned "
                        f"HTTP {baseline_status} for a normal GET."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"Original GET Status: {baseline_status}\n"
                        f"Override Header: {header_name}: {override_method}\n"
                        f"Override Response Status: {resp.status_code}\n"
                        f"Response Length: {len(resp.text)}\n"
                        f"Response Snippet: {resp.text[:300]}"
                    ),
                    remediation=(
                        "1. Disable HTTP method override headers unless explicitly required.\n"
                        "2. If method override is needed, restrict it to POST requests only.\n"
                        "3. Apply access controls based on the effective (overridden) method, not the original.\n"
                        "4. Remove framework middleware that processes method override headers:\n"
                        "   - Express: Remove 'method-override' middleware.\n"
                        "   - Django: Remove 'django.middleware.http.ConditionalGetMiddleware' if customized.\n"
                        "   - Rails: Configure 'config.middleware.delete Rack::MethodOverride'."
                    ),
                    url=url,
                    module="http_method",
                    cwe="CWE-650",
                    confirmed=True,
                    location=f"Method override handling on {parsed.path}",
                    parameter=header_name,
                    payload=f"{header_name}: {override_method}",
                    request_method="GET",
                    request_headers=f"{header_name}: {override_method}",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Send a GET request to: {url} (observe {baseline_status}).\n"
                        f"2. Send the same GET request with the header: {header_name}: {override_method}\n"
                        f"3. Run: {curl_cmd}\n"
                        f"4. Observe the server processes it as a {override_method} request."
                    ),
                    developer_fix=(
                        f"File: Middleware configuration or web server config.\n\n"
                        f"Remove or restrict method override middleware:\n\n"
                        f"  Express:\n"
                        f"    // Remove this line:\n"
                        f"    // app.use(methodOverride('{header_name}'))\n\n"
                        f"  Django:\n"
                        f"    # Ensure no custom middleware processes {header_name}\n\n"
                        f"  Rails:\n"
                        f"    config.middleware.delete Rack::MethodOverride\n\n"
                        f"  If override is required, restrict to POST only:\n"
                        f"    app.use(methodOverride('{header_name}', {{\n"
                        f"      methods: ['POST']  // Only allow override on POST\n"
                        f"    }}))"
                    ),
                    affected_component=f"Method override middleware for {parsed.path}",
                    references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods | https://portswigger.net/web-security/authentication/password-based",
                    detection_method=f"Sent a GET request with '{header_name}: {override_method}' header and observed the server processed it differently from a normal GET, indicating method override is active.",
                ))
                return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for HTTP Method Tampering...")

    tested_hosts = set()

    for url in session.crawled_urls:
        parsed = urlparse(url)
        host_path = f"{parsed.netloc}{parsed.path}"

        # Test TRACE and OPTIONS once per unique host+path
        if host_path not in tested_hosts:
            tested_hosts.add(host_path)
            _test_trace_method(session, url)
            _test_options_disclosure(session, url)

        _test_method_tampering(session, url)
        _test_method_override_headers(session, url)
