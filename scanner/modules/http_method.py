import re
from urllib.parse import urlparse

import requests

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession, build_curl

TAMPER_METHODS = ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]

METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
]

SENSITIVE_PATH_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"/admin", r"/user", r"/account", r"/profile", r"/settings",
        r"/dashboard", r"/api/", r"/manage", r"/config",
        r"/delete", r"/edit", r"/update",
    ]
]


def _is_sensitive_path(url):
    path = urlparse(url).path
    return any(p.search(path) for p in SENSITIVE_PATH_PATTERNS)


def _safe_request(session, method, url, **kwargs):
    try:
        kwargs.setdefault("timeout", session.config.timeout)
        kwargs.setdefault("allow_redirects", session.config.follow_redirects)
        kwargs.setdefault("verify", session.config.verify_ssl)
        return session.session.request(method, url, **kwargs)
    except (requests.RequestException, ValueError) as e:
        logger.debug("http_method _safe_request: %s %s failed: %s", method, url, e)
        return None


def _test_trace_method(session, url):
    resp = _safe_request(session, "TRACE", url)
    if not resp:
        return

    body = resp.text or ""
    trace_indicators = [
        resp.status_code == 200 and "TRACE" in body.upper(),
        resp.status_code == 200 and "User-Agent" in body,
        resp.headers.get("Content-Type", "").startswith("message/http"),
    ]
    if not any(trace_indicators):
        return

    parsed = urlparse(url)
    curl_cmd = build_curl("TRACE", url)
    snippet = body[:500] if body else "(empty)"
    session.add_finding(Finding(
        title="TRACE Method Enabled (Cross-Site Tracing)",
        severity=Severity.MEDIUM,
        description=(
            "The server at '{host}' accepts HTTP TRACE requests on "
            "'{path}'. The TRACE method echoes back the full HTTP request, "
            "including headers such as cookies and authorization tokens. An attacker "
            "can exploit this via Cross-Site Tracing (XST) to steal credentials from "
            "authenticated users, especially when combined with XSS vulnerabilities."
        ).format(host=parsed.netloc, path=parsed.path),
        evidence=(
            "URL: {url}\nMethod: TRACE\nResponse Status: {status}\n"
            "Content-Type: {ct}\nResponse Body (first 500 chars): {body}"
        ).format(url=url, status=resp.status_code,
                 ct=resp.headers.get('Content-Type', 'N/A'), body=snippet),
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
        location="HTTP TRACE method on {}{}".format(parsed.netloc, parsed.path),
        parameter="",
        payload="TRACE / HTTP/1.1",
        request_method="TRACE",
        response_status=resp.status_code,
        curl_command=curl_cmd,
        reproduction_steps=(
            "1. Send an HTTP TRACE request to: {url}\n"
            "2. Run: {cmd}\n"
            "3. Observe that the server echoes back the request including headers.\n"
            "4. Note: cookies and auth headers are reflected, enabling credential theft."
        ).format(url=url, cmd=curl_cmd),
        developer_fix=(
            "File: Web server configuration for {host}.\n\n"
            "Apache httpd.conf / .htaccess:\n"
            "  TraceEnable off\n\n"
            "Nginx (should already be default):\n"
            "  if ($request_method = TRACE) {{\n"
            "    return 405;\n"
            "  }}\n\n"
            "IIS web.config:\n"
            "  <security><requestFiltering><verbs>"
            "<add verb=\"TRACE\" allowed=\"false\" />"
            "</verbs></requestFiltering></security>"
        ).format(host=parsed.netloc),
        affected_component="HTTP method handling on {}".format(parsed.netloc),
        references="https://owasp.org/www-community/attacks/Cross_Site_Tracing | https://cwe.mitre.org/data/definitions/693.html",
        detection_method="Sent an HTTP TRACE request and confirmed the server echoed back the request body including headers, indicating TRACE method is enabled.",
    ))


def _test_options_disclosure(session, url):
    resp = _safe_request(session, "OPTIONS", url)
    if not resp:
        return

    allow_header = resp.headers.get("Allow", "")
    access_control = resp.headers.get("Access-Control-Allow-Methods", "")
    disclosed = allow_header or access_control
    if not disclosed:
        return

    dangerous = [m for m in ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
                 if m in disclosed.upper()]
    if not dangerous:
        return

    parsed = urlparse(url)
    curl_cmd = build_curl("OPTIONS", url)
    session.add_finding(Finding(
        title="Dangerous HTTP Methods Allowed ({})".format(", ".join(dangerous)),
        severity=Severity.LOW,
        description=(
            "The server at '{host}' responds to an OPTIONS request on "
            "'{path}' with an Allow header disclosing that the following "
            "potentially dangerous HTTP methods are available: "
            "{methods}. If these methods are not properly "
            "access-controlled, they could allow unauthorized data modification or "
            "deletion."
        ).format(host=parsed.netloc, path=parsed.path, methods=", ".join(dangerous)),
        evidence=(
            "URL: {url}\nMethod: OPTIONS\nResponse Status: {status}\n"
            "Allow Header: {allow}\nAccess-Control-Allow-Methods: {acl}\n"
            "Dangerous Methods Found: {methods}"
        ).format(url=url, status=resp.status_code, allow=allow_header,
                 acl=access_control, methods=", ".join(dangerous)),
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
        location="OPTIONS response on {}{}".format(parsed.netloc, parsed.path),
        parameter="",
        payload="OPTIONS request",
        request_method="OPTIONS",
        response_status=resp.status_code,
        curl_command=curl_cmd,
        reproduction_steps=(
            "1. Send an HTTP OPTIONS request to: {url}\n"
            "2. Run: {cmd}\n"
            "3. Examine the Allow header in the response.\n"
            "4. Note the dangerous methods listed: {methods}."
        ).format(url=url, cmd=curl_cmd, methods=", ".join(dangerous)),
        developer_fix=(
            "File: Web server configuration or application route definitions.\n\n"
            "Restrict allowed methods per endpoint:\n\n"
            "  Python/Flask:\n"
            "    @app.route('{path}', methods=['GET', 'POST'])\n\n"
            "  Node.js/Express:\n"
            "    app.route('{path}').get(handler).post(handler);\n"
            "    // Do not define .put(), .delete() unless needed\n\n"
            "  Apache .htaccess:\n"
            "    <LimitExcept GET POST>\n"
            "      Require all denied\n"
            "    </LimitExcept>"
        ).format(path=parsed.path),
        affected_component="HTTP method configuration on {}{}".format(parsed.netloc, parsed.path),
        references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
        detection_method="Sent an OPTIONS request and parsed the Allow header to identify dangerous HTTP methods that the server accepts.",
    ))


def _test_method_tampering(session, url):
    baseline_resp = session.get(url)
    if not baseline_resp:
        return

    baseline_status = baseline_resp.status_code
    is_restricted = baseline_status in (401, 403, 405)
    is_sensitive = _is_sensitive_path(url)

    if not is_restricted and not is_sensitive:
        return

    parsed = urlparse(url)

    for method in TAMPER_METHODS:
        if method in ("TRACE", "OPTIONS"):
            continue

        resp = _safe_request(session, method, url)
        if not resp:
            continue

        bypassed = (is_restricted and resp.status_code == 200) or \
                   (is_restricted and resp.status_code not in (401, 403, 405, 501) and resp.status_code < 400)
        if not bypassed:
            continue

        curl_cmd = build_curl(method, url)
        session.add_finding(Finding(
            title="HTTP Method Tampering Bypass ({})".format(method),
            severity=Severity.HIGH,
            description=(
                "The endpoint '{path}' returned HTTP {orig} for a "
                "standard GET request but returned HTTP {new} when the "
                "{method} method was used. This indicates the access control mechanism "
                "only restricts specific HTTP methods, allowing an attacker to bypass "
                "authentication or authorization by using an alternative verb."
            ).format(path=parsed.path, orig=baseline_status,
                     new=resp.status_code, method=method),
            evidence=(
                "URL: {url}\n"
                "Original Method: GET -> Status {orig}\n"
                "Tampered Method: {method} -> Status {new}\n"
                "Response Length: {rlen}\n"
                "Response Snippet: {snip}"
            ).format(url=url, orig=baseline_status, method=method,
                     new=resp.status_code, rlen=len(resp.text), snip=resp.text[:300]),
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
            location="Access control on {}".format(parsed.path),
            parameter="",
            payload="HTTP {} request".format(method),
            request_method=method,
            response_status=resp.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Attempt to access: {url} via GET (observe {orig} response).\n"
                "2. Send the same request using the {method} method.\n"
                "3. Run: {cmd}\n"
                "4. Observe that the server responds with {new} instead of {orig}."
            ).format(url=url, orig=baseline_status, method=method,
                     cmd=curl_cmd, new=resp.status_code),
            developer_fix=(
                "File: The route definition / middleware for '{path}'.\n\n"
                "VULNERABLE pattern (method-specific restriction):\n"
                "  @app.route('{path}')\n"
                "  def handler():\n"
                "    if request.method == 'GET':\n"
                "      return abort(403)  # Only blocks GET!\n\n"
                "SECURE pattern (method-agnostic restriction):\n"
                "  @app.route('{path}', methods=['GET', 'POST'])\n"
                "  @login_required\n"
                "  def handler():\n"
                "    ...  # Auth check applies to all allowed methods\n\n"
                "  # Reject all other methods via 405 (framework default when methods= is set)"
            ).format(path=parsed.path),
            affected_component="Access control on {}".format(parsed.path),
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods | https://cwe.mitre.org/data/definitions/650.html",
            detection_method="Sent HTTP {} request to an endpoint that returned {} for GET, and received a {} response indicating access control bypass.".format(method, baseline_status, resp.status_code),
        ))
        return


def _test_method_override_headers(session, url):
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
            except (requests.RequestException, ValueError) as e:
                logger.debug("http_method _test_method_override_headers: request failed: %s", e)
                continue

            if not resp:
                continue

            bypassed = False
            if is_restricted and resp.status_code == 200:
                bypassed = True
            elif is_restricted and resp.status_code not in (401, 403, 405, 501) and resp.status_code < 400:
                bypassed = True
            elif is_sensitive and not is_restricted:
                if resp.status_code != baseline_status:
                    bypassed = True
                elif abs(len(resp.text) - len(baseline_resp.text)) > len(baseline_resp.text) * 0.3:
                    bypassed = True

            if not bypassed:
                continue

            curl_cmd = build_curl("GET", url, headers={header_name: override_method})
            session.add_finding(Finding(
                title="Method Override Header Bypass ({}: {})".format(header_name, override_method),
                severity=Severity.HIGH,
                description=(
                    "The endpoint '{path}' accepts the '{hdr}' header "
                    "to override the HTTP method. When a GET request was sent with "
                    "'{hdr}: {method}', the server processed it as "
                    "a {method} request, bypassing access controls that returned "
                    "HTTP {orig} for a normal GET."
                ).format(path=parsed.path, hdr=header_name,
                         method=override_method, orig=baseline_status),
                evidence=(
                    "URL: {url}\n"
                    "Original GET Status: {orig}\n"
                    "Override Header: {hdr}: {method}\n"
                    "Override Response Status: {status}\n"
                    "Response Length: {rlen}\n"
                    "Response Snippet: {snip}"
                ).format(url=url, orig=baseline_status, hdr=header_name,
                         method=override_method, status=resp.status_code,
                         rlen=len(resp.text), snip=resp.text[:300]),
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
                location="Method override handling on {}".format(parsed.path),
                parameter=header_name,
                payload="{}: {}".format(header_name, override_method),
                request_method="GET",
                request_headers="{}: {}".format(header_name, override_method),
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Send a GET request to: {url} (observe {orig}).\n"
                    "2. Send the same GET request with the header: {hdr}: {method}\n"
                    "3. Run: {cmd}\n"
                    "4. Observe the server processes it as a {method} request."
                ).format(url=url, orig=baseline_status, hdr=header_name,
                         method=override_method, cmd=curl_cmd),
                developer_fix=(
                    "File: Middleware configuration or web server config.\n\n"
                    "Remove or restrict method override middleware:\n\n"
                    "  Express:\n"
                    "    // Remove this line:\n"
                    "    // app.use(methodOverride('{hdr}'))\n\n"
                    "  Django:\n"
                    "    # Ensure no custom middleware processes {hdr}\n\n"
                    "  Rails:\n"
                    "    config.middleware.delete Rack::MethodOverride\n\n"
                    "  If override is required, restrict to POST only:\n"
                    "    app.use(methodOverride('{hdr}', {{\n"
                    "      methods: ['POST']  // Only allow override on POST\n"
                    "    }}))"
                ).format(hdr=header_name),
                affected_component="Method override middleware for {}".format(parsed.path),
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods | https://portswigger.net/web-security/authentication/password-based",
                detection_method="Sent a GET request with '{}: {}' header and observed the server processed it differently from a normal GET, indicating method override is active.".format(header_name, override_method),
            ))
            return


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for HTTP Method Tampering...")

    tested_hosts = set()

    for url in session.crawled_urls:
        parsed = urlparse(url)
        host_path = "{}{}".format(parsed.netloc, parsed.path)

        if host_path not in tested_hosts:
            tested_hosts.add(host_path)
            _test_trace_method(session, url)
            _test_options_disclosure(session, url)

        _test_method_tampering(session, url)
        _test_method_override_headers(session, url)
