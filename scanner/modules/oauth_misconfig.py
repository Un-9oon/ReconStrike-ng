import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession


OAUTH_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/authorize",
    "/oauth2/authorize",
    "/authorize",
    "/oauth/token",
    "/oauth2/token",
    "/token",
    "/oauth/.well-known/openid-configuration",
    "/auth/realms/master/.well-known/openid-configuration",
    "/.well-known/jwks.json",
]

REDIRECT_BYPASS_PAYLOADS = [
    ("https://evil.com", "External domain redirect"),
    ("https://evil.com%23.legitimate.com", "Fragment bypass"),
    ("https://legitimate.com.evil.com", "Subdomain bypass"),
    ("https://legitimate.com@evil.com", "Userinfo bypass"),
    ("//evil.com", "Protocol-relative redirect"),
    ("/\\evil.com", "Backslash bypass"),
    ("https://evil.com/legitimate.com", "Path-based bypass"),
    ("https://evil.com?.legitimate.com", "Query bypass"),
    ("https://legitimate.com%00.evil.com", "Null byte bypass"),
    ("/./evil.com", "Dot-slash bypass"),
]

TOKEN_LEAK_PATTERNS = [
    (r"access_token=[\w\-\.]+", "Access token in URL"),
    (r"token=[\w\-\.]+", "Token in URL parameter"),
    (r"id_token=[\w\-\.]+", "ID token in URL"),
    (r"code=[\w\-\.]+", "Authorization code in URL"),
    (r"Bearer\s+[\w\-\.]+", "Bearer token exposed"),
]


def _build_curl(method, url, data=None):
    cmd = f"curl -k -X {method} '{url}'"
    if data:
        cmd += f" -d '{data}'"
    return cmd


def _check_discovery_endpoints(session, base_url):
    """Check for OAuth/OIDC discovery endpoints."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in OAUTH_DISCOVERY_PATHS:
        discovery_url = origin + path

        try:
            resp = session.get(discovery_url)
        except Exception as e:
            logger.debug("oauth_misconfig _check_discovery_endpoints: request failed: %s", e)
            continue

        if not resp or resp.status_code != 200:
            continue

        body = resp.text.lower()

        # Check for OIDC configuration
        if path.endswith("openid-configuration") or path.endswith("oauth-authorization-server"):
            if "authorization_endpoint" in body or "token_endpoint" in body or "issuer" in body:
                # Check for security issues in the configuration
                issues = []
                if '"token_endpoint_auth_methods_supported"' in resp.text:
                    if '"none"' in resp.text:
                        issues.append("Supports 'none' token endpoint auth method")
                if '"response_types_supported"' in resp.text:
                    if '"token"' in resp.text:
                        issues.append("Supports implicit flow (token in URL fragment)")
                if '"grant_types_supported"' in resp.text:
                    if '"password"' in resp.text:
                        issues.append("Supports resource owner password credentials grant")

                severity = Severity.MEDIUM if issues else Severity.INFO
                curl_cmd = _build_curl("GET", discovery_url)
                session.add_finding(Finding(
                    title="OAuth/OIDC Discovery Endpoint Exposed",
                    severity=severity,
                    description=(
                        f"An OAuth/OpenID Connect discovery endpoint was found at '{discovery_url}'. "
                        f"This endpoint exposes the OAuth server configuration, including supported "
                        f"grant types, endpoints, and authentication methods. "
                        + (
                            "The following security concerns were identified: "
                            + "; ".join(issues) + "."
                            if issues else
                            "While this endpoint is intentionally public, it reveals the OAuth "
                            "infrastructure details that attackers can leverage."
                        )
                    ),
                    evidence=(
                        f"Discovery URL: {discovery_url}\n"
                        f"Response Status: {resp.status_code}\n"
                        f"Content Length: {len(resp.text)}\n"
                        + (f"Security Issues: {'; '.join(issues)}\n" if issues else "")
                        + f"Response Preview: {resp.text[:500]}"
                    ),
                    remediation=(
                        "1. Ensure only necessary grant types are enabled.\n"
                        "2. Disable the implicit flow if not required (prefer authorization code + PKCE).\n"
                        "3. Require client authentication for the token endpoint (remove 'none').\n"
                        "4. Disable the resource owner password credentials grant if not needed.\n"
                        "5. Restrict CORS on OAuth endpoints to trusted origins only."
                    ),
                    url=base_url,
                    module="oauth",
                    cwe="CWE-346",
                    confirmed=True,
                    location=discovery_url,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Navigate to: {discovery_url}\n"
                        f"2. Review the OAuth/OIDC configuration JSON.\n"
                        f"3. Check grant_types_supported, response_types_supported, "
                        f"and token_endpoint_auth_methods_supported.\n"
                        f"4. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"OAuth Server Configuration:\n\n"
                        f"Disable insecure grant types and flows:\n"
                        f"  - Remove 'implicit' grant type (use 'authorization_code' with PKCE)\n"
                        f"  - Remove 'password' grant type unless strictly required\n"
                        f"  - Remove 'none' from token_endpoint_auth_methods_supported\n"
                        f"  - Set 'require_pkce: true' for public clients"
                    ),
                    affected_component="OAuth/OIDC server configuration",
                    references="https://openid.net/specs/openid-connect-discovery-1_0.html | https://portswigger.net/web-security/oauth",
                    detection_method=f"Discovered OAuth/OIDC configuration endpoint at {discovery_url} and analyzed the supported authentication methods and grant types.",
                ))

                # Now test redirect_uri manipulation if authorization_endpoint is found
                try:
                    import json as _json
                    config = _json.loads(resp.text)
                    auth_endpoint = config.get("authorization_endpoint", "")
                    if auth_endpoint:
                        _test_redirect_uri(session, auth_endpoint, base_url)
                except Exception as e:
                    logger.debug("oauth_misconfig _check_discovery_endpoints: JSON parse failed: %s", e)

                return

        # Check for authorize/token endpoints
        if "/authorize" in path or "/token" in path:
            if resp.status_code == 200 or resp.status_code == 302:
                if any(kw in body for kw in ("client_id", "redirect_uri", "response_type",
                                              "grant_type", "scope", "oauth", "authorize")):
                    curl_cmd = _build_curl("GET", discovery_url)
                    session.add_finding(Finding(
                        title=f"OAuth Endpoint Discovered: {path}",
                        severity=Severity.INFO,
                        description=(
                            f"An OAuth endpoint was found at '{discovery_url}'. This endpoint "
                            f"may handle authorization or token requests. Further testing for "
                            f"redirect_uri manipulation and state parameter validation is recommended."
                        ),
                        evidence=(
                            f"Endpoint: {discovery_url}\n"
                            f"Response Status: {resp.status_code}\n"
                            f"OAuth Keywords Found: True\n"
                            f"Response Preview: {resp.text[:300]}"
                        ),
                        remediation=(
                            "1. Validate redirect_uri against a strict allowlist.\n"
                            "2. Require and validate the state parameter.\n"
                            "3. Use PKCE for all OAuth flows.\n"
                            "4. Implement short-lived authorization codes."
                        ),
                        url=base_url,
                        module="oauth",
                        cwe="CWE-346",
                        confirmed=True,
                        location=discovery_url,
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Navigate to: {discovery_url}\n"
                            f"2. Review the endpoint behavior.\n"
                            f"3. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"Ensure the OAuth endpoint at {path} validates:\n"
                            f"  - redirect_uri against a strict allowlist\n"
                            f"  - state parameter for CSRF protection\n"
                            f"  - PKCE code_verifier for public clients"
                        ),
                        affected_component=f"OAuth endpoint at {path}",
                        references="https://portswigger.net/web-security/oauth | https://datatracker.ietf.org/doc/html/rfc6749",
                        detection_method=f"Discovered OAuth endpoint at {discovery_url} by probing common OAuth paths and detecting OAuth-related keywords in the response.",
                    ))


def _test_redirect_uri(session, auth_endpoint, base_url):
    """Test redirect_uri parameter for open redirect vulnerabilities."""
    parsed = urlparse(auth_endpoint)

    for payload, description in REDIRECT_BYPASS_PAYLOADS:
        # Build authorization URL with manipulated redirect_uri
        test_params = {
            "response_type": "code",
            "client_id": "test_client",
            "redirect_uri": payload,
            "scope": "openid",
            "state": "test_state_123",
        }
        test_query = urlencode(test_params)
        test_url = urlunparse(parsed._replace(query=test_query))

        try:
            resp = session.get(test_url)
        except Exception as e:
            logger.debug("oauth_misconfig _test_redirect_uri: request failed: %s", e)
            continue

        if not resp:
            continue

        # Check if the redirect_uri was accepted (not rejected with error)
        body = resp.text.lower()
        rejected = any(err in body for err in (
            "invalid redirect", "redirect_uri_mismatch", "invalid_redirect_uri",
            "unauthorized redirect", "redirect uri is not allowed",
            "invalid redirect_uri", "mismatching_redirect_uri"
        ))

        if not rejected and resp.status_code in (200, 302):
            # Check if the payload appears in a redirect Location header
            location = resp.headers.get("Location", "")
            if payload in location or (resp.status_code == 302 and "evil.com" in location):
                curl_cmd = _build_curl("GET", test_url)
                session.add_finding(Finding(
                    title=f"OAuth Open Redirect via redirect_uri - {description}",
                    severity=Severity.HIGH,
                    description=(
                        f"The OAuth authorization endpoint at '{auth_endpoint}' is vulnerable "
                        f"to open redirect via the redirect_uri parameter. The payload "
                        f"'{payload}' ({description}) was accepted and the server redirected "
                        f"to the attacker-controlled URL. This can be exploited to steal "
                        f"authorization codes or tokens."
                    ),
                    evidence=(
                        f"Authorization Endpoint: {auth_endpoint}\n"
                        f"Payload redirect_uri: {payload}\n"
                        f"Technique: {description}\n"
                        f"Response Status: {resp.status_code}\n"
                        f"Location Header: {location}\n"
                        f"Test URL: {test_url}"
                    ),
                    remediation=(
                        "1. Validate redirect_uri against a strict, pre-registered allowlist.\n"
                        "2. Use exact string matching for redirect_uri validation (no wildcards).\n"
                        "3. Reject redirect_uri with special characters, encoded values, or path traversal.\n"
                        "4. Register redirect_uris at client registration time.\n"
                        "5. Never allow open redirectors on your domain."
                    ),
                    url=base_url,
                    module="oauth",
                    cwe="CWE-346",
                    confirmed=True,
                    location=f"redirect_uri parameter in {auth_endpoint}",
                    parameter="redirect_uri",
                    payload=payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Craft an authorization URL: {test_url}\n"
                        f"2. Open the URL in a browser.\n"
                        f"3. Complete the OAuth flow.\n"
                        f"4. Observe the redirect to the attacker URL.\n"
                        f"5. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: OAuth server redirect_uri validation logic.\n\n"
                        f"VULNERABLE pattern:\n"
                        f"  if (redirect_uri.startsWith(registered_uri)) {{ allow(); }}\n\n"
                        f"SECURE pattern:\n"
                        f"  if (redirect_uri === registered_uri) {{ allow(); }}\n"
                        f"  // Exact match only, no prefix/suffix matching\n"
                        f"  // Pre-register all valid redirect_uris at client creation time"
                    ),
                    affected_component="OAuth authorization endpoint redirect_uri validation",
                    references="https://portswigger.net/web-security/oauth#leaking-authorization-codes-and-access-tokens | https://datatracker.ietf.org/doc/html/rfc6819#section-4.2.4",
                    detection_method=f"Submitted manipulated redirect_uri ({description}) to OAuth authorization endpoint and detected the server redirecting to the attacker-controlled URL.",
                ))
                return


def _check_state_parameter(session, url):
    """Check for missing or predictable state parameter in OAuth flows."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # Look for OAuth-related URLs with missing state
    if any(k in params for k in ("code", "response_type", "client_id")):
        if "state" not in params:
            curl_cmd = _build_curl("GET", url)
            session.add_finding(Finding(
                title="OAuth Missing State Parameter (CSRF Risk)",
                severity=Severity.MEDIUM,
                description=(
                    f"The URL '{url}' appears to be part of an OAuth flow but does not "
                    f"include a 'state' parameter. The state parameter is critical for "
                    f"preventing CSRF attacks against the OAuth flow. Without it, an attacker "
                    f"can forge authorization requests and potentially link their account "
                    f"to a victim's session."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"OAuth Parameters Present: {', '.join(k for k in params if k in ('code', 'response_type', 'client_id', 'redirect_uri'))}\n"
                    f"State Parameter: MISSING\n"
                    f"Response Status: N/A (detected from URL structure)"
                ),
                remediation=(
                    "1. Always include a cryptographically random 'state' parameter in authorization requests.\n"
                    "2. Bind the state to the user's session on the server side.\n"
                    "3. Verify the state parameter matches on the callback.\n"
                    "4. Use a HMAC of the session ID as the state value.\n"
                    "5. Reject callbacks with missing or invalid state."
                ),
                url=url,
                module="oauth",
                cwe="CWE-346",
                confirmed=True,
                location=f"OAuth flow at {parsed.path}",
                parameter="state",
                request_method="GET",
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Observe the OAuth URL: {url}\n"
                    f"2. Note the absence of a 'state' parameter.\n"
                    f"3. An attacker can craft a similar URL and trick a victim into visiting it.\n"
                    f"4. The victim's session will be linked to the attacker's OAuth account."
                ),
                developer_fix=(
                    f"File: The OAuth client code that initiates the authorization flow.\n\n"
                    f"VULNERABLE:\n"
                    f"  redirect_url = auth_endpoint + '?client_id=' + client_id + '&redirect_uri=' + callback\n\n"
                    f"SECURE:\n"
                    f"  import secrets\n"
                    f"  state = secrets.token_urlsafe(32)\n"
                    f"  session['oauth_state'] = state\n"
                    f"  redirect_url = auth_endpoint + '?client_id=' + client_id + "
                    f"'&redirect_uri=' + callback + '&state=' + state\n\n"
                    f"  # On callback:\n"
                    f"  if request.args.get('state') != session.pop('oauth_state', None):\n"
                    f"      abort(403)"
                ),
                affected_component=f"OAuth flow at {parsed.path}",
                references="https://datatracker.ietf.org/doc/html/rfc6749#section-10.12 | https://portswigger.net/web-security/oauth#flawed-csrf-protection",
                detection_method="Analyzed OAuth flow URL and detected absence of the 'state' parameter, which is required for CSRF protection.",
            ))


def _check_token_in_url(session, url):
    """Check if OAuth tokens are exposed in URL parameters or fragments."""
    parsed = urlparse(url)
    full_url = url

    for pattern, description in TOKEN_LEAK_PATTERNS:
        match = re.search(pattern, full_url)
        if match:
            token_snippet = match.group(0)
            # Mask most of the token
            if len(token_snippet) > 20:
                masked = token_snippet[:15] + "..." + token_snippet[-5:]
            else:
                masked = token_snippet

            curl_cmd = _build_curl("GET", url)
            session.add_finding(Finding(
                title=f"OAuth Token Exposed in URL - {description}",
                severity=Severity.HIGH,
                description=(
                    f"An OAuth token was found in the URL at '{parsed.path}'. "
                    f"Tokens in URLs are logged in browser history, server logs, referrer "
                    f"headers, and proxy logs, creating multiple vectors for token theft. "
                    f"Detection: {description}."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Token Type: {description}\n"
                    f"Token (masked): {masked}\n"
                    f"Full URL Path: {parsed.path}"
                ),
                remediation=(
                    "1. Never transmit tokens via URL parameters or fragments.\n"
                    "2. Use the authorization code flow with PKCE instead of implicit flow.\n"
                    "3. Return tokens only in response bodies over HTTPS.\n"
                    "4. Set Referrer-Policy: no-referrer on pages handling tokens.\n"
                    "5. Clear URL fragments containing tokens immediately after extraction."
                ),
                url=url,
                module="oauth",
                cwe="CWE-346",
                confirmed=True,
                location=f"URL parameter/fragment at {parsed.path}",
                parameter="token",
                request_method="GET",
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Observe the URL: {url}\n"
                    f"2. Note the token present in the URL ({description}).\n"
                    f"3. Check browser history, server access logs, and referrer headers.\n"
                    f"4. The token may be leaked to third-party services via Referer header."
                ),
                developer_fix=(
                    f"File: OAuth callback handler.\n\n"
                    f"Switch from implicit flow to authorization code flow with PKCE:\n"
                    f"  response_type=code (NOT response_type=token)\n\n"
                    f"Exchange the code server-side:\n"
                    f"  POST /token\n"
                    f"    grant_type=authorization_code\n"
                    f"    code=<code>\n"
                    f"    code_verifier=<pkce_verifier>\n\n"
                    f"Set headers on pages handling tokens:\n"
                    f"  Referrer-Policy: no-referrer\n"
                    f"  Cache-Control: no-store"
                ),
                affected_component="OAuth token delivery mechanism",
                references="https://datatracker.ietf.org/doc/html/rfc6749#section-10.3 | https://portswigger.net/web-security/oauth#leaking-authorization-codes-and-access-tokens",
                detection_method=f"Detected OAuth token pattern ({description}) in crawled URL, indicating tokens are transmitted insecurely via URL parameters.",
            ))
            return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for OAuth/OIDC Misconfigurations...")

    # Check discovery endpoints on all unique origins
    checked_origins = set()
    for url in session.crawled_urls:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in checked_origins:
            checked_origins.add(origin)
            _check_discovery_endpoints(session, url)

    # Check all crawled URLs for state parameter issues and token leakage
    for url in session.crawled_urls:
        _check_state_parameter(session, url)
        _check_token_in_url(session, url)
