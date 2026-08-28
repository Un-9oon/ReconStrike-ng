import json
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

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
    cmd = "curl -k -X {} '{}'".format(method, url)
    if data:
        cmd += " -d '{}'".format(data)
    return cmd


def _check_discovery_endpoints(session, base_url):
    parsed = urlparse(base_url)
    origin = "{}://{}".format(parsed.scheme, parsed.netloc)

    for path in OAUTH_DISCOVERY_PATHS:
        discovery_url = origin + path

        try:
            resp = session.get(discovery_url)
        except (requests.RequestException, ValueError) as e:
            logger.debug("oauth_misconfig _check_discovery_endpoints: request failed: %s", e)
            continue

        if not resp or resp.status_code != 200:
            continue

        body = resp.text.lower()

        if path.endswith("openid-configuration") or path.endswith("oauth-authorization-server"):
            if not ("authorization_endpoint" in body or "token_endpoint" in body or "issuer" in body):
                continue

            issues = []
            if '"token_endpoint_auth_methods_supported"' in resp.text and '"none"' in resp.text:
                issues.append("Supports 'none' token endpoint auth method")
            if '"response_types_supported"' in resp.text and '"token"' in resp.text:
                issues.append("Supports implicit flow (token in URL fragment)")
            if '"grant_types_supported"' in resp.text and '"password"' in resp.text:
                issues.append("Supports resource owner password credentials grant")

            severity = Severity.MEDIUM if issues else Severity.INFO
            curl_cmd = _build_curl("GET", discovery_url)
            session.add_finding(Finding(
                title="OAuth/OIDC Discovery Endpoint Exposed",
                severity=severity,
                description=(
                    "An OAuth/OpenID Connect discovery endpoint was found at '{}'. "
                    "This endpoint exposes the OAuth server configuration, including supported "
                    "grant types, endpoints, and authentication methods. ".format(discovery_url)
                    + (
                        "The following security concerns were identified: "
                        + "; ".join(issues) + "."
                        if issues else
                        "While this endpoint is intentionally public, it reveals the OAuth "
                        "infrastructure details that attackers can leverage."
                    )
                ),
                evidence=(
                    "Discovery URL: {}\n"
                    "Response Status: {}\n"
                    "Content Length: {}\n".format(discovery_url, resp.status_code, len(resp.text))
                    + ("Security Issues: {}\n".format("; ".join(issues)) if issues else "")
                    + "Response Preview: {}".format(resp.text[:500])
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
                    "1. Navigate to: {}\n"
                    "2. Review the OAuth/OIDC configuration JSON.\n"
                    "3. Check grant_types_supported, response_types_supported, "
                    "and token_endpoint_auth_methods_supported.\n"
                    "4. Run: {}".format(discovery_url, curl_cmd)
                ),
                developer_fix=(
                    "OAuth Server Configuration:\n\n"
                    "Disable insecure grant types and flows:\n"
                    "  - Remove 'implicit' grant type (use 'authorization_code' with PKCE)\n"
                    "  - Remove 'password' grant type unless strictly required\n"
                    "  - Remove 'none' from token_endpoint_auth_methods_supported\n"
                    "  - Set 'require_pkce: true' for public clients"
                ),
                affected_component="OAuth/OIDC server configuration",
                references="https://openid.net/specs/openid-connect-discovery-1_0.html | https://portswigger.net/web-security/oauth",
                detection_method="Discovered OAuth/OIDC configuration endpoint at {} and analyzed the supported authentication methods and grant types.".format(discovery_url),
            ))

            try:
                config = json.loads(resp.text)
                auth_endpoint = config.get("authorization_endpoint", "")
                if auth_endpoint:
                    _test_redirect_uri(session, auth_endpoint, base_url)
            except (ValueError, KeyError) as e:
                logger.debug("oauth_misconfig _check_discovery_endpoints: JSON parse failed: %s", e)

            return

        if "/authorize" in path or "/token" in path:
            if resp.status_code in (200, 302):
                if any(kw in body for kw in ("client_id", "redirect_uri", "response_type",
                                              "grant_type", "scope", "oauth", "authorize")):
                    curl_cmd = _build_curl("GET", discovery_url)
                    session.add_finding(Finding(
                        title="OAuth Endpoint Discovered: {}".format(path),
                        severity=Severity.INFO,
                        description=(
                            "An OAuth endpoint was found at '{}'. This endpoint "
                            "may handle authorization or token requests. Further testing for "
                            "redirect_uri manipulation and state parameter validation is recommended.".format(discovery_url)
                        ),
                        evidence=(
                            "Endpoint: {}\n"
                            "Response Status: {}\n"
                            "OAuth Keywords Found: True\n"
                            "Response Preview: {}".format(discovery_url, resp.status_code, resp.text[:300])
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
                            "1. Navigate to: {}\n"
                            "2. Review the endpoint behavior.\n"
                            "3. Run: {}".format(discovery_url, curl_cmd)
                        ),
                        developer_fix=(
                            "Ensure the OAuth endpoint at {} validates:\n"
                            "  - redirect_uri against a strict allowlist\n"
                            "  - state parameter for CSRF protection\n"
                            "  - PKCE code_verifier for public clients".format(path)
                        ),
                        affected_component="OAuth endpoint at {}".format(path),
                        references="https://portswigger.net/web-security/oauth | https://datatracker.ietf.org/doc/html/rfc6749",
                        detection_method="Discovered OAuth endpoint at {} by probing common OAuth paths and detecting OAuth-related keywords in the response.".format(discovery_url),
                    ))


def _test_redirect_uri(session, auth_endpoint, base_url):
    parsed = urlparse(auth_endpoint)

    for payload, description in REDIRECT_BYPASS_PAYLOADS:
        test_params = {
            "response_type": "code",
            "client_id": "test_client",
            "redirect_uri": payload,
            "scope": "openid",
            "state": "test_state_123",
        }
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

        try:
            resp = session.get(test_url)
        except (requests.RequestException, ValueError) as e:
            logger.debug("oauth_misconfig _test_redirect_uri: request failed: %s", e)
            continue

        if not resp:
            continue

        body = resp.text.lower()
        rejected = any(err in body for err in (
            "invalid redirect", "redirect_uri_mismatch", "invalid_redirect_uri",
            "unauthorized redirect", "redirect uri is not allowed",
            "invalid redirect_uri", "mismatching_redirect_uri"
        ))

        if not rejected and resp.status_code in (200, 302):
            location = resp.headers.get("Location", "")
            if payload in location or (resp.status_code == 302 and "evil.com" in location):
                curl_cmd = _build_curl("GET", test_url)
                session.add_finding(Finding(
                    title="OAuth Open Redirect via redirect_uri - {}".format(description),
                    severity=Severity.HIGH,
                    description=(
                        "The OAuth authorization endpoint at '{}' is vulnerable "
                        "to open redirect via the redirect_uri parameter. The payload "
                        "'{}' ({}) was accepted and the server redirected "
                        "to the attacker-controlled URL. This can be exploited to steal "
                        "authorization codes or tokens.".format(auth_endpoint, payload, description)
                    ),
                    evidence=(
                        "Authorization Endpoint: {}\n"
                        "Payload redirect_uri: {}\n"
                        "Technique: {}\n"
                        "Response Status: {}\n"
                        "Location Header: {}\n"
                        "Test URL: {}".format(auth_endpoint, payload, description, resp.status_code, location, test_url)
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
                    location="redirect_uri parameter in {}".format(auth_endpoint),
                    parameter="redirect_uri",
                    payload=payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        "1. Craft an authorization URL: {}\n"
                        "2. Open the URL in a browser.\n"
                        "3. Complete the OAuth flow.\n"
                        "4. Observe the redirect to the attacker URL.\n"
                        "5. Run: {}".format(test_url, curl_cmd)
                    ),
                    developer_fix=(
                        "File: OAuth server redirect_uri validation logic.\n\n"
                        "VULNERABLE pattern:\n"
                        "  if (redirect_uri.startsWith(registered_uri)) { allow(); }\n\n"
                        "SECURE pattern:\n"
                        "  if (redirect_uri === registered_uri) { allow(); }\n"
                        "  // Exact match only, no prefix/suffix matching\n"
                        "  // Pre-register all valid redirect_uris at client creation time"
                    ),
                    affected_component="OAuth authorization endpoint redirect_uri validation",
                    references="https://portswigger.net/web-security/oauth#leaking-authorization-codes-and-access-tokens | https://datatracker.ietf.org/doc/html/rfc6819#section-4.2.4",
                    detection_method="Submitted manipulated redirect_uri ({}) to OAuth authorization endpoint and detected the server redirecting to the attacker-controlled URL.".format(description),
                ))
                return


def _check_state_parameter(session, url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not any(k in params for k in ("code", "response_type", "client_id")):
        return
    if "state" in params:
        return

    curl_cmd = _build_curl("GET", url)
    session.add_finding(Finding(
        title="OAuth Missing State Parameter (CSRF Risk)",
        severity=Severity.MEDIUM,
        description=(
            "The URL '{}' appears to be part of an OAuth flow but does not "
            "include a 'state' parameter. The state parameter is critical for "
            "preventing CSRF attacks against the OAuth flow. Without it, an attacker "
            "can forge authorization requests and potentially link their account "
            "to a victim's session.".format(url)
        ),
        evidence=(
            "URL: {}\n"
            "OAuth Parameters Present: {}\n"
            "State Parameter: MISSING\n"
            "Response Status: N/A (detected from URL structure)".format(
                url,
                ", ".join(k for k in params if k in ("code", "response_type", "client_id", "redirect_uri")),
            )
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
        location="OAuth flow at {}".format(parsed.path),
        parameter="state",
        request_method="GET",
        curl_command=curl_cmd,
        reproduction_steps=(
            "1. Observe the OAuth URL: {}\n"
            "2. Note the absence of a 'state' parameter.\n"
            "3. An attacker can craft a similar URL and trick a victim into visiting it.\n"
            "4. The victim's session will be linked to the attacker's OAuth account.".format(url)
        ),
        developer_fix=(
            "File: The OAuth client code that initiates the authorization flow.\n\n"
            "VULNERABLE:\n"
            "  redirect_url = auth_endpoint + '?client_id=' + client_id + '&redirect_uri=' + callback\n\n"
            "SECURE:\n"
            "  import secrets\n"
            "  state = secrets.token_urlsafe(32)\n"
            "  session['oauth_state'] = state\n"
            "  redirect_url = auth_endpoint + '?client_id=' + client_id + "
            "'&redirect_uri=' + callback + '&state=' + state\n\n"
            "  # On callback:\n"
            "  if request.args.get('state') != session.pop('oauth_state', None):\n"
            "      abort(403)"
        ),
        affected_component="OAuth flow at {}".format(parsed.path),
        references="https://datatracker.ietf.org/doc/html/rfc6749#section-10.12 | https://portswigger.net/web-security/oauth#flawed-csrf-protection",
        detection_method="Analyzed OAuth flow URL and detected absence of the 'state' parameter, which is required for CSRF protection.",
    ))


def _check_token_in_url(session, url):
    parsed = urlparse(url)

    for pattern, description in TOKEN_LEAK_PATTERNS:
        match = re.search(pattern, url)
        if not match:
            continue

        token_snippet = match.group(0)
        masked = token_snippet[:15] + "..." + token_snippet[-5:] if len(token_snippet) > 20 else token_snippet

        curl_cmd = _build_curl("GET", url)
        session.add_finding(Finding(
            title="OAuth Token Exposed in URL - {}".format(description),
            severity=Severity.HIGH,
            description=(
                "An OAuth token was found in the URL at '{}'. "
                "Tokens in URLs are logged in browser history, server logs, referrer "
                "headers, and proxy logs, creating multiple vectors for token theft. "
                "Detection: {}.".format(parsed.path, description)
            ),
            evidence=(
                "URL: {}\n"
                "Token Type: {}\n"
                "Token (masked): {}\n"
                "Full URL Path: {}".format(url, description, masked, parsed.path)
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
            location="URL parameter/fragment at {}".format(parsed.path),
            parameter="token",
            request_method="GET",
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Observe the URL: {}\n"
                "2. Note the token present in the URL ({}).\n"
                "3. Check browser history, server access logs, and referrer headers.\n"
                "4. The token may be leaked to third-party services via Referer header.".format(url, description)
            ),
            developer_fix=(
                "File: OAuth callback handler.\n\n"
                "Switch from implicit flow to authorization code flow with PKCE:\n"
                "  response_type=code (NOT response_type=token)\n\n"
                "Exchange the code server-side:\n"
                "  POST /token\n"
                "    grant_type=authorization_code\n"
                "    code=<code>\n"
                "    code_verifier=<pkce_verifier>\n\n"
                "Set headers on pages handling tokens:\n"
                "  Referrer-Policy: no-referrer\n"
                "  Cache-Control: no-store"
            ),
            affected_component="OAuth token delivery mechanism",
            references="https://datatracker.ietf.org/doc/html/rfc6749#section-10.3 | https://portswigger.net/web-security/oauth#leaking-authorization-codes-and-access-tokens",
            detection_method="Detected OAuth token pattern ({}) in crawled URL, indicating tokens are transmitted insecurely via URL parameters.".format(description),
        ))
        return


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for OAuth/OIDC Misconfigurations...")

    checked_origins = set()
    for url in session.crawled_urls:
        parsed = urlparse(url)
        origin = "{}://{}".format(parsed.scheme, parsed.netloc)
        if origin not in checked_origins:
            checked_origins.add(origin)
            _check_discovery_endpoints(session, url)

    for url in session.crawled_urls:
        _check_state_parameter(session, url)
        _check_token_in_url(session, url)
