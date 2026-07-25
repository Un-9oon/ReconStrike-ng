import re
from urllib.parse import urlparse, urljoin

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession, build_curl


COMMON_WS_PATHS = [
    "/ws",
    "/ws/",
    "/websocket",
    "/websocket/",
    "/socket",
    "/socket/",
    "/socket.io/",
    "/socket.io/?EIO=4&transport=polling",
    "/sockjs/info",
    "/cable",
    "/hub",
    "/signalr/negotiate",
    "/realtime",
    "/live",
    "/stream",
    "/events",
    "/push",
    "/chat",
    "/notifications",
]

WS_UPGRADE_HEADERS = {
    "Upgrade": "websocket",
    "Connection": "Upgrade",
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
}

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
]


def _build_curl_ws(url, extra_headers=None):
    """Build a curl command for WebSocket upgrade request."""
    cmd = f"curl -k -i '{url}'"
    all_headers = dict(WS_UPGRADE_HEADERS)
    if extra_headers:
        all_headers.update(extra_headers)
    for k, v in all_headers.items():
        cmd += f" -H '{k}: {v}'"
    return cmd


def _detect_ws_endpoints(session, base_url):
    """Discover WebSocket endpoints by probing common paths."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    endpoints = []

    for path in COMMON_WS_PATHS:
        url = urljoin(base, path)
        try:
            resp = session.get(url, headers=WS_UPGRADE_HEADERS)
            if not resp:
                continue

            # WebSocket upgrade accepted
            if resp.status_code == 101:
                endpoints.append({"url": url, "status": 101, "type": "upgrade_accepted"})
                continue

            # Socket.IO polling endpoint responds with JSON
            if "socket.io" in path and resp.status_code == 200:
                if "sid" in resp.text or "websocket" in resp.text.lower():
                    endpoints.append({"url": url, "status": 200, "type": "socketio_polling"})
                    continue

            # SignalR negotiate endpoint
            if "signalr" in path and resp.status_code == 200:
                if "connectionId" in resp.text or "negotiateVersion" in resp.text:
                    endpoints.append({"url": url, "status": 200, "type": "signalr"})
                    continue

            # SockJS info endpoint
            if "sockjs" in path and resp.status_code == 200:
                if "websocket" in resp.text.lower():
                    endpoints.append({"url": url, "status": 200, "type": "sockjs"})
                    continue

            # Server returned 400 with WebSocket-related message (knows about WS)
            if resp.status_code == 400:
                body_lower = resp.text.lower()
                if any(kw in body_lower for kw in ("websocket", "upgrade", "sec-websocket")):
                    endpoints.append({"url": url, "status": 400, "type": "ws_aware"})

        except Exception as e:
            logger.debug("websocket_security _detect_ws_endpoints: operation failed: %s", e)
            continue

    # Also check crawled URLs for WebSocket indicators
    for url in session.crawled_urls:
        try:
            resp = session.get(url)
            if not resp:
                continue
            body = resp.text
            # Look for WebSocket connection code in HTML/JS
            ws_patterns = [
                r'new\s+WebSocket\s*\(\s*["\']([^"\']+)',
                r'io\(\s*["\']([^"\']+)',
                r'io\.connect\s*\(\s*["\']([^"\']+)',
                r'SockJS\s*\(\s*["\']([^"\']+)',
            ]
            for pattern in ws_patterns:
                matches = re.findall(pattern, body)
                for match in matches:
                    if match.startswith("ws://") or match.startswith("wss://"):
                        http_url = match.replace("ws://", "http://").replace("wss://", "https://")
                    elif match.startswith("/"):
                        http_url = urljoin(base, match)
                    else:
                        http_url = match
                    endpoints.append({
                        "url": http_url,
                        "status": 0,
                        "type": "js_reference",
                        "source": url,
                    })
        except Exception as e:
            logger.debug("websocket_security _detect_ws_endpoints: operation failed: %s", e)
            continue

    # Deduplicate by URL
    seen = set()
    unique = []
    for ep in endpoints:
        if ep["url"] not in seen:
            seen.add(ep["url"])
            unique.append(ep)
    return unique


def _test_origin_validation(session, endpoint):
    """Test if the WebSocket endpoint validates the Origin header."""
    url = endpoint["url"]
    parsed = urlparse(url)
    legitimate_origin = f"{parsed.scheme}://{parsed.netloc}"

    # First test with legitimate origin
    legit_headers = dict(WS_UPGRADE_HEADERS)
    legit_headers["Origin"] = legitimate_origin
    legit_resp = session.get(url, headers=legit_headers)

    if not legit_resp:
        return

    for evil_origin in EVIL_ORIGINS:
        try:
            evil_headers = dict(WS_UPGRADE_HEADERS)
            evil_headers["Origin"] = evil_origin

            resp = session.get(url, headers=evil_headers)
            if not resp:
                continue

            # If the server accepts the upgrade or returns the same status with
            # an evil origin as with the legitimate one, origin is not validated
            origin_accepted = False

            if resp.status_code == 101:
                origin_accepted = True
            elif resp.status_code == legit_resp.status_code:
                # Same response status -- check if Access-Control headers differ
                legit_acao = legit_resp.headers.get("Access-Control-Allow-Origin", "")
                evil_acao = resp.headers.get("Access-Control-Allow-Origin", "")

                if evil_acao == "*" or evil_acao == evil_origin:
                    origin_accepted = True
                elif resp.status_code == 200 and legit_resp.status_code == 200:
                    # Both return 200 with similar body -- likely no origin check
                    if abs(len(resp.text) - len(legit_resp.text)) < 50:
                        origin_accepted = True

            if origin_accepted:
                curl_cmd = _build_curl_ws(url, {"Origin": evil_origin})
                session.add_finding(Finding(
                    title="Cross-Site WebSocket Hijacking (Missing Origin Validation)",
                    severity=Severity.HIGH,
                    description=(
                        f"The WebSocket endpoint at '{url}' does not validate the Origin header. "
                        f"When a request is sent with Origin '{evil_origin}', the server responds "
                        f"identically to a legitimate origin request. This enables Cross-Site "
                        f"WebSocket Hijacking (CSWSH), where a malicious webpage can establish a "
                        f"WebSocket connection to this endpoint using the victim's cookies."
                    ),
                    evidence=(
                        f"WebSocket Endpoint: {url}\n"
                        f"Endpoint Type: {endpoint['type']}\n"
                        f"Legitimate Origin: {legitimate_origin}\n"
                        f"Evil Origin: {evil_origin}\n"
                        f"Legitimate Origin Status: {legit_resp.status_code}\n"
                        f"Evil Origin Status: {resp.status_code}\n"
                        f"ACAO Header (evil): {resp.headers.get('Access-Control-Allow-Origin', 'none')}"
                    ),
                    remediation=(
                        "1. Validate the Origin header on all WebSocket upgrade requests.\n"
                        "2. Maintain an allowlist of permitted origins and reject all others.\n"
                        "3. Use a CSRF token in the WebSocket handshake URL or first message.\n"
                        "4. Implement authentication that is not solely cookie-based for WS.\n"
                        "5. Consider using per-connection tokens passed as query parameters."
                    ),
                    url=url,
                    module="websocket",
                    cwe="CWE-1385",
                    confirmed=True,
                    location=f"WebSocket endpoint at {parsed.path or '/'}",
                    parameter="Origin",
                    payload=evil_origin,
                    request_method="GET",
                    request_headers=str(evil_headers),
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Open a browser console on https://evil.com (or any cross-origin page).\n"
                        f"2. Run: var ws = new WebSocket('{url.replace('http', 'ws')}');\n"
                        f"3. If the connection opens, the endpoint lacks origin validation.\n"
                        f"4. Alternatively, run: {curl_cmd}\n"
                        f"5. Compare response with the same request using Origin: {legitimate_origin}"
                    ),
                    developer_fix=(
                        f"Server-side WebSocket handler for {parsed.path}:\n\n"
                        "Check the Origin header before accepting the upgrade:\n\n"
                        "  Node.js (ws library):\n"
                        "    wss.on('connection', (ws, req) => {\n"
                        "      const origin = req.headers.origin;\n"
                        f"      if (origin !== '{legitimate_origin}') {{\n"
                        "        ws.close(1008, 'Invalid origin');\n"
                        "        return;\n"
                        "      }\n"
                        "    });\n\n"
                        "  Python (Django Channels):\n"
                        "    ALLOWED_HOSTS = ['yourdomain.com']\n"
                        "    # Django Channels checks Origin automatically with ALLOWED_HOSTS"
                    ),
                    affected_component=f"WebSocket origin validation at {parsed.path}",
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets | "
                        "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking"
                    ),
                    detection_method=(
                        f"Sent WebSocket upgrade requests with both a legitimate origin "
                        f"({legitimate_origin}) and a malicious origin ({evil_origin}). "
                        f"Both received identical responses, indicating no origin validation."
                    ),
                ))
                return

        except Exception as e:
            logger.debug("websocket_security _test_origin_validation: operation failed: %s", e)
            continue


def _test_ws_no_auth(session, endpoint):
    """Test if the WebSocket endpoint requires authentication."""
    url = endpoint["url"]
    parsed = urlparse(url)

    try:
        # Send upgrade request without any auth cookies/tokens
        no_auth_headers = dict(WS_UPGRADE_HEADERS)
        resp = session.get(url, headers=no_auth_headers)
        if not resp:
            return

        # Check if the endpoint accepts connections without auth
        if resp.status_code in (101, 200):
            # Verify this isn't just a public endpoint by checking
            # if the response contains meaningful data or upgrade confirmation
            is_upgrade = resp.status_code == 101
            has_ws_accept = "Sec-WebSocket-Accept" in resp.headers

            # For polling endpoints (socket.io), check if we get a session
            is_session = "sid" in resp.text if resp.text else False

            if is_upgrade or has_ws_accept or is_session:
                curl_cmd = _build_curl_ws(url)
                session.add_finding(Finding(
                    title="WebSocket Endpoint Accessible Without Authentication",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The WebSocket endpoint at '{url}' accepts connections without requiring "
                        f"authentication. An unauthenticated attacker can establish a WebSocket "
                        f"connection and potentially access real-time data, send commands, or "
                        f"interact with backend services."
                    ),
                    evidence=(
                        f"WebSocket Endpoint: {url}\n"
                        f"Endpoint Type: {endpoint['type']}\n"
                        f"Response Status: {resp.status_code}\n"
                        f"Upgrade Accepted: {is_upgrade}\n"
                        f"WS Accept Header: {has_ws_accept}\n"
                        f"Session Issued: {is_session}\n"
                        f"Response Headers: {dict(resp.headers)}"
                    ),
                    remediation=(
                        "1. Require authentication before accepting WebSocket upgrades.\n"
                        "2. Validate session tokens or JWTs during the handshake.\n"
                        "3. Pass authentication tokens as query parameters or in the first message.\n"
                        "4. Implement authorization checks for each WebSocket message type.\n"
                        "5. Rate-limit WebSocket connections per IP/user."
                    ),
                    url=url,
                    module="websocket",
                    cwe="CWE-1385",
                    confirmed=False,
                    location=f"WebSocket endpoint at {parsed.path or '/'}",
                    request_method="GET",
                    request_headers=str(no_auth_headers),
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Send a WebSocket upgrade request to {url} without any cookies or tokens.\n"
                        f"2. Observe if the server accepts the upgrade (101) or issues a session.\n"
                        f"3. Run: {curl_cmd}\n"
                        f"4. If accepted, try sending messages to enumerate functionality."
                    ),
                    developer_fix=(
                        f"WebSocket handler for {parsed.path}:\n\n"
                        "Authenticate during the upgrade handshake:\n\n"
                        "  Node.js (ws library):\n"
                        "    wss.on('upgrade', (req, socket, head) => {\n"
                        "      const token = parseToken(req);\n"
                        "      if (!verifyToken(token)) {\n"
                        "        socket.write('HTTP/1.1 401 Unauthorized\\r\\n\\r\\n');\n"
                        "        socket.destroy();\n"
                        "        return;\n"
                        "      }\n"
                        "      wss.handleUpgrade(req, socket, head, (ws) => {\n"
                        "        wss.emit('connection', ws, req);\n"
                        "      });\n"
                        "    });"
                    ),
                    affected_component=f"WebSocket authentication at {parsed.path}",
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets"
                    ),
                    detection_method=(
                        f"Sent a WebSocket upgrade request without authentication credentials "
                        f"and received a successful response (status {resp.status_code}), "
                        f"indicating the endpoint does not require authentication."
                    ),
                ))
    except Exception as e:
        logger.debug("websocket_security _test_ws_no_auth: connection failed: %s", e)


def _report_ws_endpoints(session, endpoints):
    """Report discovered WebSocket endpoints as informational findings."""
    if not endpoints:
        return

    parsed = urlparse(endpoints[0]["url"])
    ep_list = "\n".join(
        f"  - {ep['url']} (type: {ep['type']}, status: {ep['status']})"
        for ep in endpoints
    )

    session.add_finding(Finding(
        title=f"WebSocket Endpoints Discovered ({len(endpoints)} found)",
        severity=Severity.INFO,
        description=(
            f"Discovered {len(endpoints)} WebSocket endpoint(s) on {parsed.netloc}. "
            f"WebSocket endpoints should be tested for authentication, authorization, "
            f"origin validation, and input validation vulnerabilities."
        ),
        evidence=f"Discovered WebSocket endpoints:\n{ep_list}",
        remediation=(
            "1. Ensure all WebSocket endpoints require authentication.\n"
            "2. Validate the Origin header to prevent CSWSH.\n"
            "3. Implement message-level authorization checks.\n"
            "4. Validate and sanitize all incoming WebSocket messages.\n"
            "5. Implement rate limiting on WebSocket connections and messages."
        ),
        url=endpoints[0]["url"],
        module="websocket",
        cwe="CWE-1385",
        confirmed=True,
        location=f"WebSocket endpoints on {parsed.netloc}",
        request_method="GET",
        detection_method=(
            "Probed common WebSocket paths and analyzed crawled pages for WebSocket "
            "connection patterns (new WebSocket(), io(), SockJS()) to discover endpoints."
        ),
    ))


def run(session: ScanSession) -> None:
    print("\n[*] Testing WebSocket Security...")

    if not session.crawled_urls:
        return

    # Use first crawled URL as base
    base_url = next(iter(session.crawled_urls))
    endpoints = _detect_ws_endpoints(session, base_url)

    if endpoints:
        _report_ws_endpoints(session, endpoints)

        for endpoint in endpoints:
            _test_origin_validation(session, endpoint)
            _test_ws_no_auth(session, endpoint)
