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
    all_headers = dict(WS_UPGRADE_HEADERS)
    if extra_headers:
        all_headers.update(extra_headers)
    cmd = "curl -k -i '{}'".format(url)
    for k, v in all_headers.items():
        cmd += " -H '{}: {}'".format(k, v)
    return cmd


def _detect_ws_endpoints(session, base_url):
    parsed = urlparse(base_url)
    base = "{}://{}".format(parsed.scheme, parsed.netloc)
    endpoints = []

    for path in COMMON_WS_PATHS:
        url = urljoin(base, path)
        try:
            resp = session.get(url, headers=WS_UPGRADE_HEADERS)
            if not resp:
                continue

            if resp.status_code == 101:
                endpoints.append({"url": url, "status": 101, "type": "upgrade_accepted"})
                continue

            if "socket.io" in path and resp.status_code == 200:
                if "sid" in resp.text or "websocket" in resp.text.lower():
                    endpoints.append({"url": url, "status": 200, "type": "socketio_polling"})
                    continue

            if "signalr" in path and resp.status_code == 200:
                if "connectionId" in resp.text or "negotiateVersion" in resp.text:
                    endpoints.append({"url": url, "status": 200, "type": "signalr"})
                    continue

            if "sockjs" in path and resp.status_code == 200:
                if "websocket" in resp.text.lower():
                    endpoints.append({"url": url, "status": 200, "type": "sockjs"})
                    continue

            if resp.status_code == 400:
                body_lower = resp.text.lower()
                if any(kw in body_lower for kw in ("websocket", "upgrade", "sec-websocket")):
                    endpoints.append({"url": url, "status": 400, "type": "ws_aware"})

        except (OSError, ValueError) as e:
            logger.debug("websocket_security _detect_ws_endpoints: operation failed: %s", e)
            continue

    # check crawled URLs for WS indicators
    for url in session.crawled_urls:
        try:
            resp = session.get(url)
            if not resp:
                continue
            ws_patterns = [
                r'new\s+WebSocket\s*\(\s*["\']([^"\']+)',
                r'io\(\s*["\']([^"\']+)',
                r'io\.connect\s*\(\s*["\']([^"\']+)',
                r'SockJS\s*\(\s*["\']([^"\']+)',
            ]
            for pattern in ws_patterns:
                for match in re.findall(pattern, resp.text):
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
        except (OSError, ValueError) as e:
            logger.debug("websocket_security _detect_ws_endpoints: operation failed: %s", e)
            continue

    seen = set()
    unique = []
    for ep in endpoints:
        if ep["url"] not in seen:
            seen.add(ep["url"])
            unique.append(ep)
    return unique


def _test_origin_validation(session, endpoint):
    url = endpoint["url"]
    parsed = urlparse(url)
    legitimate_origin = "{}://{}".format(parsed.scheme, parsed.netloc)

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

            origin_accepted = False

            if resp.status_code == 101:
                origin_accepted = True
            elif resp.status_code == legit_resp.status_code:
                legit_acao = legit_resp.headers.get("Access-Control-Allow-Origin", "")
                evil_acao = resp.headers.get("Access-Control-Allow-Origin", "")

                if evil_acao == "*" or evil_acao == evil_origin:
                    origin_accepted = True
                elif resp.status_code == 200 and legit_resp.status_code == 200:
                    if abs(len(resp.text) - len(legit_resp.text)) < 50:
                        origin_accepted = True

            if origin_accepted:
                curl_cmd = _build_curl_ws(url, {"Origin": evil_origin})
                session.add_finding(Finding(
                    title="Cross-Site WebSocket Hijacking (Missing Origin Validation)",
                    severity=Severity.HIGH,
                    description=(
                        "The WebSocket endpoint at '{}' does not validate the Origin header. "
                        "When a request is sent with Origin '{}', the server responds "
                        "identically to a legitimate origin request. This enables Cross-Site "
                        "WebSocket Hijacking (CSWSH), where a malicious webpage can establish a "
                        "WebSocket connection to this endpoint using the victim's cookies."
                    ).format(url, evil_origin),
                    evidence=(
                        "WebSocket Endpoint: {}\n"
                        "Endpoint Type: {}\n"
                        "Legitimate Origin: {}\n"
                        "Evil Origin: {}\n"
                        "Legitimate Origin Status: {}\n"
                        "Evil Origin Status: {}\n"
                        "ACAO Header (evil): {}"
                    ).format(url, endpoint['type'], legitimate_origin, evil_origin,
                             legit_resp.status_code, resp.status_code,
                             resp.headers.get('Access-Control-Allow-Origin', 'none')),
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
                    location="WebSocket endpoint at {}".format(parsed.path or '/'),
                    parameter="Origin",
                    payload=evil_origin,
                    request_method="GET",
                    request_headers=str(evil_headers),
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        "1. Open a browser console on https://evil.com (or any cross-origin page).\n"
                        "2. Run: var ws = new WebSocket('{}');\n"
                        "3. If the connection opens, the endpoint lacks origin validation.\n"
                        "4. Alternatively, run: {}\n"
                        "5. Compare response with the same request using Origin: {}"
                    ).format(url.replace('http', 'ws'), curl_cmd, legitimate_origin),
                    developer_fix=(
                        "Server-side WebSocket handler for {}:\n\n"
                        "Check the Origin header before accepting the upgrade:\n\n"
                        "  Node.js (ws library):\n"
                        "    wss.on('connection', (ws, req) => {{\n"
                        "      const origin = req.headers.origin;\n"
                        "      if (origin !== '{}') {{\n"
                        "        ws.close(1008, 'Invalid origin');\n"
                        "        return;\n"
                        "      }}\n"
                        "    }});\n\n"
                        "  Python (Django Channels):\n"
                        "    ALLOWED_HOSTS = ['yourdomain.com']\n"
                        "    # Django Channels checks Origin automatically with ALLOWED_HOSTS"
                    ).format(parsed.path, legitimate_origin),
                    affected_component="WebSocket origin validation at {}".format(parsed.path),
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets | "
                        "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking"
                    ),
                    detection_method=(
                        "Sent WebSocket upgrade requests with both a legitimate origin "
                        "({}) and a malicious origin ({}). "
                        "Both received identical responses, indicating no origin validation."
                    ).format(legitimate_origin, evil_origin),
                ))
                return

        except (OSError, ValueError) as e:
            logger.debug("websocket_security _test_origin_validation: operation failed: %s", e)
            continue


def _test_ws_no_auth(session, endpoint):
    url = endpoint["url"]
    parsed = urlparse(url)

    try:
        no_auth_headers = dict(WS_UPGRADE_HEADERS)
        resp = session.get(url, headers=no_auth_headers)
        if not resp:
            return

        if resp.status_code in (101, 200):
            is_upgrade = resp.status_code == 101
            has_ws_accept = "Sec-WebSocket-Accept" in resp.headers
            is_session = "sid" in resp.text if resp.text else False

            if is_upgrade or has_ws_accept or is_session:
                curl_cmd = _build_curl_ws(url)
                session.add_finding(Finding(
                    title="WebSocket Endpoint Accessible Without Authentication",
                    severity=Severity.MEDIUM,
                    description=(
                        "The WebSocket endpoint at '{}' accepts connections without requiring "
                        "authentication. An unauthenticated attacker can establish a WebSocket "
                        "connection and potentially access real-time data, send commands, or "
                        "interact with backend services."
                    ).format(url),
                    evidence=(
                        "WebSocket Endpoint: {}\n"
                        "Endpoint Type: {}\n"
                        "Response Status: {}\n"
                        "Upgrade Accepted: {}\n"
                        "WS Accept Header: {}\n"
                        "Session Issued: {}\n"
                        "Response Headers: {}"
                    ).format(url, endpoint['type'], resp.status_code,
                             is_upgrade, has_ws_accept, is_session, dict(resp.headers)),
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
                    location="WebSocket endpoint at {}".format(parsed.path or '/'),
                    request_method="GET",
                    request_headers=str(no_auth_headers),
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        "1. Send a WebSocket upgrade request to {} without any cookies or tokens.\n"
                        "2. Observe if the server accepts the upgrade (101) or issues a session.\n"
                        "3. Run: {}\n"
                        "4. If accepted, try sending messages to enumerate functionality."
                    ).format(url, curl_cmd),
                    developer_fix=(
                        "WebSocket handler for {}:\n\n"
                        "Authenticate during the upgrade handshake:\n\n"
                        "  Node.js (ws library):\n"
                        "    wss.on('upgrade', (req, socket, head) => {{\n"
                        "      const token = parseToken(req);\n"
                        "      if (!verifyToken(token)) {{\n"
                        "        socket.write('HTTP/1.1 401 Unauthorized\\r\\n\\r\\n');\n"
                        "        socket.destroy();\n"
                        "        return;\n"
                        "      }}\n"
                        "      wss.handleUpgrade(req, socket, head, (ws) => {{\n"
                        "        wss.emit('connection', ws, req);\n"
                        "      }});\n"
                        "    }});"
                    ).format(parsed.path),
                    affected_component="WebSocket authentication at {}".format(parsed.path),
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets"
                    ),
                    detection_method=(
                        "Sent a WebSocket upgrade request without authentication credentials "
                        "and received a successful response (status {}), "
                        "indicating the endpoint does not require authentication."
                    ).format(resp.status_code),
                ))
    except (OSError, ValueError) as e:
        logger.debug("websocket_security _test_ws_no_auth: connection failed: %s", e)


def _report_ws_endpoints(session, endpoints):
    if not endpoints:
        return

    parsed = urlparse(endpoints[0]["url"])
    ep_list = "\n".join(
        "  - {} (type: {}, status: {})".format(ep['url'], ep['type'], ep['status'])
        for ep in endpoints
    )

    session.add_finding(Finding(
        title="WebSocket Endpoints Discovered ({} found)".format(len(endpoints)),
        severity=Severity.INFO,
        description=(
            "Discovered {} WebSocket endpoint(s) on {}. "
            "WebSocket endpoints should be tested for authentication, authorization, "
            "origin validation, and input validation vulnerabilities."
        ).format(len(endpoints), parsed.netloc),
        evidence="Discovered WebSocket endpoints:\n{}".format(ep_list),
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
        location="WebSocket endpoints on {}".format(parsed.netloc),
        request_method="GET",
        detection_method=(
            "Probed common WebSocket paths and analyzed crawled pages for WebSocket "
            "connection patterns (new WebSocket(), io(), SockJS()) to discover endpoints."
        ),
    ))


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing WebSocket Security...")

    if not session.crawled_urls:
        return

    base_url = next(iter(session.crawled_urls))
    endpoints = _detect_ws_endpoints(session, base_url)

    if endpoints:
        _report_ws_endpoints(session, endpoints)

        for endpoint in endpoints:
            _test_origin_validation(session, endpoint)
            _test_ws_no_auth(session, endpoint)
