import json
import pytest
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from scanner.core import ScanConfig, ScanSession


class VulnerableHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler with various vulnerable endpoints for testing."""

    def log_message(self, format, *args):
        # Suppress request logging during tests
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query, keep_blank_values=True)

        if path == "/":
            self._send_html(200, self._index_page())
        elif path == "/xss":
            value = params.get("q", [""])[0]
            # Deliberately reflect value unescaped (vulnerable)
            self._send_html(200, f"<html><body><h1>Search Results</h1><p>You searched for: {value}</p></body></html>")
        elif path == "/redirect":
            url = params.get("url", [""])[0]
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()
        elif path == "/api/users":
            self._send_json(200, [
                {"id": 1, "name": "alice", "email": "alice@example.com"},
                {"id": 2, "name": "bob", "email": "bob@example.com"},
            ])
        else:
            self._send_html(404, "<html><body><h1>404 Not Found</h1></body></html>")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""

        if path == "/login":
            self._send_html(200, f"<html><body><h1>Login processed</h1><p>{body}</p></body></html>")
        else:
            self._send_html(404, "<html><body><h1>404 Not Found</h1></body></html>")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET,POST,PUT,DELETE,OPTIONS,TRACE")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _index_page(self):
        return """<html>
<head><title>Test App</title></head>
<body>
<h1>Test Application</h1>
<form action="/login" method="post">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <button type="submit">Login</button>
</form>
<form action="/xss" method="get">
    <input type="text" name="q" />
    <button type="submit">Search</button>
</form>
<a href="/page1">Page 1</a>
<a href="/page2">Page 2</a>
<script src="/static/app.js"></script>
</body>
</html>"""

    def _send_html(self, status, body):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        # Deliberately omit security headers (no CSP, no X-Frame-Options, etc.)
        self.end_headers()
        self.wfile.write(encoded)

    def _send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="session")
def test_server():
    """Start a simple HTTP server on a random port for testing."""
    server = HTTPServer(("127.0.0.1", 0), VulnerableHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture
def scan_session(test_server):
    """Return a ScanSession configured to point at the test server."""
    config = ScanConfig(
        target=test_server,
        threads=1,
        timeout=5,
        depth=2,
        verify_ssl=False,
    )
    session = ScanSession(config)
    return session


@pytest.fixture
def scan_session_with_crawl(scan_session):
    """Return a ScanSession with pre-populated crawled_urls and forms."""
    base = scan_session.config.target
    scan_session.crawled_urls = {
        f"{base}/",
        f"{base}/xss?q=test",
        f"{base}/page1",
        f"{base}/page2",
    }
    scan_session.forms = [
        {
            "action": f"{base}/login",
            "method": "post",
            "source_url": f"{base}/",
            "inputs": [
                {"name": "username", "type": "text", "value": ""},
                {"name": "password", "type": "password", "value": ""},
            ],
        },
        {
            "action": f"{base}/xss",
            "method": "get",
            "source_url": f"{base}/",
            "inputs": [
                {"name": "q", "type": "text", "value": ""},
            ],
        },
    ]
    return scan_session
