#!/usr/bin/env python3
"""
Deliberately-vulnerable test fixture for ReconStrike-ng integration tests.
Runs on port 15789 (configurable via argv[1]).

Confirmed vulnerabilities:
  - Reflected XSS: /xss?q=<payload>
  - SQL-injection echo: /sqli?id=<payload>
  - IDOR: /user?id=<int> returns different PII per ID
  - Open redirect: /redirect?url=<url>
  - Weak CORS: /api/data returns Access-Control-Allow-Origin: *
  - Unlinked admin panel: /admin (not linked from index HTML)
  - Exposed .env path: /.env (returns fake secrets)
  - SSRF-shaped param: /fetch?url=<url>
"""

import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT = 15789


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # suppress noisy access logs

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query, keep_blank_values=True)

        if path == "/":
            self._html(200, """<html><head><title>VulnApp</title></head>
<body>
<h1>Vulnerable Test Application</h1>
<form action="/xss" method="get">
  <input name="q" type="text"><button type="submit">Search</button>
</form>
<form action="/sqli" method="get">
  <input name="id" type="text"><button type="submit">Lookup</button>
</form>
<a href="/page1">Page 1</a>
<a href="/redirect?url=http://example.com">Click here</a>
</body></html>""")

        elif path == "/xss":
            val = params.get("q", [""])[0]
            self._html(200, f"<html><body><h1>Results</h1><p>Query: {val}</p></body></html>")

        elif path == "/sqli":
            val = params.get("id", ["1"])[0]
            self._html(200, f"<html><body><p>ID: {val} -- near syntax error in query</p></body></html>")

        elif path == "/user":
            uid = params.get("id", ["0"])[0]
            users = {
                "1": {"id": 1, "name": "alice", "email": "alice@example.com",
                      "phone": "555-867-5309", "balance": "income: $1234"},
                "2": {"id": 2, "name": "bob", "email": "bob@corp.example.com",
                      "phone": "555-999-0000", "balance": "income: $9999",
                      "ssn": "123-45-6789"},
            }
            if uid in users:
                self._json(200, users[uid])
            else:
                self._json(404, {"error": "not found"})

        elif path == "/api/data":
            self._json(200, {"secret": "value"}, extra_headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            })

        elif path == "/api/users":
            self._json(200, [
                {"id": 1, "name": "alice"},
                {"id": 2, "name": "bob"},
            ])

        elif path == "/redirect":
            url = params.get("url", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()

        elif path == "/admin":
            self._html(200, "<html><body><h1>Admin Panel</h1><p>Not linked from index!</p></body></html>")

        elif path == "/.env":
            self._text(200, "SECRET_KEY=supersecretvalue\nDB_PASSWORD=admin123\n")

        elif path == "/fetch":
            url = params.get("url", [""])[0]
            self._html(200, f"<html><body><p>Fetching: {url}</p></body></html>")

        elif path == "/page1":
            self._html(200, "<html><body><h1>Page 1</h1></body></html>")

        else:
            self._html(404, "<html><body><h1>404</h1></body></html>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        if self.path == "/login":
            self._html(200, f"<html><body><p>Login: {body}</p><a href=\'/logout\'>logout</a></body></html>")
        else:
            self._html(404, "<html><body><h1>404</h1></body></html>")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET,POST,OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _html(self, status, body, extra_headers=None):
        enc = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(enc)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(enc)

    def _json(self, status, data, extra_headers=None):
        enc = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(enc)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(enc)

    def _text(self, status, body):
        enc = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    server = HTTPServer(("127.0.0.1", port), VulnHandler)
    print(f"VulnApp listening on http://127.0.0.1:{port}", flush=True)
    server.serve_forever()
