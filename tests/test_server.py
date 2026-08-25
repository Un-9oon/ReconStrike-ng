#!/usr/bin/env python3
"""Deliberately vulnerable test server for ReconStrike accuracy testing."""
import http.server
import json
import urllib.parse
import time

PORT = 9777

PAGES = {
    "/": """<html><head><title>Test App</title></head><body>
        <h1>Test Application</h1>
        <a href="/login">Login</a>
        <a href="/search?q=test">Search</a>
        <a href="/api/v1/users">API</a>
        <a href="/admin">Admin</a>
        <form action="/search" method="get"><input name="q"><button>Search</button></form>
        <!-- TODO: remove debug endpoint before prod -->
        </body></html>""",

    "/login": """<html><head><title>Login</title></head><body>
        <form action="/login" method="post">
        <input type="hidden" name="csrf_token" value="abc123">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
        </form></body></html>""",

    "/admin": """<html><head><title>Admin Panel</title></head><body>
        <h1>Admin Dashboard</h1>
        <form action="/admin/login" method="post">
        <input name="username"><input type="password" name="password">
        <button>Sign In</button></form>
        </body></html>""",

    "/robots.txt": """User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Disallow: /backup/
Disallow: /config/""",

    "/.env": """DB_HOST=localhost
DB_PASSWORD=supersecret123
SECRET_KEY=abcdef1234567890
API_KEY=sk-test-1234567890
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE""",

    "/api/v1/users": json.dumps([
        {"id": 1, "username": "admin", "email": "admin@test.com"},
        {"id": 2, "username": "user1", "email": "user1@test.com"},
    ]),

    "/api/v1/health": json.dumps({"status": "ok", "version": "1.0.0"}),

    "/.git/HEAD": "ref: refs/heads/main\n",
    "/.git/config": """[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = https://github.com/test/test.git
[branch "main"]
    remote = origin""",

    "/swagger.json": json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0"},
        "paths": {"/api/v1/users": {"get": {"summary": "List users"}}},
    }),
}


class TestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/search":
            q = query.get("q", [""])[0]
            body = f"""<html><head><title>Search Results</title></head><body>
                <h1>Search results for: {q}</h1>
                <p>No results found for "{q}"</p>
                <form action="/search" method="get"><input name="q" value="{q}"><button>Search</button></form>
                </body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.52")
            self.end_headers()
            self.wfile.write(body.encode())
            return

        if path in PAGES:
            self.send_response(200)
            content = PAGES[path]
            if path.startswith("/api/") or path == "/swagger.json":
                self.send_header("Content-Type", "application/json")
            elif path in ("/.env", "/.git/HEAD", "/.git/config", "/robots.txt"):
                self.send_header("Content-Type", "text/plain")
            else:
                self.send_header("Content-Type", "text/html")

            self.send_header("Server", "Apache/2.4.52")
            self.send_header("X-Powered-By", "PHP/8.1")
            self.end_headers()
            self.wfile.write(content.encode())
            return

        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""

        if self.path == "/login":
            params = urllib.parse.parse_qs(body)
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            if username == "admin" and password == "admin":
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie", "session=abc123def456ghi789; Path=/")
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<html><body>
                <form action="/login" method="post">
                <input name="username"><input type="password" name="password">
                <p style="color:red">Invalid credentials</p>
                <button>Login</button></form></body></html>""")
            return

        self.send_response(404)
        self.end_headers()

    def do_PUT(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_DELETE(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"deleted":true}')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
        self.end_headers()


if __name__ == "__main__":
    server = http.server.HTTPServer(("127.0.0.1", PORT), TestHandler)
    print(f"Test server running on http://127.0.0.1:{PORT}")
    server.serve_forever()
