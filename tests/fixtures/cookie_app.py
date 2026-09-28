#!/usr/bin/env python3
"""
Cookie-bearing test fixture for ReconStrike-ng regression tests.

Serves endpoints that set real Set-Cookie headers so that the
cookie-iteration modules (csrf, fingerprint, headers, session_security,
waf_detect, cve_check) can be tested against a target that actually
sends cookies.

Endpoints
---------
/                  Sets two cookies:
                     session=<32-char value>; HttpOnly; SameSite=Lax
                     tracker=abc123  (no flags — plain, insecure)
/csrf-test         Sets one cookie without SameSite (for csrf module test)
/no-cookies        Plain page, no Set-Cookie headers

DO NOT deploy outside a sandboxed test environment.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer


_SESSION_VALUE = "a" * 32  # 32-char predictable value for entropy tests


class CookieAppHandler(BaseHTTPRequestHandler):
    """HTTP handler that sets real cookies."""

    def log_message(self, format, *args):
        pass  # suppress during tests

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/":
            self._send_with_cookies()
        elif path == "/csrf-test":
            self._send_csrf_test()
        elif path == "/no-cookies":
            self._send_plain()
        else:
            self._send_404()

    def _send_with_cookies(self):
        body = b"<html><body><h1>Cookie App</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # Cookie 1: well-configured session cookie
        self.send_header(
            "Set-Cookie",
            f"session={_SESSION_VALUE}; HttpOnly; SameSite=Lax; Path=/",
        )
        # Cookie 2: plain tracker cookie — no HttpOnly, no SameSite, no Secure
        self.send_header("Set-Cookie", "tracker=abc123; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def _send_csrf_test(self):
        """Sets a cookie without SameSite to trigger the CSRF module check."""
        body = b"<html><body><h1>CSRF Test</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # No SameSite — should cause csrf module to consider it unprotected
        self.send_header("Set-Cookie", f"sessionid={_SESSION_VALUE}; HttpOnly; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def _send_plain(self):
        body = b"<html><body><h1>No Cookies</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_404(self):
        body = b"<html><body><h1>404 Not Found</h1></body></html>"
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def make_cookie_server(host: str = "127.0.0.1", port: int = 0) -> HTTPServer:
    """Create (but don't start) a CookieAppHandler server on a free port."""
    return HTTPServer((host, port), CookieAppHandler)
