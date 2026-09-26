#!/usr/bin/env python3
"""
Deliberately-vulnerable test fixture for ReconStrike-ng integration tests.
Runs on port 15789 (configurable via argv[1]).

This fixture is INTENTIONALLY INSECURE. It exists solely for testing the
ReconStrike-ng scanner against a controlled, local target to validate module
detection logic.

DO NOT deploy this outside a sandboxed test environment.

Confirmed vulnerabilities by module category
============================================
Injection:
  - Reflected XSS:          GET /xss?q=<payload>
  - SQL Injection (echo):   GET /sqli?id=<payload>
  - SSTI (Jinja-style):     GET /ssti?name=<payload>
  - OS Command Injection:   GET /cmdi?cmd=<payload>
  - NoSQL Injection echo:   GET /nosql?filter=<payload>
  - LDAP Injection echo:    GET /ldap?username=<payload>
  - XXE-shaped body:        POST /xxe (accepts XML)
  - Second-Order store:     POST /so/store → GET /so/view
  - LFI path echo:          GET /lfi?file=<payload>

Auth/Access Control:
  - Weak CORS:              GET /api/data (ACAO: *)
  - IDOR: different PII:    GET /user?id=<int>
  - Weak JWT:               GET /api/jwt-demo (none alg)
  - CSRF no-token form:     GET /csrf-form
  - Mass assignment echo:   POST /api/user (all fields)
  - OAuth missing state:    GET /oauth/callback (no state)
  - Open Redirect:          GET /redirect?url=<url>
  - Prototype pollution:    GET /proto?__proto__[x]=y

Server-Side:
  - SSRF-shaped param:      GET /fetch?url=<url>
  - File upload no-check:   POST /upload
  - Deserialization echo:   POST /deserialize
  - Cache-poison header:    GET /cached (X-Forwarded-Host reflected)
  - Host-header reflect:    GET /host-reflect
  - HTTP methods enabled:   TRACE / (mirrors input)
  - Race condition:          POST /race/increment (shared counter)
  - Request smuggling hint: GET /backend (chunked header inspect)
  - WebSocket echo:         WS /ws (upgrade reflected in error)

Discovery:
  - Unlinked admin panel:   GET /admin
  - Exposed .env:           GET /.env
  - GraphQL introspection:  POST /graphql
  - Info disclosure:        GET /server-info
  - Business logic:         GET /api/discount?pct=<float>

Safe endpoints (negatives for false-positive control):
  - GET /safe/xss?q=<payload>   (HTML-encodes output)
  - GET /safe/sqli?id=<int>     (parameterized-safe echo)
  - GET /safe/redirect?url=<url>(relative-only redirect)
"""

import base64
import hashlib
import json
import re
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import html as html_module

PORT = 15789

# Shared mutable state for race condition testing
_counter = 0
_counter_lock = threading.Lock()

# Second-order injection store
_so_store = {}

# JWT-like helper (deliberately weak: accepts 'none' alg)
def _make_weak_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}."  # empty signature = none alg


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # suppress noisy access logs

    # ── helpers ──────────────────────────────────────────────────────────────

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

    def _text(self, status, body, extra_headers=None):
        enc = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(enc)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(enc)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

    # ── routing ──────────────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query, keep_blank_values=True)

        # ── Root index ──
        if path == "/":
            self._html(200, """<html><head><title>VulnApp</title></head><body>
<h1>Vulnerable Test Application</h1>
<form action="/xss" method="get"><input name="q"><button>Search</button></form>
<form action="/sqli" method="get"><input name="id"><button>Lookup</button></form>
<a href="/page1">Page 1</a>
<a href="/redirect?url=http://example.com">Click here</a>
</body></html>""")

        # ══ INJECTION ══════════════════════════════════════════════════════

        # XSS — vulnerable: raw reflection
        elif path == "/xss":
            val = params.get("q", [""])[0]
            self._html(200, f"<html><body><h1>Results</h1><p>Query: {val}</p></body></html>")

        # XSS — safe: HTML-encoded (negative / false-positive control)
        elif path == "/safe/xss":
            val = html_module.escape(params.get("q", [""])[0])
            self._html(200, f"<html><body><p>Safe: {val}</p></body></html>")

        # SQLi — vulnerable: raw echo + SQL error keyword only when metachar injected
        elif path == "/sqli":
            val = params.get("id", ["1"])[0]
            import re as _re
            _has_metachar = _re.search(r"['\"\-;]", val)
            if _has_metachar:
                body = ('<html><body><p>ID: ' + val +
                        ' -- MySQLSyntaxErrorException: syntax error</p></body></html>')
            else:
                body = '<html><body><p>ID: ' + val + '</p></body></html>'
            self._html(200, body)

        # SQLi — safe: integer-cast echo (negative)
        elif path == "/safe/sqli":
            try:
                val = int(params.get("id", ["1"])[0])
            except ValueError:
                val = 1
            self._html(200, f"<html><body><p>ID: {val}</p></body></html>")

        # SSTI — raw reflection of Jinja-like expression
        elif path == "/ssti":
            val = params.get("name", ["World"])[0]
            # Simulate template evaluation indicator in response
            self._html(200, f"<html><body><p>Hello, {val}! Template engine: Jinja2 v3.1</p></body></html>")

        # OS Command Injection — echoes cmd in output (simulation, doesn't exec)
        elif path == "/cmdi":
            val = params.get("cmd", [""])[0]
            self._html(200,
                f"<html><body><pre>$ {val}\n{val}: output line 1\n</pre></body></html>")

        # NoSQL Injection — raw filter echo
        elif path == "/nosql":
            val = params.get("filter", ["{}"])[0]
            self._json(200, {"query": val, "results": [{"id": 1, "user": "alice"}]})

        # LDAP Injection — raw username echo with LDAP-filter-shaped response
        elif path == "/ldap":
            val = params.get("username", [""])[0]
            self._html(200,
                f"<html><body><p>LDAP search: (&(uid={val})(objectClass=user))</p></body></html>")

        # LFI — path echo in response
        elif path == "/lfi":
            val = params.get("file", ["index.html"])[0]
            self._html(200,
                f"<html><body><p>Loading file: {val}</p>"
                f"<pre>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1</pre>"
                f"</body></html>")

        # Second-Order Injection — view endpoint
        elif path == "/so/view":
            key = params.get("key", [""])[0]
            stored = _so_store.get(key, "(nothing stored)")
            self._html(200, f"<html><body><p>Stored value: {stored}</p></body></html>")

        # ══ AUTH / ACCESS CONTROL ══════════════════════════════════════════

        # IDOR — different PII per id, no auth check
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

        # Weak CORS — ACAO: * + ACAC: true
        elif path == "/api/data":
            self._json(200, {"secret": "value"}, extra_headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            })

        elif path == "/api/users":
            self._json(200, [{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}])

        # JWT demo — returns a 'none' alg token
        elif path == "/api/jwt-demo":
            token = _make_weak_jwt({"sub": "1", "role": "user", "exp": int(time.time()) + 3600})
            self._json(200, {"token": token, "note": "signed with alg:none"})

        # CSRF — form with no CSRF token
        elif path == "/csrf-form":
            self._html(200, """<html><body>
<form action="/api/transfer" method="POST">
  <input name="to" value="attacker">
  <input name="amount" value="1000">
  <button>Transfer</button>
</form></body></html>""")

        # OAuth missing state
        elif path == "/oauth/callback":
            code = params.get("code", [""])[0]
            # No state validation
            self._json(200, {"code_received": code, "state": None, "warning": "no state validation"})

        # Open Redirect — unvalidated
        elif path == "/redirect":
            url = params.get("url", ["/"])[0]
            self._redirect(url)

        # Open Redirect — safe: relative-only (negative)
        elif path == "/safe/redirect":
            url = params.get("url", ["/"])[0]
            if url.startswith("/") and not url.startswith("//"):
                self._redirect(url)
            else:
                self._html(400, "<html><body><p>Invalid redirect target</p></body></html>")

        # Prototype Pollution — echoes query params including __proto__
        elif path == "/proto":
            self._json(200, {"received": dict(params)})

        # ══ SERVER-SIDE ════════════════════════════════════════════════════

        # SSRF — echoes fetch target URL
        elif path == "/fetch":
            url = params.get("url", [""])[0]
            self._html(200, f"<html><body><p>Fetching: {url}</p></body></html>")

        # Cache poisoning — reflects X-Forwarded-Host header
        elif path == "/cached":
            fwd_host = self.headers.get("X-Forwarded-Host", self.headers.get("Host", ""))
            self._html(200,
                f"<html><body><p>Served from: {fwd_host}</p>"
                f"<link rel='canonical' href='https://{fwd_host}/cached'/>"
                f"</body></html>",
                extra_headers={"Cache-Control": "public, max-age=3600"})

        # Host header injection — reflects Host header raw
        elif path == "/host-reflect":
            host = self.headers.get("Host", "")
            self._html(200,
                f"<html><head><base href='http://{host}/'></head>"
                f"<body><p>Host: {host}</p></body></html>")

        # Business logic — allows absurd discounts
        elif path == "/api/discount":
            try:
                pct = float(params.get("pct", ["10"])[0])
            except ValueError:
                pct = 10.0
            # No upper bound check — allows 200%, negative discounts, etc.
            price = 100.0
            discounted = price - (price * pct / 100)
            self._json(200, {"original": price, "discount_pct": pct, "final": discounted})

        # Server info disclosure
        elif path == "/server-info":
            self._json(200, {
                "server": "Apache/2.4.41 (Ubuntu)",
                "php_version": "7.4.3",
                "db": "MySQL 5.7.32",
                "env": "production",
                "debug": True,
                "internal_ip": "10.0.0.5",
            })

        # WebSocket upgrade hint (returns 400 with upgrade headers for detection)
        elif path == "/ws":
            self._html(400,
                "<html><body><p>WebSocket endpoint — use ws:// protocol</p></body></html>",
                extra_headers={"Upgrade": "websocket", "Connection": "Upgrade"})

        # Request smuggling hint (TE header echo)
        elif path == "/backend":
            te = self.headers.get("Transfer-Encoding", "")
            self._html(200, f"<html><body><p>Backend proxy. TE: {te}</p></body></html>",
                extra_headers={"X-Backend-Server": "internal-lb-01"})

        # ══ DISCOVERY ═════════════════════════════════════════════════════

        elif path == "/admin":
            self._html(200,
                "<html><body><h1>Admin Panel</h1><p>Not linked from index!</p></body></html>")

        elif path == "/.env":
            self._text(200,
                "SECRET_KEY=supersecretvalue\nDB_PASSWORD=admin123\nAPI_KEY=sk-abc123\n")

        elif path == "/server-status":
            self._html(200,
                "<html><body><h1>Apache Status</h1><p>Total requests: 12345</p></body></html>")

        elif path == "/phpinfo.php":
            self._html(200,
                "<html><body><h1>PHP Version 7.4.3</h1>"
                "<table><tr><td>PHP Version</td><td>7.4.3</td></tr></table></body></html>")

        elif path == "/.git/config":
            self._text(200, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")

        elif path == "/swagger.json" or path == "/api-docs":
            self._json(200, {
                "swagger": "2.0",
                "info": {"title": "VulnApp API", "version": "1.0"},
                "paths": {
                    "/api/users": {"get": {"summary": "List users"}},
                    "/user": {"get": {"summary": "Get user by id"}},
                }
            })

        elif path == "/page1":
            self._html(200, "<html><body><h1>Page 1</h1></body></html>")

        elif path == "/health":
            self._json(200, {"status": "ok", "time": time.time()})

        else:
            self._html(404, "<html><body><h1>404</h1></body></html>")

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()

        # XXE — echoes DOCTYPE/entity names in response (simulation)
        if path == "/xxe":
            if "DOCTYPE" in body or "ENTITY" in body or "SYSTEM" in body:
                self._text(200,
                    f"<?xml version='1.0'?><result>Parsed: {body[:200]}"
                    f"<!-- file contents: root:x:0:0 --></result>")
            else:
                self._text(200, "<?xml version='1.0'?><result>OK</result>")

        # Second-Order Injection — store endpoint
        elif path == "/so/store":
            pairs = {}
            for part in body.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    pairs[k] = v
            key = pairs.get("key", "default")
            val = pairs.get("value", "")
            _so_store[key] = val
            self._json(200, {"stored": True, "key": key})

        # File Upload — no type/content validation
        elif path == "/upload":
            self._json(200, {
                "uploaded": True,
                "filename": "uploaded_file.php",
                "path": "/uploads/uploaded_file.php",
                "warning": "no extension check performed",
            })

        # Deserialization — echoes raw pickle/java header
        elif path == "/deserialize":
            if body.startswith("rO0") or b"\xac\xed" in body.encode("latin-1", "replace"):
                self._text(200, "Java deserialization detected. Object loaded.")
            else:
                self._text(200, f"Deserializing: {body[:50]}")

        # Mass assignment — echoes all submitted fields including role/admin
        elif path == "/api/user":
            try:
                data = json.loads(body) if body.startswith("{") else dict(
                    p.split("=", 1) for p in body.split("&") if "=" in p)
            except Exception:
                data = {}
            # Accepts and reflects any field — including admin/role
            self._json(200, {"user_created": True, "data": data})

        # Race condition — shared counter increment (not atomic)
        elif path == "/race/increment":
            global _counter
            # Deliberately non-atomic read-modify-write
            time.sleep(0.01)
            _counter += 1
            self._json(200, {"counter": _counter})

        # GraphQL — supports introspection
        elif path == "/graphql":
            self._json(200, {
                "data": {
                    "__schema": {
                        "types": [
                            {"name": "Query"}, {"name": "User"}, {"name": "Admin"}
                        ]
                    }
                }
            })

        # API transfer — CSRF target (no token check)
        elif path == "/api/transfer":
            pairs = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
            self._json(200, {"transferred": True, "to": pairs.get("to"), "amount": pairs.get("amount")})

        else:
            self._html(404, "<html><body><h1>404</h1></body></html>")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET,POST,PUT,DELETE,TRACE,OPTIONS")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_TRACE(self):
        # TRACE is deliberately enabled — mirrors the request body
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        raw = f"TRACE {self.path} HTTP/1.1\r\n"
        for k, v in self.headers.items():
            raw += f"{k}: {v}\r\n"
        enc = raw.encode("utf-8")
        self.send_header("Content-Length", str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)

    def do_PUT(self):
        self._html(200, "<html><body><p>PUT accepted</p></body></html>")

    def do_DELETE(self):
        self._html(200, "<html><body><p>DELETE accepted</p></body></html>")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    server = HTTPServer(("127.0.0.1", port), VulnHandler)
    print(f"VulnApp listening on http://127.0.0.1:{port}", flush=True)
    server.serve_forever()
