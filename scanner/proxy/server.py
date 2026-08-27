"""DAST interception proxy — HTTP/HTTPS MITM proxy with passive traffic analysis."""

import io
import socket
import ssl
import tempfile
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import requests

from scanner.log import logger
from scanner.proxy.ca_manager import CA_DIR
from scanner.proxy.history import HistoryDB, HttpTransaction
from scanner.proxy.passive_analyzer import analyze_transaction, PassiveFinding

# Whether cryptography is available for HTTPS interception
_HAS_CRYPTO = False
try:
    from scanner.proxy.ca_manager import generate_root_ca, generate_domain_cert
    _HAS_CRYPTO = True
except ImportError:
    pass


class _ProxyHandler(BaseHTTPRequestHandler):
    """HTTP(S) proxy request handler.

    Attributes set on the class by ``ProxyServer`` before the server starts:

    * ``proxy_ref`` — back-reference to the owning ``ProxyServer`` instance.
    """

    proxy_ref: "ProxyServer"

    # Timeout for upstream connections (seconds).
    upstream_timeout = 15

    # ------------------------------------------------------------------ #
    # Logging — route through scanner.log instead of stderr               #
    # ------------------------------------------------------------------ #
    def log_message(self, fmt, *args):  # noqa: D401
        logger.debug("Proxy: %s", fmt % args)

    # ------------------------------------------------------------------ #
    # HTTP methods — forward the request and capture the exchange          #
    # ------------------------------------------------------------------ #
    def _forward_request(self):
        """Forward an HTTP proxy request and record the transaction."""
        url = self.path
        parsed = urlparse(url)

        # Build request headers (drop hop-by-hop)
        hop_by_hop = {
            "proxy-connection", "connection", "keep-alive",
            "transfer-encoding", "te", "trailer",
            "proxy-authorization", "proxy-authenticate", "upgrade",
        }
        req_headers = {}
        for key, value in self.headers.items():
            if key.lower() not in hop_by_hop:
                req_headers[key] = value

        # Read body if present
        content_length = int(self.headers.get("Content-Length", 0))
        req_body = self.rfile.read(content_length) if content_length else b""

        start = time.time()
        try:
            resp = requests.request(
                method=self.command,
                url=url,
                headers=req_headers,
                data=req_body,
                allow_redirects=False,
                verify=False,
                timeout=self.upstream_timeout,
                stream=True,
            )
        except Exception as exc:
            logger.debug("Proxy upstream error for %s: %s", url, exc)
            self.send_error(502, f"Bad Gateway: {exc}")
            return

        latency = (time.time() - start) * 1000

        # Read the full response body
        resp_body = resp.content

        # Send response back to client
        try:
            self.send_response_only(resp.status_code)
            for key, value in resp.headers.items():
                if key.lower() not in hop_by_hop and key.lower() != "content-encoding":
                    self.send_header(key, value)
            # Rewrite content-length since we may have decompressed
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except BrokenPipeError:
            logger.debug("Proxy: client disconnected during response for %s", url)
            return

        # Record transaction
        resp_body_text = ""
        try:
            resp_body_text = resp_body.decode("utf-8", errors="replace")[:500_000]
        except Exception:
            pass

        txn = HttpTransaction(
            timestamp=start,
            method=self.command,
            url=url,
            host=parsed.hostname or "",
            path=parsed.path or "/",
            request_headers=req_headers,
            request_body=req_body.decode("utf-8", errors="replace")[:100_000] if req_body else "",
            status_code=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp_body_text,
            content_type=resp.headers.get("Content-Type", ""),
            content_length=len(resp_body),
            latency_ms=latency,
        )
        self.proxy_ref._record(txn)

    # Map all standard HTTP methods to the forwarder
    do_GET = _forward_request
    do_POST = _forward_request
    do_PUT = _forward_request
    do_DELETE = _forward_request
    do_PATCH = _forward_request
    do_HEAD = _forward_request
    do_OPTIONS = _forward_request

    # ------------------------------------------------------------------ #
    # CONNECT — HTTPS tunnelling with optional MITM interception          #
    # ------------------------------------------------------------------ #
    def do_CONNECT(self):
        """Handle CONNECT tunnelling for HTTPS.

        If the cryptography library is available the proxy performs MITM
        interception: it generates a per-domain certificate signed by the
        local CA, terminates TLS on the client side, reads the cleartext
        request, forwards it over a *new* TLS connection to the real
        server, and records + analyses the transaction.

        Without cryptography the proxy simply tunnels bytes opaquely (no
        analysis is performed).
        """
        host, _, port = self.path.partition(":")
        port = int(port) if port else 443

        if _HAS_CRYPTO and self.proxy_ref.ca_key is not None:
            self._connect_mitm(host, port)
        else:
            self._connect_tunnel(host, port)

    # -- Opaque tunnel (no interception) --------------------------------
    def _connect_tunnel(self, host: str, port: int):
        try:
            upstream = socket.create_connection((host, port), timeout=self.upstream_timeout)
        except Exception as exc:
            self.send_error(502, f"Cannot reach {host}:{port}: {exc}")
            return

        self.send_response_only(200, "Connection established")
        self.end_headers()

        client_sock = self.connection

        def _relay(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        t1 = threading.Thread(target=_relay, args=(client_sock, upstream), daemon=True)
        t2 = threading.Thread(target=_relay, args=(upstream, client_sock), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        upstream.close()

    # -- MITM interception -----------------------------------------------
    def _connect_mitm(self, host: str, port: int):
        """MITM interception: generate cert, terminate TLS, forward."""
        proxy = self.proxy_ref

        # Generate per-domain certificate
        try:
            cert_pem, key_pem = generate_domain_cert(
                host, proxy.ca_key, proxy.ca_cert, cache_dir=proxy.cert_cache_dir,
            )
        except Exception as exc:
            logger.warning("Proxy: failed to generate cert for %s: %s", host, exc)
            self._connect_tunnel(host, port)
            return

        # Tell the client the tunnel is established
        self.send_response_only(200, "Connection established")
        self.end_headers()

        # Write cert/key to temp files for ssl.wrap_socket
        cert_file = tempfile.NamedTemporaryFile(suffix=".crt", delete=False)
        key_file = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
        try:
            cert_file.write(cert_pem)
            cert_file.flush()
            key_file.write(key_pem)
            key_file.flush()
            cert_file.close()
            key_file.close()

            # Wrap the client connection with our generated cert
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
            try:
                client_ssl = ctx.wrap_socket(self.connection, server_side=True)
            except ssl.SSLError as exc:
                logger.debug("Proxy: client TLS handshake failed for %s: %s", host, exc)
                return

            # Read the plaintext HTTP request from the client
            try:
                req_data = self._read_http_request(client_ssl)
            except Exception as exc:
                logger.debug("Proxy: failed to read MITM request for %s: %s", host, exc)
                client_ssl.close()
                return

            if not req_data:
                client_ssl.close()
                return

            method, path, req_headers, req_body = req_data
            scheme = "https"
            url = f"{scheme}://{host}{path}"

            # Forward to the real server
            start = time.time()
            try:
                resp = requests.request(
                    method=method,
                    url=url,
                    headers=req_headers,
                    data=req_body,
                    allow_redirects=False,
                    verify=False,
                    timeout=self.upstream_timeout,
                    stream=True,
                )
            except Exception as exc:
                logger.debug("Proxy MITM upstream error for %s: %s", url, exc)
                try:
                    error_resp = (
                        b"HTTP/1.1 502 Bad Gateway\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    client_ssl.sendall(error_resp)
                except Exception:
                    pass
                client_ssl.close()
                return

            latency = (time.time() - start) * 1000
            resp_body = resp.content

            # Build raw HTTP response and send to client
            hop_by_hop = {
                "transfer-encoding", "connection", "keep-alive",
            }
            try:
                resp_line = f"HTTP/1.1 {resp.status_code} {resp.reason or ''}\r\n"
                header_lines = ""
                for k, v in resp.headers.items():
                    if k.lower() not in hop_by_hop and k.lower() != "content-encoding":
                        header_lines += f"{k}: {v}\r\n"
                header_lines += f"Content-Length: {len(resp_body)}\r\n"
                raw = resp_line.encode() + header_lines.encode() + b"\r\n" + resp_body
                client_ssl.sendall(raw)
            except Exception:
                pass

            client_ssl.close()

            # Record and analyse
            resp_body_text = ""
            try:
                resp_body_text = resp_body.decode("utf-8", errors="replace")[:500_000]
            except Exception:
                pass

            txn = HttpTransaction(
                timestamp=start,
                method=method,
                url=url,
                host=host,
                path=path,
                request_headers=req_headers,
                request_body=req_body.decode("utf-8", errors="replace")[:100_000] if req_body else "",
                status_code=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=resp_body_text,
                content_type=resp.headers.get("Content-Type", ""),
                content_length=len(resp_body),
                latency_ms=latency,
            )
            proxy._record(txn)
        finally:
            import os as _os
            try:
                _os.unlink(cert_file.name)
            except OSError:
                pass
            try:
                _os.unlink(key_file.name)
            except OSError:
                pass

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _read_http_request(sock):
        """Read one HTTP request from an SSL-wrapped socket.

        Returns ``(method, path, headers_dict, body_bytes)`` or *None*.
        """
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                return None
            buf += chunk
            if len(buf) > 1_048_576:  # 1 MB header limit
                return None

        header_end = buf.index(b"\r\n\r\n")
        header_part = buf[:header_end].decode("utf-8", errors="replace")
        body_start = buf[header_end + 4:]

        lines = header_part.split("\r\n")
        if not lines:
            return None

        request_line = lines[0].split(" ", 2)
        if len(request_line) < 2:
            return None

        method = request_line[0]
        path = request_line[1]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        # Read remaining body if Content-Length present
        content_length = int(headers.get("Content-Length", 0))
        body = body_start
        while len(body) < content_length:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk

        return method, path, headers, body[:content_length] if content_length else b""


class ProxyServer:
    """Threaded HTTP/HTTPS interception proxy with passive analysis.

    Usage::

        proxy = ProxyServer(port=8087)
        proxy.start()          # runs in a background thread
        # ... proxy traffic ...
        findings = proxy.get_findings()
        proxy.stop()
    """

    def __init__(self, port: int = 8087, ca_dir=None):
        self.port = port
        self.history = HistoryDB()
        self.findings: list[PassiveFinding] = []
        self._lock = threading.Lock()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

        # CA setup — paths stored so the CLI can point users at them
        self.ca_key: str | None = None
        self.ca_cert: str | None = None
        self.cert_cache_dir = CA_DIR / "certs"

        if _HAS_CRYPTO:
            try:
                self.ca_key, self.ca_cert = generate_root_ca(ca_dir)
                self.cert_cache_dir.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                logger.warning("Proxy: CA generation failed — HTTPS interception disabled: %s", exc)
                self.ca_key = self.ca_cert = None
        else:
            logger.warning(
                "Proxy: 'cryptography' package not installed — "
                "HTTPS traffic will be tunnelled without interception. "
                "Install with: pip install cryptography"
            )

    # ------------------------------------------------------------------ #
    # Lifecycle                                                            #
    # ------------------------------------------------------------------ #
    def start(self):
        """Start the proxy in a background daemon thread."""
        handler = _ProxyHandler
        handler.proxy_ref = self

        self._server = HTTPServer(("0.0.0.0", self.port), handler)
        self._server.timeout = 1  # allow periodic shutdown checks

        self._thread = threading.Thread(target=self._serve, daemon=True, name="dast-proxy")
        self._thread.start()
        logger.info("DAST Proxy listening on 0.0.0.0:%d", self.port)

    def _serve(self):
        """Serve until shutdown is requested."""
        while self._server:
            try:
                self._server.handle_request()
            except Exception:
                break

    def stop(self):
        """Gracefully shut down the proxy server."""
        if self._server:
            logger.info("DAST Proxy shutting down...")
            server = self._server
            self._server = None  # signals _serve loop to exit
            try:
                server.server_close()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
            self._thread = None
        # Close the history database
        self.history.close()

    # ------------------------------------------------------------------ #
    # Recording and analysis                                               #
    # ------------------------------------------------------------------ #
    def _record(self, txn: HttpTransaction):
        """Record a transaction and run passive analysis."""
        try:
            self.history.log_transaction(txn)
        except Exception as exc:
            logger.debug("Proxy: failed to log transaction: %s", exc)

        try:
            new_findings = analyze_transaction(txn)
            if new_findings:
                with self._lock:
                    self.findings.extend(new_findings)
                logger.debug(
                    "Proxy: %d passive finding(s) for %s %s",
                    len(new_findings), txn.method, txn.url,
                )
        except Exception as exc:
            logger.debug("Proxy: passive analysis error: %s", exc)

    def get_findings(self) -> list[PassiveFinding]:
        """Return a copy of all passive findings collected so far."""
        with self._lock:
            return list(self.findings)
