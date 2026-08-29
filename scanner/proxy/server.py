"""DAST interception proxy -- HTTP/HTTPS MITM with passive traffic analysis."""

import atexit
import os
import socket
import ssl
import tempfile
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

_pending_cert_files: list[str] = []

def _cleanup_cert_files():
    for f in _pending_cert_files:
        try:
            os.unlink(f)
        except OSError:
            pass
    _pending_cert_files.clear()


atexit.register(_cleanup_cert_files)

import requests

from scanner.log import logger
from scanner.proxy.ca_manager import CA_DIR
from scanner.proxy.history import HistoryDB, HttpTransaction
from scanner.proxy.passive_analyzer import analyze_transaction, PassiveFinding

_HAS_CRYPTO = False
try:
    from scanner.proxy.ca_manager import generate_root_ca, generate_domain_cert
    _HAS_CRYPTO = True
except ImportError:
    pass

HOP_BY_HOP = {"proxy-connection", "connection", "keep-alive", "transfer-encoding",
               "te", "trailer", "proxy-authorization", "proxy-authenticate", "upgrade"}


class _ProxyHandler(BaseHTTPRequestHandler):
    proxy_ref: "ProxyServer"
    upstream_timeout = 15

    def log_message(self, fmt, *args):
        logger.debug("Proxy: %s", fmt % args)

    def _forward_request(self):
        url = self.path
        parsed = urlparse(url)

        req_headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
        content_length = int(self.headers.get("Content-Length", 0))
        req_body = self.rfile.read(content_length) if content_length else b""

        start = time.time()
        try:
            resp = requests.request(
                method=self.command, url=url, headers=req_headers, data=req_body,
                allow_redirects=False, verify=False, timeout=self.upstream_timeout, stream=True)
        except (requests.RequestException, OSError) as exc:
            logger.debug("Proxy upstream error for %s: %s", url, exc)
            self.send_error(502, "Bad Gateway: {}".format(exc))
            return

        latency = (time.time() - start) * 1000
        resp_body = resp.content

        try:
            self.send_response_only(resp.status_code)
            for key, value in resp.headers.items():
                if key.lower() not in HOP_BY_HOP and key.lower() != "content-encoding":
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except BrokenPipeError:
            logger.debug("Proxy: client disconnected during response for %s", url)
            return

        resp_body_text = ""
        try:
            resp_body_text = resp_body.decode("utf-8", errors="replace")[:500_000]
        except (UnicodeDecodeError, ValueError):
            pass

        txn = HttpTransaction(
            timestamp=start, method=self.command, url=url,
            host=parsed.hostname or "", path=parsed.path or "/",
            request_headers=req_headers,
            request_body=req_body.decode("utf-8", errors="replace")[:100_000] if req_body else "",
            status_code=resp.status_code, response_headers=dict(resp.headers),
            response_body=resp_body_text,
            content_type=resp.headers.get("Content-Type", ""),
            content_length=len(resp_body), latency_ms=latency,
        )
        self.proxy_ref._record(txn)

    do_GET = do_POST = do_PUT = do_DELETE = _forward_request
    do_PATCH = do_HEAD = do_OPTIONS = _forward_request

    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        port = int(port) if port else 443

        if _HAS_CRYPTO and self.proxy_ref.ca_key is not None:
            self._connect_mitm(host, port)
        else:
            self._connect_tunnel(host, port)

    def _connect_tunnel(self, host: str, port: int):
        try:
            upstream = socket.create_connection((host, port), timeout=self.upstream_timeout)
        except OSError as exc:
            self.send_error(502, "Cannot reach {}:{}: {}".format(host, port, exc))
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
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t1 = threading.Thread(target=_relay, args=(client_sock, upstream), daemon=True)
        t2 = threading.Thread(target=_relay, args=(upstream, client_sock), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        upstream.close()

    def _connect_mitm(self, host: str, port: int):
        proxy = self.proxy_ref
        try:
            cert_pem, key_pem = generate_domain_cert(
                host, proxy.ca_key, proxy.ca_cert, cache_dir=proxy.cert_cache_dir)
        except (OSError, ValueError) as exc:
            logger.warning("Proxy: failed to generate cert for %s: %s", host, exc)
            self._connect_tunnel(host, port)
            return

        self.send_response_only(200, "Connection established")
        self.end_headers()

        cert_fd, cert_path = tempfile.mkstemp(suffix=".crt")
        key_fd, key_path = tempfile.mkstemp(suffix=".key")
        os.fchmod(cert_fd, 0o600)
        os.fchmod(key_fd, 0o600)
        _pending_cert_files.extend([cert_path, key_path])
        try:
            os.write(cert_fd, cert_pem)
            os.close(cert_fd)
            os.write(key_fd, key_pem)
            os.close(key_fd)

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            try:
                client_ssl = ctx.wrap_socket(self.connection, server_side=True)
            except ssl.SSLError as exc:
                logger.debug("Proxy: client TLS handshake failed for %s: %s", host, exc)
                return

            try:
                req_data = self._read_http_request(client_ssl)
            except (OSError, ValueError) as exc:
                logger.debug("Proxy: failed to read MITM request for %s: %s", host, exc)
                client_ssl.close()
                return

            if not req_data:
                client_ssl.close()
                return

            method, path, req_headers, req_body = req_data
            url = "https://{}{}".format(host, path)

            start = time.time()
            try:
                resp = requests.request(
                    method=method, url=url, headers=req_headers, data=req_body,
                    allow_redirects=False, verify=False, timeout=self.upstream_timeout, stream=True)
            except (requests.RequestException, OSError) as exc:
                logger.debug("Proxy MITM upstream error for %s: %s", url, exc)
                try:
                    client_ssl.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass
                client_ssl.close()
                return

            latency = (time.time() - start) * 1000
            resp_body = resp.content

            mitm_hop = {"transfer-encoding", "connection", "keep-alive"}
            try:
                resp_line = "HTTP/1.1 {} {}\r\n".format(resp.status_code, resp.reason or "")
                header_lines = "".join(
                    "{}: {}\r\n".format(k, v) for k, v in resp.headers.items()
                    if k.lower() not in mitm_hop and k.lower() != "content-encoding")
                header_lines += "Content-Length: {}\r\n".format(len(resp_body))
                client_ssl.sendall(resp_line.encode() + header_lines.encode() + b"\r\n" + resp_body)
            except OSError:
                pass
            client_ssl.close()

            resp_body_text = ""
            try:
                resp_body_text = resp_body.decode("utf-8", errors="replace")[:500_000]
            except (UnicodeDecodeError, ValueError):
                pass

            txn = HttpTransaction(
                timestamp=start, method=method, url=url, host=host, path=path,
                request_headers=req_headers,
                request_body=req_body.decode("utf-8", errors="replace")[:100_000] if req_body else "",
                status_code=resp.status_code, response_headers=dict(resp.headers),
                response_body=resp_body_text,
                content_type=resp.headers.get("Content-Type", ""),
                content_length=len(resp_body), latency_ms=latency,
            )
            proxy._record(txn)
        finally:
            for f in [cert_path, key_path]:
                try:
                    os.unlink(f)
                    _pending_cert_files.remove(f)
                except (OSError, ValueError):
                    pass

    @staticmethod
    def _read_http_request(sock):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                return None
            buf += chunk
            if len(buf) > 1_048_576:
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

        method, path = request_line[0], request_line[1]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        content_length = int(headers.get("Content-Length", 0))
        body = body_start
        while len(body) < content_length:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk

        return method, path, headers, body[:content_length] if content_length else b""


class ProxyServer:
    def __init__(self, port: int = 8087, ca_dir=None, bind_addr: str = "127.0.0.1"):
        self.port = port
        self.bind_addr = bind_addr
        self.history = HistoryDB()
        self.findings: list[PassiveFinding] = []
        self._lock = threading.Lock()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

        self.ca_key: str | None = None
        self.ca_cert: str | None = None
        self.cert_cache_dir = CA_DIR / "certs"

        if _HAS_CRYPTO:
            try:
                self.ca_key, self.ca_cert = generate_root_ca(ca_dir)
                self.cert_cache_dir.mkdir(parents=True, exist_ok=True)
            except (OSError, ValueError) as exc:
                logger.warning("Proxy: CA generation failed -- HTTPS interception disabled: %s", exc)
                self.ca_key = self.ca_cert = None
        else:
            logger.warning(
                "Proxy: 'cryptography' package not installed -- "
                "HTTPS traffic will be tunnelled without interception. "
                "Install with: pip install cryptography")

    def start(self):
        handler = _ProxyHandler
        handler.proxy_ref = self
        self._server = HTTPServer((self.bind_addr, self.port), handler)
        self._server.timeout = 1
        self._thread = threading.Thread(target=self._serve, daemon=True, name="dast-proxy")
        self._thread.start()
        logger.info("DAST Proxy listening on %s:%d", self.bind_addr, self.port)
        if self.bind_addr != "127.0.0.1":
            logger.warning("Proxy bound to %s -- accessible from the network. "
                           "Ensure firewall rules are in place.", self.bind_addr)

    def _serve(self):
        while self._server:
            try:
                self._server.handle_request()
            except OSError:
                break

    def stop(self):
        if self._server:
            logger.info("DAST Proxy shutting down...")
            server = self._server
            self._server = None
            try:
                server.server_close()
            except OSError:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
            self._thread = None
        self.history.close()

    def _record(self, txn: HttpTransaction):
        try:
            self.history.log_transaction(txn)
        except OSError as exc:
            logger.debug("Proxy: failed to log transaction: %s", exc)

        try:
            new_findings = analyze_transaction(txn)
            if new_findings:
                with self._lock:
                    self.findings.extend(new_findings)
                logger.debug("Proxy: %d passive finding(s) for %s %s",
                             len(new_findings), txn.method, txn.url)
        except (ValueError, KeyError, OSError) as exc:
            logger.debug("Proxy: passive analysis error: %s", exc)

    def get_findings(self) -> list[PassiveFinding]:
        with self._lock:
            return list(self.findings)
