import re
import socket
import time
import threading
import ipaddress
import urllib3
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

import requests
from colorama import Fore, Style

from scanner.log import logger
from scanner.identity_manager import IdentityManager, ANMConfig


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self):
        return {
            "CRITICAL": "\033[38;5;88m",
            "HIGH": Fore.RED,
            "MEDIUM": Fore.YELLOW,
            "LOW": Fore.GREEN,
            "INFO": Fore.BLUE,
        }[self.value]

    @property
    def score(self):
        return {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 2.0, "INFO": 0.0}[self.value]


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    url: str
    module: str
    cwe: str = ""
    confirmed: bool = False
    location: str = ""
    parameter: str = ""
    payload: str = ""
    request_method: str = ""
    request_headers: str = ""
    request_body: str = ""
    response_status: int = 0
    response_headers: str = ""
    curl_command: str = ""
    reproduction_steps: str = ""
    developer_fix: str = ""
    affected_component: str = ""
    references: str = ""
    detection_method: str = ""

    @property
    def confidence(self):
        return "Confirmed" if self.confirmed else "Tentative"


SENSITIVE_PARAM_PATTERNS = re.compile(
    r'(password|passwd|pass|pwd|secret|auth|token|access_token|api_key|apikey|bearer)=[^&]+',
    re.IGNORECASE
)


def _redact_sensitive(text: str) -> str:
    if not text:
        return ""
    text = SENSITIVE_PARAM_PATTERNS.sub(r'\1=[REDACTED]', text)
    text = re.sub(r'(Authorization:\s*)(Bearer|Basic)?\s*[A-Za-z0-9._~\-+/=]+', r'\1\2 [REDACTED]', text, flags=re.IGNORECASE)
    return text


def shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def build_curl(method: str, url: str, headers: dict = None, data: str = None) -> str:
    safe_url = _redact_sensitive(url)
    cmd = f"curl -k -X {method} {shell_quote(safe_url)}"
    if headers:
        for k, v in headers.items():
            v = "[REDACTED]" if k.lower() in ("authorization", "cookie", "x-api-key") else _redact_sensitive(str(v))
            cmd += " -H {}".format(shell_quote("{}: {}".format(k, v)))
    if data:
        cmd += f" -d {shell_quote(_redact_sensitive(data))}"
    return cmd


@dataclass
class ScanConfig:
    target: str
    threads: int = 10
    timeout: int = 10
    depth: int = 3
    user_agent: str = "ReconStrike-ng/3.1.1 (Security Audit)"
    auth_url: str = ""
    auth_username: str = ""
    auth_password: str = ""
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    verify_ssl: bool = True
    follow_redirects: bool = True
    scan_modules: list = field(default_factory=list)
    proxy: str = ""
    rate_limit: float = 0
    scope_include: str = ""
    scope_exclude: str = ""
    anm_config: ANMConfig = field(default_factory=ANMConfig)


MAX_RESPONSE_SIZE = 10 * 1024 * 1024

PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _resolve_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, ValueError):
        return None


def _is_private_ip(hostname: str) -> bool:
    resolved = _resolve_ip(hostname)
    if not resolved:
        return False
    try:
        return any(ipaddress.ip_address(resolved) in net for net in PRIVATE_IP_RANGES)
    except ValueError:
        return False


def _check_ssrf(url: str, target_url: str) -> bool:
    host = urlparse(url).netloc.split(":")[0]
    target_host = urlparse(target_url).netloc.split(":")[0]
    if not host:
        return False
    return _is_private_ip(host) and not _is_private_ip(target_host)


def _domain_matches(url: str, reference_url: str) -> bool:
    return urlparse(url).netloc.lower() == urlparse(reference_url).netloc.lower()


def _sanitize_path(path: str) -> str:
    abs_path = os.path.abspath(path)
    cwd = os.path.abspath(os.getcwd())
    rel = os.path.relpath(abs_path, start=cwd)
    if rel.startswith("..") or os.path.isabs(rel):
        return os.path.join(cwd, os.path.basename(path) or "output")
    return abs_path


class ScanSession:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        if not config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session.headers.update({"User-Agent": config.user_agent, **config.headers})
        if config.cookies:
            self.session.cookies.update(config.cookies)
        self.findings: list[Finding] = []
        self.crawled_urls: set[str] = set()
        self.forms: list[dict] = []
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self._last_request_time: float = 0
        self._request_count: int = 0
        self._lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._scope_include_re = None
        self._scope_exclude_re = None
        if config.scope_exclude:
            try:
                self._scope_exclude_re = re.compile(config.scope_exclude, re.IGNORECASE)
            except re.error as e:
                logger.error("Invalid --scope-exclude regex: %s", e)
        self._consecutive_fails = 0
        self._consecutive_blocks = 0
        self._warned_block = False
        self._warned_fail = False

        self.identity_manager: Optional[IdentityManager] = None
        if config.anm_config.enabled:
            self.identity_manager = IdentityManager(config.anm_config)
            self.identity_manager.apply_to_session(self.session)
            logger.info("ANM: Adaptive Network Masking ACTIVE")
            if config.anm_config.use_tor:
                logger.info("ANM: Traffic routed through Tor (SOCKS5 %s:%d)",
                            config.anm_config.tor_socks_host, config.anm_config.tor_socks_port)
            if config.anm_config.proxy_pool:
                logger.info("ANM: Proxy pool loaded (%d proxies)", len(config.anm_config.proxy_pool))
            if config.anm_config.rotate_mac:
                logger.info("ANM: MAC rotation enabled on interface %s",
                            config.anm_config.network_interface)
            if config.anm_config.rotate_ua:
                logger.info("ANM: User-Agent rotation enabled")

    def authenticate(self) -> bool:
        if not self.config.auth_url:
            return True
        try:
            auth_parsed = urlparse(self.config.auth_url)
            auth_domain = auth_parsed.netloc.lower()
            resp = self.session.get(self.config.auth_url, timeout=self.config.timeout)
            if not resp:
                return False
            from .crawler import extract_forms
            forms = extract_forms(resp.text, self.config.auth_url)

            login_form = None
            for form in forms:
                input_names = [i["name"].lower() for i in form["inputs"] if i.get("name")]
                if any("pass" in n for n in input_names):
                    login_form = form
                    break

            if not login_form:
                logger.warning("No login form found at %s", self.config.auth_url)
                return False

            post_data = {}
            for inp in login_form["inputs"]:
                name = inp.get("name", "")
                if not name:
                    continue
                nl = name.lower()
                if any(k in nl for k in ("user", "email", "login")):
                    post_data[name] = self.config.auth_username
                elif "pass" in nl:
                    post_data[name] = self.config.auth_password
                elif inp.get("value"):
                    post_data[name] = inp["value"]

            action = login_form.get("action", self.config.auth_url)
            action_parsed = urlparse(action)

            # refuse credential submission over HTTP downgrade
            if auth_parsed.scheme == "https" and action_parsed.scheme == "http":
                logger.error("Refusing to send credentials over unencrypted HTTP action (%s).", action)
                return False

            # refuse cross-domain credential submission
            action_domain = action_parsed.netloc.lower()
            if action_domain and action_domain != auth_domain:
                logger.error(
                    "Login form action points to different domain (%s != %s). Refusing to send credentials.",
                    action_domain, auth_domain,
                )
                return False

            resp = self.session.post(action, data=post_data, timeout=self.config.timeout)
            if not resp:
                return False

            if resp.status_code == 200 and "logout" in resp.text.lower():
                logger.info("Authentication successful")
                return True
            if resp.status_code in (301, 302, 303):
                logger.info("Authentication likely successful (redirect)")
                return True

            logger.warning("Authentication result uncertain (status %s)", resp.status_code)
            return True

        except (requests.RequestException, OSError, ValueError) as e:
            logger.error("Authentication failed: %s", type(e).__name__)
            return False

    def add_finding(self, finding: Finding):
        with self._lock:
            for existing in self.findings:
                if existing.title == finding.title and existing.url == finding.url:
                    return
            finding.description = _redact_sensitive(finding.description)
            finding.evidence = _redact_sensitive(finding.evidence)
            self.findings.append(finding)

        conf = "CONFIRMED" if finding.confirmed else "TENTATIVE"
        parsed = urlparse(finding.url)
        path_query = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
        display_url = path_query if len(path_query) <= 80 else path_query[:77] + "..."

        logger.info(
            "[%s] %s | Target: %s://%s | Path: %s [%s]",
            finding.severity.value, finding.title,
            parsed.scheme, parsed.netloc, display_url, conf,
        )

    def _rate_limit(self):
        sleep_time = 0.0
        with self._rate_lock:
            if self.config.rate_limit > 0:
                interval = 1.0 / self.config.rate_limit
                now = time.time()
                elapsed = now - self._last_request_time
                if elapsed < interval:
                    sleep_time = interval - elapsed
                    self._last_request_time = now + sleep_time
                else:
                    self._last_request_time = now
            self._request_count += 1
        if sleep_time > 0:
            time.sleep(sleep_time)

    def _track_response_status(self, resp: Optional[requests.Response], exc: Optional[Exception] = None):
        with self._lock:
            if exc is not None or resp is None:
                self._consecutive_fails += 1
                if self._consecutive_fails >= 5 and not self._warned_fail:
                    self._warned_fail = True
                    logger.error(
                        "High request failure rate / timeouts detected (5+ failed requests). "
                        "Target host may be dropping connections or firewalling your IP."
                    )
                if self.identity_manager:
                    rotated = self.identity_manager.signal_connection_fail()
                    if rotated:
                        self.identity_manager.apply_to_session(self.session)
                        self._warned_fail = False
                        self._consecutive_fails = 0
                        logger.info("ANM: Identity rotated after connection failures. Resuming scan.")
            else:
                self._consecutive_fails = 0

                if resp.status_code in (429, 403):
                    self._consecutive_blocks += 1
                    if self._consecutive_blocks >= 3 and not self._warned_block:
                        self._warned_block = True
                        logger.warning(
                            "Target returned HTTP %s multiple times. "
                            "Target WAF or rate-limiter is actively blocking/throttling requests.",
                            resp.status_code,
                        )

                    if self.identity_manager:
                        rotated = self.identity_manager.signal_block(resp.status_code)
                        if rotated:
                            self.identity_manager.apply_to_session(self.session)
                            self._warned_block = False
                            self._consecutive_blocks = 0
                            logger.info("ANM: Identity rotated after HTTP %s blocks. Resuming scan.", resp.status_code)
                        elif self._consecutive_blocks >= 3:
                            logger.info("AUTO-EVASION: Adaptive throttling engaged. Delaying requests to bypass WAF...")
                            self.config.rate_limit = max(self.config.rate_limit, 0.5)
                    elif self._consecutive_blocks >= 3:
                        logger.info("AUTO-EVASION: Adaptive throttling engaged. Delaying requests to bypass WAF...")
                        self.config.rate_limit = 0.5
                else:
                    self._consecutive_blocks = 0
                    if self.identity_manager:
                        self.identity_manager.reset_counters()

    def _in_scope(self, url: str) -> bool:
        if self._scope_exclude_re and self._scope_exclude_re.search(url):
            return False
        if self._scope_include_re and not self._scope_include_re.search(url):
            return False
        return True

    def _safe_read(self, resp: requests.Response) -> Optional[requests.Response]:
        if resp is None:
            self._track_response_status(None)
            return None

        if resp.history and _check_ssrf(resp.url, self.config.target):
            resp.close()
            self._track_response_status(None)
            return None

        if resp.headers.get("Content-Length"):
            try:
                if int(resp.headers["Content-Length"]) > MAX_RESPONSE_SIZE:
                    resp.close()
                    self._track_response_status(None)
                    return None
            except ValueError:
                pass

        try:
            chunks = []
            total = 0
            for chunk in resp.iter_content(chunk_size=65536):
                total += len(chunk)
                if total > MAX_RESPONSE_SIZE:
                    resp.close()
                    self._track_response_status(None)
                    return None
                chunks.append(chunk)
            resp._content = b"".join(chunks)
        except (requests.RequestException, OSError, ValueError) as e:
            self._track_response_status(None, exc=e)
            return None

        self._track_response_status(resp)
        return resp

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            if _check_ssrf(url, self.config.target):
                return None
            self._rate_limit()
            kwargs.setdefault("timeout", self.config.timeout)
            kwargs.setdefault("allow_redirects", self.config.follow_redirects)
            kwargs.setdefault("stream", True)
            return self._safe_read(self.session.get(url, **kwargs))
        except requests.RequestException as e:
            self._track_response_status(None, exc=e)
            return None

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            if _check_ssrf(url, self.config.target):
                return None
            self._rate_limit()
            kwargs.setdefault("timeout", self.config.timeout)
            kwargs.setdefault("stream", True)
            return self._safe_read(self.session.post(url, **kwargs))
        except requests.RequestException as e:
            self._track_response_status(None, exc=e)
            return None

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            kwargs.setdefault("timeout", self.config.timeout)
            resp = self.session.head(url, **kwargs)
            self._track_response_status(resp)
            return resp
        except requests.RequestException as e:
            self._track_response_status(None, exc=e)
            return None
