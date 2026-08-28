"""Adaptive Network Masking (ANM) -- runtime identity rotation engine.

Rotates IPs (Tor/proxy pool/DHCP), MAC addresses, and User-Agent strings
to evade blocking during scans. Wired into ScanSession so block events
trigger automatic identity switches.
"""

import logging
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from scanner.log import logger

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.53 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
]


@dataclass
class IdentityState:
    ip_address: str = "unknown"
    mac_address: str = "unknown"
    user_agent: str = ""
    proxy: str = ""
    rotation_count: int = 0
    last_rotation: float = 0.0


@dataclass
class ANMConfig:
    enabled: bool = False
    use_tor: bool = False
    tor_socks_host: str = "127.0.0.1"
    tor_socks_port: int = 9050
    tor_control_port: int = 9051
    tor_password: str = ""
    proxy_pool_file: str = ""
    proxy_pool: list = field(default_factory=list)
    auto_scrape_proxies: bool = True
    dhcp_renewal: bool = True
    waf_evasion: bool = True
    rotate_mac: bool = False
    network_interface: str = ""
    rotate_ua: bool = True
    min_rotation_interval: float = 10.0
    cooldown_after_block: float = 3.0
    max_rotations_per_scan: int = 50
    block_threshold: int = 3
    fail_threshold: int = 5


# WAF evasion header sets -- randomised to defeat header fingerprinting
_WAF_EVASION_HEADERS_POOL = [
    {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
     "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br",
     "DNT": "1", "Connection": "keep-alive", "Upgrade-Insecure-Requests": "1"},
    {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
     "Accept-Language": "en-GB,en;q=0.9", "Accept-Encoding": "gzip, deflate",
     "Connection": "keep-alive", "Cache-Control": "max-age=0"},
    {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
     "Accept-Language": "en-US,en;q=0.9,fr;q=0.8", "Accept-Encoding": "gzip, deflate, br, zstd",
     "Connection": "keep-alive", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
     "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1"},
    {"Accept": "*/*", "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
     "Accept-Encoding": "gzip, deflate", "Connection": "keep-alive",
     "Pragma": "no-cache", "Cache-Control": "no-cache"},
    {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
     "Accept-Language": "ja,en-US;q=0.9,en;q=0.8", "Accept-Encoding": "gzip, deflate, br",
     "Connection": "keep-alive", "Upgrade-Insecure-Requests": "1",
     "Sec-Ch-Ua-Platform": '"Windows"'},
]

_FREE_PROXY_APIS = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=elite",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
]


def _scrape_free_proxies(max_proxies: int = 20) -> list[str]:
    """Fetch free anonymous proxies from public APIs. Best-effort, never raises."""
    try:
        import requests as _req
    except ImportError:
        return []

    proxies: list[str] = []
    for api_url in _FREE_PROXY_APIS:
        if len(proxies) >= max_proxies:
            break
        try:
            resp = _req.get(api_url, timeout=8)
            if resp.status_code != 200:
                continue
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line and len(line) < 50:
                    proxy = "http://{}".format(line) if not line.startswith(("http", "socks")) else line
                    proxies.append(proxy)
                    if len(proxies) >= max_proxies:
                        break
        except (OSError, ValueError):
            continue

    if proxies:
        logger.info("ANM: Auto-scraped %d free proxies from public lists", len(proxies))
        logger.warning("ANM: Public proxies are UNTRUSTED -- they can intercept scan traffic "
                       "including credentials. Use --proxy-pool with your own vetted proxies for sensitive scans.")
    return proxies


def _run_cmd(args, timeout=10):
    """Run a subprocess silently, return True on success."""
    try:
        subprocess.check_call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _renew_dhcp_lease(interface: str = "") -> bool:
    """Release and renew DHCP lease. Requires elevated privileges."""
    system = platform.system()

    if system == "Windows":
        iface_args = [interface] if interface else []
        if _run_cmd(["ipconfig", "/release"] + iface_args):
            time.sleep(1)
            if _run_cmd(["ipconfig", "/renew"] + iface_args, timeout=15):
                logger.info("ANM: DHCP lease renewed via ipconfig")
                return True
        logger.warning("ANM: Windows DHCP renewal failed")
        return False

    if system == "Linux":
        if os.geteuid() != 0:
            logger.warning("ANM: DHCP renewal requires root. Skipping.")
            return False

        iface = interface or _detect_default_interface()
        if not iface:
            logger.warning("ANM: Cannot detect interface for DHCP renewal.")
            return False

        if shutil.which("dhclient"):
            if _run_cmd(["dhclient", "-r", iface]):
                time.sleep(1)
                if _run_cmd(["dhclient", iface], timeout=15):
                    logger.info("ANM: DHCP renewed via dhclient on %s", iface)
                    return True

        if shutil.which("nmcli"):
            if _run_cmd(["nmcli", "device", "disconnect", iface]):
                time.sleep(2)
                if _run_cmd(["nmcli", "device", "connect", iface], timeout=15):
                    logger.info("ANM: DHCP renewed via nmcli on %s", iface)
                    return True

        logger.warning("ANM: Linux DHCP renewal failed (no dhclient or nmcli).")
        return False

    logger.warning("ANM: DHCP renewal not supported on %s", system)
    return False


def _send_tor_newnym(control_host: str, control_port: int, password: str) -> bool:
    """Send SIGNAL NEWNYM to Tor ControlPort for a new circuit."""
    try:
        with socket.create_connection((control_host, control_port), timeout=5) as sock:
            auth = 'AUTHENTICATE "{}"\r\n'.format(password).encode() if password else b'AUTHENTICATE\r\n'
            sock.sendall(auth)
            resp = sock.recv(1024).decode()
            if "250" not in resp:
                logger.error("Tor ControlPort auth failed: %s", resp.strip())
                return False
            sock.sendall(b'SIGNAL NEWNYM\r\n')
            resp = sock.recv(1024).decode()
            if "250" not in resp:
                logger.warning("Tor NEWNYM signal failed: %s", resp.strip())
                return False
            logger.info("ANM: Tor circuit renewed (NEWNYM)")
            return True
    except (socket.error, OSError) as exc:
        logger.error("ANM: Cannot reach Tor ControlPort at %s:%d -- %s", control_host, control_port, exc)
        return False


def _get_current_ip_via_tor(socks_host: str, socks_port: int) -> str:
    try:
        import requests as _req
        proxies = {"http": "socks5h://{}:{}".format(socks_host, socks_port),
                    "https": "socks5h://{}:{}".format(socks_host, socks_port)}
        resp = _req.get("https://api.ipify.org?format=text", proxies=proxies, timeout=10)
        if resp.status_code == 200:
            return resp.text.strip()
    except (OSError, ValueError):
        pass
    return "unknown"


_MAC_RE = re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")


def _detect_default_interface() -> str:
    try:
        route = Path("/proc/net/route")
        if route.exists():
            for line in route.read_text().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    except OSError:
        pass

    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True, timeout=5)
        tokens = out.split()
        for i, tok in enumerate(tokens):
            if tok == "dev" and i + 1 < len(tokens):
                return tokens[i + 1]
    except (subprocess.SubprocessError, OSError):
        pass
    return ""


def _get_current_mac(interface: str) -> str:
    try:
        path = Path("/sys/class/net/{}/address".format(interface))
        if path.exists():
            return path.read_text().strip()
    except OSError:
        pass
    return "unknown"


def _generate_random_mac() -> str:
    """Generate a random unicast, locally-administered MAC."""
    import secrets
    raw = secrets.token_bytes(6)
    first_octet = (raw[0] & 0xFE) | 0x02
    octets = [first_octet] + list(raw[1:])
    return ":".join("{:02x}".format(b) for b in octets)


def _validate_iface(interface: str) -> bool:
    if not re.match(r'^[a-zA-Z0-9._-]+$', interface):
        logger.error("ANM: Invalid interface name: %s", interface)
        return False
    if not Path("/sys/class/net/{}".format(interface)).exists():
        logger.error("ANM: Interface %s does not exist", interface)
        return False
    return True


def _set_mac_address(interface: str, new_mac: str) -> bool:
    if platform.system() != "Linux":
        logger.warning("ANM: MAC rotation only supported on Linux")
        return False
    if os.geteuid() != 0:
        logger.warning("ANM: MAC rotation requires root. Skipping.")
        return False
    if not _validate_iface(interface):
        return False

    try:
        for cmd in [["ip", "link", "set", interface, "down"],
                    ["ip", "link", "set", interface, "address", new_mac],
                    ["ip", "link", "set", interface, "up"]]:
            _run_cmd(cmd, timeout=5)
        logger.info("ANM: MAC changed to %s on %s", new_mac, interface)
        return True
    except subprocess.SubprocessError:
        pass

    # fallback: macchanger
    if shutil.which("macchanger"):
        try:
            _run_cmd(["ip", "link", "set", interface, "down"], timeout=5)
            _run_cmd(["macchanger", "-m", new_mac, interface], timeout=5)
            _run_cmd(["ip", "link", "set", interface, "up"], timeout=5)
            logger.info("ANM: MAC changed via macchanger to %s on %s", new_mac, interface)
            return True
        except subprocess.SubprocessError as exc:
            logger.error("ANM: macchanger failed -- %s", exc)
    return False


def _restore_mac_address(interface: str, original_mac: str) -> bool:
    if not original_mac or original_mac == "unknown" or platform.system() != "Linux":
        return False
    return _set_mac_address(interface, original_mac)


class IdentityManager:
    """Orchestrates runtime identity rotation for evasion resilience. Thread-safe."""

    def __init__(self, config: ANMConfig):
        self.config = config
        self._lock = threading.Lock()
        self._state = IdentityState()
        self._original_mac = ""
        self._proxy_index = 0
        self._block_counter = 0
        self._fail_counter = 0
        self._rotation_history: list[dict] = []
        self._shutting_down = False

        if config.proxy_pool_file and os.path.isfile(config.proxy_pool_file):
            self._load_proxy_pool(config.proxy_pool_file)

        # auto-detect interface for MAC rotation
        if config.rotate_mac and not config.network_interface:
            config.network_interface = _detect_default_interface()
            if config.network_interface:
                logger.info("ANM: Auto-detected interface: %s", config.network_interface)
            else:
                logger.warning("ANM: Could not detect interface. MAC rotation disabled.")
                config.rotate_mac = False

        if config.rotate_mac and config.network_interface:
            self._original_mac = _get_current_mac(config.network_interface)
            self._state.mac_address = self._original_mac

        if config.rotate_ua:
            self._state.user_agent = random.choice(_UA_POOL)

        if config.use_tor:
            self._state.proxy = "socks5h://{}:{}".format(config.tor_socks_host, config.tor_socks_port)
            self._state.ip_address = _get_current_ip_via_tor(config.tor_socks_host, config.tor_socks_port)
            logger.info("ANM: Tor exit IP -- %s", self._state.ip_address)

    @property
    def state(self) -> IdentityState:
        with self._lock:
            return IdentityState(
                ip_address=self._state.ip_address,
                mac_address=self._state.mac_address,
                user_agent=self._state.user_agent,
                proxy=self._state.proxy,
                rotation_count=self._state.rotation_count,
                last_rotation=self._state.last_rotation,
            )

    @property
    def current_proxy(self) -> str:
        with self._lock:
            return self._state.proxy

    @property
    def current_ua(self) -> str:
        with self._lock:
            return self._state.user_agent

    @property
    def rotation_count(self) -> int:
        with self._lock:
            return self._state.rotation_count

    @property
    def rotation_history(self) -> list:
        with self._lock:
            return list(self._rotation_history)

    def signal_block(self, status_code: int = 0) -> bool:
        """Record a block event, rotate if threshold met."""
        with self._lock:
            self._block_counter += 1
            if self._block_counter >= self.config.block_threshold:
                self._block_counter = 0
                return self._do_rotate("ip_block", "HTTP {}".format(status_code))
        return False

    def signal_connection_fail(self) -> bool:
        with self._lock:
            self._fail_counter += 1
            if self._fail_counter >= self.config.fail_threshold:
                self._fail_counter = 0
                return self._do_rotate("connection_fail", "connection drops")
        return False

    def reset_counters(self):
        with self._lock:
            self._block_counter = 0
            self._fail_counter = 0

    def rotate(self, reason: str = "manual") -> bool:
        with self._lock:
            return self._do_rotate("manual", reason)

    def _do_rotate(self, trigger: str, detail: str) -> bool:
        """Execute rotation. Caller must hold self._lock."""
        now = time.time()
        if now - self._state.last_rotation < self.config.min_rotation_interval:
            return False
        if self._state.rotation_count >= self.config.max_rotations_per_scan:
            logger.warning("ANM: Max rotations reached (%d)", self.config.max_rotations_per_scan)
            return False

        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trigger": trigger, "detail": detail, "actions": [],
        }
        success = False

        # IP rotation
        if self._rotate_ip():
            record["actions"].append("ip_rotated")
            success = True

        # MAC -- only on connection-level bans
        if self.config.rotate_mac and trigger in ("connection_fail", "manual"):
            if self._rotate_mac():
                record["actions"].append("mac_rotated")
                success = True

        # UA (always, it's free)
        if self.config.rotate_ua:
            self._rotate_ua()
            record["actions"].append("ua_rotated")
            success = True

        # WAF header randomisation
        if self.config.waf_evasion and trigger in ("ip_block", "waf_detected", "manual"):
            self._rotate_waf_headers()
            record["actions"].append("waf_headers_randomised")
            success = True

        # last resort: exponential backoff
        if not success:
            delay = self._apply_exponential_backoff()
            record["actions"].append("backoff_{:.1f}s".format(delay))
            success = True

        if success:
            self._state.rotation_count += 1
            self._state.last_rotation = now
            self._rotation_history.append(record)
            logger.info("ANM: Rotation #%d -- trigger=%s, actions=[%s]",
                        self._state.rotation_count, trigger, ", ".join(record["actions"]))
            time.sleep(self.config.cooldown_after_block)

        return success

    def _rotate_ip(self) -> bool:
        """Cascade: Tor -> proxy pool -> auto-scrape -> DHCP renewal."""
        # Tor
        if self.config.use_tor:
            ok = _send_tor_newnym(self.config.tor_socks_host, self.config.tor_control_port, self.config.tor_password)
            if ok:
                time.sleep(2)
                old_ip = self._state.ip_address
                self._state.ip_address = _get_current_ip_via_tor(self.config.tor_socks_host, self.config.tor_socks_port)
                self._state.proxy = "socks5h://{}:{}".format(self.config.tor_socks_host, self.config.tor_socks_port)
                if self._state.ip_address != old_ip:
                    logger.info("ANM: IP rotated via Tor -- %s -> %s", old_ip, self._state.ip_address)
                else:
                    logger.warning("ANM: Tor NEWNYM sent but exit IP unchanged")
                return True

        # proxy pool round-robin
        if self.config.proxy_pool:
            old_proxy = self._state.proxy
            self._proxy_index = (self._proxy_index + 1) % len(self.config.proxy_pool)
            self._state.proxy = self.config.proxy_pool[self._proxy_index]
            logger.info("ANM: Proxy rotated -- %s -> %s", old_proxy or "(direct)", self._state.proxy)
            return True

        # auto-scrape if pool empty
        if self.config.auto_scrape_proxies and not self.config.proxy_pool:
            logger.info("ANM: No proxies configured, auto-scraping...")
            scraped = _scrape_free_proxies(max_proxies=20)
            if scraped:
                self.config.proxy_pool = scraped
                random.shuffle(self.config.proxy_pool)
                self._proxy_index = 0
                self._state.proxy = self.config.proxy_pool[0]
                logger.info("ANM: IP via auto-scraped proxy -- %s", self._state.proxy)
                return True
            logger.warning("ANM: Auto-scrape found no proxies, trying DHCP...")

        # DHCP
        if self.config.dhcp_renewal:
            if _renew_dhcp_lease(interface=self.config.network_interface or ""):
                logger.info("ANM: IP rotated via DHCP renewal")
                self._state.proxy = ""
                return True

        logger.warning("ANM: All IP rotation strategies exhausted. "
                       "Enable --tor, --proxy-pool, or run as root for DHCP.")
        return False

    def _rotate_mac(self) -> bool:
        if not self.config.network_interface:
            return False
        new_mac = _generate_random_mac()
        ok = _set_mac_address(self.config.network_interface, new_mac)
        if ok:
            self._state.mac_address = new_mac
        return ok

    def _rotate_ua(self):
        current = self._state.user_agent
        candidates = [ua for ua in _UA_POOL if ua != current]
        self._state.user_agent = random.choice(candidates) if candidates else random.choice(_UA_POOL)

    def _rotate_waf_headers(self):
        self._waf_headers = random.choice(_WAF_EVASION_HEADERS_POOL)
        logger.debug("ANM: WAF evasion headers randomised")

    def _apply_exponential_backoff(self) -> float:
        n = self._state.rotation_count + 1
        base_delay = min(5 * (2 ** (n - 1)), 120)
        jitter = base_delay * random.uniform(-0.3, 0.3)
        delay = max(1.0, base_delay + jitter)
        logger.info("ANM: Backoff %.1fs (rotation #%d, no IP/MAC available)", delay, n)
        time.sleep(delay)
        return delay

    def _load_proxy_pool(self, filepath: str):
        try:
            with open(filepath) as f:
                proxies = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if not line.startswith(("http://", "https://", "socks4://", "socks5://")):
                            line = "http://{}".format(line)
                        proxies.append(line)
                self.config.proxy_pool = proxies
                logger.info("ANM: Loaded %d proxies from %s", len(proxies), filepath)
        except (IOError, OSError) as exc:
            logger.error("ANM: Failed to load proxy pool from %s -- %s", filepath, exc)

    def apply_to_session(self, session_obj):
        """Push current identity into the requests.Session."""
        proxy = self._state.proxy
        if proxy:
            session_obj.proxies.update({"http": proxy, "https": proxy})
        else:
            session_obj.proxies.clear()

        if self._state.user_agent:
            session_obj.headers["User-Agent"] = self._state.user_agent

        if hasattr(self, "_waf_headers") and self._waf_headers:
            for key, value in self._waf_headers.items():
                session_obj.headers[key] = value

    def shutdown(self):
        if self._shutting_down:
            return
        self._shutting_down = True

        if self.config.rotate_mac and self._original_mac and self._original_mac != "unknown":
            logger.info("ANM: Restoring original MAC %s on %s",
                        self._original_mac, self.config.network_interface)
            _restore_mac_address(self.config.network_interface, self._original_mac)

        if self._state.rotation_count > 0:
            logger.info("ANM: Session complete -- %d rotation(s)", self._state.rotation_count)

    def get_summary(self) -> dict:
        with self._lock:
            return {
                "enabled": self.config.enabled,
                "total_rotations": self._state.rotation_count,
                "methods": {
                    "tor": self.config.use_tor,
                    "proxy_pool": bool(self.config.proxy_pool),
                    "auto_scrape_proxies": self.config.auto_scrape_proxies,
                    "dhcp_renewal": self.config.dhcp_renewal,
                    "waf_evasion": self.config.waf_evasion,
                    "mac_rotation": self.config.rotate_mac,
                    "ua_rotation": self.config.rotate_ua,
                },
                "current_identity": {
                    "ip": self._state.ip_address,
                    "mac": self._state.mac_address,
                    "user_agent": self._state.user_agent,
                    "proxy": self._state.proxy,
                },
                "history": list(self._rotation_history),
            }
