"""Adaptive Network Masking (ANM) — Runtime identity rotation engine.

Provides transparent IP rotation (via Tor circuit renewal or proxy pool
cycling), MAC address spoofing for the active network interface, and
User-Agent fingerprint randomisation.  Designed to be wired into
`ScanSession` so that block events (HTTP 429 / 403 bursts, connection
resets) automatically trigger a new identity without interrupting the
scan.

Usage
-----
The `IdentityManager` is instantiated once per scan and attached to the
session.  When `ScanSession._track_response_status` detects a blocking
pattern, it calls ``identity_manager.rotate()`` which picks the best
strategy (IP, MAC, UA, or all) for the situation.

CLI flags exposed by ``reconstrike.py``::

    --anm                   Enable Adaptive Network Masking
    --tor                   Route traffic through Tor (SOCKS5 127.0.0.1:9050)
    --tor-control-port PORT Tor ControlPort for NEWNYM (default: 9051)
    --tor-password PASS     Tor ControlPort hashed password
    --proxy-pool FILE       Newline-delimited proxy list for round-robin
    --rotate-mac            Enable runtime MAC address rotation
    --rotate-ua             Enable User-Agent fingerprint rotation
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


# ---------------------------------------------------------------------------
# User-Agent pool — common browsers to blend in with regular traffic
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class IdentityState:
    """Snapshot of the current network identity."""
    ip_address: str = "unknown"
    mac_address: str = "unknown"
    user_agent: str = ""
    proxy: str = ""
    rotation_count: int = 0
    last_rotation: float = 0.0


@dataclass
class ANMConfig:
    """Configuration for the Adaptive Network Masking subsystem."""
    enabled: bool = False

    # Tor integration
    use_tor: bool = False
    tor_socks_host: str = "127.0.0.1"
    tor_socks_port: int = 9050
    tor_control_port: int = 9051
    tor_password: str = ""

    # Proxy pool
    proxy_pool_file: str = ""
    proxy_pool: list = field(default_factory=list)

    # Fallback strategies (zero-config, cross-platform)
    auto_scrape_proxies: bool = True   # scrape free proxies at runtime
    dhcp_renewal: bool = True          # renew DHCP lease for new IP
    waf_evasion: bool = True           # randomise headers to bypass WAF fingerprinting

    # MAC rotation
    rotate_mac: bool = False
    network_interface: str = ""  # auto-detected if empty

    # UA rotation
    rotate_ua: bool = True  # on by default when ANM enabled

    # Timing
    min_rotation_interval: float = 10.0   # seconds between rotations
    cooldown_after_block: float = 3.0     # pause after identity switch
    max_rotations_per_scan: int = 50      # safety cap

    # Thresholds — how many consecutive blocks before rotating
    block_threshold: int = 3
    fail_threshold: int = 5


# ---------------------------------------------------------------------------
# WAF evasion header pool — randomised to defeat header fingerprinting
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Free proxy auto-scraping (zero-config fallback)
# ---------------------------------------------------------------------------
_FREE_PROXY_APIS = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=elite",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
]


def _scrape_free_proxies(max_proxies: int = 20) -> list[str]:
    """Fetch free anonymous proxies from public APIs.

    Returns a list of validated proxy URLs.  Best-effort — returns
    whatever is available; never raises.
    """
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
                # Basic format validation: host:port
                if ":" in line and len(line) < 50:
                    proxy = f"http://{line}" if not line.startswith(("http", "socks")) else line
                    proxies.append(proxy)
                    if len(proxies) >= max_proxies:
                        break
        except Exception:
            continue

    if proxies:
        logger.info("ANM: Auto-scraped %d free proxies from public lists", len(proxies))
    return proxies


# ---------------------------------------------------------------------------
# DHCP lease renewal (cross-platform IP refresh)
# ---------------------------------------------------------------------------
def _renew_dhcp_lease(interface: str = "") -> bool:
    """Release and renew DHCP lease to obtain a new IP.

    Works on both Windows (ipconfig) and Linux (dhclient / NetworkManager).
    Requires elevated privileges.  Returns True if renewal succeeded.
    """
    system = platform.system()

    if system == "Windows":
        try:
            if interface:
                subprocess.check_call(
                    ["ipconfig", "/release", interface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                time.sleep(1)
                subprocess.check_call(
                    ["ipconfig", "/renew", interface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            else:
                subprocess.check_call(
                    ["ipconfig", "/release"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                time.sleep(1)
                subprocess.check_call(
                    ["ipconfig", "/renew"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            logger.info("ANM: DHCP lease renewed via ipconfig (Windows)")
            return True
        except (subprocess.SubprocessError, FileNotFoundError) as exc:
            logger.warning("ANM: Windows DHCP renewal failed — %s", exc)
            return False

    elif system == "Linux":
        if os.geteuid() != 0:
            logger.warning("ANM: DHCP renewal requires root privileges. Skipping.")
            return False

        iface = interface or _detect_default_interface()
        if not iface:
            logger.warning("ANM: Cannot detect interface for DHCP renewal.")
            return False

        # Try dhclient first (most common)
        if shutil.which("dhclient"):
            try:
                subprocess.check_call(
                    ["dhclient", "-r", iface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                time.sleep(1)
                subprocess.check_call(
                    ["dhclient", iface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                logger.info("ANM: DHCP lease renewed via dhclient on %s", iface)
                return True
            except subprocess.SubprocessError:
                pass

        # Fallback: NetworkManager nmcli
        if shutil.which("nmcli"):
            try:
                subprocess.check_call(
                    ["nmcli", "device", "disconnect", iface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                time.sleep(2)
                subprocess.check_call(
                    ["nmcli", "device", "connect", iface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                logger.info("ANM: DHCP lease renewed via nmcli on %s", iface)
                return True
            except subprocess.SubprocessError:
                pass

        logger.warning("ANM: Linux DHCP renewal failed (no dhclient or nmcli).")
        return False

    else:
        logger.warning("ANM: DHCP renewal not supported on %s", system)
        return False


# ---------------------------------------------------------------------------
# Tor control helpers
# ---------------------------------------------------------------------------
def _send_tor_newnym(control_host: str, control_port: int, password: str) -> bool:
    """Send SIGNAL NEWNYM to the Tor ControlPort to get a new circuit."""
    try:
        with socket.create_connection((control_host, control_port), timeout=5) as sock:
            if password:
                sock.sendall(f'AUTHENTICATE "{password}"\r\n'.encode())
            else:
                sock.sendall(b'AUTHENTICATE\r\n')
            resp = sock.recv(1024).decode()
            if "250" not in resp:
                logger.error("Tor ControlPort auth failed: %s", resp.strip())
                return False
            sock.sendall(b'SIGNAL NEWNYM\r\n')
            resp = sock.recv(1024).decode()
            if "250" not in resp:
                logger.warning("Tor NEWNYM signal failed: %s", resp.strip())
                return False
            logger.info("ANM: Tor circuit renewed (NEWNYM signal sent)")
            return True
    except (socket.error, OSError) as exc:
        logger.error("ANM: Cannot reach Tor ControlPort at %s:%d — %s",
                      control_host, control_port, exc)
        return False


def _get_current_ip_via_tor(socks_host: str, socks_port: int) -> str:
    """Resolve our current exit IP through the Tor SOCKS proxy."""
    try:
        import requests as _req
        proxies = {"http": f"socks5h://{socks_host}:{socks_port}",
                    "https": f"socks5h://{socks_host}:{socks_port}"}
        resp = _req.get("https://api.ipify.org?format=text", proxies=proxies, timeout=10)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception:
        pass
    return "unknown"


# ---------------------------------------------------------------------------
# MAC address helpers (Linux only — requires root / CAP_NET_ADMIN)
# ---------------------------------------------------------------------------
_MAC_RE = re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")


def _detect_default_interface() -> str:
    """Return the default network interface on Linux."""
    try:
        route = Path("/proc/net/route")
        if route.exists():
            for line in route.read_text().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    except Exception:
        pass

    # Fallback: ip route
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"],
                                       text=True, timeout=5)
        for token_idx, token in enumerate(out.split()):
            if token == "dev" and token_idx + 1 < len(out.split()):
                return out.split()[token_idx + 1]
    except Exception:
        pass

    return ""


def _get_current_mac(interface: str) -> str:
    """Read the current MAC address for the given interface."""
    try:
        path = Path(f"/sys/class/net/{interface}/address")
        if path.exists():
            return path.read_text().strip()
    except Exception:
        pass
    return "unknown"


def _generate_random_mac() -> str:
    """Generate a random unicast, locally-administered MAC address."""
    # Set the locally administered bit (bit 1 of first octet) and
    # clear the multicast bit (bit 0 of first octet)
    first_octet = random.randint(0x00, 0xFF) & 0xFE | 0x02
    octets = [first_octet] + [random.randint(0x00, 0xFF) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in octets)


def _set_mac_address(interface: str, new_mac: str) -> bool:
    """Change the MAC address on a Linux interface.

    Requires root or CAP_NET_ADMIN capability.  Falls back to
    `macchanger` if available.
    """
    if platform.system() != "Linux":
        logger.warning("ANM: MAC rotation is only supported on Linux")
        return False

    # Check if we have permission (running as root or have capabilities)
    if os.geteuid() != 0:
        logger.warning("ANM: MAC rotation requires root privileges. Skipping.")
        return False

    try:
        # Method 1: Use ip link (standard, no extra deps)
        subprocess.check_call(
            ["ip", "link", "set", interface, "down"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
        )
        subprocess.check_call(
            ["ip", "link", "set", interface, "address", new_mac],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
        )
        subprocess.check_call(
            ["ip", "link", "set", interface, "up"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
        )
        logger.info("ANM: MAC address changed to %s on %s", new_mac, interface)
        return True

    except subprocess.SubprocessError:
        # Method 2: Try macchanger if installed
        if shutil.which("macchanger"):
            try:
                subprocess.check_call(
                    ["ip", "link", "set", interface, "down"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
                )
                subprocess.check_call(
                    ["macchanger", "-m", new_mac, interface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
                )
                subprocess.check_call(
                    ["ip", "link", "set", interface, "up"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
                )
                logger.info("ANM: MAC changed via macchanger to %s on %s", new_mac, interface)
                return True
            except subprocess.SubprocessError as exc:
                logger.error("ANM: macchanger failed — %s", exc)

    return False


def _restore_mac_address(interface: str, original_mac: str) -> bool:
    """Restore the original MAC address on shutdown."""
    if not original_mac or original_mac == "unknown" or platform.system() != "Linux":
        return False
    return _set_mac_address(interface, original_mac)


# ---------------------------------------------------------------------------
# Main Identity Manager
# ---------------------------------------------------------------------------
class IdentityManager:
    """Orchestrates runtime identity rotation for evasion resilience.

    Monitors the scan session for block signals and transparently rotates
    IP addresses, MAC addresses, and User-Agent strings to maintain
    continuous scanning.

    Thread-safe — all state mutations are guarded by a lock.
    """

    def __init__(self, config: ANMConfig):
        self.config = config
        self._lock = threading.Lock()
        self._state = IdentityState()
        self._original_mac: str = ""
        self._proxy_index: int = 0
        self._block_counter: int = 0
        self._fail_counter: int = 0
        self._rotation_history: list[dict] = []
        self._shutting_down = False

        # Load proxy pool if specified
        if config.proxy_pool_file and os.path.isfile(config.proxy_pool_file):
            self._load_proxy_pool(config.proxy_pool_file)

        # Detect default interface for MAC rotation
        if config.rotate_mac and not config.network_interface:
            config.network_interface = _detect_default_interface()
            if config.network_interface:
                logger.info("ANM: Auto-detected network interface: %s", config.network_interface)
            else:
                logger.warning("ANM: Could not detect network interface. MAC rotation disabled.")
                config.rotate_mac = False

        # Snapshot the original MAC before we touch anything
        if config.rotate_mac and config.network_interface:
            self._original_mac = _get_current_mac(config.network_interface)
            self._state.mac_address = self._original_mac

        # Set initial UA
        if config.rotate_ua:
            self._state.user_agent = random.choice(_UA_POOL)

        # Detect initial IP if Tor is active
        if config.use_tor:
            self._state.proxy = f"socks5h://{config.tor_socks_host}:{config.tor_socks_port}"
            self._state.ip_address = _get_current_ip_via_tor(
                config.tor_socks_host, config.tor_socks_port
            )
            logger.info("ANM: Tor exit IP — %s", self._state.ip_address)

    @property
    def state(self) -> IdentityState:
        """Return the current identity state (read-only snapshot)."""
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

    # ----- Block event API (called by ScanSession) -----

    def signal_block(self, status_code: int = 0) -> bool:
        """Record a block event and trigger rotation if threshold is met.

        Returns True if a rotation was executed.
        """
        with self._lock:
            self._block_counter += 1
            if self._block_counter >= self.config.block_threshold:
                self._block_counter = 0
                return self._do_rotate("ip_block", f"HTTP {status_code}")
        return False

    def signal_connection_fail(self) -> bool:
        """Record a connection failure and trigger rotation if threshold is met."""
        with self._lock:
            self._fail_counter += 1
            if self._fail_counter >= self.config.fail_threshold:
                self._fail_counter = 0
                return self._do_rotate("connection_fail", "connection drops")
        return False

    def reset_counters(self):
        """Reset block/fail counters (called when a request succeeds)."""
        with self._lock:
            self._block_counter = 0
            self._fail_counter = 0

    # ----- Manual rotation -----

    def rotate(self, reason: str = "manual") -> bool:
        """Force an immediate identity rotation."""
        with self._lock:
            return self._do_rotate("manual", reason)

    # ----- Core rotation logic (must be called under self._lock) -----

    def _do_rotate(self, trigger: str, detail: str) -> bool:
        """Execute the actual rotation. Caller must hold self._lock.

        Decision matrix by trigger type:
        ┌──────────────────┬────────┬─────┬────┬─────────┬──────────┐
        │ Trigger          │ IP rot │ MAC │ UA │ WAF hdrs│ Backoff  │
        ├──────────────────┼────────┼─────┼────┼─────────┼──────────┤
        │ ip_block (429)   │   ✓    │     │  ✓ │    ✓    │ fallback │
        │ ip_block (403)   │   ✓    │     │  ✓ │    ✓    │ fallback │
        │ connection_fail  │   ✓    │  ✓  │  ✓ │         │ fallback │
        │ waf_detected     │   ✓    │     │  ✓ │    ✓    │ fallback │
        │ manual           │   ✓    │  ✓  │  ✓ │    ✓    │          │
        └──────────────────┴────────┴─────┴────┴─────────┴──────────┘
        """
        now = time.time()

        # Rate-limit rotations
        if now - self._state.last_rotation < self.config.min_rotation_interval:
            return False

        # Safety cap
        if self._state.rotation_count >= self.config.max_rotations_per_scan:
            logger.warning(
                "ANM: Maximum rotations reached (%d). Continuing with current identity.",
                self.config.max_rotations_per_scan,
            )
            return False

        rotation_record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trigger": trigger,
            "detail": detail,
            "actions": [],
        }

        success = False

        # 1. Rotate IP (full fallback chain)
        ip_rotated = self._rotate_ip()
        if ip_rotated:
            rotation_record["actions"].append("ip_rotated")
            success = True

        # 2. Rotate MAC — on connection-level bans (drops, resets, device bans)
        if self.config.rotate_mac and trigger in ("connection_fail", "manual"):
            mac_rotated = self._rotate_mac()
            if mac_rotated:
                rotation_record["actions"].append("mac_rotated")
                success = True

        # 3. Rotate User-Agent (always, it's free)
        if self.config.rotate_ua:
            self._rotate_ua()
            rotation_record["actions"].append("ua_rotated")
            success = True

        # 4. WAF evasion — randomise request headers to defeat fingerprinting
        if self.config.waf_evasion and trigger in ("ip_block", "waf_detected", "manual"):
            self._rotate_waf_headers()
            rotation_record["actions"].append("waf_headers_randomised")
            success = True

        # 5. Last resort — if nothing else worked, apply exponential backoff
        if not success:
            backoff = self._apply_exponential_backoff()
            rotation_record["actions"].append(f"backoff_{backoff:.1f}s")
            success = True  # backoff always "succeeds" as a strategy

        if success:
            self._state.rotation_count += 1
            self._state.last_rotation = now
            self._rotation_history.append(rotation_record)
            logger.info(
                "ANM: Identity rotation #%d — trigger=%s, actions=[%s]",
                self._state.rotation_count,
                trigger,
                ", ".join(rotation_record["actions"]),
            )
            # Post-rotation cooldown
            time.sleep(self.config.cooldown_after_block)

        return success

    def _rotate_ip(self) -> bool:
        """Rotate IP through a cascading fallback chain.

        Priority order:
          1. Tor circuit renewal  (--tor)
          2. Proxy pool cycling   (--proxy-pool or auto-scraped)
          3. DHCP lease renewal   (cross-platform, no config needed)

        Each strategy is tried in order; first success wins.
        """
        # Strategy 1: Tor circuit renewal
        if self.config.use_tor:
            ok = _send_tor_newnym(
                self.config.tor_socks_host,
                self.config.tor_control_port,
                self.config.tor_password,
            )
            if ok:
                time.sleep(2)  # wait for new circuit
                new_ip = _get_current_ip_via_tor(
                    self.config.tor_socks_host, self.config.tor_socks_port
                )
                old_ip = self._state.ip_address
                self._state.ip_address = new_ip
                self._state.proxy = f"socks5h://{self.config.tor_socks_host}:{self.config.tor_socks_port}"
                if new_ip != old_ip:
                    logger.info("ANM: IP rotated via Tor — %s → %s", old_ip, new_ip)
                else:
                    logger.warning("ANM: Tor NEWNYM sent but exit IP unchanged (may need longer wait)")
                return True
            # Tor failed — fall through to next strategy

        # Strategy 2: Proxy pool round-robin (manual or auto-scraped)
        if self.config.proxy_pool:
            old_proxy = self._state.proxy
            self._proxy_index = (self._proxy_index + 1) % len(self.config.proxy_pool)
            new_proxy = self.config.proxy_pool[self._proxy_index]
            self._state.proxy = new_proxy
            logger.info("ANM: Proxy rotated — %s → %s", old_proxy or "(direct)", new_proxy)
            return True

        # Strategy 2b: Auto-scrape free proxies if pool is empty (zero-config)
        if self.config.auto_scrape_proxies and not self.config.proxy_pool:
            logger.info("ANM: No proxies configured. Auto-scraping free proxy list...")
            scraped = _scrape_free_proxies(max_proxies=20)
            if scraped:
                self.config.proxy_pool = scraped
                random.shuffle(self.config.proxy_pool)
                self._proxy_index = 0
                self._state.proxy = self.config.proxy_pool[0]
                logger.info("ANM: IP rotated via auto-scraped proxy — %s", self._state.proxy)
                return True
            logger.warning("ANM: Auto-scrape found no proxies. Trying DHCP renewal...")

        # Strategy 3: DHCP lease renewal (cross-platform, works on Windows + Linux)
        if self.config.dhcp_renewal:
            iface = self.config.network_interface or ""
            ok = _renew_dhcp_lease(interface=iface)
            if ok:
                logger.info("ANM: IP rotated via DHCP lease renewal")
                # Clear proxy — we're going direct with new DHCP IP
                self._state.proxy = ""
                return True

        logger.warning(
            "ANM: All IP rotation strategies exhausted. "
            "Consider enabling --tor, --proxy-pool, or running with elevated privileges for DHCP renewal."
        )
        return False

    def _rotate_mac(self) -> bool:
        """Rotate MAC address on the active interface.

        Handles the edge case where the device itself is banned by its
        hardware address (common in LAN-level and WiFi-level blocking).
        """
        if not self.config.network_interface:
            return False
        new_mac = _generate_random_mac()
        ok = _set_mac_address(self.config.network_interface, new_mac)
        if ok:
            self._state.mac_address = new_mac
        return ok

    def _rotate_ua(self):
        """Pick a new random User-Agent."""
        current = self._state.user_agent
        candidates = [ua for ua in _UA_POOL if ua != current]
        self._state.user_agent = random.choice(candidates) if candidates else random.choice(_UA_POOL)

    def _rotate_waf_headers(self):
        """Randomise request headers to defeat WAF fingerprinting.

        Many WAFs fingerprint clients by their Accept, Accept-Language,
        Accept-Encoding, and Sec-Fetch-* headers.  Swapping these makes
        the scanner appear as a different browser on every rotation.
        """
        self._waf_headers = random.choice(_WAF_EVASION_HEADERS_POOL)
        logger.debug("ANM: WAF evasion headers randomised")

    def _apply_exponential_backoff(self) -> float:
        """Apply exponential backoff with jitter as the absolute last resort.

        Even when we can't change our IP/MAC, slowing down with
        randomised timing breaks rate-limiter patterns.
        """
        rotation_num = self._state.rotation_count + 1
        # Exponential: 5s, 10s, 20s, 40s... capped at 120s
        base_delay = min(5 * (2 ** (rotation_num - 1)), 120)
        # Add ±30% jitter to avoid predictable patterns
        jitter = base_delay * random.uniform(-0.3, 0.3)
        delay = max(1.0, base_delay + jitter)
        logger.info(
            "ANM: Exponential backoff — pausing %.1fs (rotation #%d, no IP/MAC rotation available)",
            delay, rotation_num,
        )
        time.sleep(delay)
        return delay

    # ----- Proxy pool management -----

    def _load_proxy_pool(self, filepath: str):
        """Load proxy list from a newline-delimited file."""
        try:
            with open(filepath) as f:
                proxies = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Normalise: ensure scheme prefix
                        if not line.startswith(("http://", "https://", "socks4://", "socks5://")):
                            line = f"http://{line}"
                        proxies.append(line)
                self.config.proxy_pool = proxies
                logger.info("ANM: Loaded %d proxies from %s", len(proxies), filepath)
        except (IOError, OSError) as exc:
            logger.error("ANM: Failed to load proxy pool from %s — %s", filepath, exc)

    # ----- Session integration helpers -----

    def apply_to_session(self, session_obj):
        """Push the current identity into the requests.Session object.

        Called after every rotation to update the live session's proxy,
        User-Agent, and WAF evasion headers transparently.
        """
        # Update proxy
        proxy = self._state.proxy
        if proxy:
            session_obj.proxies.update({"http": proxy, "https": proxy})
        else:
            session_obj.proxies.clear()

        # Update User-Agent
        if self._state.user_agent:
            session_obj.headers["User-Agent"] = self._state.user_agent

        # Apply WAF evasion headers (if randomised)
        if hasattr(self, "_waf_headers") and self._waf_headers:
            for key, value in self._waf_headers.items():
                session_obj.headers[key] = value

    # ----- Cleanup -----

    def shutdown(self):
        """Restore original MAC address and log rotation summary."""
        if self._shutting_down:
            return
        self._shutting_down = True

        if self.config.rotate_mac and self._original_mac and self._original_mac != "unknown":
            logger.info("ANM: Restoring original MAC address %s on %s",
                        self._original_mac, self.config.network_interface)
            _restore_mac_address(self.config.network_interface, self._original_mac)

        total = self._state.rotation_count
        if total > 0:
            logger.info("ANM: Session complete — %d identity rotation(s) performed", total)

    def get_summary(self) -> dict:
        """Return a summary dict suitable for JSON/HTML reports."""
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
