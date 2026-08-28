import random
import time
import logging

logger = logging.getLogger("reconstrike-ng")


BROWSER_PROFILES = {
    "chrome_win": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "DNT": "1",
    },
    "chrome_mac": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"macOS"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
    },
    "firefox_win": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
        "DNT": "1",
        "Sec-GPC": "1",
    },
    "firefox_linux": {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
        "Sec-GPC": "1",
    },
    "safari_mac": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Connection": "keep-alive",
    },
    "edge_win": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    },
    "chrome_android": {
        "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        "Sec-Ch-Ua-Mobile": "?1",
        "Sec-Ch-Ua-Platform": '"Android"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    },
    "safari_iphone": {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Connection": "keep-alive",
    },
}

SEC_FETCH_CONTEXTS = {
    "direct": {"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate"},
    "same_origin": {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate"},
    "cross_site": {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"},
    "ajax": {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"},
    "image": {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"},
    "script": {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "script"},
}


class HumanTimer:
    """Simulates realistic browsing cadence with burst/pause patterns."""

    SPEED_PROFILES = {
        "slow": {"min": 3.0, "max": 12.0, "burst_pause": 15.0, "long_pause_chance": 0.15},
        "normal": {"min": 1.0, "max": 5.0, "burst_pause": 8.0, "long_pause_chance": 0.10},
        "fast": {"min": 0.3, "max": 2.0, "burst_pause": 4.0, "long_pause_chance": 0.05},
    }

    def __init__(self, speed: str = "normal"):
        self.speed = speed
        self._request_count = 0
        self._burst_count = 0
        self._burst_size = random.randint(3, 7)

    def wait(self):
        self._request_count += 1
        self._burst_count += 1
        p = self.SPEED_PROFILES.get(self.speed, self.SPEED_PROFILES["normal"])

        if self._burst_count >= self._burst_size:
            self._burst_count = 0
            self._burst_size = random.randint(3, 8)
            pause = random.uniform(p["burst_pause"] * 0.7, p["burst_pause"] * 1.5)
            logger.debug("Stealth: Burst pause %.1fs (simulating page reading)", pause)
            time.sleep(pause)
            return

        if random.random() < p["long_pause_chance"]:
            pause = random.uniform(10, 30)
            logger.debug("Stealth: Long pause %.1fs (simulating distraction)", pause)
            time.sleep(pause)
            return

        mean = (p["min"] + p["max"]) / 2
        std = (p["max"] - p["min"]) / 4
        delay = max(p["min"], min(random.gauss(mean, std), p["max"] * 1.5))
        delay = max(0.1, delay + random.uniform(-0.1, 0.3))
        time.sleep(delay)


class StealthConfig:
    def __init__(self, speed: str = "normal", rotate_profile: bool = True):
        self.speed = speed
        self.rotate_profile = rotate_profile
        self.timer = HumanTimer(speed)
        self._current_profile_name = None
        self._current_profile = None
        self._referrer_chain: list[str] = []
        self._visit_count = 0
        self._profile_lifespan = random.randint(20, 50)
        self._pick_profile()

    def _pick_profile(self):
        name = random.choice(list(BROWSER_PROFILES.keys()))
        self._current_profile_name = name
        self._current_profile = BROWSER_PROFILES[name].copy()
        self._profile_lifespan = random.randint(20, 50)
        self._visit_count = 0
        logger.debug("Stealth: Using browser profile: %s", name)

    def get_headers(self, url: str, context: str = "same_origin") -> dict:
        self._visit_count += 1
        if self.rotate_profile and self._visit_count >= self._profile_lifespan:
            self._pick_profile()

        headers = self._current_profile.copy()
        headers.update(SEC_FETCH_CONTEXTS.get(context, SEC_FETCH_CONTEXTS["same_origin"]))

        if self._referrer_chain and context != "direct":
            headers["Referer"] = self._referrer_chain[-1]

        if context in ("direct", "same_origin"):
            self._referrer_chain.append(url)
            if len(self._referrer_chain) > 10:
                self._referrer_chain.pop(0)

        return headers

    def wait(self):
        self.timer.wait()

    @property
    def profile_name(self) -> str:
        return self._current_profile_name or "unknown"


def apply_stealth(session, stealth_cfg: StealthConfig):
    """Apply stealth browser profile to a requests session."""
    headers = stealth_cfg.get_headers("", context="direct")
    headers.pop("Referer", None)
    session.headers.update(headers)
    logger.info("Stealth: Applied browser profile '%s'", stealth_cfg.profile_name)
