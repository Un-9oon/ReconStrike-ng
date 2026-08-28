import json
import re
import sqlite3
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path

import requests

from scanner.log import logger

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = Path.home() / ".reconstrike-ng" / "nvd_cache"
CACHE_DB = CACHE_DIR / "nvd_cache.db"
CACHE_TTL = 86400


@dataclass
class CVEResult:
    cve_id: str
    description: str
    cvss_score: float = 0.0
    cvss_severity: str = ""
    cvss_vector: str = ""
    published: str = ""
    modified: str = ""
    cpe_match: str = ""
    references: list[str] = field(default_factory=list)
    exploit_available: bool = False
    weaknesses: list[str] = field(default_factory=list)


class NVDClient:
    def __init__(self, api_key: str = "", cache_path: Path | str | None = None):
        self.api_key = api_key
        self.cache_path = Path(cache_path) if cache_path else CACHE_DB
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_request_time = 0.0
        self._request_count = 0
        self._init_cache()

    def _init_cache(self):
        conn = sqlite3.connect(str(self.cache_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                query_key TEXT PRIMARY KEY,
                results TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _rate_limit(self):
        with self._lock:
            now = time.time()
            max_requests = 50 if self.api_key else 5
            if self._request_count >= max_requests:
                elapsed = now - self._last_request_time
                if elapsed < 30.0:
                    sleep_time = 30.0 - elapsed + 0.5
                    logger.debug("NVD: Rate limit reached, waiting %.1fs", sleep_time)
                    time.sleep(sleep_time)
                self._request_count = 0
            self._request_count += 1
            self._last_request_time = time.time()

    def _check_cache(self, query_key: str) -> list[dict] | None:
        conn = sqlite3.connect(str(self.cache_path))
        row = conn.execute(
            "SELECT results, timestamp FROM cve_cache WHERE query_key = ?",
            (query_key,)).fetchone()
        conn.close()
        if row and time.time() - row[1] < CACHE_TTL:
            return json.loads(row[0])
        return None

    def _store_cache(self, query_key: str, results: list[dict]):
        conn = sqlite3.connect(str(self.cache_path))
        conn.execute(
            "INSERT OR REPLACE INTO cve_cache (query_key, results, timestamp) VALUES (?, ?, ?)",
            (query_key, json.dumps(results), time.time()))
        conn.commit()
        conn.close()

    def _query_api(self, params: dict) -> dict:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            logger.error("NVD: API request failed -- %s", e)
            return {}

    def search_by_cpe(self, cpe_string: str, max_results: int = 20) -> list[CVEResult]:
        cache_key = "cpe:{}:{}".format(cpe_string, max_results)
        cached = self._check_cache(cache_key)
        if cached is not None:
            logger.debug("NVD: Cache hit for %s", cpe_string)
            return [CVEResult(**r) for r in cached]

        self._rate_limit()
        data = self._query_api({"cpeName": cpe_string, "resultsPerPage": min(max_results, 100)})
        if not data:
            return []

        results = self._parse_response(data)
        self._store_cache(cache_key, [r.__dict__ for r in results])
        return results

    def search_by_keyword(self, keyword: str, max_results: int = 20) -> list[CVEResult]:
        cache_key = "kw:{}:{}".format(keyword, max_results)
        cached = self._check_cache(cache_key)
        if cached is not None:
            return [CVEResult(**r) for r in cached]

        self._rate_limit()
        data = self._query_api({"keywordSearch": keyword, "resultsPerPage": min(max_results, 100)})
        if not data:
            return []

        results = self._parse_response(data)
        self._store_cache(cache_key, [r.__dict__ for r in results])
        return results

    def _parse_response(self, data: dict) -> list[CVEResult]:
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})

            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            cvss_score, cvss_severity, cvss_vector = 0.0, "", ""
            metrics = cve.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(key, [])
                if metric_list:
                    d = metric_list[0].get("cvssData", {})
                    cvss_score = d.get("baseScore", 0.0)
                    cvss_severity = d.get("baseSeverity", "")
                    cvss_vector = d.get("vectorString", "")
                    break

            refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
            exploit_available = any(
                any(t in ["Exploit", "Third Party Advisory"] for t in ref.get("tags", []))
                for ref in cve.get("references", []))

            weaknesses = [desc.get("value", "")
                          for w in cve.get("weaknesses", [])
                          for desc in w.get("description", [])
                          if desc.get("lang") == "en"]

            results.append(CVEResult(
                cve_id=cve.get("id", ""), description=description,
                cvss_score=cvss_score, cvss_severity=cvss_severity,
                cvss_vector=cvss_vector,
                published=cve.get("published", ""),
                modified=cve.get("lastModified", ""),
                references=refs[:10], exploit_available=exploit_available,
                weaknesses=weaknesses,
            ))

        results.sort(key=lambda r: r.cvss_score, reverse=True)
        return results

    def clear_cache(self):
        conn = sqlite3.connect(str(self.cache_path))
        conn.execute("DELETE FROM cve_cache")
        conn.commit()
        conn.close()
        logger.info("NVD: Cache cleared")


def build_cpe_string(vendor: str, product: str, version: str = "*") -> str:
    vendor = vendor.lower().replace(" ", "_")
    product = product.lower().replace(" ", "_")
    return "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*".format(vendor, product, version or "*")


SOFTWARE_CPE_MAP = {
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "php": ("php", "php"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "wordpress": ("wordpress", "wordpress"),
    "tomcat": ("apache", "tomcat"),
    "iis": ("microsoft", "internet_information_services"),
    "openssl": ("openssl", "openssl"),
    "jquery": ("jquery", "jquery"),
    "spring": ("vmware", "spring_framework"),
    "django": ("djangoproject", "django"),
    "flask": ("palletsprojects", "flask"),
    "express": ("expressjs", "express"),
    "node.js": ("nodejs", "node.js"),
    "openssh": ("openbsd", "openssh"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd_project", "proftpd"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "kibana": ("elastic", "kibana"),
    "grafana": ("grafana", "grafana"),
    "jenkins": ("jenkins", "jenkins"),
    "docker": ("docker", "docker"),
    "kubernetes": ("kubernetes", "kubernetes"),
    "rabbitmq": ("vmware", "rabbitmq"),
    "memcached": ("memcached", "memcached"),
}


def lookup_cves_for_service(software: str, version: str, api_key: str = "") -> list[CVEResult]:
    cpe_info = SOFTWARE_CPE_MAP.get(software.lower().strip())
    if not cpe_info:
        client = NVDClient(api_key=api_key)
        return client.search_by_keyword("{} {}".format(software, version) if version else software)

    client = NVDClient(api_key=api_key)
    return client.search_by_cpe(build_cpe_string(cpe_info[0], cpe_info[1], version))
