"""NVD CVE API v2.0 client with local SQLite cache.

Queries the NIST National Vulnerability Database for CVEs matching
detected CPE strings (software/version combinations).  Uses a local
SQLite cache to avoid redundant API calls and respect rate limits.

Rate limits:
    Without API key: 5 requests per 30 seconds
    With API key:    50 requests per 30 seconds
    (Get a free key at https://nvd.nist.gov/developers/request-an-api-key)
"""

import json
import re
import sqlite3
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import requests

from scanner.log import logger


# NVD API v2.0 endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Default cache location
CACHE_DIR = Path.home() / ".reconstrike" / "nvd_cache"
CACHE_DB = CACHE_DIR / "nvd_cache.db"

# Cache TTL: 24 hours
CACHE_TTL = 86400


@dataclass
class CVEResult:
    """A CVE entry returned from the NVD."""
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
    """Client for the NIST NVD CVE API v2.0 with local caching."""

    def __init__(self, api_key: str = "", cache_path: Path | str | None = None):
        self.api_key = api_key
        self.cache_path = Path(cache_path) if cache_path else CACHE_DB
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_request_time = 0.0
        self._request_count = 0
        self._init_cache()

    def _init_cache(self):
        """Initialize the SQLite cache."""
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
        """Respect NVD API rate limits."""
        with self._lock:
            now = time.time()
            max_requests = 50 if self.api_key else 5
            window = 30.0

            if self._request_count >= max_requests:
                elapsed = now - self._last_request_time
                if elapsed < window:
                    sleep_time = window - elapsed + 0.5
                    logger.debug("NVD: Rate limit reached, waiting %.1fs", sleep_time)
                    time.sleep(sleep_time)
                self._request_count = 0

            self._request_count += 1
            self._last_request_time = time.time()

    def _check_cache(self, query_key: str) -> list[dict] | None:
        """Check if results are cached and fresh."""
        conn = sqlite3.connect(str(self.cache_path))
        row = conn.execute(
            "SELECT results, timestamp FROM cve_cache WHERE query_key = ?",
            (query_key,)
        ).fetchone()
        conn.close()

        if row:
            timestamp = row[1]
            if time.time() - timestamp < CACHE_TTL:
                return json.loads(row[0])
        return None

    def _store_cache(self, query_key: str, results: list[dict]):
        """Store results in the cache."""
        conn = sqlite3.connect(str(self.cache_path))
        conn.execute(
            "INSERT OR REPLACE INTO cve_cache (query_key, results, timestamp) VALUES (?, ?, ?)",
            (query_key, json.dumps(results), time.time())
        )
        conn.commit()
        conn.close()

    def search_by_cpe(self, cpe_string: str, max_results: int = 20) -> list[CVEResult]:
        """Search for CVEs matching a CPE string.

        Args:
            cpe_string: CPE 2.3 string (e.g., "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
            max_results: Maximum number of CVEs to return.

        Returns:
            List of CVEResult objects sorted by CVSS score (highest first).
        """
        cache_key = f"cpe:{cpe_string}:{max_results}"

        # Check cache first
        cached = self._check_cache(cache_key)
        if cached is not None:
            logger.debug("NVD: Cache hit for %s", cpe_string)
            return [CVEResult(**r) for r in cached]

        # Query NVD API
        self._rate_limit()

        params = {
            "cpeName": cpe_string,
            "resultsPerPage": min(max_results, 100),
        }
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            logger.error("NVD: API request failed — %s", e)
            return []

        results = self._parse_response(data)

        # Cache results
        self._store_cache(cache_key, [r.__dict__ for r in results])

        return results

    def search_by_keyword(self, keyword: str, max_results: int = 20) -> list[CVEResult]:
        """Search for CVEs by keyword (software name).

        Useful when an exact CPE string is not available.
        """
        cache_key = f"kw:{keyword}:{max_results}"

        cached = self._check_cache(cache_key)
        if cached is not None:
            return [CVEResult(**r) for r in cached]

        self._rate_limit()

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 100),
        }
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            logger.error("NVD: API request failed — %s", e)
            return []

        results = self._parse_response(data)
        self._store_cache(cache_key, [r.__dict__ for r in results])
        return results

    def _parse_response(self, data: dict) -> list[CVEResult]:
        """Parse NVD API v2.0 response into CVEResult objects."""
        results = []
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")

            # Extract description (English)
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CVSS scores (prefer v3.1, fall back to v3.0, then v2.0)
            cvss_score = 0.0
            cvss_severity = ""
            cvss_vector = ""
            metrics = cve_data.get("metrics", {})

            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    cvss_severity = cvss_data.get("baseSeverity", "")
                    cvss_vector = cvss_data.get("vectorString", "")
                    break

            # Extract references
            references = []
            for ref in cve_data.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)
                    # Check for exploit tags
                    tags = ref.get("tags", [])
                    # Exploit availability check done below

            # Check exploit availability from references
            exploit_available = any(
                any(t in ["Exploit", "Third Party Advisory"] for t in ref.get("tags", []))
                for ref in cve_data.get("references", [])
            )

            # Extract weaknesses (CWEs)
            weaknesses = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        weaknesses.append(desc.get("value", ""))

            # Published/modified dates
            published = cve_data.get("published", "")
            modified = cve_data.get("lastModified", "")

            results.append(CVEResult(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                cvss_vector=cvss_vector,
                published=published,
                modified=modified,
                references=references[:10],
                exploit_available=exploit_available,
                weaknesses=weaknesses,
            ))

        # Sort by CVSS score (highest first)
        results.sort(key=lambda r: r.cvss_score, reverse=True)
        return results

    def clear_cache(self):
        """Clear the entire NVD cache."""
        conn = sqlite3.connect(str(self.cache_path))
        conn.execute("DELETE FROM cve_cache")
        conn.commit()
        conn.close()
        logger.info("NVD: Cache cleared")


def build_cpe_string(vendor: str, product: str, version: str = "*") -> str:
    """Build a CPE 2.3 string from vendor, product, and version.

    Example:
        build_cpe_string("apache", "http_server", "2.4.49")
        -> "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    """
    # Normalize
    vendor = vendor.lower().replace(" ", "_")
    product = product.lower().replace(" ", "_")
    version = version or "*"

    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


# Common software name to CPE mapping
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


def lookup_cves_for_service(software: str, version: str,
                            api_key: str = "") -> list[CVEResult]:
    """Convenience function: look up CVEs for a detected service.

    Automatically builds the CPE string from the software name and version,
    queries the NVD, and returns results.
    """
    software_lower = software.lower().strip()

    cpe_info = SOFTWARE_CPE_MAP.get(software_lower)
    if not cpe_info:
        # Fall back to keyword search
        client = NVDClient(api_key=api_key)
        search_term = f"{software} {version}" if version else software
        return client.search_by_keyword(search_term)

    vendor, product = cpe_info
    cpe = build_cpe_string(vendor, product, version)

    client = NVDClient(api_key=api_key)
    return client.search_by_cpe(cpe)
