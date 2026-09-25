import re
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from scanner.log import logger

SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf")

# Common application routes tried during wordlist-based endpoint discovery.
# These are added to the crawl queue regardless of whether HTML links them.
COMMON_ROUTES = [
    "/admin", "/admin/", "/dashboard", "/dashboard/",
    "/login", "/login/", "/logout",
    "/register", "/signup",
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/user", "/api/me",
    "/api/health", "/api/status",
    "/settings", "/profile", "/account",
    "/upload", "/uploads",
    "/reset-password", "/forgot-password",
    "/graphql", "/graphiql",
    "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json",
    "/redoc", "/docs",
    "/.env", "/.git/config", "/config",
    "/robots.txt", "/sitemap.xml",
]


def extract_forms(html: str, base_url: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        action = urljoin(base_url, action) if action else base_url
        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            info = {"name": tag.get("name", ""), "type": tag.get("type", "text"),
                    "value": tag.get("value", "")}
            if tag.name == "select":
                info["type"] = "select"
                opts = tag.find_all("option")
                if opts:
                    info["value"] = opts[0].get("value", "")
            inputs.append(info)
        forms.append({"action": action, "method": form.get("method", "get").lower(), "inputs": inputs})
    return forms


def extract_links(html: str, base_url: str, scope_domain: str) -> set[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all(["a", "link", "script", "img", "iframe", "frame"]):
        href = tag.get("href") or tag.get("src")
        if not href:
            continue
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.netloc and parsed.netloc != scope_domain:
            continue
        clean = "{}://{}{}".format(parsed.scheme, parsed.netloc, parsed.path)
        if parsed.query:
            clean += "?" + parsed.query
        links.add(clean)
    return links


def extract_comments(html: str) -> list[str]:
    return re.findall(r"<!--(.*?)-->", html, re.DOTALL)


def extract_js_urls(html: str, base_url: str) -> set[str]:
    urls = set()
    patterns = [
        r'(?:href|src|action|url)\s*[=:]\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
    ]
    for pattern in patterns:
        for match in re.findall(pattern, html):
            if match.startswith(("http://", "https://", "/")):
                urls.add(urljoin(base_url, match))
    return urls


class Crawler:
    def __init__(self, scan_session):
        self.session = scan_session
        self.config = scan_session.config
        self.visited = set()
        self.scope_domain = urlparse(self.config.target).netloc
        # Extra seed URLs supplied by the operator (--extra-urls / --seed-urls)
        self._extra_seeds: list = list(getattr(self.config, "extra_urls", []) or [])

    def crawl(self) -> None:
        logger.info("Starting crawler on %s", self.config.target)

        # ── Phase 0: discover seed URLs from robots.txt / sitemap / OpenAPI ──
        self._seed_from_discovery()

        # ── Phase 1: operator-supplied extra seeds ──────────────────────────
        for url in self._extra_seeds:
            self._crawl_url(url.strip(), depth=0)

        # ── Phase 2: standard link-following crawl ──────────────────────────
        self._crawl_url(self.config.target, depth=0)

        # ── Phase 3: wordlist-based active route discovery ──────────────────
        self._wordlist_probe()

        logger.info(
            "Crawling complete: %d URLs discovered, %d forms found",
            len(self.session.crawled_urls), len(self.session.forms)
        )

        # Attach a coverage report to the session for use by reporters
        self.session.coverage_report = {
            "urls_discovered": len(self.session.crawled_urls),
            "forms_found": len(self.session.forms),
            "extra_seeds_supplied": len(self._extra_seeds),
            "wordlist_routes_probed": len(COMMON_ROUTES),
        }

    def _crawl_url(self, url: str, depth: int) -> None:
        if depth > self.config.depth:
            return
        normalized = self._normalize(url)
        if normalized in self.visited:
            return
        self.visited.add(normalized)

        resp = self.session.get(url)
        if not resp:
            return

        self.session.crawled_urls.add(url)
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return

        html = resp.text
        for form in extract_forms(html, url):
            form["source_url"] = url
            self.session.forms.append(form)

        for link in extract_links(html, url, self.scope_domain) | extract_js_urls(html, url):
            parsed = urlparse(link)
            if parsed.netloc != self.scope_domain:
                continue
            if any(parsed.path.lower().endswith(ext) for ext in SKIP_EXT):
                self.session.crawled_urls.add(link)
                continue
            self._crawl_url(link, depth + 1)

    def _normalize(self, url: str) -> str:
        parsed = urlparse(url)
        params = "&".join("{}=".format(k) for k in sorted(parse_qs(parsed.query).keys()))
        return "{}://{}{}?{}".format(parsed.scheme, parsed.netloc, parsed.path, params)

    # ── Discovery helpers ──────────────────────────────────────────────────

    def _seed_from_discovery(self) -> None:
        """Harvest extra seed URLs from robots.txt, sitemap.xml, and OpenAPI specs."""
        base = self.config.target.rstrip("/")

        # robots.txt
        for path in ("/robots.txt",):
            resp = self.session.get(base + path)
            if resp and resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("allow:", "disallow:", "sitemap:")):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            val = parts[1].strip()
                            if val.startswith("http"):
                                url = val
                            elif val.startswith("/"):
                                url = base + val
                            else:
                                continue
                            parsed = urlparse(url)
                            if parsed.netloc == self.scope_domain or not parsed.netloc:
                                self._crawl_url(url, depth=0)

        # sitemap.xml (and any Sitemap: references found in robots.txt)
        for path in ("/sitemap.xml", "/sitemap_index.xml"):
            resp = self.session.get(base + path)
            if resp and resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", ""):
                for loc in re.findall(r"<loc>([^<]+)</loc>", resp.text):
                    loc = loc.strip()
                    parsed = urlparse(loc)
                    if parsed.netloc == self.scope_domain:
                        self._crawl_url(loc, depth=0)

        # OpenAPI / Swagger specs
        for path in ("/openapi.json", "/swagger.json", "/api-docs", "/api/swagger.json"):
            resp = self.session.get(base + path)
            if resp and resp.status_code == 200:
                ct = resp.headers.get("Content-Type", "")
                if "json" in ct or "yaml" in ct:
                    import json as _json
                    try:
                        spec = _json.loads(resp.text)
                        server_url = ""
                        for srv in spec.get("servers", []):
                            url_candidate = srv.get("url", "")
                            if url_candidate.startswith("http"):
                                p = urlparse(url_candidate)
                                if p.netloc == self.scope_domain:
                                    server_url = url_candidate.rstrip("/")
                                    break
                            elif url_candidate.startswith("/"):
                                server_url = base + url_candidate.rstrip("/")
                                break
                        if not server_url:
                            server_url = base
                        for api_path in spec.get("paths", {}):
                            # Replace path params like {id} with a placeholder
                            clean = re.sub(r"\{[^}]+\}", "1", api_path)
                            self._crawl_url(server_url + clean, depth=0)
                    except Exception:
                        pass
                    break  # only parse the first spec found

    def _wordlist_probe(self) -> None:
        """Probe common application routes not necessarily linked from HTML."""
        base = self.config.target.rstrip("/")
        newly_found = 0
        for route in COMMON_ROUTES:
            candidate = base + route
            normalized = self._normalize(candidate)
            if normalized in self.visited:
                continue
            resp = self.session.get(candidate)
            if resp and resp.status_code not in (404, 410):
                self.session.crawled_urls.add(candidate)
                self.visited.add(normalized)
                newly_found += 1
                # Do one level of link-follow on discovered routes
                if resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", ""):
                    html = resp.text
                    for form in extract_forms(html, candidate):
                        form["source_url"] = candidate
                        self.session.forms.append(form)
                    for link in extract_links(html, candidate, self.scope_domain):
                        parsed = urlparse(link)
                        if parsed.netloc == self.scope_domain:
                            self._crawl_url(link, depth=1)
        if newly_found:
            logger.info(
                "Wordlist discovery: found %d additional live routes (not linked from HTML)",
                newly_found
            )
