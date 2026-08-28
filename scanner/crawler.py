import re
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from scanner.log import logger

SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf")


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

    def crawl(self) -> None:
        logger.info("Starting crawler on %s", self.config.target)
        self._crawl_url(self.config.target, depth=0)
        logger.info("Crawling complete: %d URLs, %d forms", len(self.session.crawled_urls), len(self.session.forms))

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
