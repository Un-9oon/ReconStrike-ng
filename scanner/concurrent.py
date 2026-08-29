import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

from scanner.core import ScanSession, _is_private_ip
from scanner.log import logger

MAX_URLS = 500
MAX_FORMS = 200

SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf")


class ConcurrentCrawler:
    def __init__(self, session: ScanSession):
        self.session = session
        self.config = session.config
        self.visited = set()
        self.scope_domain = urlparse(self.config.target).netloc
        self._lock = threading.Lock()
        self._total_urls = 0

    def crawl(self):
        from scanner.crawler import extract_links, extract_forms, extract_js_urls

        logger.info("Starting concurrent crawler (%d threads)...", self.config.threads)
        start = time.time()

        queue = [self.config.target]
        depth_map = {self.config.target: 0}

        while queue and self._total_urls < MAX_URLS:
            batch = queue[:self.config.threads * 2]
            queue = queue[len(batch):]

            with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
                futures = {}
                for url in batch:
                    normalized = self._normalize(url)
                    with self._lock:
                        if normalized in self.visited:
                            continue
                        self.visited.add(normalized)
                    futures[pool.submit(self._fetch, url)] = url

                for future in as_completed(futures):
                    url = futures[future]
                    result = future.result()
                    if not result:
                        continue

                    resp, new_links, forms = result
                    with self._lock:
                        self.session.crawled_urls.add(url)
                        self._total_urls += 1
                        for form in forms:
                            form["source_url"] = url
                            if len(self.session.forms) < MAX_FORMS:
                                if not any(f["action"] == form["action"] and f["method"] == form["method"]
                                           for f in self.session.forms):
                                    self.session.forms.append(form)

                    current_depth = depth_map.get(url, 0)
                    if current_depth < self.config.depth:
                        for link in new_links:
                            with self._lock:
                                if self._normalize(link) not in self.visited and self._total_urls < MAX_URLS:
                                    depth_map[link] = current_depth + 1
                                    queue.append(link)

        logger.info("Crawling complete: %d URLs, %d forms (%.1fs)",
                     len(self.session.crawled_urls), len(self.session.forms), time.time() - start)

    def _fetch(self, url):
        from scanner.crawler import extract_links, extract_forms, extract_js_urls

        hostname = urlparse(url).netloc.split(":")[0]
        if _is_private_ip(hostname) and hostname not in urlparse(self.config.target).netloc:
            return None

        resp = self.session.get(url)
        if not resp:
            return None

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return resp, set(), []

        html = resp.text
        links = extract_links(html, url, self.scope_domain)
        js_urls = extract_js_urls(html, url)

        all_urls = set()
        for link in links | js_urls:
            lp = urlparse(link)
            if lp.netloc and lp.netloc != self.scope_domain:
                continue
            if any(lp.path.lower().endswith(ext) for ext in SKIP_EXT):
                continue
            all_urls.add(link)

        return resp, all_urls, extract_forms(html, url)

    def _normalize(self, url):
        parsed = urlparse(url)
        params = "&".join("{}=".format(k) for k in sorted(parse_qs(parsed.query).keys()))
        return "{}://{}{}?{}".format(parsed.scheme, parsed.netloc, parsed.path, params)
