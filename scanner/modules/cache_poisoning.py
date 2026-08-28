import re
import hashlib
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession, build_curl


UNKEYED_HEADER_PAYLOADS = [
    {
        "header": "X-Forwarded-Host",
        "value": "poisoned-cache-{nonce}.evil.com",
        "description": "X-Forwarded-Host: commonly used by reverse proxies to indicate the original host",
    },
    {
        "header": "X-Original-URL",
        "value": "/poisoned-{nonce}",
        "description": "X-Original-URL: used by some frameworks (IIS/Symfony) to override the request path",
    },
    {
        "header": "X-Rewrite-URL",
        "value": "/poisoned-{nonce}",
        "description": "X-Rewrite-URL: similar to X-Original-URL, used for URL rewriting",
    },
    {
        "header": "X-Forwarded-Scheme",
        "value": "nothttps",
        "description": "X-Forwarded-Scheme: used to indicate the original protocol",
    },
    {
        "header": "X-Forwarded-Proto",
        "value": "nothttps",
        "description": "X-Forwarded-Proto: indicates the protocol used by the client",
    },
    {
        "header": "X-Host",
        "value": "poisoned-cache-{nonce}.evil.com",
        "description": "X-Host: alternative host header used by some load balancers",
    },
    {
        "header": "X-Forwarded-Server",
        "value": "poisoned-cache-{nonce}.evil.com",
        "description": "X-Forwarded-Server: identifies the server name of the proxy",
    },
    {
        "header": "X-HTTP-Method-Override",
        "value": "POST",
        "description": "X-HTTP-Method-Override: overrides the HTTP method, may cause cache key confusion",
    },
    {
        "header": "X-Forwarded-Port",
        "value": "1337",
        "description": "X-Forwarded-Port: overrides the port, may be reflected in generated URLs",
    },
]

CACHE_INDICATOR_HEADERS = [
    "X-Cache", "X-Cache-Status", "CF-Cache-Status", "X-Varnish",
    "Age", "X-Served-By", "X-Cache-Hits", "X-Proxy-Cache",
    "Fastly-Debug-Digest", "X-CDN", "X-Akamai-Request-ID", "X-Cache-Key",
]


def _generate_nonce():
    return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]


def _build_curl_header(method, url, header_name, header_value):
    return "curl -k -X {} '{}' -H '{}: {}'".format(method, url, header_name, header_value)


def _get_cache_info(resp):
    if not resp:
        return {}

    info = {h: resp.headers.get(h) for h in CACHE_INDICATOR_HEADERS if resp.headers.get(h)}

    cc = resp.headers.get("Cache-Control", "")
    if cc:
        info["Cache-Control"] = cc
        info["is_cacheable"] = not any(d in cc.lower() for d in ("no-store", "no-cache", "private"))
    else:
        info["is_cacheable"] = None

    if resp.headers.get("Set-Cookie"):
        info["has_set_cookie"] = True

    return info


def _is_cached_response(cache_info):
    for key in ("X-Cache", "X-Cache-Status"):
        if "HIT" in cache_info.get(key, "").upper():
            return True
    if cache_info.get("CF-Cache-Status", "").upper() == "HIT":
        return True
    for key in ("Age", "X-Cache-Hits"):
        val = cache_info.get(key)
        if val and int(val) > 0:
            return True
    return False


def _test_unkeyed_headers(session, url):
    parsed = urlparse(url)
    nonce = _generate_nonce()

    baseline = session.get(url)
    if not baseline:
        return

    for payload_info in UNKEYED_HEADER_PAYLOADS:
        header_name = payload_info["header"]
        header_value = payload_info["value"].replace("{nonce}", nonce)

        try:
            cache_buster = "cb={}".format(_generate_nonce())
            busted_url = "{}&{}".format(url, cache_buster) if "?" in url else "{}?{}".format(url, cache_buster)

            resp = session.get(busted_url, headers={header_name: header_value})
            if not resp:
                continue

            reflected = header_value in (resp.text or "")

            if not reflected:
                if header_name in ("X-Forwarded-Scheme", "X-Forwarded-Proto"):
                    if resp.status_code in (301, 302) and header_value in str(resp.headers):
                        reflected = True
                if header_name == "X-Forwarded-Port" and ":{}".format(header_value) in resp.text:
                    reflected = True

            if not reflected:
                continue

            # Check if the poisoned response gets cached
            is_cached = False
            second_resp = session.get(busted_url)
            if second_resp:
                second_cache = _get_cache_info(second_resp)
                if _is_cached_response(second_cache) and header_value in (second_resp.text or ""):
                    is_cached = True

            severity = Severity.HIGH if is_cached else Severity.MEDIUM
            curl_cmd = _build_curl_header("GET", url, header_name, header_value)

            snippet = ""
            idx = resp.text.find(header_value)
            if idx >= 0:
                start = max(0, idx - 60)
                end = min(len(resp.text), idx + len(header_value) + 60)
                snippet = resp.text[start:end].replace('\n', ' ').strip()

            cache_info = _get_cache_info(resp)

            session.add_finding(Finding(
                title="Web Cache Poisoning via {}{}".format(
                    header_name, " (Cached)" if is_cached else " (Reflected)"),
                severity=severity,
                description=(
                    "The unkeyed header '{}' is reflected in the response from "
                    "'{}'. {}. {}"
                ).format(
                    header_name, parsed.path, payload_info['description'],
                    "The poisoned response was confirmed to be cached and served to "
                    "subsequent visitors, making this a confirmed cache poisoning vulnerability."
                    if is_cached else
                    "While the value is reflected, cache poisoning could not be confirmed "
                    "in this test. The vulnerability may still be exploitable if caching "
                    "is enabled on a CDN or proxy layer."
                ),
                evidence=(
                    "Target URL: {}\n"
                    "Header: {}: {}\n"
                    "Reflected in Response: Yes\n"
                    "Reflected Snippet: {}\n"
                    "Response Status: {}\n"
                    "Cache Poisoned: {}\n"
                    "Cache Headers: {}"
                ).format(url, header_name, header_value, snippet,
                         resp.status_code, is_cached, cache_info),
                remediation=(
                    "1. Do not use the '{}' header value in responses without "
                    "including it in the cache key.\n"
                    "2. Configure the cache to include '{}' in the Vary header.\n"
                    "3. Strip or ignore unrecognized headers at the edge/CDN layer.\n"
                    "4. Use Cache-Control: no-store for responses that include user-influenced data.\n"
                    "5. Configure the CDN/cache to normalize or reject unexpected headers."
                ).format(header_name, header_name),
                url=url,
                module="cache_poisoning",
                cwe="CWE-349",
                confirmed=is_cached,
                location="Response generation at {}".format(parsed.path),
                parameter=header_name,
                payload="{}: {}".format(header_name, header_value),
                request_method="GET",
                request_headers="{}: {}".format(header_name, header_value),
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Send a GET request to {} with the header:\n"
                    "   {}: {}\n"
                    "2. Check if the value appears in the response body.\n"
                    "3. Send a normal GET to the same URL and check if the poisoned "
                    "response is served from cache.\n"
                    "4. Run: {}\n"
                    "5. Then immediately: curl -k '{}' (check for cached poison)"
                ).format(url, header_name, header_value, curl_cmd, url),
                developer_fix=(
                    "Server-side code at {path}:\n\n"
                    "Do not trust or reflect the '{h}' header:\n\n"
                    "  VULNERABLE:\n"
                    "    host = req.headers['{h}'] || req.headers['host']\n"
                    "    res.send(`<link href=\"https://${{host}}/style.css\">`)\n\n"
                    "  SECURE:\n"
                    "    const host = config.PUBLIC_HOST;\n"
                    "    res.set('Vary', '{h}');\n"
                    "    res.send(`<link href=\"https://${{host}}/style.css\">`)"
                ).format(path=parsed.path, h=header_name),
                affected_component="Response generation and caching at {}".format(parsed.path),
                references=(
                    "https://portswigger.net/research/practical-web-cache-poisoning | "
                    "https://portswigger.net/web-security/web-cache-poisoning | "
                    "https://cwe.mitre.org/data/definitions/349.html"
                ),
                detection_method=(
                    "Injected '{}: {}' as an unkeyed header and "
                    "detected the value reflected in the response body{}"
                ).format(header_name, header_value,
                         ". Confirmed poisoned response was cached and served to subsequent "
                         "requests without the header." if is_cached else "."),
            ))

        except (OSError, ValueError) as e:
            logger.debug("cache_poisoning _test_unkeyed_headers: operation failed: %s", e)
            continue


def _test_parameter_cloaking(session, url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    nonce = _generate_nonce()

    for param in params:
        cloaked_url = "{};poisoned={}".format(url, nonce)
        try:
            resp = session.get(cloaked_url)
            if not resp or nonce not in (resp.text or ""):
                continue

            cache_info = _get_cache_info(resp)

            clean_resp = session.get(url)
            cached_poison = bool(clean_resp and nonce in (clean_resp.text or ""))

            if not cached_poison and not _is_cached_response(cache_info):
                continue

            curl_cmd = "curl -k '{}'".format(cloaked_url)
            session.add_finding(Finding(
                title="Web Cache Poisoning via Parameter Cloaking (Semicolon)",
                severity=Severity.HIGH,
                description=(
                    "The URL '{}' is vulnerable to parameter cloaking using "
                    "semicolons. The cache treats the semicolon-separated parameter as "
                    "part of the path (unkeyed), but the application processes it as a "
                    "query parameter. This allows an attacker to inject parameters that "
                    "bypass cache key computation."
                ).format(parsed.path),
                evidence=(
                    "Target URL: {}\n"
                    "Cloaked URL: {}\n"
                    "Injected Value Reflected: Yes (nonce: {})\n"
                    "Cached Poison: {}\n"
                    "Cache Headers: {}\n"
                    "Response Status: {}"
                ).format(url, cloaked_url, nonce, cached_poison,
                         cache_info, resp.status_code),
                remediation=(
                    "1. Normalize URL parsing at the cache layer to treat semicolons "
                    "the same as the application.\n"
                    "2. Configure the cache to include the full URL (including semicolon "
                    "parameters) in the cache key.\n"
                    "3. Strip semicolons from URLs at the edge before caching.\n"
                    "4. Use Vary headers to include relevant parameters in the cache key."
                ),
                url=url,
                module="cache_poisoning",
                cwe="CWE-349",
                confirmed=cached_poison,
                location="URL parsing at {}".format(parsed.path),
                parameter="semicolon-cloaked parameter",
                payload=";poisoned={}".format(nonce),
                request_method="GET",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Send: {}\n"
                    "2. Check if the nonce '{}' appears in the response.\n"
                    "3. Send a normal request to {} and check if the poisoned "
                    "response is cached.\n"
                    "4. Compare cache keys between the cloaked and normal URLs."
                ).format(curl_cmd, nonce, url),
                developer_fix=(
                    "Normalize URL parsing at the edge:\n\n"
                    "  Nginx:\n"
                    "    set $cache_key $scheme$request_method$host$uri$is_args$args;\n\n"
                    "  Varnish:\n"
                    "    set req.url = regsuball(req.url, \";.*$\", \"\");"
                ),
                affected_component="Cache key computation at {}".format(parsed.netloc),
                references=(
                    "https://portswigger.net/research/web-cache-entanglement | "
                    "https://portswigger.net/web-security/web-cache-poisoning"
                ),
                detection_method=(
                    "Appended a semicolon-separated parameter (;poisoned={}) to "
                    "the URL and detected the value reflected in the response, "
                    "indicating the cache and application parse the URL differently."
                ).format(nonce),
            ))
            return
        except (OSError, ValueError) as e:
            logger.debug("cache_poisoning _test_parameter_cloaking: operation failed: %s", e)
            continue


def _test_fat_get(session, url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    nonce = _generate_nonce()

    for param, values in params.items():
        original = values[0] if values else ""
        poisoned_val = "poisoned-{}".format(nonce)

        try:
            resp = session.get(url, data={param: poisoned_val})
            if not resp or poisoned_val not in (resp.text or ""):
                continue

            cache_info = _get_cache_info(resp)
            curl_cmd = "curl -k -X GET '{}' -d '{}={}'".format(url, param, poisoned_val)

            session.add_finding(Finding(
                title="Web Cache Poisoning via Fat GET Request",
                severity=Severity.MEDIUM,
                description=(
                    "The endpoint '{}' processes body parameters in GET requests. "
                    "When the parameter '{}' was sent in the GET body with a different "
                    "value than in the query string, the body value was reflected. If the "
                    "cache keys only on the URL (ignoring the body), an attacker can poison "
                    "the cache by sending a GET with a malicious body."
                ).format(parsed.path, param),
                evidence=(
                    "Target URL: {}\n"
                    "Parameter: {}\n"
                    "Query Value: {}\n"
                    "Body Value: {}\n"
                    "Body Value Reflected: Yes\n"
                    "Cache Headers: {}\n"
                    "Response Status: {}"
                ).format(url, param, original, poisoned_val,
                         cache_info, resp.status_code),
                remediation=(
                    "1. Do not process body parameters in GET requests.\n"
                    "2. Configure the web framework to ignore request bodies for GET/HEAD.\n"
                    "3. If the cache ignores GET bodies, ensure the app does too.\n"
                    "4. Reject GET requests that contain a body at the edge/proxy level."
                ),
                url=url,
                module="cache_poisoning",
                cwe="CWE-349",
                confirmed=False,
                location="Request body parsing at {}".format(parsed.path),
                parameter=param,
                payload="{}={} (in GET body)".format(param, poisoned_val),
                request_method="GET",
                request_body="{}={}".format(param, poisoned_val),
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Run: {}\n"
                    "2. Check if '{}' appears in the response instead "
                    "of the original value '{}'.\n"
                    "3. Send a normal GET to {} and check if the poisoned response "
                    "is served from cache.\n"
                    "4. If cached, the cache keys on URL only, not the body."
                ).format(curl_cmd, poisoned_val, original, url),
                developer_fix=(
                    "Handler for GET {path}:\n\n"
                    "Do not read body parameters in GET handlers:\n\n"
                    "  Express.js:\n"
                    "    app.get('/path', (req, res) => {{\n"
                    "      const value = req.query.param;  // OK\n"
                    "      // NOT: req.body.param  // Dangerous in GET\n"
                    "    }});\n\n"
                    "  Flask:\n"
                    "    @app.route('/path')\n"
                    "    def handler():\n"
                    "        value = request.args.get('param')  # OK\n"
                    "        # NOT: request.form.get('param')  # Dangerous in GET"
                ).format(path=parsed.path),
                affected_component="GET request body parsing at {}".format(parsed.path),
                references=(
                    "https://portswigger.net/research/web-cache-entanglement | "
                    "https://portswigger.net/web-security/web-cache-poisoning"
                ),
                detection_method=(
                    "Sent a GET request with a body parameter ({}={}) "
                    "that differed from the query string value. The body value was reflected "
                    "in the response, indicating the application processes GET bodies."
                ).format(param, poisoned_val),
            ))
            return

        except (OSError, ValueError) as e:
            logger.debug("cache_poisoning _test_fat_get: operation failed: %s", e)
            continue


def _test_cache_header_presence(session, url):
    parsed = urlparse(url)

    try:
        resp = session.get(url)
        if not resp:
            return

        cache_info = _get_cache_info(resp)
        cache_headers_found = {
            k: v for k, v in cache_info.items()
            if k in CACHE_INDICATOR_HEADERS and v
        }
        if not cache_headers_found:
            return

        risks = []
        if cache_info.get("is_cacheable") is True:
            risks.append("Response is publicly cacheable")
        if cache_info.get("has_set_cookie"):
            risks.append("Cached response includes Set-Cookie header")
        if "Vary" not in resp.headers:
            risks.append("No Vary header (cache may not differentiate by request headers)")

        if not risks:
            return

        curl_cmd = "curl -k -I '{}'".format(url)
        session.add_finding(Finding(
            title="Caching Infrastructure Detected with Risky Configuration",
            severity=Severity.INFO,
            description=(
                "The endpoint '{}' is served through a caching layer with "
                "potentially risky configuration. The following cache-related headers were "
                "detected: {}. Misconfigurations in "
                "caching can lead to cache poisoning, sensitive data leakage, or session fixation."
            ).format(parsed.path, ', '.join(cache_headers_found.keys())),
            evidence=(
                "Target URL: {}\n"
                "Cache Headers:\n{}\n"
                "Cache-Control: {}\n"
                "Vary: {}\n"
                "Risks:\n{}"
            ).format(
                url,
                "\n".join("  {}: {}".format(k, v) for k, v in cache_headers_found.items()),
                cache_info.get('Cache-Control', 'not set'),
                resp.headers.get('Vary', 'not set'),
                "\n".join("  - {}".format(r) for r in risks),
            ),
            remediation=(
                "1. Set appropriate Cache-Control headers (no-store for sensitive pages).\n"
                "2. Use Vary headers to differentiate cached responses by relevant request headers.\n"
                "3. Never cache responses that contain Set-Cookie headers.\n"
                "4. Review CDN/cache configuration to ensure proper key composition.\n"
                "5. Strip sensitive headers before caching (Authorization, Cookie)."
            ),
            url=url,
            module="cache_poisoning",
            cwe="CWE-349",
            confirmed=True,
            location="Caching configuration at {}".format(parsed.netloc),
            request_method="GET",
            response_status=resp.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Run: {}\n"
                "2. Inspect the response headers for cache indicators.\n"
                "3. Check Cache-Control, Vary, and X-Cache headers.\n"
                "4. Look for Set-Cookie in cached responses."
            ).format(curl_cmd),
            developer_fix=(
                "Cache configuration:\n\n"
                "  For sensitive pages:\n"
                "    Cache-Control: no-store, no-cache, must-revalidate, private\n\n"
                "  For public static assets:\n"
                "    Cache-Control: public, max-age=31536000, immutable\n"
                "    Vary: Accept-Encoding\n\n"
                "  Never cache responses with Set-Cookie:\n"
                "    Varnish: if (beresp.http.Set-Cookie) { set beresp.uncacheable = true; }"
            ),
            affected_component="Caching layer at {}".format(parsed.netloc),
            references=(
                "https://portswigger.net/web-security/web-cache-poisoning | "
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching"
            ),
            detection_method=(
                "Analyzed response headers for cache infrastructure indicators and "
                "identified risky caching configurations: {}".format("; ".join(risks))
            ),
        ))
    except (OSError, ValueError) as e:
        logger.debug("cache_poisoning _test_cache_header_presence: operation failed: %s", e)


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for Web Cache Poisoning...")

    tested_paths = set()
    for url in session.crawled_urls:
        parsed = urlparse(url)
        path_key = "{}{}".format(parsed.netloc, parsed.path)

        if path_key in tested_paths:
            continue
        tested_paths.add(path_key)

        _test_unkeyed_headers(session, url)
        _test_parameter_cloaking(session, url)
        _test_fat_get(session, url)
        _test_cache_header_presence(session, url)
