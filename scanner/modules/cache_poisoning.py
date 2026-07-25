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
    "X-Cache",
    "X-Cache-Status",
    "CF-Cache-Status",
    "X-Varnish",
    "Age",
    "X-Served-By",
    "X-Cache-Hits",
    "X-Proxy-Cache",
    "Fastly-Debug-Digest",
    "X-CDN",
    "X-Akamai-Request-ID",
    "X-Cache-Key",
]


def _generate_nonce():
    """Generate a unique nonce for cache busting and payload tracking."""
    return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]


def _build_curl_header(method, url, header_name, header_value):
    cmd = f"curl -k -X {method} '{url}' -H '{header_name}: {header_value}'"
    return cmd


def _get_cache_info(resp):
    """Extract caching information from response headers."""
    if not resp:
        return {}

    info = {}
    for header in CACHE_INDICATOR_HEADERS:
        value = resp.headers.get(header)
        if value:
            info[header] = value

    # Parse Cache-Control
    cc = resp.headers.get("Cache-Control", "")
    if cc:
        info["Cache-Control"] = cc
        info["is_cacheable"] = not any(
            d in cc.lower() for d in ("no-store", "no-cache", "private")
        )
    else:
        info["is_cacheable"] = None

    # Check for Set-Cookie (cached responses with Set-Cookie are a risk)
    if resp.headers.get("Set-Cookie"):
        info["has_set_cookie"] = True

    return info


def _is_cached_response(cache_info):
    """Determine if the response appears to be served from cache."""
    cache_status = cache_info.get("X-Cache", "").upper()
    if "HIT" in cache_status:
        return True

    cache_status = cache_info.get("X-Cache-Status", "").upper()
    if "HIT" in cache_status:
        return True

    cf_status = cache_info.get("CF-Cache-Status", "").upper()
    if cf_status == "HIT":
        return True

    age = cache_info.get("Age")
    if age and int(age) > 0:
        return True

    hits = cache_info.get("X-Cache-Hits")
    if hits and int(hits) > 0:
        return True

    return False


def _is_value_reflected(resp_text, value):
    """Check if the injected value appears in the response body."""
    if not resp_text or not value:
        return False
    return value in resp_text


def _test_unkeyed_headers(session, url):
    """Test if unkeyed headers are reflected in cached responses."""
    parsed = urlparse(url)
    nonce = _generate_nonce()

    # Get a clean baseline
    baseline = session.get(url)
    if not baseline:
        return

    baseline_cache = _get_cache_info(baseline)

    for payload_info in UNKEYED_HEADER_PAYLOADS:
        header_name = payload_info["header"]
        header_value = payload_info["value"].replace("{nonce}", nonce)

        try:
            # Send request with the unkeyed header and a cache buster
            # to ensure we get a fresh response
            cache_buster = f"cb={_generate_nonce()}"
            if "?" in url:
                busted_url = f"{url}&{cache_buster}"
            else:
                busted_url = f"{url}?{cache_buster}"

            resp = session.get(busted_url, headers={header_name: header_value})
            if not resp:
                continue

            reflected = _is_value_reflected(resp.text, header_value)
            cache_info = _get_cache_info(resp)

            if not reflected:
                # For scheme/proto headers, check for redirect or scheme change
                if header_name in ("X-Forwarded-Scheme", "X-Forwarded-Proto"):
                    if resp.status_code in (301, 302) and header_value in str(resp.headers):
                        reflected = True
                # For port header, check if port appears in generated URLs
                if header_name == "X-Forwarded-Port":
                    if f":{header_value}" in resp.text:
                        reflected = True

            if not reflected:
                continue

            # The header value is reflected. Now check if it gets cached.
            # Send the same request again without the header to see if the
            # poisoned response is served from cache.
            is_cached = False
            second_resp = session.get(busted_url)
            if second_resp:
                second_cache = _get_cache_info(second_resp)
                if _is_cached_response(second_cache):
                    # Check if the poisoned value persists in the cached response
                    if _is_value_reflected(second_resp.text, header_value):
                        is_cached = True

            severity = Severity.HIGH if is_cached else Severity.MEDIUM
            confirmed = is_cached

            curl_cmd = _build_curl_header("GET", url, header_name, header_value)

            # Extract the reflected snippet
            snippet = ""
            idx = resp.text.find(header_value)
            if idx >= 0:
                start = max(0, idx - 60)
                end = min(len(resp.text), idx + len(header_value) + 60)
                snippet = resp.text[start:end].replace('\n', ' ').strip()

            session.add_finding(Finding(
                title=(
                    f"Web Cache Poisoning via {header_name}"
                    + (" (Cached)" if is_cached else " (Reflected)")
                ),
                severity=severity,
                description=(
                    f"The unkeyed header '{header_name}' is reflected in the response from "
                    f"'{parsed.path}'. {payload_info['description']}. "
                    + (
                        f"The poisoned response was confirmed to be cached and served to "
                        f"subsequent visitors, making this a confirmed cache poisoning vulnerability."
                        if is_cached else
                        f"While the value is reflected, cache poisoning could not be confirmed "
                        f"in this test. The vulnerability may still be exploitable if caching "
                        f"is enabled on a CDN or proxy layer."
                    )
                ),
                evidence=(
                    f"Target URL: {url}\n"
                    f"Header: {header_name}: {header_value}\n"
                    f"Reflected in Response: Yes\n"
                    f"Reflected Snippet: {snippet}\n"
                    f"Response Status: {resp.status_code}\n"
                    f"Cache Poisoned: {is_cached}\n"
                    f"Cache Headers: {cache_info}"
                ),
                remediation=(
                    f"1. Do not use the '{header_name}' header value in responses without "
                    f"including it in the cache key.\n"
                    f"2. Configure the cache to include '{header_name}' in the Vary header.\n"
                    "3. Strip or ignore unrecognized headers at the edge/CDN layer.\n"
                    "4. Use Cache-Control: no-store for responses that include user-influenced data.\n"
                    "5. Configure the CDN/cache to normalize or reject unexpected headers."
                ),
                url=url,
                module="cache_poisoning",
                cwe="CWE-349",
                confirmed=confirmed,
                location=f"Response generation at {parsed.path}",
                parameter=header_name,
                payload=f"{header_name}: {header_value}",
                request_method="GET",
                request_headers=f"{header_name}: {header_value}",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Send a GET request to {url} with the header:\n"
                    f"   {header_name}: {header_value}\n"
                    f"2. Check if the value appears in the response body.\n"
                    f"3. Send a normal GET to the same URL and check if the poisoned "
                    f"response is served from cache.\n"
                    f"4. Run: {curl_cmd}\n"
                    f"5. Then immediately: curl -k '{url}' (check for cached poison)"
                ),
                developer_fix=(
                    f"Server-side code at {parsed.path}:\n\n"
                    f"Do not trust or reflect the '{header_name}' header:\n\n"
                    f"  VULNERABLE:\n"
                    f"    host = req.headers['{header_name}'] || req.headers['host']\n"
                    f"    res.send(`<link href=\"https://${{host}}/style.css\">`)\n\n"
                    f"  SECURE:\n"
                    f"    // Use a configured, trusted hostname\n"
                    f"    const host = config.PUBLIC_HOST;\n"
                    f"    res.set('Vary', '{header_name}');  // If you must use it\n"
                    f"    res.send(`<link href=\"https://${{host}}/style.css\">`)"
                ),
                affected_component=f"Response generation and caching at {parsed.path}",
                references=(
                    "https://portswigger.net/research/practical-web-cache-poisoning | "
                    "https://portswigger.net/web-security/web-cache-poisoning | "
                    "https://cwe.mitre.org/data/definitions/349.html"
                ),
                detection_method=(
                    f"Injected '{header_name}: {header_value}' as an unkeyed header and "
                    f"detected the value reflected in the response body"
                    + (". Confirmed poisoned response was cached and served to subsequent "
                       "requests without the header." if is_cached else ".")
                ),
            ))

        except Exception as e:
            logger.debug("cache_poisoning _test_unkeyed_headers: operation failed: %s", e)
            continue


def _test_parameter_cloaking(session, url):
    """Test for parameter cloaking (using semicolons, encoding, or duplicate params)."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    nonce = _generate_nonce()

    for param, values in params.items():
        original = values[0] if values else ""

        # Test semicolon-separated parameters (some caches treat ; as & but apps don't)
        cloaked_url = f"{url};poisoned={nonce}"
        try:
            resp = session.get(cloaked_url)
            if not resp:
                continue

            if _is_value_reflected(resp.text, nonce):
                cache_info = _get_cache_info(resp)

                # Check if this gets cached under the original URL's cache key
                # (cache may ignore the semicolon parameter)
                clean_resp = session.get(url)
                cached_poison = False
                if clean_resp and _is_value_reflected(clean_resp.text, nonce):
                    cached_poison = True

                if cached_poison or _is_cached_response(cache_info):
                    curl_cmd = f"curl -k '{cloaked_url}'"
                    session.add_finding(Finding(
                        title="Web Cache Poisoning via Parameter Cloaking (Semicolon)",
                        severity=Severity.HIGH,
                        description=(
                            f"The URL '{parsed.path}' is vulnerable to parameter cloaking using "
                            f"semicolons. The cache treats the semicolon-separated parameter as "
                            f"part of the path (unkeyed), but the application processes it as a "
                            f"query parameter. This allows an attacker to inject parameters that "
                            f"bypass cache key computation."
                        ),
                        evidence=(
                            f"Target URL: {url}\n"
                            f"Cloaked URL: {cloaked_url}\n"
                            f"Injected Value Reflected: Yes (nonce: {nonce})\n"
                            f"Cached Poison: {cached_poison}\n"
                            f"Cache Headers: {cache_info}\n"
                            f"Response Status: {resp.status_code}"
                        ),
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
                        location=f"URL parsing at {parsed.path}",
                        parameter="semicolon-cloaked parameter",
                        payload=f";poisoned={nonce}",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Send: {curl_cmd}\n"
                            f"2. Check if the nonce '{nonce}' appears in the response.\n"
                            f"3. Send a normal request to {url} and check if the poisoned "
                            f"response is cached.\n"
                            f"4. Compare cache keys between the cloaked and normal URLs."
                        ),
                        developer_fix=(
                            "Normalize URL parsing at the edge:\n\n"
                            "  Nginx:\n"
                            "    # Strip semicolons from cache key\n"
                            "    set $cache_key $scheme$request_method$host$uri$is_args$args;\n\n"
                            "  Varnish:\n"
                            "    # Normalize URL before cache lookup\n"
                            "    set req.url = regsuball(req.url, \";.*$\", \"\");"
                        ),
                        affected_component=f"Cache key computation at {parsed.netloc}",
                        references=(
                            "https://portswigger.net/research/web-cache-entanglement | "
                            "https://portswigger.net/web-security/web-cache-poisoning"
                        ),
                        detection_method=(
                            f"Appended a semicolon-separated parameter (;poisoned={nonce}) to "
                            f"the URL and detected the value reflected in the response, "
                            f"indicating the cache and application parse the URL differently."
                        ),
                    ))
                    return
        except Exception as e:
            logger.debug("cache_poisoning _test_parameter_cloaking: operation failed: %s", e)
            continue


def _test_fat_get(session, url):
    """Test for fat GET attacks (GET request with body parameters)."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    nonce = _generate_nonce()

    for param, values in params.items():
        original = values[0] if values else ""

        try:
            # Send a GET request with a body that overrides a query parameter
            fat_data = {param: f"poisoned-{nonce}"}
            resp = session.get(url, data=fat_data)
            if not resp:
                continue

            if _is_value_reflected(resp.text, f"poisoned-{nonce}"):
                cache_info = _get_cache_info(resp)

                curl_cmd = f"curl -k -X GET '{url}' -d '{param}=poisoned-{nonce}'"
                session.add_finding(Finding(
                    title="Web Cache Poisoning via Fat GET Request",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The endpoint '{parsed.path}' processes body parameters in GET requests. "
                        f"When the parameter '{param}' was sent in the GET body with a different "
                        f"value than in the query string, the body value was reflected. If the "
                        f"cache keys only on the URL (ignoring the body), an attacker can poison "
                        f"the cache by sending a GET with a malicious body."
                    ),
                    evidence=(
                        f"Target URL: {url}\n"
                        f"Parameter: {param}\n"
                        f"Query Value: {original}\n"
                        f"Body Value: poisoned-{nonce}\n"
                        f"Body Value Reflected: Yes\n"
                        f"Cache Headers: {cache_info}\n"
                        f"Response Status: {resp.status_code}"
                    ),
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
                    location=f"Request body parsing at {parsed.path}",
                    parameter=param,
                    payload=f"{param}=poisoned-{nonce} (in GET body)",
                    request_method="GET",
                    request_body=f"{param}=poisoned-{nonce}",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Run: {curl_cmd}\n"
                        f"2. Check if 'poisoned-{nonce}' appears in the response instead "
                        f"of the original value '{original}'.\n"
                        f"3. Send a normal GET to {url} and check if the poisoned response "
                        f"is served from cache.\n"
                        f"4. If cached, the cache keys on URL only, not the body."
                    ),
                    developer_fix=(
                        f"Handler for GET {parsed.path}:\n\n"
                        "Do not read body parameters in GET handlers:\n\n"
                        "  Express.js:\n"
                        "    app.get('/path', (req, res) => {\n"
                        "      const value = req.query.param;  // OK\n"
                        "      // NOT: req.body.param  // Dangerous in GET\n"
                        "    });\n\n"
                        "  Flask:\n"
                        "    @app.route('/path')\n"
                        "    def handler():\n"
                        "        value = request.args.get('param')  # OK\n"
                        "        # NOT: request.form.get('param')  # Dangerous in GET"
                    ),
                    affected_component=f"GET request body parsing at {parsed.path}",
                    references=(
                        "https://portswigger.net/research/web-cache-entanglement | "
                        "https://portswigger.net/web-security/web-cache-poisoning"
                    ),
                    detection_method=(
                        f"Sent a GET request with a body parameter ({param}=poisoned-{nonce}) "
                        f"that differed from the query string value. The body value was reflected "
                        f"in the response, indicating the application processes GET bodies."
                    ),
                ))
                return

        except Exception as e:
            logger.debug("cache_poisoning _test_fat_get: operation failed: %s", e)
            continue


def _test_cache_header_presence(session, url):
    """Report on caching infrastructure detected for the target."""
    parsed = urlparse(url)

    try:
        resp = session.get(url)
        if not resp:
            return

        cache_info = _get_cache_info(resp)
        if not cache_info:
            return

        # Only report if we actually found cache-related headers
        cache_headers_found = {
            k: v for k, v in cache_info.items()
            if k in CACHE_INDICATOR_HEADERS and v
        }

        if not cache_headers_found:
            return

        # Check for risky caching configurations
        risks = []
        if cache_info.get("is_cacheable") is True:
            risks.append("Response is publicly cacheable")
        if cache_info.get("has_set_cookie"):
            risks.append("Cached response includes Set-Cookie header")
        if "Vary" not in resp.headers:
            risks.append("No Vary header (cache may not differentiate by request headers)")

        if not risks:
            return

        curl_cmd = f"curl -k -I '{url}'"
        session.add_finding(Finding(
            title="Caching Infrastructure Detected with Risky Configuration",
            severity=Severity.INFO,
            description=(
                f"The endpoint '{parsed.path}' is served through a caching layer with "
                f"potentially risky configuration. The following cache-related headers were "
                f"detected: {', '.join(cache_headers_found.keys())}. Misconfigurations in "
                f"caching can lead to cache poisoning, sensitive data leakage, or session fixation."
            ),
            evidence=(
                f"Target URL: {url}\n"
                f"Cache Headers:\n"
                + "\n".join(f"  {k}: {v}" for k, v in cache_headers_found.items())
                + f"\nCache-Control: {cache_info.get('Cache-Control', 'not set')}\n"
                f"Vary: {resp.headers.get('Vary', 'not set')}\n"
                f"Risks:\n"
                + "\n".join(f"  - {r}" for r in risks)
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
            location=f"Caching configuration at {parsed.netloc}",
            request_method="GET",
            response_status=resp.status_code,
            curl_command=curl_cmd,
            reproduction_steps=(
                f"1. Run: {curl_cmd}\n"
                f"2. Inspect the response headers for cache indicators.\n"
                f"3. Check Cache-Control, Vary, and X-Cache headers.\n"
                f"4. Look for Set-Cookie in cached responses."
            ),
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
            affected_component=f"Caching layer at {parsed.netloc}",
            references=(
                "https://portswigger.net/web-security/web-cache-poisoning | "
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching"
            ),
            detection_method=(
                "Analyzed response headers for cache infrastructure indicators and "
                "identified risky caching configurations: " + "; ".join(risks)
            ),
        ))
    except Exception as e:
        logger.debug("cache_poisoning _test_cache_header_presence: operation failed: %s", e)


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Web Cache Poisoning...")

    tested_paths = set()
    for url in session.crawled_urls:
        parsed = urlparse(url)
        path_key = f"{parsed.netloc}{parsed.path}"

        # Avoid testing the same path multiple times with different query params
        if path_key in tested_paths:
            continue
        tested_paths.add(path_key)

        _test_unkeyed_headers(session, url)
        _test_parameter_cloaking(session, url)
        _test_fat_get(session, url)
        _test_cache_header_presence(session, url)
