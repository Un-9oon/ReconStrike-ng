import json
import re
from urllib.parse import urljoin

import requests

from scanner.log import logger

from scanner.core import Finding, Severity, ScanSession


def detect_api_endpoints(session: ScanSession) -> list[dict]:
    endpoints = []
    for url in session.crawled_urls:
        resp = session.get(url)
        if not resp:
            continue

        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type:
            endpoints.append({
                "url": url, "type": "REST",
                "content_type": content_type, "methods": ["GET"],
            })

        seen = {e["url"] for e in endpoints}
        for path in set(re.findall(r'["\'](/api/v?\d*/?[^"\'?\s#]+)["\']', resp.text)):
            full_url = urljoin(session.config.target, path)
            if full_url not in seen:
                endpoints.append({"url": full_url, "type": "REST", "content_type": "", "methods": []})
                seen.add(full_url)

    return endpoints


def scan_api_endpoints(session: ScanSession):
    logger.info("Scanning API endpoints...")
    endpoints = detect_api_endpoints(session)
    if not endpoints:
        logger.info("No API endpoints detected.")
        return

    logger.info("Found %d API endpoints", len(endpoints))
    checks = [_check_api_auth, _check_api_cors, _check_api_rate_limit,
              _check_api_methods, _check_api_versioning, _check_api_verbose_errors]
    for ep in endpoints:
        for check in checks:
            check(session, ep)


def _check_api_auth(session: ScanSession, endpoint: dict):
    import requests as _requests
    unauth = _requests.Session()
    unauth.verify = session.config.verify_ssl
    unauth.headers.update({"User-Agent": session.config.user_agent})
    if session.config.proxy:
        unauth.proxies.update({"http": session.config.proxy, "https": session.config.proxy})

    try:
        resp = unauth.get(endpoint["url"], timeout=session.config.timeout)
    except (requests.RequestException, ValueError):
        return

    if resp.status_code != 200 or "application/json" not in resp.headers.get("Content-Type", ""):
        return
    try:
        data = resp.json()
        if isinstance(data, (list, dict)) and data:
            auth_resp = session.get(endpoint["url"])
            if auth_resp and auth_resp.text == resp.text:
                session.add_finding(Finding(
                    title="API Endpoint Accessible Without Authentication",
                    severity=Severity.HIGH,
                    description="API endpoint {} returns data without authentication.".format(endpoint['url']),
                    evidence="URL: {}\nStatus: 200\nReturns JSON data without auth headers.".format(endpoint['url']),
                    remediation="Require authentication for all API endpoints. Use API keys, OAuth, or JWT.",
                    url=endpoint["url"], module="api", cwe="CWE-306", confirmed=True,
                ))
    except (json.JSONDecodeError, ValueError):
        pass


def _check_api_cors(session: ScanSession, endpoint: dict):
    resp = session.get(endpoint["url"], headers={"Origin": "https://evil-test.com"})
    if not resp:
        return

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "https://evil-test.com" and acac.lower() == "true":
        session.add_finding(Finding(
            title="API CORS: Origin Reflection with Credentials",
            severity=Severity.HIGH,
            description="API endpoint reflects arbitrary Origin with credentials allowed.",
            evidence="URL: {}\nACAO: {}\nACAC: {}".format(endpoint['url'], acao, acac),
            remediation="Use strict Origin whitelisting for API endpoints.",
            url=endpoint["url"], module="api", cwe="CWE-942", confirmed=True,
        ))


def _check_api_rate_limit(session: ScanSession, endpoint: dict):
    resp = session.get(endpoint["url"])
    if not resp:
        return

    rate_headers = ["X-RateLimit-Limit", "X-Rate-Limit-Limit",
                    "RateLimit-Limit", "Retry-After", "X-RateLimit-Remaining"]
    resp_lower = {k.lower() for k in resp.headers}
    if not any(h.lower() in resp_lower for h in rate_headers):
        session.add_finding(Finding(
            title="API Missing Rate Limiting Headers", severity=Severity.LOW,
            description="API endpoint does not return rate limiting headers.",
            evidence="URL: {}\nNo X-RateLimit-* or RateLimit-* headers found.".format(endpoint['url']),
            remediation="Implement rate limiting on all API endpoints.",
            url=endpoint["url"], module="api", cwe="CWE-770", confirmed=True,
        ))


def _check_api_methods(session: ScanSession, endpoint: dict):
    dangerous = []
    for method in ["PUT", "DELETE", "PATCH"]:
        try:
            resp = session.session.request(
                method, endpoint["url"],
                timeout=session.config.timeout, verify=session.config.verify_ssl,
            )
            if resp.status_code not in (404, 405, 501):
                dangerous.append((method, resp.status_code))
        except (requests.RequestException, ValueError):
            pass

    if dangerous:
        methods_str = ", ".join("{}({})".format(m, s) for m, s in dangerous)
        session.add_finding(Finding(
            title="API Accepts Dangerous Methods: {}".format(methods_str),
            severity=Severity.INFO,
            description="API endpoint accepts: {}.".format(methods_str),
            evidence="URL: {}\nMethods: {}".format(endpoint['url'], methods_str),
            remediation="Ensure destructive HTTP methods require proper authorization.",
            url=endpoint["url"], module="api", cwe="CWE-284", confirmed=True,
        ))


def _check_api_versioning(session: ScanSession, endpoint: dict):
    url = endpoint["url"]
    version_match = re.search(r'/api/v(\d+)/', url)
    if not version_match:
        return

    current_ver = int(version_match.group(1))
    if current_ver <= 1:
        return

    for old_ver in range(1, current_ver):
        old_url = url.replace("/v{}/".format(current_ver), "/v{}/".format(old_ver))
        resp = session.get(old_url)
        if resp and resp.status_code == 200 and "json" in resp.headers.get("Content-Type", ""):
            session.add_finding(Finding(
                title="Old API Version Still Accessible: v{}".format(old_ver),
                severity=Severity.LOW,
                description="API v{} is still accessible. Old versions may lack security patches.".format(old_ver),
                evidence="Current: {}\nOld: {}\nStatus: 200".format(url, old_url),
                remediation="Deprecate and disable old API versions. Redirect to current version.",
                url=old_url, module="api", cwe="CWE-1104", confirmed=True,
            ))
            break


def _check_api_verbose_errors(session: ScanSession, endpoint: dict):
    test_payloads = [
        ("{}?id=abc'\"".format(endpoint['url']), "Invalid input"),
        ("{}/../../etc/passwd".format(endpoint['url']), "Path traversal"),
    ]
    verbose_indicators = ["stack", "traceback", "exception", "debug",
                          "line ", "file ", "at /", "at \\"]

    for test_url, desc in test_payloads:
        resp = session.get(test_url)
        if not resp or "json" not in resp.headers.get("Content-Type", ""):
            continue
        try:
            error_text = json.dumps(resp.json()).lower()
            if any(ind in error_text for ind in verbose_indicators):
                session.add_finding(Finding(
                    title="API Verbose Error Response", severity=Severity.MEDIUM,
                    description="API returns detailed error information including stack traces or file paths.",
                    evidence="URL: {}\nError contains: {}".format(test_url, error_text[:200]),
                    remediation="Return generic error messages in production. Log details server-side only.",
                    url=endpoint["url"], module="api", cwe="CWE-209", confirmed=True,
                ))
                return
        except (json.JSONDecodeError, ValueError):
            pass
