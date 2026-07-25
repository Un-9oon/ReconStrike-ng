import json
import re
from urllib.parse import urljoin

from scanner.core import Finding, Severity, ScanSession


def detect_api_endpoints(session: ScanSession) -> list[dict]:
    """Discover REST/GraphQL API endpoints from crawled content."""
    endpoints = []

    for url in session.crawled_urls:
        resp = session.get(url)
        if not resp:
            continue

        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type:
            endpoints.append({
                "url": url,
                "type": "REST",
                "content_type": content_type,
                "methods": ["GET"],
            })

        api_patterns = re.findall(
            r'["\'](/api/v?\d*/?[^"\'?\s#]+)["\']', resp.text
        )
        for path in set(api_patterns):
            full_url = urljoin(session.config.target, path)
            if full_url not in {e["url"] for e in endpoints}:
                endpoints.append({
                    "url": full_url,
                    "type": "REST",
                    "content_type": "",
                    "methods": [],
                })

    return endpoints


def scan_api_endpoints(session: ScanSession):
    """Advanced API-specific security checks."""
    print("\n[*] Scanning API endpoints...")

    endpoints = detect_api_endpoints(session)
    if not endpoints:
        print("  [*] No API endpoints detected.")
        return

    print(f"  [+] Found {len(endpoints)} API endpoints")

    for ep in endpoints:
        _check_api_auth(session, ep)
        _check_api_cors(session, ep)
        _check_api_rate_limit(session, ep)
        _check_api_methods(session, ep)
        _check_api_versioning(session, ep)
        _check_api_verbose_errors(session, ep)


def _check_api_auth(session: ScanSession, endpoint: dict):
    import requests as _requests
    unauth_session = _requests.Session()
    unauth_session.verify = session.config.verify_ssl
    unauth_session.headers.update({"User-Agent": session.config.user_agent})
    if session.config.proxy:
        unauth_session.proxies.update({
            "http": session.config.proxy,
            "https": session.config.proxy,
        })

    try:
        resp = unauth_session.get(endpoint["url"], timeout=session.config.timeout)
    except Exception:
        return

    if resp.status_code == 200:
        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                data = resp.json()
                if isinstance(data, (list, dict)) and data:
                    auth_resp = session.get(endpoint["url"])
                    if auth_resp and auth_resp.text == resp.text:
                        session.add_finding(Finding(
                            title=f"API Endpoint Accessible Without Authentication",
                            severity=Severity.HIGH,
                            description=f"API endpoint {endpoint['url']} returns data without authentication.",
                            evidence=f"URL: {endpoint['url']}\nStatus: 200\nReturns JSON data without auth headers.",
                            remediation="Require authentication for all API endpoints. Use API keys, OAuth, or JWT.",
                            url=endpoint["url"],
                            module="api",
                            cwe="CWE-306",
                            confirmed=True,
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
            description=f"API endpoint reflects arbitrary Origin with credentials allowed.",
            evidence=f"URL: {endpoint['url']}\nACAO: {acao}\nACAC: {acac}",
            remediation="Use strict Origin whitelisting for API endpoints.",
            url=endpoint["url"],
            module="api",
            cwe="CWE-942",
            confirmed=True,
        ))


def _check_api_rate_limit(session: ScanSession, endpoint: dict):
    resp = session.get(endpoint["url"])
    if not resp:
        return

    rate_headers = [
        "X-RateLimit-Limit", "X-Rate-Limit-Limit",
        "RateLimit-Limit", "Retry-After",
        "X-RateLimit-Remaining",
    ]
    has_rate_limit = any(h.lower() in {k.lower() for k in resp.headers} for h in rate_headers)

    if not has_rate_limit:
        session.add_finding(Finding(
            title="API Missing Rate Limiting Headers",
            severity=Severity.LOW,
            description=f"API endpoint does not return rate limiting headers.",
            evidence=f"URL: {endpoint['url']}\nNo X-RateLimit-* or RateLimit-* headers found.",
            remediation="Implement rate limiting on all API endpoints.",
            url=endpoint["url"],
            module="api",
            cwe="CWE-770",
            confirmed=True,
        ))


def _check_api_methods(session: ScanSession, endpoint: dict):
    dangerous_results = []
    for method in ["PUT", "DELETE", "PATCH"]:
        try:
            resp = session.session.request(
                method, endpoint["url"],
                timeout=session.config.timeout, verify=session.config.verify_ssl
            )
            if resp.status_code not in (404, 405, 501):
                dangerous_results.append((method, resp.status_code))
        except Exception:
            pass

    if dangerous_results:
        methods_str = ", ".join(f"{m}({s})" for m, s in dangerous_results)
        session.add_finding(Finding(
            title=f"API Accepts Dangerous Methods: {methods_str}",
            severity=Severity.INFO,
            description=f"API endpoint accepts: {methods_str}.",
            evidence=f"URL: {endpoint['url']}\nMethods: {methods_str}",
            remediation="Ensure destructive HTTP methods require proper authorization.",
            url=endpoint["url"],
            module="api",
            cwe="CWE-284",
            confirmed=True,
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
        old_url = url.replace(f"/v{current_ver}/", f"/v{old_ver}/")
        resp = session.get(old_url)
        if resp and resp.status_code == 200:
            content_type = resp.headers.get("Content-Type", "")
            if "json" in content_type:
                session.add_finding(Finding(
                    title=f"Old API Version Still Accessible: v{old_ver}",
                    severity=Severity.LOW,
                    description=f"API v{old_ver} is still accessible. Old versions may lack security patches.",
                    evidence=f"Current: {url}\nOld: {old_url}\nStatus: 200",
                    remediation="Deprecate and disable old API versions. Redirect to current version.",
                    url=old_url,
                    module="api",
                    cwe="CWE-1104",
                    confirmed=True,
                ))
                break


def _check_api_verbose_errors(session: ScanSession, endpoint: dict):
    test_payloads = [
        (f"{endpoint['url']}?id=abc'\"", "Invalid input"),
        (f"{endpoint['url']}/../../etc/passwd", "Path traversal"),
    ]

    for test_url, desc in test_payloads:
        resp = session.get(test_url)
        if not resp:
            continue

        content_type = resp.headers.get("Content-Type", "")
        if "json" not in content_type:
            continue

        try:
            data = resp.json()
            error_text = json.dumps(data)
            verbose_indicators = [
                "stack", "traceback", "exception", "debug",
                "line ", "file ", "at /", "at \\",
            ]
            if any(ind in error_text.lower() for ind in verbose_indicators):
                session.add_finding(Finding(
                    title="API Verbose Error Response",
                    severity=Severity.MEDIUM,
                    description=f"API returns detailed error information including stack traces or file paths.",
                    evidence=f"URL: {test_url}\nError contains: {error_text[:200]}",
                    remediation="Return generic error messages in production. Log details server-side only.",
                    url=endpoint["url"],
                    module="api",
                    cwe="CWE-209",
                    confirmed=True,
                ))
                return
        except (json.JSONDecodeError, ValueError):
            pass
