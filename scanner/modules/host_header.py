"""
Host Header Injection Module for ReconStrike-ng

Tests for Host header injection, password-reset poisoning, and web cache
poisoning via Host header manipulation.
"""

from urllib.parse import urlparse
from scanner.core import ScanSession, Finding, Severity

EVIL_HOST = "evil-host-header-test.com"
FORWARDED_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
]


def run(session: ScanSession) -> None:
    """Entry point for the Host Header Injection scanner module."""
    tested_host_paths = set()

    for url in list(session.crawled_urls):
        parsed = urlparse(url)
        host_path = f"{parsed.netloc}{parsed.path}"
        if host_path not in tested_host_paths:
            tested_host_paths.add(host_path)
            _test_host_header_direct(session, url)
            _test_forwarded_headers(session, url)


def _test_host_header_direct(session: ScanSession, url: str) -> None:
    """Test replacing the Host header directly with an arbitrary domain."""
    parsed = urlparse(url)
    original_host = parsed.netloc

    headers = {"Host": EVIL_HOST}
    resp = session.get(url, headers=headers, allow_redirects=False)

    if not resp:
        return

    # Check 1: Reflected Host in response body (links, scripts, etc.)
    reflections = _find_reflections(resp.text, EVIL_HOST)
    if reflections:
        reflection = reflections[0]
        session.add_finding(Finding(
            module="host_header",
            title="Host Header Reflection / Injection",
            severity=Severity.HIGH,
            url=url,
            description=(
                f"The application at '{original_host}' reflects a manipulated Host header "
                f"value in its response. When the Host header was set to '{EVIL_HOST}', "
                f"the injected value appeared in the {reflection['location']}. "
                f"The injected host appears in a URL/link context, which could be exploited "
                f"for password reset poisoning, cache poisoning, or phishing."
            ),
            evidence=(
                f"URL: {url}\n"
                f"Original Host: {original_host}\n"
                f"Injected Host: {EVIL_HOST}\n"
                f"Reflection Location: {reflection['location']}\n"
                f"In Link/URL Context: {reflection['in_link']}\n"
                f"Response Status: {resp.status_code}\n"
                f"Context: {reflection['snippet']}"
            ),
            cwe="CWE-644",
            remediation=(
                "Validate the Host header against a whitelist of trusted domain names. "
                "Use relative URLs for links and redirects instead of absolute URLs built "
                "from the Host header."
            ),
        ))

    # Check 2: Host header reflected in redirect Location
    if resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("Location", "")
        if EVIL_HOST in location:
            session.add_finding(Finding(
                module="host_header",
                title="Host Header Injection in Redirect Location",
                severity=Severity.HIGH,
                url=url,
                description=(
                    f"The application uses the client-supplied Host header to construct "
                    f"redirect URLs. When the Host header was set to '{EVIL_HOST}', the "
                    f"Location header returned was '{location}'. An attacker can use this "
                    f"to redirect users to arbitrary external domains."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Original Host: {original_host}\n"
                    f"Injected Host: {EVIL_HOST}\n"
                    f"Location Header: {location}\n"
                    f"Response Status: {resp.status_code}"
                ),
                cwe="CWE-601",
                remediation=(
                    "Use relative URLs in Location headers, or validate the Host header "
                    "against an explicit whitelist before constructing redirect targets."
                ),
            ))


def _test_forwarded_headers(session: ScanSession, url: str) -> None:
    """Test override headers like X-Forwarded-Host for reflection/injection."""

    for header_name in FORWARDED_HEADERS:
        headers = {header_name: EVIL_HOST}
        resp = session.get(url, headers=headers, allow_redirects=False)

        if not resp:
            continue

        reflections = _find_reflections(resp.text, EVIL_HOST)
        if reflections:
            reflection = reflections[0]
            session.add_finding(Finding(
                module="host_header",
                title=f"Host Override via {header_name}",
                severity=Severity.HIGH,
                url=url,
                description=(
                    f"The application processes the '{header_name}' header and reflects "
                    f"its value in the response body. When '{header_name}' was set to "
                    f"'{EVIL_HOST}', the injected value was reflected. This indicates "
                    f"that backend components trust reverse-proxy headers without "
                    f"validation, enabling host header attack vectors."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Header Used: {header_name}\n"
                    f"Injected Host: {EVIL_HOST}\n"
                    f"Response Status: {resp.status_code}\n"
                    f"Context: {reflection['snippet']}"
                ),
                cwe="CWE-644",
                remediation=(
                    f"Disable support for '{header_name}' if reverse proxies are not in use, "
                    f"or ensure the front-end proxy strips or overrides unverified "
                    f"forwarded headers before passing requests to backend application servers."
                ),
            ))

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if EVIL_HOST in location:
                session.add_finding(Finding(
                    module="host_header",
                    title=f"Host Override via {header_name} in Redirect",
                    severity=Severity.HIGH,
                    url=url,
                    description=(
                        f"The application uses the '{header_name}' header value to build "
                        f"redirect URLs. Injected header value '{EVIL_HOST}' was reflected "
                        f"in the Location header: '{location}'."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"Header Used: {header_name}\n"
                        f"Injected Host: {EVIL_HOST}\n"
                        f"Location Header: {location}\n"
                        f"Response Status: {resp.status_code}"
                    ),
                    cwe="CWE-601",
                    remediation=(
                        f"Ensure '{header_name}' headers from untrusted clients are stripped "
                        f"by the edge proxy or web server."
                    ),
                ))


def _find_reflections(html_content: str, search_str: str) -> list:
    """Find occurrences of search_str in html_content and extract context."""
    results = []
    lower_html = html_content.lower()
    lower_search = search_str.lower()

    idx = 0
    while True:
        pos = lower_html.find(lower_search, idx)
        if pos == -1:
            break

        start = max(0, pos - 40)
        end = min(len(html_content), pos + len(search_str) + 40)
        snippet = html_content[start:end].replace("\n", " ").replace("\r", "")

        in_link = False
        tag_start = html_content.rfind("<", 0, pos)
        tag_end = html_content.find(">", pos)
        if tag_start != -1 and tag_end != -1 and tag_start < tag_end:
            tag_content = html_content[tag_start:tag_end + 1].lower()
            if any(attr in tag_content for attr in ("href=", "src=", "action=")):
                in_link = True

        location = "HTML attribute / URL context" if in_link else "response body text"

        results.append({
            "snippet": snippet,
            "in_link": in_link,
            "location": location,
        })

        idx = pos + len(search_str)

    return results
