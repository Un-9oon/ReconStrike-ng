import math
import string
import collections
from urllib.parse import urlparse

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession


COMMON_SESSION_NAMES = [
    "JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "session_id",
    "sessionid", "sid", "sess", "token", "connect.sid", "ci_session",
    "CFID", "CFTOKEN", "laravel_session", "_session_id", "rack.session",
]


def _calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not value:
        return 0.0
    freq = collections.Counter(value)
    length = len(value)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return entropy


def _find_session_cookies(cookies) -> list:
    """Identify session cookies from a cookie jar."""
    session_cookies = []
    for cookie in cookies:
        name_lower = cookie.name.lower()
        for known in COMMON_SESSION_NAMES:
            if known.lower() in name_lower:
                session_cookies.append(cookie)
                break
        else:
            if len(cookie.value) >= 16 and _calculate_entropy(cookie.value) > 3.0:
                session_cookies.append(cookie)
    return session_cookies


def _check_cookie_attributes(session: ScanSession, url: str) -> None:
    """Check session cookie security attributes."""
    resp = session.get(url)
    if not resp:
        return

    set_cookie_headers = resp.headers.get("Set-Cookie", "")
    if not set_cookie_headers:
        raw_headers = resp.raw._original_response.msg if hasattr(resp, "raw") else {}
        if hasattr(raw_headers, "getallmatchingheaders"):
            pass

    session_cookies = _find_session_cookies(resp.cookies)
    if not session_cookies:
        session_cookies = _find_session_cookies(session.session.cookies)

    if not session_cookies:
        return

    for cookie in session_cookies:
        issues = []
        parsed = urlparse(url)

        if not cookie.secure:
            issues.append("Missing 'Secure' flag - cookie sent over unencrypted HTTP")

        has_httponly = getattr(cookie, "_rest", {}).get("HttpOnly", None) is not None
        if not has_httponly:
            if hasattr(cookie, "has_nonstandard_attr"):
                has_httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")
            if not has_httponly:
                issues.append("Missing 'HttpOnly' flag - cookie accessible via JavaScript (XSS risk)")

        samesite = None
        if hasattr(cookie, "_rest"):
            for key in cookie._rest:
                if key.lower() == "samesite":
                    samesite = cookie._rest[key]
                    break
        if samesite is None:
            issues.append("Missing 'SameSite' attribute - vulnerable to CSRF via cross-site requests")
        elif str(samesite).lower() == "none":
            issues.append("SameSite=None - cookie sent on all cross-site requests (CSRF risk)")

        if cookie.path and cookie.path != "/":
            pass
        elif not cookie.path:
            issues.append("No explicit Path set - defaults to current directory")

        if cookie.domain and cookie.domain.startswith("."):
            parent_parts = cookie.domain.lstrip(".").split(".")
            if len(parent_parts) <= 2:
                issues.append(
                    f"Overly broad Domain='{cookie.domain}' - cookie shared across all subdomains"
                )

        if not issues:
            continue

        severity = Severity.MEDIUM
        if any("HttpOnly" in i for i in issues) or any("Secure" in i for i in issues):
            severity = Severity.HIGH

        curl_cmd = f"curl -k -v -I '{url}' 2>&1 | grep -i set-cookie"
        evidence_lines = [
            f"Cookie Name: {cookie.name}",
            f"Cookie Domain: {cookie.domain or '(not set)'}",
            f"Cookie Path: {cookie.path or '(not set)'}",
            f"Secure: {cookie.secure}",
            f"Issues found:",
        ] + [f"  - {issue}" for issue in issues]

        session.add_finding(Finding(
            title=f"Insecure Session Cookie: {cookie.name}",
            severity=severity,
            description=(
                f"The session cookie '{cookie.name}' is missing critical security attributes. "
                f"Found {len(issues)} issue(s): {'; '.join(issues)}."
            ),
            evidence="\n".join(evidence_lines),
            remediation=(
                "Set all security attributes on session cookies:\n"
                "  Set-Cookie: session=<value>; HttpOnly; Secure; SameSite=Lax; Path=/"
            ),
            url=url,
            module="session_security",
            cwe="CWE-614",
            confirmed=True,
            location=f"Set-Cookie header for '{cookie.name}'",
            curl_command=curl_cmd,
            reproduction_steps=(
                f"1. Send a GET request to {url}\n"
                f"2. Inspect Set-Cookie response headers\n"
                f"3. Check for HttpOnly, Secure, SameSite attributes on '{cookie.name}'\n"
                f"4. Run: {curl_cmd}"
            ),
            developer_fix=(
                "Configure your session middleware to set all security flags:\n\n"
                "PHP:\n"
                "  session.cookie_httponly = 1\n"
                "  session.cookie_secure = 1\n"
                "  session.cookie_samesite = Lax\n\n"
                "Express.js:\n"
                "  app.use(session({\n"
                "    cookie: { httpOnly: true, secure: true, sameSite: 'lax' }\n"
                "  }));\n\n"
                "Django:\n"
                "  SESSION_COOKIE_HTTPONLY = True\n"
                "  SESSION_COOKIE_SECURE = True\n"
                "  SESSION_COOKIE_SAMESITE = 'Lax'\n\n"
                "Java (Spring):\n"
                "  server.servlet.session.cookie.http-only=true\n"
                "  server.servlet.session.cookie.secure=true"
            ),
            affected_component="Session management / cookie configuration",
            references=(
                "https://owasp.org/www-community/controls/SecureCookieAttribute\n"
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"
            ),
            detection_method=(
                "Fetched the target URL and inspected Set-Cookie response headers for "
                "session-related cookies. Checked each cookie for HttpOnly, Secure, "
                "SameSite, Path, and Domain attributes."
            ),
        ))


def _check_session_fixation(session: ScanSession, url: str) -> None:
    """Test for session fixation vulnerability."""
    resp = session.get(url)
    if not resp:
        return

    session_cookies = _find_session_cookies(resp.cookies)
    if not session_cookies:
        session_cookies = _find_session_cookies(session.session.cookies)
    if not session_cookies:
        return

    for cookie in session_cookies:
        original_value = cookie.value

        fixed_session_id = "FIXATED_SESSION_" + "A" * 32
        session.session.cookies.set(cookie.name, fixed_session_id, domain=cookie.domain, path=cookie.path or "/")

        resp2 = session.get(url)
        if not resp2:
            session.session.cookies.set(cookie.name, original_value, domain=cookie.domain, path=cookie.path or "/")
            continue

        current_value = None
        for c in resp2.cookies:
            if c.name == cookie.name:
                current_value = c.value
                break
        if current_value is None:
            for c in session.session.cookies:
                if c.name == cookie.name:
                    current_value = c.value
                    break

        session.session.cookies.set(cookie.name, original_value, domain=cookie.domain, path=cookie.path or "/")

        if current_value == fixed_session_id:
            curl_cmd = (
                f"curl -k -v -b '{cookie.name}={fixed_session_id}' '{url}' "
                f"2>&1 | grep -i set-cookie"
            )
            session.add_finding(Finding(
                title=f"Session Fixation: {cookie.name}",
                severity=Severity.HIGH,
                description=(
                    f"The server accepts a client-supplied session ID in cookie '{cookie.name}' "
                    f"without regenerating it. An attacker can fixate a victim's session by "
                    f"setting a known session ID before the victim authenticates."
                ),
                evidence=(
                    f"Cookie: {cookie.name}\n"
                    f"Fixated Value Sent: {fixed_session_id}\n"
                    f"Value After Request: {current_value}\n"
                    f"Session ID was NOT regenerated by the server."
                ),
                remediation=(
                    "Always regenerate session IDs after authentication and privilege changes. "
                    "Reject unknown or externally-set session identifiers."
                ),
                url=url,
                module="session_security",
                cwe="CWE-384",
                confirmed=True,
                location=f"Session cookie '{cookie.name}'",
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Set a known session cookie: {cookie.name}={fixed_session_id}\n"
                    f"2. Send a request to {url} with the fixed session ID\n"
                    f"3. Observe that the server does not regenerate the session ID\n"
                    f"4. The attacker's known session ID persists, enabling session fixation\n"
                    f"5. Run: {curl_cmd}"
                ),
                developer_fix=(
                    "Regenerate the session ID on every authentication event:\n\n"
                    "PHP:\n"
                    "  session_regenerate_id(true);  // after login\n\n"
                    "Java:\n"
                    "  request.getSession().invalidate();\n"
                    "  request.getSession(true);  // new session after login\n\n"
                    "Express.js:\n"
                    "  req.session.regenerate((err) => { /* post-login logic */ });\n\n"
                    "Django:\n"
                    "  request.session.cycle_key()  // built-in on login\n\n"
                    "Also reject session IDs not generated by the server."
                ),
                affected_component="Session management",
                references=(
                    "https://owasp.org/www-community/attacks/Session_fixation\n"
                    "https://cwe.mitre.org/data/definitions/384.html"
                ),
                detection_method=(
                    "Set a known (attacker-controlled) session ID in the cookie and "
                    "sent a request. Checked whether the server regenerated the session "
                    "ID or accepted the fixated value."
                ),
            ))
            break


def _check_session_randomness(session: ScanSession, url: str) -> None:
    """Collect multiple session IDs and analyze entropy/patterns."""
    collected_ids = []
    cookie_name = None

    for _ in range(10):
        import requests as req_lib
        fresh = req_lib.Session()
        fresh.verify = session.config.verify_ssl
        fresh.headers.update({"User-Agent": session.config.user_agent})
        try:
            resp = fresh.get(url, timeout=session.config.timeout, allow_redirects=True)
        except Exception as e:
            logger.debug("session_security _check_session_randomness: operation failed: %s", e)
            continue
        if not resp:
            continue

        for c in resp.cookies:
            name_lower = c.name.lower()
            for known in COMMON_SESSION_NAMES:
                if known.lower() in name_lower:
                    collected_ids.append(c.value)
                    cookie_name = c.name
                    break

    if len(collected_ids) < 5:
        return

    min_len = min(len(sid) for sid in collected_ids)
    max_len = max(len(sid) for sid in collected_ids)
    avg_entropy = sum(_calculate_entropy(sid) for sid in collected_ids) / len(collected_ids)

    issues = []

    if min_len < 16:
        issues.append(f"Short session IDs detected (min length: {min_len} chars, recommend >= 32)")

    if avg_entropy < 3.5:
        issues.append(f"Low entropy in session IDs (avg: {avg_entropy:.2f} bits/char, recommend >= 4.0)")

    unique = set(collected_ids)
    if len(unique) < len(collected_ids):
        duplicates = len(collected_ids) - len(unique)
        issues.append(f"Duplicate session IDs detected ({duplicates} duplicates in {len(collected_ids)} samples)")

    hex_chars = set(string.hexdigits)
    all_hex = all(set(sid).issubset(hex_chars) for sid in collected_ids)
    all_same_len = min_len == max_len

    if all_same_len and all_hex and min_len <= 16:
        sorted_ids = sorted(collected_ids)
        sequential = False
        try:
            int_ids = [int(sid, 16) for sid in sorted_ids]
            diffs = [int_ids[i + 1] - int_ids[i] for i in range(len(int_ids) - 1)]
            if len(set(diffs)) == 1:
                sequential = True
        except ValueError:
            pass
        if sequential:
            issues.append("Sequential session IDs detected - trivially predictable")

    if not issues:
        return

    severity = Severity.HIGH if any("Sequential" in i or "Duplicate" in i for i in issues) else Severity.MEDIUM

    curl_cmd = f"for i in $(seq 1 5); do curl -k -s -D - '{url}' | grep -i set-cookie; done"

    session.add_finding(Finding(
        title=f"Weak Session ID Generation: {cookie_name}",
        severity=severity,
        description=(
            f"Analysis of {len(collected_ids)} session IDs from '{cookie_name}' "
            f"reveals weaknesses in session token generation. "
            f"Issues: {'; '.join(issues)}."
        ),
        evidence=(
            f"Cookie: {cookie_name}\n"
            f"Samples collected: {len(collected_ids)}\n"
            f"Unique IDs: {len(unique)}\n"
            f"Length range: {min_len}-{max_len}\n"
            f"Average entropy: {avg_entropy:.2f} bits/char\n"
            f"Sample IDs:\n"
            + "\n".join(f"  {sid}" for sid in collected_ids[:5])
        ),
        remediation=(
            "Use a cryptographically secure random number generator (CSPRNG) to "
            "produce session IDs of at least 128 bits (32 hex characters). "
            "Avoid sequential or predictable patterns."
        ),
        url=url,
        module="session_security",
        cwe="CWE-330",
        confirmed=True if severity == Severity.HIGH else False,
        location=f"Session ID generation for '{cookie_name}'",
        curl_command=curl_cmd,
        reproduction_steps=(
            f"1. Request {url} multiple times with fresh sessions (no cookies)\n"
            f"2. Collect the '{cookie_name}' values from Set-Cookie headers\n"
            f"3. Analyze the collected IDs for length, entropy, and patterns\n"
            f"4. Run: {curl_cmd}"
        ),
        developer_fix=(
            "Use your framework's built-in session ID generator which uses CSPRNG:\n\n"
            "PHP: Ensure session.entropy_length >= 32, session.hash_function = sha256\n"
            "Java: Use SecureRandom for session ID generation\n"
            "Python: Use os.urandom() or secrets.token_hex(32)\n"
            "Node.js: Use crypto.randomBytes(32).toString('hex')\n\n"
            "Session IDs should be at least 128 bits of entropy."
        ),
        affected_component="Session ID generation",
        references=(
            "https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length\n"
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        ),
        detection_method=(
            "Collected multiple session IDs by making fresh requests without cookies. "
            "Analyzed the IDs for length, Shannon entropy, uniqueness, and sequential patterns."
        ),
    ))


def _check_cookie_scope(session: ScanSession, url: str) -> None:
    """Check for overly permissive cookie scope."""
    resp = session.get(url)
    if not resp:
        return

    parsed = urlparse(url)
    all_cookies = list(resp.cookies) + list(session.session.cookies)

    for cookie in all_cookies:
        name_lower = cookie.name.lower()
        is_session = False
        for known in COMMON_SESSION_NAMES:
            if known.lower() in name_lower:
                is_session = True
                break

        if not is_session:
            continue

        if cookie.domain:
            domain = cookie.domain.lstrip(".")
            target_domain = parsed.hostname or ""

            domain_parts = domain.split(".")
            target_parts = target_domain.split(".")

            if (
                len(domain_parts) <= 2
                and len(target_parts) > 2
                and cookie.domain.startswith(".")
            ):
                curl_cmd = f"curl -k -v '{url}' 2>&1 | grep -i 'set-cookie.*{cookie.name}'"
                session.add_finding(Finding(
                    title=f"Overly Broad Cookie Scope: {cookie.name}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Session cookie '{cookie.name}' is scoped to domain '{cookie.domain}', "
                        f"which includes all subdomains. If any subdomain is compromised, the "
                        f"attacker can steal or manipulate this session cookie."
                    ),
                    evidence=(
                        f"Cookie: {cookie.name}\n"
                        f"Domain: {cookie.domain}\n"
                        f"Path: {cookie.path or '/'}\n"
                        f"Target: {target_domain}\n"
                        f"Risk: Cookie shared with all subdomains of {domain}"
                    ),
                    remediation=(
                        f"Restrict the cookie domain to the specific subdomain: "
                        f"Domain={target_domain}"
                    ),
                    url=url,
                    module="session_security",
                    cwe="CWE-1275",
                    confirmed=True,
                    location=f"Cookie domain scope for '{cookie.name}'",
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Request {url} and inspect Set-Cookie headers\n"
                        f"2. Note that '{cookie.name}' has Domain={cookie.domain}\n"
                        f"3. This cookie is sent to ALL subdomains of {domain}\n"
                        f"4. A compromised subdomain can access this session cookie\n"
                        f"5. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"Set the cookie domain to the specific host rather than the parent domain:\n"
                        f"  Set-Cookie: {cookie.name}=<value>; Domain={target_domain}; "
                        f"HttpOnly; Secure; SameSite=Lax; Path=/\n\n"
                        f"Avoid using wildcard/parent domains (.{domain}) unless absolutely necessary."
                    ),
                    affected_component="Cookie scope configuration",
                    references=(
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#define_where_cookies_are_sent\n"
                        "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes"
                    ),
                    detection_method=(
                        "Inspected session cookie Domain attribute and compared it against "
                        "the target hostname. Flagged cookies scoped to parent domains that "
                        "include all subdomains."
                    ),
                ))


def run(session: ScanSession) -> None:
    """Run session security checks."""
    print("\n[*] Testing session security...")
    target = session.config.target

    _check_cookie_attributes(session, target)
    _check_session_fixation(session, target)
    _check_session_randomness(session, target)
    _check_cookie_scope(session, target)

    for url in list(session.crawled_urls)[:5]:
        if url != target:
            _check_cookie_attributes(session, url)
