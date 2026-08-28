import math
import string
import collections
from urllib.parse import urlparse

import requests

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession

COMMON_SESSION_NAMES = [
    "JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "session_id",
    "sessionid", "sid", "sess", "token", "connect.sid", "ci_session",
    "CFID", "CFTOKEN", "laravel_session", "_session_id", "rack.session",
]


def _calculate_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = collections.Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _find_session_cookies(cookies) -> list:
    session_cookies = []
    for cookie in cookies:
        name_lower = cookie.name.lower()
        matched = any(known.lower() in name_lower for known in COMMON_SESSION_NAMES)
        if matched or (len(cookie.value) >= 16 and _calculate_entropy(cookie.value) > 3.0):
            session_cookies.append(cookie)
    return session_cookies


def _check_cookie_attributes(session: ScanSession, url: str) -> None:
    resp = session.get(url)
    if not resp:
        return

    # Try response cookies first, fall back to session jar
    session_cookies = _find_session_cookies(resp.cookies) or _find_session_cookies(session.session.cookies)
    if not session_cookies:
        return

    for cookie in session_cookies:
        issues = []
        parsed = urlparse(url)

        if not cookie.secure:
            issues.append("Missing 'Secure' flag - cookie sent over unencrypted HTTP")

        has_httponly = getattr(cookie, "_rest", {}).get("HttpOnly", None) is not None
        if not has_httponly and hasattr(cookie, "has_nonstandard_attr"):
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

        if not cookie.path:
            issues.append("No explicit Path set - defaults to current directory")

        if cookie.domain and cookie.domain.startswith("."):
            parent_parts = cookie.domain.lstrip(".").split(".")
            if len(parent_parts) <= 2:
                issues.append("Overly broad Domain='{}' - shared across all subdomains".format(cookie.domain))

        if not issues:
            continue

        severity = Severity.HIGH if any(flag in i for i in issues for flag in ("HttpOnly", "Secure")) else Severity.MEDIUM
        curl_cmd = "curl -k -v -I '{}' 2>&1 | grep -i set-cookie".format(url)

        evidence_lines = [
            "Cookie Name: {}".format(cookie.name),
            "Cookie Domain: {}".format(cookie.domain or "(not set)"),
            "Cookie Path: {}".format(cookie.path or "(not set)"),
            "Secure: {}".format(cookie.secure),
            "Issues found:",
        ] + ["  - {}".format(issue) for issue in issues]

        session.add_finding(Finding(
            title="Insecure Session Cookie: {}".format(cookie.name),
            severity=severity,
            description=(
                "The session cookie '{}' is missing critical security attributes. "
                "Found {} issue(s): {}.".format(cookie.name, len(issues), "; ".join(issues))
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
            location="Set-Cookie header for '{}'".format(cookie.name),
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. GET {}\n"
                "2. Inspect Set-Cookie response headers\n"
                "3. Check for HttpOnly, Secure, SameSite on '{}'\n"
                "4. Run: {}".format(url, cookie.name, curl_cmd)
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
                "Inspected Set-Cookie headers for session cookies, checking "
                "HttpOnly, Secure, SameSite, Path, and Domain attributes."
            ),
        ))


def _check_session_fixation(session: ScanSession, url: str) -> None:
    resp = session.get(url)
    if not resp:
        return

    session_cookies = _find_session_cookies(resp.cookies) or _find_session_cookies(session.session.cookies)
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

        # Check both response and session jar for the cookie value
        current_value = None
        for jar in (resp2.cookies, session.session.cookies):
            for c in jar:
                if c.name == cookie.name:
                    current_value = c.value
                    break
            if current_value is not None:
                break

        session.session.cookies.set(cookie.name, original_value, domain=cookie.domain, path=cookie.path or "/")

        if current_value != fixed_session_id:
            continue

        curl_cmd = "curl -k -v -b '{}={}' '{}' 2>&1 | grep -i set-cookie".format(
            cookie.name, fixed_session_id, url)

        session.add_finding(Finding(
            title="Session Fixation: {}".format(cookie.name),
            severity=Severity.HIGH,
            description=(
                "The server accepts a client-supplied session ID in cookie '{}' "
                "without regenerating it. An attacker can fixate a victim's session "
                "by pre-setting a known session ID before authentication.".format(cookie.name)
            ),
            evidence=(
                "Cookie: {}\nFixated Value Sent: {}\n"
                "Value After Request: {}\n"
                "Session ID was NOT regenerated.".format(
                    cookie.name, fixed_session_id, current_value)
            ),
            remediation=(
                "Always regenerate session IDs after authentication and privilege changes. "
                "Reject unknown or externally-set session identifiers."
            ),
            url=url,
            module="session_security",
            cwe="CWE-384",
            confirmed=True,
            location="Session cookie '{}'".format(cookie.name),
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Set cookie: {}={}\n"
                "2. Request {}\n"
                "3. Observe server does not regenerate session ID\n"
                "4. Run: {}".format(cookie.name, fixed_session_id, url, curl_cmd)
            ),
            developer_fix=(
                "Regenerate session ID on every authentication event:\n\n"
                "PHP: session_regenerate_id(true);\n"
                "Java: request.getSession().invalidate(); request.getSession(true);\n"
                "Express: req.session.regenerate(cb);\n"
                "Django: request.session.cycle_key()\n\n"
                "Also reject session IDs not generated by the server."
            ),
            affected_component="Session management",
            references=(
                "https://owasp.org/www-community/attacks/Session_fixation\n"
                "https://cwe.mitre.org/data/definitions/384.html"
            ),
            detection_method=(
                "Set a known session ID in the cookie, sent a request, and "
                "confirmed the server accepted it without regeneration."
            ),
        ))
        break


def _check_session_randomness(session: ScanSession, url: str) -> None:
    collected_ids = []
    cookie_name = None

    import requests as req_lib
    for _ in range(10):
        fresh = req_lib.Session()
        fresh.verify = session.config.verify_ssl
        fresh.headers.update({"User-Agent": session.config.user_agent})
        try:
            resp = fresh.get(url, timeout=session.config.timeout, allow_redirects=True)
        except (requests.RequestException, ValueError) as e:
            logger.debug("session_security randomness: %s", e)
            continue
        if not resp:
            continue

        for c in resp.cookies:
            if any(known.lower() in c.name.lower() for known in COMMON_SESSION_NAMES):
                collected_ids.append(c.value)
                cookie_name = c.name
                break

    if len(collected_ids) < 5:
        return

    min_len = min(len(sid) for sid in collected_ids)
    max_len = max(len(sid) for sid in collected_ids)
    avg_entropy = sum(_calculate_entropy(sid) for sid in collected_ids) / len(collected_ids)
    unique = set(collected_ids)

    issues = []
    if min_len < 16:
        issues.append("Short session IDs (min length: {} chars, recommend >= 32)".format(min_len))
    if avg_entropy < 3.5:
        issues.append("Low entropy (avg: {:.2f} bits/char, recommend >= 4.0)".format(avg_entropy))
    if len(unique) < len(collected_ids):
        issues.append("{} duplicate(s) in {} samples".format(len(collected_ids) - len(unique), len(collected_ids)))

    # Check for sequential hex IDs
    hex_chars = set(string.hexdigits)
    if min_len == max_len and min_len <= 16 and all(set(sid).issubset(hex_chars) for sid in collected_ids):
        try:
            int_ids = sorted(int(sid, 16) for sid in collected_ids)
            diffs = [int_ids[i + 1] - int_ids[i] for i in range(len(int_ids) - 1)]
            if len(set(diffs)) == 1:
                issues.append("Sequential session IDs - trivially predictable")
        except ValueError:
            pass

    if not issues:
        return

    severity = Severity.HIGH if any(kw in i for i in issues for kw in ("Sequential", "duplicate")) else Severity.MEDIUM
    curl_cmd = "for i in $(seq 1 5); do curl -k -s -D - '{}' | grep -i set-cookie; done".format(url)

    session.add_finding(Finding(
        title="Weak Session ID Generation: {}".format(cookie_name),
        severity=severity,
        description=(
            "Analysis of {} session IDs from '{}' reveals weaknesses: {}.".format(
                len(collected_ids), cookie_name, "; ".join(issues))
        ),
        evidence=(
            "Cookie: {}\nSamples: {}\nUnique: {}\n"
            "Length range: {}-{}\nAvg entropy: {:.2f} bits/char\n"
            "Sample IDs:\n{}".format(
                cookie_name, len(collected_ids), len(unique),
                min_len, max_len, avg_entropy,
                "\n".join("  {}".format(sid) for sid in collected_ids[:5]))
        ),
        remediation=(
            "Use a CSPRNG to produce session IDs of at least 128 bits "
            "(32 hex characters). Avoid sequential or predictable patterns."
        ),
        url=url,
        module="session_security",
        cwe="CWE-330",
        confirmed=severity == Severity.HIGH,
        location="Session ID generation for '{}'".format(cookie_name),
        curl_command=curl_cmd,
        reproduction_steps=(
            "1. Request {} multiple times with fresh sessions\n"
            "2. Collect '{}' values from Set-Cookie headers\n"
            "3. Analyze for length, entropy, patterns\n"
            "4. Run: {}".format(url, cookie_name, curl_cmd)
        ),
        developer_fix=(
            "Use your framework's built-in CSPRNG session ID generator:\n\n"
            "PHP: session.entropy_length >= 32, session.hash_function = sha256\n"
            "Java: SecureRandom for session ID generation\n"
            "Python: os.urandom() or secrets.token_hex(32)\n"
            "Node.js: crypto.randomBytes(32).toString('hex')\n\n"
            "Session IDs should be at least 128 bits of entropy."
        ),
        affected_component="Session ID generation",
        references=(
            "https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length\n"
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        ),
        detection_method=(
            "Collected multiple session IDs from fresh requests and analyzed "
            "length, Shannon entropy, uniqueness, and sequential patterns."
        ),
    ))


def _check_cookie_scope(session: ScanSession, url: str) -> None:
    resp = session.get(url)
    if not resp:
        return

    parsed = urlparse(url)
    all_cookies = list(resp.cookies) + list(session.session.cookies)

    for cookie in all_cookies:
        if not any(known.lower() in cookie.name.lower() for known in COMMON_SESSION_NAMES):
            continue

        if not cookie.domain or not cookie.domain.startswith("."):
            continue

        domain = cookie.domain.lstrip(".")
        target_domain = parsed.hostname or ""
        domain_parts = domain.split(".")
        target_parts = target_domain.split(".")

        if len(domain_parts) > 2 or len(target_parts) <= 2:
            continue

        curl_cmd = "curl -k -v '{}' 2>&1 | grep -i 'set-cookie.*{}'".format(url, cookie.name)
        session.add_finding(Finding(
            title="Overly Broad Cookie Scope: {}".format(cookie.name),
            severity=Severity.MEDIUM,
            description=(
                "Session cookie '{}' is scoped to domain '{}', including all "
                "subdomains. A compromised subdomain can steal or manipulate "
                "this session cookie.".format(cookie.name, cookie.domain)
            ),
            evidence=(
                "Cookie: {}\nDomain: {}\nPath: {}\n"
                "Target: {}\nRisk: Cookie shared with all subdomains of {}".format(
                    cookie.name, cookie.domain, cookie.path or "/", target_domain, domain)
            ),
            remediation="Restrict cookie domain to the specific subdomain: Domain={}".format(target_domain),
            url=url,
            module="session_security",
            cwe="CWE-1275",
            confirmed=True,
            location="Cookie domain scope for '{}'".format(cookie.name),
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Request {} and inspect Set-Cookie headers\n"
                "2. Note '{}' has Domain={}\n"
                "3. Cookie is sent to ALL subdomains of {}\n"
                "4. Run: {}".format(url, cookie.name, cookie.domain, domain, curl_cmd)
            ),
            developer_fix=(
                "Set cookie domain to the specific host:\n"
                "  Set-Cookie: {}=<value>; Domain={}; HttpOnly; Secure; SameSite=Lax; Path=/\n\n"
                "Avoid wildcard/parent domains (.{}) unless necessary.".format(
                    cookie.name, target_domain, domain)
            ),
            affected_component="Cookie scope configuration",
            references=(
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#define_where_cookies_are_sent\n"
                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes"
            ),
            detection_method=(
                "Compared session cookie Domain attribute against the target hostname, "
                "flagging cookies scoped to parent domains covering all subdomains."
            ),
        ))


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing session security...")
    target = session.config.target

    _check_cookie_attributes(session, target)
    _check_session_fixation(session, target)
    _check_session_randomness(session, target)
    _check_cookie_scope(session, target)

    for url in list(session.crawled_urls)[:5]:
        if url != target:
            _check_cookie_attributes(session, url)
