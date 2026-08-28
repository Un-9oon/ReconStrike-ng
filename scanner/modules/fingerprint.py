import re

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger

TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {
            r"PHP/(\S+)": "PHP {}",
            r"ASP\.NET": "ASP.NET",
            r"Express": "Express.js",
            r"Servlet": "Java Servlet",
        },
        "Server": {
            r"Apache/(\S+)": "Apache {}",
            r"nginx/(\S+)": "Nginx {}",
            r"Microsoft-IIS/(\S+)": "IIS {}",
            r"Caddy": "Caddy",
            r"LiteSpeed": "LiteSpeed",
            r"gunicorn": "Gunicorn (Python)",
            r"Werkzeug/(\S+)": "Werkzeug {} (Flask)",
            r"uvicorn": "Uvicorn (Python ASGI)",
            r"Kestrel": "ASP.NET Kestrel",
            r"Cowboy": "Cowboy (Erlang/Elixir)",
        },
        "X-Generator": {
            r"(.+)": "Generator: {}",
        },
    },
    "body": [
        (r'<meta[^>]*generator[^>]*content=["\']([^"\']+)', "CMS/Framework: {}"),
        (r'wp-content/|wp-includes/', "WordPress"),
        (r'Joomla!|/media/jui/', "Joomla"),
        (r'/sites/default/files|drupal\.js', "Drupal"),
        (r'cdn\.shopify\.com', "Shopify"),
        (r'Mage\.Cookies|/skin/frontend/|/mage/', "Magento"),
        (r'laravel_session', "Laravel"),
        (r'csrfmiddlewaretoken', "Django"),
        (r'data-turbolinks|action_controller', "Ruby on Rails"),
        (r'/_next/static|__NEXT_DATA__', "Next.js"),
        (r'__NUXT__|/_nuxt/', "Nuxt.js"),
        (r'data-reactroot|__REACT_DEVTOOLS|_reactRoot', "React"),
        (r'ng-app=|ng-controller=|\[ngIf\]', "Angular"),
        (r'v-bind:|v-model=|__VUE__', "Vue.js"),
        (r'__svelte', "Svelte"),
        (r'Werkzeug/', "Flask"),
        (r'connect\.sid', "Express.js"),
        (r'JSESSIONID', "Spring (Java)"),
        (r'phpMyAdmin', "phpMyAdmin"),
    ],
    "cookies": {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java",
        "ASP.NET_SessionId": "ASP.NET",
        "connect.sid": "Express.js",
        "laravel_session": "Laravel",
        "csrftoken": "Django",
        "_rails": "Ruby on Rails",
        "ci_session": "CodeIgniter",
        "CAKEPHP": "CakePHP",
    },
}

WAF_SIGNATURES = [
    {"name": "Cloudflare", "headers": {"Server": "cloudflare", "CF-RAY": ""}, "cookies": ["__cfduid", "__cf_bm", "cf_clearance"]},
    {"name": "AWS WAF", "headers": {"X-AMZ-": "", "X-Amzn-": ""}, "cookies": ["awselb", "AWSALB"]},
    {"name": "Akamai", "headers": {"X-Akamai-": ""}, "cookies": ["AKA_A2", "akamai"]},
    {"name": "Sucuri", "headers": {"X-Sucuri-": ""}, "cookies": ["sucuri_"]},
    {"name": "ModSecurity", "headers": {"Server": "mod_security"}, "cookies": []},
    {"name": "Imperva/Incapsula", "headers": {"X-CDN": "Imperva"}, "cookies": ["visid_incap_", "incap_ses_"]},
    {"name": "F5 BIG-IP", "headers": {}, "cookies": ["BIGipServer", "TS0"]},
    {"name": "Barracuda", "headers": {"barra_counter_session": ""}, "cookies": ["barra_counter_session"]},
    {"name": "Fastly", "headers": {"X-Served-By": "", "X-Cache": "", "Via": ".*varnish"}, "cookies": []},
]

_DETECTION = (
    "Analyzed HTTP response headers (Server, X-Powered-By, X-AspNet-Version) and response "
    "body patterns to identify server software, frameworks, and versions. Cross-references "
    "with known EOL databases for outdated software detection."
)


def run(session: ScanSession) -> None:
    logger.info("\n[*] Fingerprinting technologies and detecting WAF...")

    resp = session.get(session.config.target)
    if not resp:
        return

    detected_tech = set()
    curl_cmd = "curl -kI '{}'".format(session.config.target)

    # Header fingerprinting
    for header_name, patterns in TECH_SIGNATURES["headers"].items():
        header_val = resp.headers.get(header_name, "")
        if not header_val:
            continue
        for pattern, label in patterns.items():
            match = re.search(pattern, header_val, re.IGNORECASE)
            if match:
                groups = match.groups()
                detected_tech.add(label.format(groups[0]) if groups else label)

    # Body pattern matching
    for pattern, label in TECH_SIGNATURES["body"]:
        match = re.search(pattern, resp.text, re.IGNORECASE)
        if match:
            groups = match.groups()
            detected_tech.add(label.format(groups[0]) if groups else label)

    for cookie_name, tech in TECH_SIGNATURES["cookies"].items():
        for cookie in resp.cookies:
            if cookie_name.lower() in cookie.name.lower():
                detected_tech.add(tech)

    if detected_tech:
        tech_list = sorted(detected_tech)
        logger.info(" [+] Detected technologies: {}".format(", ".join(tech_list)))

        version_exposed = [t for t in tech_list if re.search(r'\d+\.\d+', t)]
        if version_exposed:
            session.add_finding(Finding(
                title="Technology Stack Fingerprinted (Versions Exposed)",
                severity=Severity.LOW,
                description=(
                    "Server reveals technology versions: {}. "
                    "Version information helps attackers identify known CVEs for specific software versions."
                ).format(", ".join(version_exposed)),
                evidence="Technologies detected: {}".format(", ".join(tech_list)),
                remediation="Suppress version numbers in Server, X-Powered-By headers. Remove generator meta tags.",
                url=session.config.target,
                module="fingerprint",
                cwe="CWE-200",
                confirmed=True,
                location="HTTP response headers and HTML body",
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Send: {cmd}\n"
                    "2. Observe Server/X-Powered-By headers revealing versions.\n"
                    "3. Technologies found: {techs}"
                ).format(cmd=curl_cmd, techs=", ".join(tech_list)),
                developer_fix=(
                    "Apache: ServerTokens Prod; ServerSignature Off\n"
                    "Nginx: server_tokens off;\n"
                    "PHP: expose_php = Off in php.ini\n"
                    "Express: app.disable('x-powered-by')\n"
                    "Remove <meta name=\"generator\"> tags from HTML."
                ),
                affected_component="Server headers / HTML meta tags",
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                detection_method=_DETECTION,
            ))
        else:
            session.add_finding(Finding(
                title="Technology Stack Identified",
                severity=Severity.INFO,
                description="Technologies detected: {}.".format(", ".join(tech_list)),
                evidence="Technologies: {}".format(", ".join(tech_list)),
                remediation="Consider removing unnecessary technology indicators.",
                url=session.config.target,
                module="fingerprint",
                cwe="CWE-200",
                confirmed=True,
                location="HTTP response headers and HTML body",
                curl_command=curl_cmd,
                detection_method=_DETECTION,
            ))

    # WAF detection
    detected_waf = []
    for waf in WAF_SIGNATURES:
        found = False
        for header_name, header_pattern in waf["headers"].items():
            for resp_header, resp_value in resp.headers.items():
                if header_name.lower() in resp_header.lower():
                    if not header_pattern or re.search(header_pattern, resp_value, re.IGNORECASE):
                        found = True
                        break
            if found:
                break

        if not found:
            for cookie_pattern in waf["cookies"]:
                for cookie in resp.cookies:
                    if cookie_pattern.lower() in cookie.name.lower():
                        found = True
                        break
                if found:
                    break

        if found:
            detected_waf.append(waf["name"])

    if detected_waf:
        waf_list = ", ".join(detected_waf)
        logger.info(" [+] WAF/CDN detected: {}".format(waf_list))
        session.add_finding(Finding(
            title="WAF/CDN Detected: {}".format(waf_list),
            severity=Severity.INFO,
            description="Web Application Firewall or CDN detected: {}. Some scan results may be affected by WAF filtering.".format(waf_list),
            evidence="Detected via header/cookie analysis: {}".format(waf_list),
            remediation="Informational. WAF provides defense-in-depth but should not be the only protection.",
            url=session.config.target,
            module="fingerprint",
            cwe="CWE-200",
            confirmed=True,
            location="HTTP response headers and cookies",
            curl_command=curl_cmd,
            detection_method=_DETECTION,
        ))
    else:
        logger.info(" [*] No WAF/CDN detected.")

    _check_version_vulns(session, detected_tech)


def _check_version_vulns(session, tech_set):
    known_eol = {
        "PHP 5": "PHP 5.x is End-of-Life and no longer receives security patches.",
        "PHP 7.0": "PHP 7.0 is End-of-Life.",
        "PHP 7.1": "PHP 7.1 is End-of-Life.",
        "PHP 7.2": "PHP 7.2 is End-of-Life.",
        "PHP 7.3": "PHP 7.3 is End-of-Life.",
        "PHP 7.4": "PHP 7.4 is End-of-Life.",
        "PHP 8.0": "PHP 8.0 is End-of-Life.",
        "Apache 2.2": "Apache 2.2 is End-of-Life.",
    }

    for tech in tech_set:
        for pattern, message in known_eol.items():
            if tech.startswith(pattern):
                session.add_finding(Finding(
                    title="End-of-Life Software: {}".format(tech),
                    severity=Severity.HIGH,
                    description="{} Running EOL software means no security patches for newly discovered vulnerabilities.".format(message),
                    evidence="Detected: {}".format(tech),
                    remediation="Upgrade to a currently supported version.",
                    url=session.config.target,
                    module="fingerprint",
                    cwe="CWE-1104",
                    confirmed=True,
                    location="Server technology version",
                    developer_fix="Upgrade {} to the latest supported version.\nCheck https://endoflife.date/ for EOL schedules.".format(tech.split()[0]),
                    affected_component="{} installation".format(tech),
                    references="https://endoflife.date/",
                    detection_method=_DETECTION,
                ))
