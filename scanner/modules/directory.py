from urllib.parse import urljoin, urlparse

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger

SENSITIVE_PATHS = [
    "/.env", "/.env.bak", "/.env.local", "/.env.production",
    "/config.php", "/config.yml", "/config.json", "/config.xml",
    "/wp-config.php", "/wp-config.php.bak",
    "/settings.py", "/settings.ini", "/application.properties",
    "/appsettings.json", "/web.config",
    "/.git/HEAD", "/.git/config", "/.gitignore",
    "/.svn/entries", "/.hg/store",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/dump.sql", "/database.sql", "/site.tar.gz",
    "/admin", "/admin/", "/administrator/",
    "/wp-admin/", "/phpmyadmin/", "/adminer.php",
    "/cpanel", "/manager/html", "/_admin",
    "/admin/login", "/dashboard", "/panel",
    "/phpinfo.php", "/info.php", "/test.php",
    "/debug", "/debug/", "/_debug",
    "/server-status", "/server-info",
    "/elmah.axd", "/trace.axd",
    "/.well-known/security.txt",
    "/swagger-ui.html", "/swagger.json", "/api-docs",
    "/openapi.json", "/graphql", "/graphiql",
    "/api/v1/", "/api/v2/",
    "/Dockerfile", "/docker-compose.yml", "/.dockerenv",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/favicon.ico", "/humans.txt",
    "/error.log", "/access.log", "/debug.log",
    "/logs/", "/log/",
    "/package.json", "/composer.json", "/Gemfile",
    "/requirements.txt", "/Pipfile",
    "/.github/workflows/", "/.gitlab-ci.yml",
    "/Jenkinsfile", "/.circleci/config.yml",
]

DIRECTORY_LISTING_INDICATORS = [
    "Index of /", "Directory listing for", "Parent Directory",
    "<title>Directory listing", "Directory Listing",
]

SENSITIVE_CONTENT_PATTERNS = {
    "/.env": ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "AWS_", "REDIS_"],
    "/.git/HEAD": ["ref: refs/"],
    "/.git/config": ["[remote", "[branch", "repositoryformatversion"],
    "/phpinfo.php": ["phpinfo()", "PHP Version", "php.ini"],
}

ADMIN_PATHS = {
    "/admin", "/admin/", "/administrator/", "/wp-admin/",
    "/phpmyadmin/", "/adminer.php", "/admin/login", "/dashboard", "/panel",
}

API_PATHS = {
    "/swagger-ui.html", "/swagger.json", "/api-docs",
    "/openapi.json", "/graphql", "/graphiql",
}

_DETECTION_METHOD = (
    "Brute-forced common directory and file paths via HTTP requests. "
    "Uses soft-404 detection to filter custom error pages that return HTTP 200."
)


def _build_curl(url):
    return "curl -k -s -o /dev/null -w '%{{http_code}}' '{}'".format(url)


def run(session: ScanSession) -> None:
    logger.info("\n[*] Scanning for sensitive files and directories...")

    soft404_resp = session.get(urljoin(session.config.target, "/vulnscan_nonexistent_page_404_test"))
    soft404_text = soft404_resp.text[:2000] if soft404_resp and soft404_resp.status_code == 200 else None

    target_parsed = urlparse(session.config.target)
    host = target_parsed.netloc

    for path in SENSITIVE_PATHS:
        url = urljoin(session.config.target, path)
        resp = session.get(url, allow_redirects=False)
        if not resp:
            continue

        if resp.status_code == 200:
            content = resp.text[:5000]
            content_type = resp.headers.get("Content-Type", "")

            # Soft-404 filtering
            if soft404_text and path not in SENSITIVE_CONTENT_PATTERNS:
                from difflib import SequenceMatcher
                if SequenceMatcher(None, content[:2000], soft404_text).ratio() > 0.85:
                    continue

            # Directory listing
            if any(ind in content for ind in DIRECTORY_LISTING_INDICATORS):
                snippet = content[:300].replace('\n', ' ').strip()
                session.add_finding(Finding(
                    title="Directory Listing Enabled: {}".format(path),
                    severity=Severity.MEDIUM,
                    description=(
                        "Directory listing is enabled at {}, exposing the internal file structure "
                        "of the web application. An attacker can browse all files in this directory, "
                        "potentially discovering sensitive files, backup archives, configuration files, "
                        "or source code that should not be publicly accessible."
                    ).format(path),
                    evidence=(
                        "URL: {}\nStatus: 200\nContent-Type: {}\n"
                        "Directory listing indicators found in response body.\n"
                        "Response Snippet: {}..."
                    ).format(url, content_type, snippet),
                    remediation=(
                        "1. Disable directory listing in the web server configuration.\n"
                        "2. For Apache: Remove 'Options Indexes' or add 'Options -Indexes'.\n"
                        "3. For Nginx: Remove 'autoindex on;' from the location block.\n"
                        "4. Add a default index file to prevent fallback to directory listing.\n"
                        "5. Audit directory contents and remove non-web-accessible files."
                    ),
                    url=url,
                    module="directory",
                    cwe="CWE-548",
                    confirmed=True,
                    location="Directory path '{}' on {}".format(path, host),
                    parameter="",
                    payload="",
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=_build_curl(url),
                    reproduction_steps=(
                        "1. Navigate to: {}\n"
                        "2. Observe the directory listing showing file names and sizes.\n"
                        "3. Click on any listed file to access it directly."
                    ).format(url),
                    developer_fix=(
                        "Apache (.htaccess or httpd.conf):\n"
                        "  Options -Indexes\n\n"
                        "Nginx:\n"
                        "  location {path} {{\n"
                        "      autoindex off;\n"
                        "  }}\n\n"
                        "IIS (web.config):\n"
                        "  <directoryBrowse enabled=\"false\" />"
                    ).format(path=path),
                    affected_component="Web server directory listing at {}".format(path),
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information | "
                        "https://cwe.mitre.org/data/definitions/548.html"
                    ),
                    detection_method=_DETECTION_METHOD,
                ))
                continue

            confirmed = False
            if path in SENSITIVE_CONTENT_PATTERNS:
                if any(p in content for p in SENSITIVE_CONTENT_PATTERNS[path]):
                    confirmed = True

            # Environment files
            if path.endswith((".env", ".env.bak", ".env.local", ".env.production")):
                env_markers = ["DB_", "SECRET", "API_KEY", "PASSWORD"]
                matched_vars = [p for p in env_markers if p in content]
                if matched_vars:
                    env_lines = content.split('\n')[:10]
                    redacted = []
                    for line in env_lines:
                        if '=' in line and not line.strip().startswith('#'):
                            redacted.append("{}=<REDACTED>".format(line.split('=', 1)[0]))
                        else:
                            redacted.append(line)

                    session.add_finding(Finding(
                        title="Environment File Exposed: {}".format(path),
                        severity=Severity.CRITICAL,
                        description=(
                            "The environment configuration file at {} is publicly accessible and "
                            "contains sensitive configuration data including database credentials, API keys, "
                            "and secret tokens. This is a critical information disclosure that can lead to "
                            "full application and database compromise."
                        ).format(path),
                        evidence=(
                            "URL: {}\nStatus: {}\nMatched Patterns: {}\n"
                            "Content Preview (redacted values):\n{}"
                        ).format(url, resp.status_code, ', '.join(matched_vars),
                                 '\n'.join(redacted)),
                        remediation=(
                            "1. Immediately rotate ALL credentials found in the exposed file.\n"
                            "2. Block access to .env files in the web server configuration.\n"
                            "3. Move .env files outside the web root directory.\n"
                            "4. Add .env to .gitignore to prevent committing to version control.\n"
                            "5. Audit access logs for any prior access to this file."
                        ),
                        url=url,
                        module="directory",
                        cwe="CWE-538",
                        confirmed=True,
                        location="File '{}' in web root on {}".format(path, host),
                        parameter="",
                        payload="",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command="curl -k -s '{}'".format(url),
                        reproduction_steps=(
                            "1. Request the URL: {}\n"
                            "2. Observe the response contains environment variables with sensitive values.\n"
                            "3. Note database credentials, API keys, and secret tokens are exposed."
                        ).format(url),
                        developer_fix=(
                            "Apache (.htaccess):\n"
                            "  <FilesMatch \"^\\.env\">\n"
                            "      Order allow,deny\n"
                            "      Deny from all\n"
                            "  </FilesMatch>\n\n"
                            "Nginx:\n"
                            "  location ~ /\\.env {{\n"
                            "      deny all;\n"
                            "      return 404;\n"
                            "  }}\n\n"
                            "Move .env outside the web root:\n"
                            "  # Instead of /var/www/html/.env use /var/www/.env"
                        ),
                        affected_component="Environment configuration file at {}".format(path),
                        references=(
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information | "
                            "https://cwe.mitre.org/data/definitions/538.html"
                        ),
                        detection_method=_DETECTION_METHOD,
                    ))
                    continue

            if "/.git/" in path and confirmed:
                session.add_finding(Finding(
                    title="Git Repository Exposed: {}".format(path),
                    severity=Severity.HIGH,
                    description=(
                        "Git repository metadata is accessible at {}. An attacker can reconstruct "
                        "the entire source code of the application by downloading Git objects. This "
                        "exposes source code, commit history, developer information, and potentially "
                        "hardcoded credentials or API keys."
                    ).format(path),
                    evidence=(
                        "URL: {}\nStatus: {}\n"
                        "Content matches Git repository file patterns.\n"
                        "Content Preview: {}"
                    ).format(url, resp.status_code, content[:200]),
                    remediation=(
                        "1. Block access to the .git directory immediately.\n"
                        "2. Audit the repository for hardcoded secrets and rotate them.\n"
                        "3. Review commit history for sensitive data.\n"
                        "4. Ensure .git is excluded from deployment artifacts.\n"
                        "5. Use server configuration to deny access to hidden files."
                    ),
                    url=url,
                    module="directory",
                    cwe="CWE-538",
                    confirmed=True,
                    location="Git metadata at '{}' on {}".format(path, host),
                    parameter="",
                    payload="",
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command="curl -k -s '{}'".format(url),
                    reproduction_steps=(
                        "1. Request: {}\n"
                        "2. Observe Git metadata in the response.\n"
                        "3. Use git-dumper to reconstruct the full repository:\n"
                        "   git-dumper {} output_dir\n"
                        "4. Browse the recovered source code and commit history."
                    ).format(url, urljoin(session.config.target, '/.git/')),
                    developer_fix=(
                        "Apache (.htaccess):\n"
                        "  RedirectMatch 404 /\\.git\n\n"
                        "Nginx:\n"
                        "  location ~ /\\.git {{\n"
                        "      deny all;\n"
                        "      return 404;\n"
                        "  }}\n\n"
                        "Deployment: Use .dockerignore or .gitattributes export-ignore:\n"
                        "  .git"
                    ),
                    affected_component="Version control metadata at {}".format(path),
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces | "
                        "https://cwe.mitre.org/data/definitions/538.html"
                    ),
                    detection_method=_DETECTION_METHOD,
                ))
                continue

            if path in ("/phpinfo.php", "/info.php", "/test.php") and confirmed:
                session.add_finding(Finding(
                    title="PHP Info Page Exposed: {}".format(path),
                    severity=Severity.MEDIUM,
                    description=(
                        "A PHP information disclosure page is accessible at {}. This reveals "
                        "detailed server configuration including PHP version, loaded modules, "
                        "environment variables, file paths, and database connection settings."
                    ).format(path),
                    evidence=(
                        "URL: {}\nStatus: {}\n"
                        "Response contains phpinfo() output with server configuration details."
                    ).format(url, resp.status_code),
                    remediation=(
                        "1. Delete phpinfo/test/info files from the production server.\n"
                        "2. Add a deployment check to prevent debug files from reaching production.\n"
                        "3. If needed for debugging, restrict access by IP or require authentication.\n"
                        "4. Audit for other debug/test files."
                    ),
                    url=url,
                    module="directory",
                    cwe="CWE-200",
                    confirmed=True,
                    location="Debug file '{}' on {}".format(path, host),
                    parameter="",
                    payload="",
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=_build_curl(url),
                    reproduction_steps=(
                        "1. Navigate to: {}\n"
                        "2. Observe the full PHP configuration page.\n"
                        "3. Note exposed: PHP version, extensions, environment variables, file paths."
                    ).format(url),
                    developer_fix=(
                        "Remove the file:\n"
                        "  rm {path}\n\n"
                        "Add to deployment pipeline:\n"
                        "  RUN find /var/www -name 'phpinfo.php' -o -name 'info.php' -o -name 'test.php' | xargs rm -f\n\n"
                        "If access is needed, restrict by IP:\n"
                        "  <Files \"phpinfo.php\">\n"
                        "      Require ip 10.0.0.0/8\n"
                        "  </Files>"
                    ).format(path=path),
                    affected_component="PHP debug/info page at {}".format(path),
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server | "
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ),
                    detection_method=_DETECTION_METHOD,
                ))
                continue

            if path in ADMIN_PATHS and "text/html" in content_type:
                if any(kw in content.lower() for kw in ("login", "password", "sign in", "username")):
                    session.add_finding(Finding(
                        title="Admin Interface Found: {}".format(path),
                        severity=Severity.INFO,
                        description=(
                            "An administrative interface was discovered at {}. "
                            "The page contains a login form. While authentication is required, "
                            "its public discoverability allows attackers to target it with "
                            "brute-force or credential-stuffing attacks."
                        ).format(path),
                        evidence=(
                            "URL: {}\nStatus: {}\nContent-Type: {}\n"
                            "Login-related keywords detected in response body."
                        ).format(url, resp.status_code, content_type),
                        remediation=(
                            "1. Restrict access to admin interfaces by IP address.\n"
                            "2. Implement multi-factor authentication for all admin accounts.\n"
                            "3. Consider renaming the admin path to a non-standard URL.\n"
                            "4. Implement account lockout after failed login attempts.\n"
                            "5. Add rate limiting to the login endpoint."
                        ),
                        url=url,
                        module="directory",
                        cwe="CWE-200",
                        confirmed=True,
                        location="Admin interface at '{}' on {}".format(path, host),
                        parameter="",
                        payload="",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=_build_curl(url),
                        reproduction_steps=(
                            "1. Navigate to: {}\n"
                            "2. Observe the admin login page is publicly accessible.\n"
                            "3. Note any additional information disclosed."
                        ).format(url),
                        developer_fix=(
                            "Nginx:\n"
                            "  location {path} {{\n"
                            "      allow 10.0.0.0/8;\n"
                            "      allow 192.168.0.0/16;\n"
                            "      deny all;\n"
                            "  }}\n\n"
                            "Apache (.htaccess):\n"
                            "  <Location \"{path}\">\n"
                            "      Require ip 10.0.0.0/8 192.168.0.0/16\n"
                            "  </Location>"
                        ).format(path=path),
                        affected_component="Administrative interface at {}".format(path),
                        references=(
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces | "
                            "https://cwe.mitre.org/data/definitions/200.html"
                        ),
                        detection_method=_DETECTION_METHOD,
                    ))
                    continue

            if path in API_PATHS and ("text/html" in content_type or "application/json" in content_type):
                session.add_finding(Finding(
                    title="API Documentation Exposed: {}".format(path),
                    severity=Severity.LOW,
                    description=(
                        "API documentation or interactive interface is publicly accessible at {}. "
                        "This exposes the full API surface area including endpoints, parameters, "
                        "data models, and authentication mechanisms."
                    ).format(path),
                    evidence=(
                        "URL: {}\nStatus: {}\nContent-Type: {}\n"
                        "Response contains API documentation/interface content."
                    ).format(url, resp.status_code, content_type),
                    remediation=(
                        "1. Restrict API documentation access in production.\n"
                        "2. Require authentication to view API docs.\n"
                        "3. Ensure no internal-only endpoints are documented.\n"
                        "4. Disable interactive 'Try it out' features in production."
                    ),
                    url=url,
                    module="directory",
                    cwe="CWE-200",
                    confirmed=confirmed,
                    location="API documentation at '{}' on {}".format(path, host),
                    parameter="",
                    payload="",
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=_build_curl(url),
                    reproduction_steps=(
                        "1. Navigate to: {}\n"
                        "2. Observe the API documentation listing all available endpoints.\n"
                        "3. Note exposed endpoint paths, parameters, and auth requirements."
                    ).format(url),
                    developer_fix=(
                        "Spring Boot (application.yml):\n"
                        "  springdoc:\n"
                        "    api-docs:\n"
                        "      enabled: false\n\n"
                        "Express.js:\n"
                        "  if (process.env.NODE_ENV !== 'production') {{\n"
                        "      app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));\n"
                        "  }}"
                    ),
                    affected_component="API documentation endpoint at {}".format(path),
                    references=(
                        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/ | "
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ),
                    detection_method=_DETECTION_METHOD,
                ))

            if path == "/robots.txt" and resp.status_code == 200:
                disallowed = [
                    line.split(":", 1)[1].strip()
                    for line in content.split("\n")
                    if line.strip().lower().startswith("disallow")
                ]
                if disallowed:
                    disallowed_list = ', '.join(disallowed[:10])
                    session.add_finding(Finding(
                        title="Robots.txt Reveals Hidden Paths",
                        severity=Severity.INFO,
                        description=(
                            "The robots.txt file discloses {} restricted paths. While "
                            "intended to guide search engine crawlers, it creates a roadmap of "
                            "sensitive paths for attackers. Disallowed paths often point to admin "
                            "panels, internal APIs, or restricted areas."
                        ).format(len(disallowed)),
                        evidence=(
                            "URL: {}\nStatus: {}\nDisallowed Paths: {}"
                        ).format(url, resp.status_code, disallowed_list),
                        remediation=(
                            "1. Review all disallowed paths and ensure they are protected by authentication.\n"
                            "2. Do not rely on robots.txt for security.\n"
                            "3. Consider removing sensitive paths from robots.txt and securing them server-side.\n"
                            "4. Use 'noindex' meta tags instead for pages that should not appear in search results."
                        ),
                        url=url,
                        module="directory",
                        cwe="CWE-200",
                        confirmed=True,
                        location="robots.txt at {}".format(host),
                        parameter="",
                        payload="",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command="curl -k -s '{}'".format(url),
                        reproduction_steps=(
                            "1. Request: {}\n"
                            "2. Review the 'Disallow' directives.\n"
                            "3. Attempt to access each disallowed path.\n"
                            "4. Disallowed paths found: {}"
                        ).format(url, disallowed_list),
                        developer_fix=(
                            "Protect sensitive paths with authentication, not robots.txt:\n\n"
                            "For pages that should not be indexed, use meta tags:\n"
                            "  <meta name=\"robots\" content=\"noindex, nofollow\">\n\n"
                            "Enforce authentication on restricted paths:\n"
                            "  location /admin {{\n"
                            "      auth_basic \"Restricted\";\n"
                            "      auth_basic_user_file /etc/nginx/.htpasswd;\n"
                            "  }}"
                        ),
                        affected_component="robots.txt information disclosure",
                        references=(
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage | "
                            "https://cwe.mitre.org/data/definitions/200.html"
                        ),
                        detection_method=_DETECTION_METHOD,
                    ))

        elif resp.status_code == 403:
            interesting_403 = ("/.env", "/.git/", "/admin", "/phpmyadmin", "/config")
            if any(path.startswith(p) for p in interesting_403):
                session.add_finding(Finding(
                    title="Forbidden Path Exists: {}".format(path),
                    severity=Severity.INFO,
                    description=(
                        "The path {} returns HTTP 403 Forbidden, confirming the resource exists "
                        "but access is denied. The 403 response (instead of 404) reveals the "
                        "existence of this path, which may help attackers map the application "
                        "structure and identify targets for bypass attempts."
                    ).format(path),
                    evidence=(
                        "URL: {}\nStatus: 403 Forbidden\n"
                        "The server confirms the path exists but denies access."
                    ).format(url),
                    remediation=(
                        "1. Return 404 instead of 403 for paths that should be hidden.\n"
                        "2. If the resource should be accessible to certain users, implement proper authentication.\n"
                        "3. Review the server configuration to ensure the restriction is intentional."
                    ),
                    url=url,
                    module="directory",
                    cwe="CWE-200",
                    confirmed=True,
                    location="Path '{}' on {}".format(path, host),
                    parameter="",
                    payload="",
                    request_method="GET",
                    response_status=403,
                    curl_command=_build_curl(url),
                    reproduction_steps=(
                        "1. Send a GET request to: {}\n"
                        "2. Observe the HTTP 403 Forbidden response.\n"
                        "3. Compare with a non-existent path (which should return 404)."
                    ).format(url),
                    developer_fix=(
                        "Nginx:\n"
                        "  location {path} {{\n"
                        "      return 404;\n"
                        "  }}\n\n"
                        "Apache:\n"
                        "  <Location \"{path}\">\n"
                        "      Redirect 404 /\n"
                        "  </Location>"
                    ).format(path=path),
                    affected_component="Access control for {}".format(path),
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information | "
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ),
                    detection_method=_DETECTION_METHOD,
                ))
