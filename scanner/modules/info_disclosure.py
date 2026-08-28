import re
from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession
from scanner.crawler import extract_comments
from scanner.log import logger

SENSITIVE_PATTERNS = [
    (r'(?:aws_access_key_id|AKIA)[A-Z0-9]{12,}', "AWS Access Key", Severity.CRITICAL),
    (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', "Private Key", Severity.CRITICAL),
    (r'(?:sk-|pk_live_|sk_live_|rk_live_)[a-zA-Z0-9]{20,}', "API Secret Key", Severity.CRITICAL),
    (r'(?:jdbc|mysql|postgresql|mongodb)://[^\s<"\']+:[^\s<"\']+@[^\s<"\']+', "Database Connection String", Severity.CRITICAL),
]

COMMENT_PATTERNS = [
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']?\S{4,}', "Password in Comment", Severity.HIGH),
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[a-zA-Z0-9_-]{16,}', "API Key in Comment", Severity.HIGH),
    (r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
     "Internal IP Address in Comment", Severity.LOW),
]

ERROR_PAGE_PATTERNS = [
    (r'(?:Traceback \(most recent call last\)|Fatal error:.*?in\s+/[\w./]+\s+on\s+line\s+\d+)',
     "Application Error with Path", Severity.MEDIUM),
]

STACK_TRACE_PATTERN = r'(?:^\s+at\s+[\w.$]+\([\w.]+:\d+\).*\n){3,}'

_DETECTION = (
    "Scanned response bodies, headers, and HTML comments for leaked sensitive data: "
    "email addresses, IP addresses, API keys, database connection strings, stack traces, "
    "and debug information using pattern-matching analysis."
)


def _build_curl(method, url, headers=None):
    cmd = "curl -k -X {} '{}'".format(method, url)
    if headers:
        for k, v in headers.items():
            cmd += " -H '{}: {}'".format(k, v)
    return cmd


def run(session: ScanSession) -> None:
    logger.info("\n[*] Checking for information disclosure...")

    for url in session.crawled_urls:
        resp = session.get(url)
        if not resp:
            continue

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/javascript" not in content_type:
            continue

        body = resp.text
        parsed = urlparse(url)

        # Sensitive data in page body
        for pattern, name, severity in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if not matches:
                continue
            sample = matches[0] if isinstance(matches[0], str) else str(matches[0])
            masked = sample[:8] + "..." + sample[-4:] if len(sample) > 16 else sample[:8] + "..."

            session.add_finding(Finding(
                title="Information Disclosure: {}".format(name),
                severity=severity,
                description=(
                    "A {lname} was found exposed in the page content at {url}. "
                    "This sensitive credential is directly accessible to anyone who views "
                    "the page source, enabling unauthorized access to backend services, "
                    "cloud infrastructure, or databases depending on the key type."
                ).format(lname=name.lower(), url=url),
                evidence=(
                    "Pattern Matched: {name}\nSample (masked): {masked}\n"
                    "Total Occurrences: {count}\nContent-Type: {ct}\nResponse Status: {status}"
                ).format(name=name, masked=masked, count=len(matches),
                         ct=content_type, status=resp.status_code),
                remediation=(
                    "1. Immediately rotate the exposed credential and revoke the old one.\n"
                    "2. Move all secrets to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).\n"
                    "3. Audit version control history for previously committed secrets using tools like truffleHog or git-secrets.\n"
                    "4. Implement pre-commit hooks to prevent secrets from being committed.\n"
                    "5. Add the file to .gitignore if it should never be tracked."
                ),
                url=url,
                module="info_disclosure",
                cwe="CWE-200",
                confirmed=True,
                location="Page body at {}".format(parsed.path),
                parameter="",
                payload="",
                request_method="GET",
                response_status=resp.status_code,
                curl_command=_build_curl("GET", url),
                reproduction_steps=(
                    "1. Open the target URL: {url}\n"
                    "2. View the page source (Ctrl+U or right-click > View Page Source).\n"
                    "3. Search for the pattern matching '{lname}'.\n"
                    "4. Observe the exposed credential in the response body.\n"
                    "5. The secret '{masked}' is visible to any unauthenticated user."
                ).format(url=url, lname=name.lower(), masked=masked),
                developer_fix=(
                    "File: The server-side code or template that renders {path}.\n"
                    "Fix: Remove hardcoded secrets and load them from environment variables.\n"
                    "Example (Python):\n"
                    "  import os\n"
                    "  secret = os.environ.get('SECRET_KEY')  # Instead of hardcoding\n"
                    "Example (Node.js):\n"
                    "  const secret = process.env.SECRET_KEY;  // Instead of hardcoding\n"
                    "Also: Ensure .env files are in .gitignore and never served statically."
                ).format(path=parsed.path),
                affected_component="Page content at {}".format(parsed.path),
                references=(
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage | "
                    "https://cwe.mitre.org/data/definitions/200.html | "
                    "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html"
                ),
                detection_method=_DETECTION,
            ))

        # Stack traces
        if re.search(STACK_TRACE_PATTERN, body, re.MULTILINE):
            trace_match = re.search(r'((?:^\s+at\s+[\w.$]+\([\w.]+:\d+\).*\n){1,5})', body, re.MULTILINE)
            trace_snippet = trace_match.group(0).strip()[:300] if trace_match else "Multiple consecutive 'at ...' lines found"

            session.add_finding(Finding(
                title="Stack Trace Exposed",
                severity=Severity.MEDIUM,
                description=(
                    "A full stack trace is visible in the response at {url}. "
                    "Stack traces reveal internal file paths, class names, method names, "
                    "and line numbers that help attackers map the application's internal "
                    "architecture and identify specific framework versions or vulnerable components."
                ).format(url=url),
                evidence="URL: {}\nStack Trace Snippet:\n{}\nResponse Status: {}".format(
                    url, trace_snippet, resp.status_code),
                remediation=(
                    "1. Disable detailed error messages and stack traces in production.\n"
                    "2. Configure custom error pages that show user-friendly messages.\n"
                    "3. Log detailed errors server-side only (e.g., to a log aggregation service).\n"
                    "4. Set DEBUG=False (Django), display_errors=Off (PHP), or NODE_ENV=production (Express)."
                ),
                url=url,
                module="info_disclosure",
                cwe="CWE-209",
                confirmed=True,
                location="Response body at {}".format(parsed.path),
                parameter="", payload="",
                request_method="GET",
                response_status=resp.status_code,
                curl_command=_build_curl("GET", url),
                reproduction_steps=(
                    "1. Open the target URL: {url}\n"
                    "2. Observe the HTTP response body.\n"
                    "3. A full stack trace with internal file paths and line numbers is visible.\n"
                    "4. This information reveals the application's internal structure to attackers."
                ).format(url=url),
                developer_fix=(
                    "File: Application configuration or error handler.\n"
                    "Fix: Disable verbose error output in production.\n"
                    "  - Django: Set DEBUG = False in settings.py\n"
                    "  - Flask: Set app.debug = False and use app.errorhandler(500)\n"
                    "  - Express: Use a custom error middleware:\n"
                    "    app.use((err, req, res, next) => {{\n"
                    "      console.error(err.stack); // Log server-side only\n"
                    "      res.status(500).send('Internal Server Error');\n"
                    "    }});\n"
                    "  - PHP: Set display_errors = Off in php.ini"
                ),
                affected_component="Error handling at {}".format(parsed.path),
                references=(
                    "https://owasp.org/www-community/Improper_Error_Handling | "
                    "https://cwe.mitre.org/data/definitions/209.html | "
                    "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
                ),
                detection_method=_DETECTION,
            ))

        # HTML comments with sensitive data
        for comment in extract_comments(body):
            comment = comment.strip()
            if len(comment) < 10:
                continue
            for pattern, name, severity in COMMENT_PATTERNS:
                if re.search(pattern, comment, re.IGNORECASE):
                    session.add_finding(Finding(
                        title="Sensitive HTML Comment: {}".format(name),
                        severity=severity,
                        description=(
                            "An HTML comment on {url} contains a {lname}. "
                            "HTML comments are visible to anyone who views the page source. "
                            "Developers often leave debugging information, credentials, or "
                            "internal notes in comments that should be stripped before deployment."
                        ).format(url=url, lname=name.lower()),
                        evidence=(
                            "Comment Content: <!-- {} -->\n"
                            "Pattern Matched: {}\nResponse Status: {}"
                        ).format(comment[:200], name, resp.status_code),
                        remediation=(
                            "1. Remove all sensitive HTML comments before deploying to production.\n"
                            "2. Use server-side comments (e.g., <%-- --%> in JSP, {# #} in Jinja2) that are stripped during rendering.\n"
                            "3. Add a build step or linter rule to strip HTML comments from production output.\n"
                            "4. Review templates for TODO/FIXME/HACK comments containing sensitive data."
                        ),
                        url=url,
                        module="info_disclosure",
                        cwe="CWE-615",
                        confirmed=True,
                        location="HTML comment in page body at {}".format(parsed.path),
                        parameter="", payload="",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=_build_curl("GET", url),
                        reproduction_steps=(
                            "1. Open the target URL: {url}\n"
                            "2. View the page source (Ctrl+U).\n"
                            "3. Search for HTML comments containing '{keyword}'.\n"
                            "4. Observe the sensitive information exposed in the comment."
                        ).format(url=url, keyword=name.lower().split()[0]),
                        developer_fix=(
                            "File: The template or HTML file that renders {path}.\n"
                            "Fix: Remove the comment or replace it with a server-side comment.\n"
                            "  - Jinja2: Use {{# This is a server-side comment #}} instead of <!-- -->\n"
                            "  - Django: Use {{%- comment -%}}...{{%- endcomment -%}}\n"
                            "  - PHP: Use <?php /* comment */ ?> instead of <!-- -->\n"
                            "  - Build step: Add html-minifier or similar to strip comments:\n"
                            "    html-minifier --remove-comments input.html -o output.html"
                        ).format(path=parsed.path),
                        affected_component="HTML template for {}".format(parsed.path),
                        references=(
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage | "
                            "https://cwe.mitre.org/data/definitions/615.html"
                        ),
                        detection_method=_DETECTION,
                    ))
                    break

        # Error page patterns in regular pages
        for pattern, name, severity in ERROR_PAGE_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if not match:
                continue
            error_snippet = match.group(0)[:200]
            session.add_finding(Finding(
                title="Error Information Leakage: {}".format(name),
                severity=severity,
                description=(
                    "The response at {url} contains a {lname} that reveals internal "
                    "server paths, framework details, or application structure. This information "
                    "assists attackers in fingerprinting the technology stack and identifying "
                    "specific files to target."
                ).format(url=url, lname=name.lower()),
                evidence="Error Content: {}\nResponse Status: {}\nContent-Type: {}".format(
                    error_snippet, resp.status_code, content_type),
                remediation=(
                    "1. Disable detailed error messages in production environments.\n"
                    "2. Configure custom error pages that do not reveal internal paths or line numbers.\n"
                    "3. Log errors to a server-side logging service instead of displaying them.\n"
                    "4. Ensure framework debug mode is disabled in production."
                ),
                url=url,
                module="info_disclosure",
                cwe="CWE-209",
                confirmed=True,
                location="Response body at {}".format(parsed.path),
                parameter="", payload="",
                request_method="GET",
                response_status=resp.status_code,
                curl_command=_build_curl("GET", url),
                reproduction_steps=(
                    "1. Send a GET request to: {url}\n"
                    "2. Observe the response body.\n"
                    "3. The response contains a detailed error message with internal paths.\n"
                    "4. Error snippet: {snip}"
                ).format(url=url, snip=error_snippet[:100]),
                developer_fix=(
                    "File: Application error handler or web server configuration.\n"
                    "Fix: Configure production error handling to suppress details.\n"
                    "  - Apache: Set ServerSignature Off and ErrorDocument directives\n"
                    "  - Nginx: Use error_page directive with custom static HTML\n"
                    "  - PHP: Set display_errors = Off and log_errors = On in php.ini\n"
                    "  - Python/Django: Set DEBUG = False, configure LOGGING to file\n"
                    "  - Node/Express: app.set('env', 'production')"
                ),
                affected_component="Error handling for {}".format(parsed.path),
                references=(
                    "https://owasp.org/www-community/Improper_Error_Handling | "
                    "https://cwe.mitre.org/data/definitions/209.html"
                ),
                detection_method=_DETECTION,
            ))

    _check_error_pages(session)


def _check_error_pages(session):
    url = "{}/nonexistent_page_vulnscan_test_404".format(session.config.target)
    resp = session.get(url)
    if not resp:
        return

    body = resp.text
    parsed = urlparse(url)
    trigger_type = "404 Page"

    for pattern, name, severity in ERROR_PAGE_PATTERNS:
        match = re.search(pattern, body, re.IGNORECASE)
        if not match:
            continue
        error_snippet = match.group(0)[:200]

        session.add_finding(Finding(
            title="Error Page Leaks Information ({})".format(trigger_type),
            severity=severity,
            description=(
                "Requesting a non-existent page triggers a {tt} response that "
                "reveals {lname}. Custom error pages should not expose internal "
                "application details such as file paths, framework versions, or stack traces."
            ).format(tt=trigger_type, lname=name.lower()),
            evidence="Trigger: {}\nError Content: {}\nResponse Status: {}".format(
                trigger_type, error_snippet, resp.status_code),
            remediation=(
                "1. Configure custom error pages for all HTTP error codes (404, 500, etc.).\n"
                "2. Ensure error pages do not reveal server paths, framework names, or version numbers.\n"
                "3. Return a generic 'Page Not Found' message for 404 errors.\n"
                "4. Log detailed error information server-side only."
            ),
            url=url,
            module="info_disclosure",
            cwe="CWE-209",
            confirmed=True,
            location="Error page at {}".format(parsed.path),
            parameter="", payload="",
            request_method="GET",
            response_status=resp.status_code,
            curl_command=_build_curl("GET", url),
            reproduction_steps=(
                "1. Send a GET request to a non-existent URL: {url}\n"
                "2. Observe the {tt} error response.\n"
                "3. The error page reveals internal details: {snip}\n"
                "4. This information helps attackers fingerprint the application stack."
            ).format(url=url, tt=trigger_type, snip=error_snippet[:100]),
            developer_fix=(
                "File: Web server or application error handler configuration.\n"
                "Fix: Add custom error pages.\n"
                "  - Apache (.htaccess):\n"
                "    ErrorDocument 404 /custom_404.html\n"
                "    ErrorDocument 500 /custom_500.html\n"
                "  - Nginx (nginx.conf):\n"
                "    error_page 404 /custom_404.html;\n"
                "    error_page 500 502 503 504 /custom_50x.html;\n"
                "  - Django (urls.py):\n"
                "    handler404 = 'myapp.views.custom_404'\n"
                "  - Express:\n"
                "    app.use((req, res) => res.status(404).sendFile('404.html'));"
            ),
            affected_component="Error page handler for {}".format(trigger_type),
            references=(
                "https://owasp.org/www-community/Improper_Error_Handling | "
                "https://cwe.mitre.org/data/definitions/209.html | "
                "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
            ),
            detection_method=_DETECTION,
        ))

    if re.search(STACK_TRACE_PATTERN, body, re.MULTILINE):
        trace_match = re.search(r'((?:^\s+at\s+[\w.$]+\([\w.]+:\d+\).*\n){1,5})', body, re.MULTILINE)
        trace_snippet = trace_match.group(0).strip()[:300] if trace_match else "Multiple 'at ...' lines"

        session.add_finding(Finding(
            title="Error Page Exposes Stack Trace ({})".format(trigger_type),
            severity=Severity.MEDIUM,
            description=(
                "Triggering a {tt} error reveals a full stack trace in the response. "
                "Stack traces expose internal file paths, class hierarchies, and line numbers "
                "that significantly aid attackers in understanding the application architecture."
            ).format(tt=trigger_type),
            evidence="Trigger: {}\nStack Trace Snippet:\n{}\nResponse Status: {}".format(
                trigger_type, trace_snippet, resp.status_code),
            remediation=(
                "1. Disable stack trace output in production environments.\n"
                "2. Configure custom error pages for all error codes.\n"
                "3. Use centralized logging to capture errors server-side.\n"
                "4. Set framework-specific production flags (DEBUG=False, NODE_ENV=production)."
            ),
            url=url,
            module="info_disclosure",
            cwe="CWE-209",
            confirmed=True,
            location="Error page response body",
            parameter="", payload="",
            request_method="GET",
            response_status=resp.status_code,
            curl_command=_build_curl("GET", url),
            reproduction_steps=(
                "1. Send a GET request to: {url}\n"
                "2. The server returns a {tt} error.\n"
                "3. Observe the full stack trace in the response body.\n"
                "4. Internal file paths and line numbers are exposed."
            ).format(url=url, tt=trigger_type),
            developer_fix=(
                "File: Application error handler or framework configuration.\n"
                "Fix: Suppress stack traces in production.\n"
                "  - Django: DEBUG = False in settings.py\n"
                "  - Flask: app.debug = False\n"
                "  - Express:\n"
                "    if (process.env.NODE_ENV === 'production') {{\n"
                "      app.use((err, req, res, next) => {{\n"
                "        res.status(500).send('Internal Server Error');\n"
                "      }});\n"
                "    }}\n"
                "  - Spring Boot: server.error.include-stacktrace=never"
            ),
            affected_component="Error page handler for {}".format(trigger_type),
            references=(
                "https://owasp.org/www-community/Improper_Error_Handling | "
                "https://cwe.mitre.org/data/definitions/209.html | "
                "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
            ),
            detection_method=_DETECTION,
        ))
