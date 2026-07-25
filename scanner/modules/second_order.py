import re
import hashlib
from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession, build_curl


# Unique marker prefix to avoid false positives
_MARKER = "RS2ND"

# Payloads organized by injection type with unique markers for tracking
SQLI_PAYLOADS = [
    ("' OR '{m}' = '{m}", "SQL injection (string OR)"),
    ("1; SELECT '{m}' --", "SQL injection (stacked query)"),
    ("' UNION SELECT '{m}' --", "SQL injection (UNION)"),
]

XSS_PAYLOADS = [
    ('<img src=x onerror="alert(\'{m}\')"/>', "XSS (img onerror)"),
    ("<script>{m}</script>", "XSS (script tag)"),
    ('"><svg onload=alert("{m}")>', "XSS (svg onload)"),
    ("javascript:{m}//", "XSS (javascript protocol)"),
]

SSTI_PAYLOADS = [
    ("${{7*'{m}'}}", "SSTI (generic expression)"),
    ("{{{{{m}}}}}", "SSTI (Jinja2/Twig double braces)"),
    ("<%='{m}'%>", "SSTI (ERB template)"),
    ("#{{'{m}'}}", "SSTI (Ruby interpolation)"),
]

# Form field patterns that are likely to store and display user input
STORAGE_FIELD_PATTERNS = re.compile(
    r"(name|username|user|display|nick|alias|first|last|full|title|"
    r"bio|about|description|comment|message|body|content|text|"
    r"note|feedback|review|address|company|organization|website|"
    r"url|link|profile|signature|motto|tagline|headline|subject|"
    r"answer|response|reply|summary)",
    re.IGNORECASE,
)

# Pages likely to display stored content
DISPLAY_PATH_PATTERNS = [
    re.compile(r"/(profile|user|account|member)", re.IGNORECASE),
    re.compile(r"/(comment|review|feedback|post|article|blog)", re.IGNORECASE),
    re.compile(r"/(dashboard|admin|panel|manage)", re.IGNORECASE),
    re.compile(r"/(list|view|show|display|detail|page|index)", re.IGNORECASE),
    re.compile(r"/(search|results|output|report)", re.IGNORECASE),
    re.compile(r"/(forum|thread|topic|board|discussion)", re.IGNORECASE),
]


def _generate_marker(payload_type, param_name, form_action):
    """Generate a unique marker for tracking payload->observation relationships."""
    raw = f"{payload_type}:{param_name}:{form_action}"
    short_hash = hashlib.md5(raw.encode()).hexdigest()[:8]
    return f"{_MARKER}{short_hash}"


def _is_storage_field(name):
    """Check if a field name suggests it stores and displays user input."""
    return bool(STORAGE_FIELD_PATTERNS.search(name)) if name else False


def _is_display_page(url):
    """Check if a URL is likely to display stored content."""
    for pattern in DISPLAY_PATH_PATTERNS:
        if pattern.search(url):
            return True
    return False


def _build_payloads_with_markers(marker):
    """Build all payload variants with the given marker."""
    payloads = []
    for template, desc in SQLI_PAYLOADS:
        payloads.append((template.format(m=marker), desc, "SQL Injection"))
    for template, desc in XSS_PAYLOADS:
        payloads.append((template.format(m=marker), desc, "Cross-Site Scripting"))
    for template, desc in SSTI_PAYLOADS:
        payloads.append((template.format(m=marker), desc, "Server-Side Template Injection"))
    return payloads


def _submit_payloads(session, form):
    """Submit payloads into storage-capable form fields and return tracking info."""
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)

    if method != "post":
        return []

    tracking = []

    baseline_data = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            baseline_data[name] = inp.get("value", "test")

    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue

        if not _is_storage_field(name):
            continue

        marker = _generate_marker("all", name, action)
        payloads = _build_payloads_with_markers(marker)

        for payload, description, injection_type in payloads:
            test_data = dict(baseline_data)
            test_data[name] = payload

            resp = session.post(action, data=test_data)
            if not resp:
                continue

            # Check if submission was accepted (not rejected with error)
            if resp.status_code in (200, 201, 301, 302, 303):
                tracking.append({
                    "marker": marker,
                    "payload": payload,
                    "description": description,
                    "injection_type": injection_type,
                    "parameter": name,
                    "form_action": action,
                    "source_url": source_url,
                    "method": method,
                    "submit_status": resp.status_code,
                    "test_data": test_data,
                })
                break  # One payload per field to avoid noise

    return tracking


def _check_for_reflections(session, tracking):
    """Crawl display pages to check if submitted payloads appear unescaped."""
    if not tracking:
        return

    # Collect all markers to search for
    marker_map = {}
    for entry in tracking:
        marker_map[entry["marker"]] = entry

    # Check all crawled URLs and specifically display pages
    urls_to_check = set()
    for url in session.crawled_urls:
        if _is_display_page(url):
            urls_to_check.add(url)

    # Also add source URLs and common display pages
    parsed_target = urlparse(list(session.crawled_urls)[0]) if session.crawled_urls else None
    if parsed_target:
        base = f"{parsed_target.scheme}://{parsed_target.netloc}"
        common_pages = [
            "/", "/profile", "/dashboard", "/admin", "/users",
            "/comments", "/posts", "/reviews", "/search",
        ]
        for page in common_pages:
            urls_to_check.add(base + page)

    # Add form source URLs
    for entry in tracking:
        urls_to_check.add(entry["source_url"])

    for url in urls_to_check:
        resp = session.get(url)
        if not resp or resp.status_code != 200:
            continue

        body = resp.text

        for marker, entry in marker_map.items():
            if marker not in body:
                continue

            # Marker found! Check if the payload is reflected unescaped
            payload = entry["payload"]
            injection_type = entry["injection_type"]
            description = entry["description"]
            param = entry["parameter"]
            form_action = entry["form_action"]
            source_url = entry["source_url"]

            # Determine the severity and confirmation based on what we find
            confirmed = False
            reflected_raw = False
            evidence_detail = ""

            if injection_type == "Cross-Site Scripting":
                # Check for unescaped XSS markers
                xss_patterns = [
                    f"<script>{marker}</script>",
                    f'onerror="alert(\'{marker}\')"',
                    f'onload=alert("{marker}")',
                    f"javascript:{marker}",
                ]
                for xss_pat in xss_patterns:
                    if xss_pat in body:
                        confirmed = True
                        reflected_raw = True
                        evidence_detail = f"Unescaped XSS payload found in page source: {xss_pat}"
                        break
                if not reflected_raw:
                    evidence_detail = f"XSS marker '{marker}' found in page but payload may be partially escaped."

            elif injection_type == "SQL Injection":
                # The marker appearing in the output suggests the SQL was interpreted
                confirmed = False
                evidence_detail = (
                    f"SQL injection marker '{marker}' appeared in page content at {url}. "
                    f"This suggests the injected value was stored and is rendered, "
                    f"which could indicate SQL injection if the value was processed by a query."
                )

            elif injection_type == "Server-Side Template Injection":
                # Check if the template expression was evaluated
                if marker in body and "{{" not in body.split(marker)[0][-20:]:
                    confirmed = True
                    evidence_detail = (
                        f"SSTI marker '{marker}' was rendered in the page, indicating "
                        f"the template expression was evaluated server-side."
                    )
                else:
                    evidence_detail = (
                        f"SSTI marker '{marker}' appeared in page content."
                    )

            # Extract the context around the marker in the page
            marker_idx = body.find(marker)
            context_start = max(0, marker_idx - 100)
            context_end = min(len(body), marker_idx + len(marker) + 100)
            context_snippet = body[context_start:context_end].replace('\n', ' ').strip()

            severity = Severity.HIGH if confirmed else Severity.MEDIUM
            submit_curl = build_curl(
                "POST", form_action,
                data="&".join(f"{k}={v}" for k, v in entry["test_data"].items()),
            )
            observe_curl = build_curl("GET", url)

            session.add_finding(Finding(
                title=f"Second-Order {injection_type} (Stored via '{param}', Reflected on {urlparse(url).path})",
                severity=severity,
                description=(
                    f"A {injection_type.lower()} payload was submitted via the form field "
                    f"'{param}' at '{form_action}' and later appeared in the page at '{url}'. "
                    f"This is a second-order injection: the payload is stored by the application "
                    f"during submission and then rendered (potentially unsanitized) when the "
                    f"affected page is viewed. {evidence_detail}"
                ),
                evidence=(
                    f"Injection Point:\n"
                    f"  Form Action: {form_action}\n"
                    f"  Field: {param}\n"
                    f"  Payload: {payload}\n"
                    f"  Submission Status: {entry['submit_status']}\n\n"
                    f"Observation Point:\n"
                    f"  Page URL: {url}\n"
                    f"  Marker Found: {marker}\n"
                    f"  Raw Payload Reflected: {reflected_raw}\n"
                    f"  Context: {context_snippet}"
                ),
                remediation=(
                    "1. Sanitize and validate all user input BEFORE storage, not just on output.\n"
                    "2. Apply context-aware output encoding when rendering stored data:\n"
                    "   - HTML context: HTML-encode (<, >, &, \", ')\n"
                    "   - JavaScript context: JavaScript-encode\n"
                    "   - SQL context: Use parameterized queries\n"
                    "3. Use Content Security Policy (CSP) to mitigate stored XSS impact.\n"
                    "4. Implement input validation with allowlists for expected data formats.\n"
                    "5. Use a template engine with auto-escaping enabled by default."
                ),
                url=url,
                module="second_order",
                cwe="CWE-74",
                confirmed=confirmed,
                location=f"Stored via form field '{param}' at {form_action}, reflected on {url}",
                parameter=param,
                payload=payload,
                request_method="POST",
                request_body="&".join(f"{k}={v}" for k, v in entry["test_data"].items()),
                response_status=resp.status_code,
                curl_command=submit_curl,
                reproduction_steps=(
                    f"1. Submit the payload via the form:\n"
                    f"   Run: {submit_curl}\n"
                    f"2. Navigate to the observation page: {url}\n"
                    f"   Run: {observe_curl}\n"
                    f"3. Search the page source for the marker: {marker}\n"
                    f"4. Verify the payload context: {context_snippet[:200]}"
                ),
                developer_fix=(
                    f"File: Two locations need fixing:\n\n"
                    f"1. Input handler for POST {form_action} (storage):\n"
                    f"   Sanitize '{param}' before storing:\n"
                    f"     Python: from markupsafe import escape\n"
                    f"     {param} = escape(request.form['{param}'])\n\n"
                    f"2. Template rendering {urlparse(url).path} (output):\n"
                    f"   Ensure auto-escaping is enabled:\n"
                    f"     Jinja2: {{{{ {param} }}}} (auto-escaped by default)\n"
                    f"     Django: {{{{ {param}|escape }}}}\n"
                    f"     Node.js/EJS: <%%= {param} %> (escaped, not <%- )\n\n"
                    f"3. For SQL: Use parameterized queries:\n"
                    f"     cursor.execute('INSERT INTO table ({param}) VALUES (%s)', [{param}])"
                ),
                affected_component=f"Data flow: {form_action} (input) -> database -> {urlparse(url).path} (output)",
                references="https://owasp.org/www-community/attacks/Second_Order_Injection | https://portswigger.net/web-security/cross-site-scripting/stored",
                detection_method=(
                    f"Submitted a {injection_type.lower()} payload with unique marker '{marker}' "
                    f"via form field '{param}' at '{form_action}', then crawled display pages "
                    f"and found the marker reflected at '{url}', confirming second-order injection."
                ),
            ))


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Second-Order Injection...")

    all_tracking = []

    # Phase 1: Submit payloads into storage-capable forms
    for form in session.forms:
        tracking = _submit_payloads(session, form)
        all_tracking.extend(tracking)

    if not all_tracking:
        return

    # Phase 2: Check display pages for reflected payloads
    _check_for_reflections(session, all_tracking)
