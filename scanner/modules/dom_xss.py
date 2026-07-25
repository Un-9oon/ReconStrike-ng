import re
from urllib.parse import urlparse, urljoin

from scanner.core import Finding, Severity, ScanSession, build_curl


# Dangerous sinks that execute or render untrusted content
DANGEROUS_SINKS = [
    {
        "pattern": r"\.innerHTML\s*=",
        "name": "innerHTML",
        "risk": "Directly renders HTML, allowing script injection if the value contains user input.",
    },
    {
        "pattern": r"\.outerHTML\s*=",
        "name": "outerHTML",
        "risk": "Replaces the element and its contents with raw HTML, enabling script injection.",
    },
    {
        "pattern": r"document\.write\s*\(",
        "name": "document.write",
        "risk": "Writes raw HTML to the document stream, executing any embedded scripts.",
    },
    {
        "pattern": r"document\.writeln\s*\(",
        "name": "document.writeln",
        "risk": "Same as document.write but appends a newline; equally dangerous.",
    },
    {
        "pattern": r"\.insertAdjacentHTML\s*\(",
        "name": "insertAdjacentHTML",
        "risk": "Inserts HTML at a specified position, can execute scripts in the injected content.",
    },
    {
        "pattern": r"\beval\s*\(",
        "name": "eval()",
        "risk": "Executes arbitrary JavaScript code from a string argument.",
    },
    {
        "pattern": r"\bsetTimeout\s*\(\s*[\"'`]",
        "name": "setTimeout (string)",
        "risk": "When called with a string argument, acts as eval() and executes the string as code.",
    },
    {
        "pattern": r"\bsetTimeout\s*\(\s*[a-zA-Z_$]",
        "name": "setTimeout (variable)",
        "risk": "If the first argument is a user-controlled variable containing a string, it acts as eval().",
    },
    {
        "pattern": r"\bsetInterval\s*\(\s*[\"'`]",
        "name": "setInterval (string)",
        "risk": "When called with a string argument, repeatedly executes the string as code.",
    },
    {
        "pattern": r"new\s+Function\s*\(",
        "name": "new Function()",
        "risk": "Creates a function from a string body, equivalent to eval() for code execution.",
    },
    {
        "pattern": r"\.src\s*=",
        "name": ".src assignment",
        "risk": "Setting src on script/iframe/img elements can load attacker-controlled resources.",
    },
    {
        "pattern": r"\.href\s*=",
        "name": ".href assignment",
        "risk": "Setting href can redirect users or inject javascript: URIs.",
    },
    {
        "pattern": r"\.action\s*=",
        "name": ".action assignment",
        "risk": "Setting form action can redirect form submissions to attacker-controlled endpoints.",
    },
    {
        "pattern": r"location\s*=",
        "name": "location assignment",
        "risk": "Direct location assignment can enable open redirects or javascript: URI execution.",
    },
    {
        "pattern": r"location\.href\s*=",
        "name": "location.href assignment",
        "risk": "Assigning to location.href navigates the page, enabling javascript: URI attacks.",
    },
    {
        "pattern": r"location\.replace\s*\(",
        "name": "location.replace()",
        "risk": "Replaces current URL without history entry, can execute javascript: URIs.",
    },
    {
        "pattern": r"location\.assign\s*\(",
        "name": "location.assign()",
        "risk": "Navigates to a new URL, can execute javascript: URIs if user-controlled.",
    },
    {
        "pattern": r"\.setAttribute\s*\(\s*[\"'](?:on\w+|href|src|action|data|formaction)",
        "name": "setAttribute (event/URL)",
        "risk": "Setting event handlers or URL attributes via setAttribute can inject code.",
    },
    {
        "pattern": r"jQuery\.html\s*\(|\.html\s*\(\s*[^)]+\)",
        "name": "jQuery .html()",
        "risk": "jQuery's .html() parses and executes script tags in the injected HTML.",
    },
    {
        "pattern": r"\$\s*\(\s*[\"'`]?\s*<",
        "name": "jQuery $('<html>')",
        "risk": "Creating jQuery elements from HTML strings can execute embedded scripts.",
    },
    {
        "pattern": r"\.append\s*\(\s*[\"'`]?\s*<",
        "name": "jQuery .append('<html>')",
        "risk": "Appending raw HTML via jQuery can execute scripts in the content.",
    },
    {
        "pattern": r"\.prepend\s*\(\s*[\"'`]?\s*<",
        "name": "jQuery .prepend('<html>')",
        "risk": "Prepending raw HTML via jQuery can execute scripts in the content.",
    },
]

# User-controllable sources
CONTROLLABLE_SOURCES = [
    {
        "pattern": r"location\.hash",
        "name": "location.hash",
        "controllability": "Fully user-controlled via URL fragment (#value). Not sent to server.",
    },
    {
        "pattern": r"location\.search",
        "name": "location.search",
        "controllability": "Fully user-controlled via URL query string (?key=value).",
    },
    {
        "pattern": r"location\.href",
        "name": "location.href (as source)",
        "controllability": "Contains the full URL, including user-controlled query and fragment.",
    },
    {
        "pattern": r"location\.pathname",
        "name": "location.pathname",
        "controllability": "User-controlled via URL path. May be partially controlled in some routing setups.",
    },
    {
        "pattern": r"document\.referrer",
        "name": "document.referrer",
        "controllability": "Controlled by the referring page. Attacker can set this via a link from their site.",
    },
    {
        "pattern": r"document\.URL",
        "name": "document.URL",
        "controllability": "Contains the full URL, similar to location.href.",
    },
    {
        "pattern": r"document\.documentURI",
        "name": "document.documentURI",
        "controllability": "Contains the full document URI, similar to document.URL.",
    },
    {
        "pattern": r"document\.cookie",
        "name": "document.cookie",
        "controllability": "May contain values set by user-controlled subdomains or XSS on related origins.",
    },
    {
        "pattern": r"window\.name",
        "name": "window.name",
        "controllability": "Persists across navigations. Attacker can set it via window.open() or iframe name.",
    },
    {
        "pattern": r"window\.postMessage|addEventListener\s*\(\s*[\"']message",
        "name": "postMessage",
        "controllability": "Receives cross-origin messages. Attacker can send arbitrary data from their page.",
    },
    {
        "pattern": r"localStorage\.getItem|localStorage\[",
        "name": "localStorage",
        "controllability": "May contain values previously set via XSS or same-origin scripts.",
    },
    {
        "pattern": r"sessionStorage\.getItem|sessionStorage\[",
        "name": "sessionStorage",
        "controllability": "May contain values previously set via XSS or same-origin scripts.",
    },
    {
        "pattern": r"URLSearchParams",
        "name": "URLSearchParams",
        "controllability": "Typically used to parse user-controlled query strings.",
    },
    {
        "pattern": r"decodeURIComponent\s*\(\s*(?:location|document\.URL|window\.location)",
        "name": "decodeURIComponent(location.*)",
        "controllability": "Decodes URL-encoded user input from the URL, often flows into sinks.",
    },
]

# Patterns that suggest sanitization is NOT applied
NO_SANITIZATION_INDICATORS = [
    r"\.innerHTML\s*=\s*(?:location|document\.URL|document\.referrer|window\.name|decodeURI)",
    r"document\.write\s*\(\s*(?:location|document\.URL|document\.referrer|window\.name|decodeURI)",
    r"eval\s*\(\s*(?:location|document\.URL|document\.referrer|window\.name|decodeURI)",
    r"\.innerHTML\s*=\s*['\"]?\s*\+\s*(?:location|document\.URL|document\.referrer)",
    r"document\.write\s*\(\s*['\"]?\s*\+\s*(?:location|document\.URL|document\.referrer)",
    r"location\.href\s*=\s*(?:location\.hash|location\.search|document\.referrer|window\.name)",
    r"jQuery\.html\s*\(\s*(?:location|document\.URL|document\.referrer|window\.name)",
    r"\.html\s*\(\s*(?:location|document\.URL|document\.referrer|window\.name)",
]

# Patterns that suggest sanitization IS applied (lower risk)
SANITIZATION_INDICATORS = [
    r"DOMPurify\.sanitize",
    r"sanitizeHTML",
    r"escapeHtml",
    r"textContent\s*=",
    r"createTextNode",
    r"encodeURIComponent",
    r"\.replace\s*\(\s*/[<>\"'&]/",
    r"xss\s*filter",
    r"sanitize\s*\(",
]


def _extract_js_from_html(html):
    """Extract inline JavaScript from HTML content."""
    scripts = []

    # Extract <script> tag contents
    script_tags = re.findall(
        r'<script[^>]*?(?:type\s*=\s*["\']?(?:text/javascript|application/javascript|module)["\']?[^>]*?)?>(.*?)</script>',
        html,
        re.DOTALL | re.IGNORECASE,
    )
    scripts.extend(script_tags)

    # Also capture scripts without a type attribute (default is JS)
    default_scripts = re.findall(
        r'<script(?:\s+(?!type)[^>]*)?>(.*?)</script>',
        html,
        re.DOTALL | re.IGNORECASE,
    )
    scripts.extend(default_scripts)

    # Extract inline event handlers
    event_handlers = re.findall(
        r'on(?:click|load|error|mouseover|focus|blur|change|submit|input|keyup|keydown)\s*=\s*["\']([^"\']+)',
        html,
        re.IGNORECASE,
    )
    scripts.extend(event_handlers)

    # Extract javascript: URIs
    js_uris = re.findall(
        r'(?:href|src|action)\s*=\s*["\']javascript:([^"\']+)',
        html,
        re.IGNORECASE,
    )
    scripts.extend(js_uris)

    return scripts


def _extract_linked_js_urls(html, base_url):
    """Extract URLs of linked JavaScript files."""
    js_urls = []
    src_matches = re.findall(
        r'<script[^>]+src\s*=\s*["\']([^"\']+)',
        html,
        re.IGNORECASE,
    )
    for src in src_matches:
        if src.startswith("//"):
            js_urls.append("https:" + src)
        elif src.startswith("/"):
            js_urls.append(urljoin(base_url, src))
        elif src.startswith("http"):
            js_urls.append(src)
        else:
            js_urls.append(urljoin(base_url, src))
    return js_urls


def _find_sinks(js_code):
    """Find dangerous sinks in JavaScript code."""
    found = []
    for sink in DANGEROUS_SINKS:
        matches = list(re.finditer(sink["pattern"], js_code))
        if matches:
            for match in matches:
                # Extract the line containing the match
                start = js_code.rfind('\n', 0, match.start()) + 1
                end = js_code.find('\n', match.end())
                if end == -1:
                    end = min(match.end() + 100, len(js_code))
                line = js_code[start:end].strip()

                found.append({
                    "name": sink["name"],
                    "risk": sink["risk"],
                    "line": line[:200],
                    "position": match.start(),
                })
    return found


def _find_sources(js_code):
    """Find user-controllable sources in JavaScript code."""
    found = []
    for source in CONTROLLABLE_SOURCES:
        matches = list(re.finditer(source["pattern"], js_code))
        if matches:
            for match in matches:
                start = js_code.rfind('\n', 0, match.start()) + 1
                end = js_code.find('\n', match.end())
                if end == -1:
                    end = min(match.end() + 100, len(js_code))
                line = js_code[start:end].strip()

                found.append({
                    "name": source["name"],
                    "controllability": source["controllability"],
                    "line": line[:200],
                    "position": match.start(),
                })
    return found


def _check_direct_flows(js_code):
    """Check for direct source-to-sink data flows without sanitization."""
    flows = []
    for pattern in NO_SANITIZATION_INDICATORS:
        matches = list(re.finditer(pattern, js_code, re.IGNORECASE))
        for match in matches:
            start = js_code.rfind('\n', 0, match.start()) + 1
            end = js_code.find('\n', match.end())
            if end == -1:
                end = min(match.end() + 100, len(js_code))
            line = js_code[start:end].strip()
            flows.append(line[:200])
    return flows


def _has_sanitization(js_code):
    """Check if the code contains sanitization patterns."""
    for pattern in SANITIZATION_INDICATORS:
        if re.search(pattern, js_code, re.IGNORECASE):
            return True
    return False


def _analyze_js(session, js_code, source_url, js_source_desc):
    """Analyze JavaScript code for DOM XSS patterns."""
    if not js_code or len(js_code) < 10:
        return

    parsed = urlparse(source_url)
    sinks = _find_sinks(js_code)
    sources = _find_sources(js_code)
    direct_flows = _check_direct_flows(js_code)
    has_sanitization = _has_sanitization(js_code)

    # Priority 1: Direct source-to-sink flows (highest confidence)
    if direct_flows:
        flow_evidence = "\n".join(f"  - {f}" for f in direct_flows[:5])
        curl_cmd = build_curl("GET", source_url)

        session.add_finding(Finding(
            title="DOM-Based XSS (Direct Source-to-Sink Flow)",
            severity=Severity.HIGH,
            description=(
                f"JavaScript code at '{source_url}' contains direct data flows from "
                f"user-controllable sources to dangerous sinks without sanitization. "
                f"An attacker can craft a URL that injects malicious content via the DOM "
                f"without server interaction. Found in: {js_source_desc}."
            ),
            evidence=(
                f"Source URL: {source_url}\n"
                f"JS Source: {js_source_desc}\n"
                f"Direct Source-to-Sink Flows:\n{flow_evidence}\n"
                f"Sanitization Detected: {has_sanitization}\n"
                f"Total Sinks Found: {len(sinks)}\n"
                f"Total Sources Found: {len(sources)}"
            ),
            remediation=(
                "1. Never pass user-controllable data directly to innerHTML, document.write, "
                "eval, or other dangerous sinks.\n"
                "2. Use textContent or innerText instead of innerHTML for text content.\n"
                "3. If HTML rendering is necessary, use DOMPurify.sanitize() on all input.\n"
                "4. Implement a strict Content-Security-Policy that blocks inline scripts.\n"
                "5. Use the Trusted Types API to enforce safe sink usage."
            ),
            url=source_url,
            module="dom_xss",
            cwe="CWE-79",
            confirmed=True,
            location=f"JavaScript in {js_source_desc}",
            payload="Varies by flow (see evidence for specific patterns)",
            request_method="GET",
            response_status=200,
            curl_command=curl_cmd,
            reproduction_steps=(
                f"1. Open: {source_url}\n"
                f"2. View page source or use browser DevTools to find the JavaScript.\n"
                f"3. Identify the vulnerable code patterns listed in the evidence.\n"
                f"4. Craft a URL with a malicious fragment/query:\n"
                f"   {source_url}#<img src=x onerror=alert(1)>\n"
                f"   {source_url}?param=<script>alert(1)</script>\n"
                f"5. Check if the payload executes in the browser."
            ),
            developer_fix=(
                f"File: {js_source_desc}\n\n"
                "Replace dangerous sink patterns:\n\n"
                "  VULNERABLE:\n"
                "    element.innerHTML = location.hash.slice(1);\n"
                "    document.write(decodeURIComponent(location.search));\n\n"
                "  SECURE:\n"
                "    element.textContent = location.hash.slice(1);\n"
                "    // Or with DOMPurify:\n"
                "    element.innerHTML = DOMPurify.sanitize(location.hash.slice(1));\n\n"
                "  CSP header:\n"
                "    Content-Security-Policy: default-src 'self'; script-src 'self'; "
                "require-trusted-types-for 'script'"
            ),
            affected_component=f"Client-side JavaScript at {parsed.path}",
            references=(
                "https://owasp.org/www-community/attacks/DOM_Based_XSS | "
                "https://portswigger.net/web-security/cross-site-scripting/dom-based | "
                "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
            ),
            detection_method=(
                "Static analysis of JavaScript code identified direct data flows from "
                "user-controllable sources (location.hash, location.search, document.referrer, "
                "postMessage, window.name) to dangerous DOM sinks (innerHTML, document.write, "
                "eval) without sanitization."
            ),
        ))
        return

    # Priority 2: Sources and sinks both present (potential flow)
    if sinks and sources and not has_sanitization:
        # Check proximity -- sources and sinks near each other suggest a flow
        potential_flows = []
        for source in sources:
            for sink in sinks:
                # If within ~500 chars of each other in the code, likely related
                distance = abs(source["position"] - sink["position"])
                if distance < 500:
                    potential_flows.append({
                        "source": source,
                        "sink": sink,
                        "distance": distance,
                    })

        if potential_flows:
            flow_evidence = "\n".join(
                f"  Source: {f['source']['name']} -> Sink: {f['sink']['name']}\n"
                f"    Source line: {f['source']['line']}\n"
                f"    Sink line: {f['sink']['line']}"
                for f in potential_flows[:3]
            )

            curl_cmd = build_curl("GET", source_url)
            session.add_finding(Finding(
                title="Potential DOM-Based XSS (Source Near Sink)",
                severity=Severity.MEDIUM,
                description=(
                    f"JavaScript code at '{source_url}' contains both user-controllable "
                    f"sources and dangerous sinks in close proximity, without apparent "
                    f"sanitization. While a direct data flow was not confirmed through "
                    f"static analysis, the proximity suggests data may flow from source "
                    f"to sink. Found in: {js_source_desc}."
                ),
                evidence=(
                    f"Source URL: {source_url}\n"
                    f"JS Source: {js_source_desc}\n"
                    f"Potential Flows ({len(potential_flows)}):\n{flow_evidence}\n"
                    f"Sanitization Detected: No"
                ),
                remediation=(
                    "1. Audit the identified source-sink pairs to confirm if data flows between them.\n"
                    "2. Use textContent instead of innerHTML where possible.\n"
                    "3. Apply DOMPurify.sanitize() before passing data to any HTML-rendering sink.\n"
                    "4. Implement Content-Security-Policy with strict-dynamic.\n"
                    "5. Enable Trusted Types to prevent unsafe sink usage."
                ),
                url=source_url,
                module="dom_xss",
                cwe="CWE-79",
                confirmed=False,
                location=f"JavaScript in {js_source_desc}",
                request_method="GET",
                response_status=200,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Open: {source_url}\n"
                    f"2. Open browser DevTools (F12) -> Sources tab.\n"
                    f"3. Search for the sink patterns listed in the evidence.\n"
                    f"4. Trace the data flow from the source to the sink.\n"
                    f"5. If a flow exists, craft a test URL:\n"
                    f"   {source_url}#<img src=x onerror=alert(document.domain)>\n"
                    f"6. Check browser console for execution."
                ),
                developer_fix=(
                    f"File: {js_source_desc}\n\n"
                    "Audit and fix each source-sink pair:\n\n"
                    "  1. Replace innerHTML/outerHTML with textContent where HTML is not needed.\n"
                    "  2. If HTML is needed, sanitize first:\n"
                    "     element.innerHTML = DOMPurify.sanitize(userInput);\n"
                    "  3. Replace eval/setTimeout(string) with safer alternatives:\n"
                    "     setTimeout(() => safeFunction(arg), delay);\n"
                    "  4. Validate URLs before assigning to location/href/src:\n"
                    "     if (url.startsWith('/') || url.startsWith(window.origin)) { ... }"
                ),
                affected_component=f"Client-side JavaScript at {parsed.path}",
                references=(
                    "https://owasp.org/www-community/attacks/DOM_Based_XSS | "
                    "https://portswigger.net/web-security/cross-site-scripting/dom-based"
                ),
                detection_method=(
                    "Static analysis found user-controllable sources and dangerous sinks "
                    f"in close proximity (within 500 chars) in JavaScript code without "
                    f"detected sanitization patterns."
                ),
            ))
            return

    # Priority 3: Sinks without sanitization (informational)
    if sinks and not has_sanitization:
        high_risk_sinks = [
            s for s in sinks
            if s["name"] in ("innerHTML", "document.write", "eval()", "outerHTML",
                             "new Function()", "jQuery .html()")
        ]

        if high_risk_sinks:
            sink_evidence = "\n".join(
                f"  - {s['name']}: {s['line']}"
                for s in high_risk_sinks[:5]
            )

            curl_cmd = build_curl("GET", source_url)
            session.add_finding(Finding(
                title="Dangerous DOM Sinks Without Sanitization",
                severity=Severity.LOW,
                description=(
                    f"JavaScript code at '{source_url}' uses {len(high_risk_sinks)} dangerous "
                    f"DOM sink(s) (innerHTML, document.write, eval, etc.) without detected "
                    f"sanitization. While no user-controllable source was found flowing into "
                    f"these sinks in this static analysis, they represent potential DOM XSS "
                    f"vectors if user data reaches them through indirect paths. "
                    f"Found in: {js_source_desc}."
                ),
                evidence=(
                    f"Source URL: {source_url}\n"
                    f"JS Source: {js_source_desc}\n"
                    f"Dangerous Sinks ({len(high_risk_sinks)}):\n{sink_evidence}\n"
                    f"User Sources Detected: {len(sources)}\n"
                    f"Sanitization Detected: No"
                ),
                remediation=(
                    "1. Replace innerHTML with textContent where HTML rendering is not needed.\n"
                    "2. Replace document.write with DOM API methods (createElement, appendChild).\n"
                    "3. Replace eval/setTimeout(string) with direct function references.\n"
                    "4. If sinks must be used, implement DOMPurify sanitization.\n"
                    "5. Enable Trusted Types via CSP to enforce safe sink usage."
                ),
                url=source_url,
                module="dom_xss",
                cwe="CWE-79",
                confirmed=False,
                location=f"JavaScript in {js_source_desc}",
                request_method="GET",
                response_status=200,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Open: {source_url}\n"
                    f"2. View page source and search for the sink patterns.\n"
                    f"3. Trace what data flows into each sink.\n"
                    f"4. If any user input reaches a sink, test with:\n"
                    f"   <img src=x onerror=alert(document.domain)>"
                ),
                developer_fix=(
                    f"File: {js_source_desc}\n\n"
                    "Refactor dangerous sinks:\n\n"
                    "  element.innerHTML = data;\n"
                    "  -> element.textContent = data;\n\n"
                    "  document.write(html);\n"
                    "  -> const el = document.createElement('div');\n"
                    "     el.textContent = text;\n"
                    "     document.body.appendChild(el);\n\n"
                    "  eval(code);\n"
                    "  -> Use JSON.parse() for data, direct function calls for logic."
                ),
                affected_component=f"Client-side JavaScript at {parsed.path}",
                references=(
                    "https://owasp.org/www-community/attacks/DOM_Based_XSS | "
                    "https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API"
                ),
                detection_method=(
                    f"Static analysis identified {len(high_risk_sinks)} high-risk DOM sinks "
                    f"(innerHTML, document.write, eval, etc.) in JavaScript code without "
                    f"accompanying sanitization patterns."
                ),
            ))


def _test_page(session, url):
    """Analyze a page for DOM XSS vulnerabilities."""
    parsed = urlparse(url)

    resp = session.get(url)
    if not resp:
        return
    if resp.status_code != 200:
        return

    content_type = resp.headers.get("Content-Type", "")
    if "html" not in content_type and "javascript" not in content_type:
        return

    body = resp.text

    # Analyze inline JavaScript
    inline_scripts = _extract_js_from_html(body)
    if inline_scripts:
        combined_inline = "\n".join(inline_scripts)
        _analyze_js(session, combined_inline, url, f"inline scripts at {parsed.path}")

    # Analyze linked JavaScript files (only same-origin)
    linked_urls = _extract_linked_js_urls(body, url)
    target_host = parsed.netloc
    for js_url in linked_urls:
        js_parsed = urlparse(js_url)

        # Only analyze same-origin scripts
        if js_parsed.netloc and js_parsed.netloc != target_host:
            continue

        try:
            js_resp = session.get(js_url)
            if js_resp and js_resp.status_code == 200:
                js_content_type = js_resp.headers.get("Content-Type", "")
                if "javascript" in js_content_type or "text/" in js_content_type:
                    _analyze_js(
                        session, js_resp.text, url,
                        f"linked script {js_parsed.path}"
                    )
        except Exception:
            continue


def run(session: ScanSession) -> None:
    print("\n[*] Testing for DOM-Based XSS...")

    for url in session.crawled_urls:
        _test_page(session, url)
