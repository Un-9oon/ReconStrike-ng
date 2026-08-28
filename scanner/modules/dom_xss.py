import re
from urllib.parse import urlparse, urljoin

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession, build_curl


DANGEROUS_SINKS = [
    (r"\.innerHTML\s*=", "innerHTML",
     "Directly renders HTML, allowing script injection if the value contains user input."),
    (r"\.outerHTML\s*=", "outerHTML",
     "Replaces the element and its contents with raw HTML, enabling script injection."),
    (r"document\.write\s*\(", "document.write",
     "Writes raw HTML to the document stream, executing any embedded scripts."),
    (r"document\.writeln\s*\(", "document.writeln",
     "Same as document.write but appends a newline; equally dangerous."),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML",
     "Inserts HTML at a specified position, can execute scripts in the injected content."),
    (r"\beval\s*\(", "eval()",
     "Executes arbitrary JavaScript code from a string argument."),
    (r"\bsetTimeout\s*\(\s*[\"'`]", "setTimeout (string)",
     "When called with a string argument, acts as eval() and executes the string as code."),
    (r"\bsetTimeout\s*\(\s*[a-zA-Z_$]", "setTimeout (variable)",
     "If the first argument is a user-controlled variable containing a string, it acts as eval()."),
    (r"\bsetInterval\s*\(\s*[\"'`]", "setInterval (string)",
     "When called with a string argument, repeatedly executes the string as code."),
    (r"new\s+Function\s*\(", "new Function()",
     "Creates a function from a string body, equivalent to eval() for code execution."),
    (r"\.src\s*=", ".src assignment",
     "Setting src on script/iframe/img elements can load attacker-controlled resources."),
    (r"\.href\s*=", ".href assignment",
     "Setting href can redirect users or inject javascript: URIs."),
    (r"\.action\s*=", ".action assignment",
     "Setting form action can redirect form submissions to attacker-controlled endpoints."),
    (r"location\s*=", "location assignment",
     "Direct location assignment can enable open redirects or javascript: URI execution."),
    (r"location\.href\s*=", "location.href assignment",
     "Assigning to location.href navigates the page, enabling javascript: URI attacks."),
    (r"location\.replace\s*\(", "location.replace()",
     "Replaces current URL without history entry, can execute javascript: URIs."),
    (r"location\.assign\s*\(", "location.assign()",
     "Navigates to a new URL, can execute javascript: URIs if user-controlled."),
    (r"\.setAttribute\s*\(\s*[\"'](?:on\w+|href|src|action|data|formaction)",
     "setAttribute (event/URL)",
     "Setting event handlers or URL attributes via setAttribute can inject code."),
    (r"jQuery\.html\s*\(|\.html\s*\(\s*[^)]+\)", "jQuery .html()",
     "jQuery's .html() parses and executes script tags in the injected HTML."),
    (r"\$\s*\(\s*[\"'`]?\s*<", "jQuery $('<html>')",
     "Creating jQuery elements from HTML strings can execute embedded scripts."),
    (r"\.append\s*\(\s*[\"'`]?\s*<", "jQuery .append('<html>')",
     "Appending raw HTML via jQuery can execute scripts in the content."),
    (r"\.prepend\s*\(\s*[\"'`]?\s*<", "jQuery .prepend('<html>')",
     "Prepending raw HTML via jQuery can execute scripts in the content."),
]

CONTROLLABLE_SOURCES = [
    (r"location\.hash", "location.hash",
     "Fully user-controlled via URL fragment (#value). Not sent to server."),
    (r"location\.search", "location.search",
     "Fully user-controlled via URL query string (?key=value)."),
    (r"location\.href", "location.href (as source)",
     "Contains the full URL, including user-controlled query and fragment."),
    (r"location\.pathname", "location.pathname",
     "User-controlled via URL path."),
    (r"document\.referrer", "document.referrer",
     "Controlled by the referring page. Attacker can set this via a link from their site."),
    (r"document\.URL", "document.URL",
     "Contains the full URL, similar to location.href."),
    (r"document\.documentURI", "document.documentURI",
     "Contains the full document URI."),
    (r"document\.cookie", "document.cookie",
     "May contain values set by user-controlled subdomains or XSS on related origins."),
    (r"window\.name", "window.name",
     "Persists across navigations. Attacker can set it via window.open() or iframe name."),
    (r"window\.postMessage|addEventListener\s*\(\s*[\"']message", "postMessage",
     "Receives cross-origin messages. Attacker can send arbitrary data from their page."),
    (r"localStorage\.getItem|localStorage\[", "localStorage",
     "May contain values previously set via XSS or same-origin scripts."),
    (r"sessionStorage\.getItem|sessionStorage\[", "sessionStorage",
     "May contain values previously set via XSS or same-origin scripts."),
    (r"URLSearchParams", "URLSearchParams",
     "Typically used to parse user-controlled query strings."),
    (r"decodeURIComponent\s*\(\s*(?:location|document\.URL|window\.location)",
     "decodeURIComponent(location.*)",
     "Decodes URL-encoded user input from the URL, often flows into sinks."),
]

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

SANITIZATION_INDICATORS = [
    r"DOMPurify\.sanitize", r"sanitizeHTML", r"escapeHtml",
    r"textContent\s*=", r"createTextNode", r"encodeURIComponent",
    r"\.replace\s*\(\s*/[<>\"'&]/", r"xss\s*filter", r"sanitize\s*\(",
]


def _extract_js_from_html(html):
    scripts = re.findall(
        r'<script[^>]*?(?:type\s*=\s*["\']?(?:text/javascript|application/javascript|module)["\']?[^>]*?)?>(.*?)</script>',
        html, re.DOTALL | re.IGNORECASE,
    )
    scripts += re.findall(
        r'<script(?:\s+(?!type)[^>]*)?>(.*?)</script>',
        html, re.DOTALL | re.IGNORECASE,
    )
    scripts += re.findall(
        r'on(?:click|load|error|mouseover|focus|blur|change|submit|input|keyup|keydown)\s*=\s*["\']([^"\']+)',
        html, re.IGNORECASE,
    )
    scripts += re.findall(
        r'(?:href|src|action)\s*=\s*["\']javascript:([^"\']+)',
        html, re.IGNORECASE,
    )
    return scripts


def _extract_linked_js_urls(html, base_url):
    urls = []
    for src in re.findall(r'<script[^>]+src\s*=\s*["\']([^"\']+)', html, re.IGNORECASE):
        if src.startswith("//"):
            urls.append("https:" + src)
        elif src.startswith("http"):
            urls.append(src)
        else:
            urls.append(urljoin(base_url, src))
    return urls


def _extract_line(js_code, match):
    start = js_code.rfind('\n', 0, match.start()) + 1
    end = js_code.find('\n', match.end())
    if end == -1:
        end = min(match.end() + 100, len(js_code))
    return js_code[start:end].strip()[:200]


def _find_matches(js_code, patterns):
    """Generic finder for sinks or sources."""
    found = []
    for pattern, name, info in patterns:
        for match in re.finditer(pattern, js_code):
            found.append({
                "name": name,
                "info": info,
                "line": _extract_line(js_code, match),
                "position": match.start(),
            })
    return found


def _check_direct_flows(js_code):
    flows = []
    for pattern in NO_SANITIZATION_INDICATORS:
        for match in re.finditer(pattern, js_code, re.IGNORECASE):
            flows.append(_extract_line(js_code, match))
    return flows


def _has_sanitization(js_code):
    return any(re.search(p, js_code, re.IGNORECASE) for p in SANITIZATION_INDICATORS)


def _analyze_js(session, js_code, source_url, js_source_desc):
    if not js_code or len(js_code) < 10:
        return

    parsed = urlparse(source_url)
    sinks = _find_matches(js_code, DANGEROUS_SINKS)
    sources = _find_matches(js_code, CONTROLLABLE_SOURCES)
    direct_flows = _check_direct_flows(js_code)
    sanitized = _has_sanitization(js_code)

    if direct_flows:
        flow_evidence = "\n".join("  - {}".format(f) for f in direct_flows[:5])
        curl_cmd = build_curl("GET", source_url)

        session.add_finding(Finding(
            title="DOM-Based XSS (Direct Source-to-Sink Flow)",
            severity=Severity.HIGH,
            description=(
                "JavaScript code at '{}' contains direct data flows from "
                "user-controllable sources to dangerous sinks without sanitization. "
                "An attacker can craft a URL that injects malicious content via the DOM "
                "without server interaction. Found in: {}."
            ).format(source_url, js_source_desc),
            evidence=(
                "Source URL: {}\n"
                "JS Source: {}\n"
                "Direct Source-to-Sink Flows:\n{}\n"
                "Sanitization Detected: {}\n"
                "Total Sinks Found: {}\n"
                "Total Sources Found: {}"
            ).format(source_url, js_source_desc, flow_evidence,
                     sanitized, len(sinks), len(sources)),
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
            location="JavaScript in {}".format(js_source_desc),
            payload="Varies by flow (see evidence for specific patterns)",
            request_method="GET",
            response_status=200,
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Open: {url}\n"
                "2. View page source or use browser DevTools to find the JavaScript.\n"
                "3. Identify the vulnerable code patterns listed in the evidence.\n"
                "4. Craft a URL with a malicious fragment/query:\n"
                "   {url}#<img src=x onerror=alert(1)>\n"
                "   {url}?param=<script>alert(1)</script>\n"
                "5. Check if the payload executes in the browser."
            ).format(url=source_url),
            developer_fix=(
                "File: {}\n\n"
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
            ).format(js_source_desc),
            affected_component="Client-side JavaScript at {}".format(parsed.path),
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

    # Sources and sinks both present, no sanitization -- check proximity
    if sinks and sources and not sanitized:
        potential_flows = [
            {"source": src, "sink": snk, "distance": abs(src["position"] - snk["position"])}
            for src in sources for snk in sinks
            if abs(src["position"] - snk["position"]) < 500
        ]

        if potential_flows:
            flow_evidence = "\n".join(
                "  Source: {} -> Sink: {}\n"
                "    Source line: {}\n"
                "    Sink line: {}".format(
                    f['source']['name'], f['sink']['name'],
                    f['source']['line'], f['sink']['line'])
                for f in potential_flows[:3]
            )

            curl_cmd = build_curl("GET", source_url)
            session.add_finding(Finding(
                title="Potential DOM-Based XSS (Source Near Sink)",
                severity=Severity.MEDIUM,
                description=(
                    "JavaScript code at '{}' contains both user-controllable "
                    "sources and dangerous sinks in close proximity, without apparent "
                    "sanitization. While a direct data flow was not confirmed through "
                    "static analysis, the proximity suggests data may flow from source "
                    "to sink. Found in: {}."
                ).format(source_url, js_source_desc),
                evidence=(
                    "Source URL: {}\n"
                    "JS Source: {}\n"
                    "Potential Flows ({}):\n{}\n"
                    "Sanitization Detected: No"
                ).format(source_url, js_source_desc, len(potential_flows), flow_evidence),
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
                location="JavaScript in {}".format(js_source_desc),
                request_method="GET",
                response_status=200,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Open: {url}\n"
                    "2. Open browser DevTools (F12) -> Sources tab.\n"
                    "3. Search for the sink patterns listed in the evidence.\n"
                    "4. Trace the data flow from the source to the sink.\n"
                    "5. If a flow exists, craft a test URL:\n"
                    "   {url}#<img src=x onerror=alert(document.domain)>\n"
                    "6. Check browser console for execution."
                ).format(url=source_url),
                developer_fix=(
                    "File: {}\n\n"
                    "Audit and fix each source-sink pair:\n\n"
                    "  1. Replace innerHTML/outerHTML with textContent where HTML is not needed.\n"
                    "  2. If HTML is needed, sanitize first:\n"
                    "     element.innerHTML = DOMPurify.sanitize(userInput);\n"
                    "  3. Replace eval/setTimeout(string) with safer alternatives:\n"
                    "     setTimeout(() => safeFunction(arg), delay);\n"
                    "  4. Validate URLs before assigning to location/href/src:\n"
                    "     if (url.startsWith('/') || url.startsWith(window.origin)) {{ ... }}"
                ).format(js_source_desc),
                affected_component="Client-side JavaScript at {}".format(parsed.path),
                references=(
                    "https://owasp.org/www-community/attacks/DOM_Based_XSS | "
                    "https://portswigger.net/web-security/cross-site-scripting/dom-based"
                ),
                detection_method=(
                    "Static analysis found user-controllable sources and dangerous sinks "
                    "in close proximity (within 500 chars) in JavaScript code without "
                    "detected sanitization patterns."
                ),
            ))
            return

    # Sinks without sanitization (informational)
    if sinks and not sanitized:
        high_risk_names = ("innerHTML", "document.write", "eval()", "outerHTML",
                           "new Function()", "jQuery .html()")
        high_risk_sinks = [s for s in sinks if s["name"] in high_risk_names]

        if high_risk_sinks:
            sink_evidence = "\n".join(
                "  - {}: {}".format(s['name'], s['line'])
                for s in high_risk_sinks[:5]
            )
            curl_cmd = build_curl("GET", source_url)

            session.add_finding(Finding(
                title="Dangerous DOM Sinks Without Sanitization",
                severity=Severity.LOW,
                description=(
                    "JavaScript code at '{}' uses {} dangerous "
                    "DOM sink(s) without detected sanitization. While no user-controllable "
                    "source was found flowing into these sinks, they represent potential "
                    "DOM XSS vectors if user data reaches them through indirect paths. "
                    "Found in: {}."
                ).format(source_url, len(high_risk_sinks), js_source_desc),
                evidence=(
                    "Source URL: {}\n"
                    "JS Source: {}\n"
                    "Dangerous Sinks ({}):\n{}\n"
                    "User Sources Detected: {}\n"
                    "Sanitization Detected: No"
                ).format(source_url, js_source_desc, len(high_risk_sinks),
                         sink_evidence, len(sources)),
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
                location="JavaScript in {}".format(js_source_desc),
                request_method="GET",
                response_status=200,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Open: {}\n"
                    "2. View page source and search for the sink patterns.\n"
                    "3. Trace what data flows into each sink.\n"
                    "4. If any user input reaches a sink, test with:\n"
                    "   <img src=x onerror=alert(document.domain)>"
                ).format(source_url),
                developer_fix=(
                    "File: {}\n\n"
                    "Refactor dangerous sinks:\n\n"
                    "  element.innerHTML = data;\n"
                    "  -> element.textContent = data;\n\n"
                    "  document.write(html);\n"
                    "  -> const el = document.createElement('div');\n"
                    "     el.textContent = text;\n"
                    "     document.body.appendChild(el);\n\n"
                    "  eval(code);\n"
                    "  -> Use JSON.parse() for data, direct function calls for logic."
                ).format(js_source_desc),
                affected_component="Client-side JavaScript at {}".format(parsed.path),
                references=(
                    "https://owasp.org/www-community/attacks/DOM_Based_XSS | "
                    "https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API"
                ),
                detection_method=(
                    "Static analysis identified {} high-risk DOM sinks "
                    "in JavaScript code without accompanying sanitization patterns."
                ).format(len(high_risk_sinks)),
            ))


def _test_page(session, url):
    parsed = urlparse(url)
    resp = session.get(url)
    if not resp or resp.status_code != 200:
        return

    content_type = resp.headers.get("Content-Type", "")
    if "html" not in content_type and "javascript" not in content_type:
        return

    body = resp.text

    inline_scripts = _extract_js_from_html(body)
    if inline_scripts:
        _analyze_js(session, "\n".join(inline_scripts), url,
                     "inline scripts at {}".format(parsed.path))

    # Only analyze same-origin linked scripts
    target_host = parsed.netloc
    for js_url in _extract_linked_js_urls(body, url):
        js_parsed = urlparse(js_url)
        if js_parsed.netloc and js_parsed.netloc != target_host:
            continue
        try:
            js_resp = session.get(js_url)
            if not js_resp or js_resp.status_code != 200:
                continue
            ct = js_resp.headers.get("Content-Type", "")
            if "javascript" in ct or "text/" in ct:
                _analyze_js(session, js_resp.text, url,
                             "linked script {}".format(js_parsed.path))
        except (OSError, ValueError) as e:
            logger.debug("dom_xss _test_page: request failed: %s", e)


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for DOM-Based XSS...")

    for url in session.crawled_urls:
        _test_page(session, url)
