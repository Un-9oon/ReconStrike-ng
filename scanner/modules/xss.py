import re
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession, build_curl
from scanner.log import logger


def _random_tag():
    return "vs" + "".join(random.choices(string.ascii_lowercase, k=8))


REFLECTION_PAYLOADS = [
    ("<{tag}>", "<{tag}>"),
    ("<img src=x onerror={tag}>", "<img src=x onerror={tag}>"),
    ("<svg onload={tag}>", "<svg onload={tag}>"),
    ("'\"><{tag}>", "<{tag}>"),
    ("<script>{tag}</script>", "<script>{tag}</script>"),
    ("<details open ontoggle={tag}>", "<details open ontoggle={tag}>"),
]

SAFE_CONTEXTS_RE = re.compile(
    r'<!--.*?-->|<textarea[^>]*>.*?</textarea>|<title[^>]*>.*?</title>',
    re.DOTALL | re.IGNORECASE
)


def _is_in_safe_context(body: str, needle: str) -> bool:
    return any(needle in m.group(0) for m in SAFE_CONTEXTS_RE.finditer(body))


def _detect_context(body: str, marker: str) -> str:
    idx = body.find(marker)
    if idx == -1:
        return "none"
    before = body[max(0, idx - 200):idx]
    if re.search(r'<script[^>]*>[^<]*$', before, re.IGNORECASE | re.DOTALL):
        return "js_string"
    if re.search(r'=\s*["\'][^"\']*$', before):
        return "html_attr"
    return "html_body"


def _get_snippet(text, needle, pad=40):
    idx = text.find(needle)
    if idx == -1:
        return ""
    start, end = max(0, idx - pad), min(len(text), idx + len(needle) + pad)
    return text[start:end].replace('\n', ' ')


def _check_url_params(session: ScanSession, url: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    for param in params:
        tag = _random_tag()
        params_test = dict(params)
        params_test[param] = [tag]
        test_url = urlunparse(parsed._replace(query=urlencode(params_test, doseq=True)))
        resp = session.get(test_url)
        if not resp or tag not in resp.text:
            continue
        if _is_in_safe_context(resp.text, tag):
            continue

        context = _detect_context(resp.text, tag)
        if context == "none":
            continue

        for payload_tpl, check in REFLECTION_PAYLOADS:
            tag2 = _random_tag()
            payload = payload_tpl.format(tag=tag2)
            expected = check.format(tag=tag2)
            params_test[param] = [payload]
            test_url2 = urlunparse(parsed._replace(query=urlencode(params_test, doseq=True)))
            resp2 = session.get(test_url2)
            if not resp2 or expected not in resp2.text:
                continue
            if _is_in_safe_context(resp2.text, expected):
                continue

            snippet = _get_snippet(resp2.text, expected)
            session.add_finding(Finding(
                title="Reflected XSS via URL Parameter",
                severity=Severity.HIGH,
                description=(
                    "The URL parameter '{}' is reflected without output encoding. "
                    "Reflection occurs in a '{}' context, allowing injection of "
                    "arbitrary HTML/JavaScript that executes in the victim's browser.".format(param, context)
                ),
                evidence=(
                    "Parameter: {}\nInjection Context: {}\nPayload: {}\n"
                    "Reflected As: {}\nSnippet: ...{}...\nStatus: {}".format(
                        param, context, payload, expected, snippet, resp2.status_code)
                ),
                remediation=(
                    "1. Apply context-aware output encoding on all user input before rendering.\n"
                    "2. Use framework auto-escaping (Jinja2, React JSX, Django templates).\n"
                    "3. Implement Content-Security-Policy to restrict inline scripts.\n"
                    "4. Set HttpOnly on session cookies to limit XSS impact."
                ),
                url=url,
                module="xss",
                cwe="CWE-79",
                confirmed=True,
                location="URL parameter '{}' in query string".format(param),
                parameter=param,
                payload=payload,
                request_method="GET",
                response_status=resp2.status_code,
                curl_command=build_curl("GET", test_url2),
                reproduction_steps=(
                    "1. Open: {}\n"
                    "2. Set '{}' parameter to: {}\n"
                    "3. Full URL: {}\n"
                    "4. Observe unencoded reflection in {} context.".format(
                        url, param, payload, test_url2, context)
                ),
                developer_fix=(
                    "File: Server-side handler for '{}' that renders '{}' into HTML.\n"
                    "Fix: HTML-encode the parameter before output.\n"
                    "  Jinja2: {{{{ {} | e }}}}\n"
                    "  PHP: htmlspecialchars(${}, ENT_QUOTES, 'UTF-8')\n"
                    "  Node/Express: use a template engine with auto-escaping".format(
                        parsed.path, param, param, param)
                ),
                affected_component="Route handler for {}".format(parsed.path),
                references="https://owasp.org/www-community/attacks/xss/ | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                detection_method="Injected XSS payloads into URL parameters and confirmed unescaped reflection in the response HTML via baseline comparison.",
            ))
            return


def _check_forms(session: ScanSession, form: dict):
    for inp in form["inputs"]:
        name = inp.get("name")
        if not name or inp.get("type") in ("hidden", "submit", "button", "file"):
            continue

        tag = _random_tag()
        post_data = {
            other.get("name"): (tag if other.get("name") == name else other.get("value", "test"))
            for other in form["inputs"] if other.get("name")
        }

        method = form["method"]
        resp = session.post(form["action"], data=post_data) if method == "post" else session.get(form["action"], params=post_data)
        if not resp or tag not in resp.text or _is_in_safe_context(resp.text, tag):
            continue

        for payload_tpl, check in REFLECTION_PAYLOADS[:4]:
            tag2 = _random_tag()
            payload = payload_tpl.format(tag=tag2)
            expected = check.format(tag=tag2)
            post_data[name] = payload

            resp2 = session.post(form["action"], data=post_data) if method == "post" else session.get(form["action"], params=post_data)
            if not resp2 or expected not in resp2.text or _is_in_safe_context(resp2.text, expected):
                continue

            method_upper = method.upper()
            data_str = "&".join("{}={}".format(k, v) for k, v in post_data.items())
            source_url = form.get("source_url", form["action"])

            session.add_finding(Finding(
                title="Reflected XSS via Form Input",
                severity=Severity.HIGH,
                description=(
                    "Form field '{}' submitted to {} reflects user input without "
                    "sanitization. An attacker can inject arbitrary JavaScript, "
                    "potentially stealing sessions or acting as authenticated users.".format(
                        name, form["action"])
                ),
                evidence=(
                    "Form Action: {}\nMethod: {}\nField: {}\n"
                    "Type: {}\nPayload: {}\nReflected: {}\nStatus: {}".format(
                        form["action"], method_upper, name,
                        inp.get("type", "text"), payload, expected, resp2.status_code)
                ),
                remediation=(
                    "1. HTML-encode all form input before rendering in responses.\n"
                    "2. Implement CSP to block inline scripts.\n"
                    "3. Validate and sanitize input server-side.\n"
                    "4. Use framework auto-escaping."
                ),
                url=source_url,
                module="xss",
                cwe="CWE-79",
                confirmed=True,
                location="Form field '{}' (type: {}) at {}".format(name, inp.get("type", "text"), form["action"]),
                parameter=name,
                payload=payload,
                request_method=method_upper,
                request_body=data_str,
                response_status=resp2.status_code,
                curl_command=build_curl(method_upper, form["action"], data=data_str) if method_upper == "POST" else build_curl("GET", "{}?{}".format(form["action"], data_str)),
                reproduction_steps=(
                    "1. Navigate to: {}\n"
                    "2. Find the form submitting to: {}\n"
                    "3. Enter in '{}': {}\n"
                    "4. Submit and observe unencoded reflection.".format(
                        source_url, form["action"], name, payload)
                ),
                developer_fix=(
                    "File: Handler for {} {} that renders '{}'.\n"
                    "Fix: Apply output encoding on '{}'. Add CSP header.".format(
                        method_upper, form["action"], name, name)
                ),
                affected_component="{} {} - form field '{}'".format(method_upper, form["action"], name),
                references="https://owasp.org/www-community/attacks/xss/",
                detection_method="Injected XSS payloads into form fields and confirmed unescaped reflection in the response HTML via baseline comparison.",
            ))
            return


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for Cross-Site Scripting (XSS)...")

    for url in session.crawled_urls:
        if urlparse(url).query:
            _check_url_params(session, url)

    for form in session.forms:
        _check_forms(session, form)
