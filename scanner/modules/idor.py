import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession, build_curl
from scanner.log import logger

ID_PARAMS = [
    "id", "uid", "user_id", "userid", "account", "account_id",
    "profile", "profile_id", "doc_id", "order_id", "invoice_id",
    "file_id", "record_id", "pid", "project_id",
]

EXCLUDE_PARAMS = {
    "page", "offset", "limit", "sort", "order", "per_page", "pagesize",
    "start", "count", "skip", "cursor", "tab", "step", "index",
    "category", "cat", "type", "lang", "year", "month", "day",
}

ID_PATH_PATTERNS = [
    r"/users?/(\d+)",
    r"/profiles?/(\d+)",
    r"/accounts?/(\d+)",
    r"/orders?/(\d+)",
    r"/invoices?/(\d+)",
]

PII_PATTERNS = [
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    r'\b\d{3}-\d{2}-\d{4}\b',
    r'(?:balance|salary|income|credit|debit)\s*[:=]\s*[\d$]',
]

_DETECTION = (
    "Modified numeric ID parameters in URLs (e.g., id=1 to id=2) and compared responses. "
    "If different valid data is returned for adjacent IDs without authorization checks, "
    "this confirms insecure direct object reference."
)


def _contains_pii(text):
    return any(re.search(p, text, re.IGNORECASE) for p in PII_PATTERNS)


def _responses_differ_meaningfully(resp1_text, resp2_text):
    if resp1_text == resp2_text:
        return False
    len_ratio = len(resp2_text) / max(len(resp1_text), 1)
    if len_ratio < 0.5 or len_ratio > 2.0:
        return True
    common = set(resp1_text.split()) & set(resp2_text.split())
    total = set(resp1_text.split()) | set(resp2_text.split())
    return len(common) / len(total) < 0.80 if total else False


def _check_param_idor(session, url, param, original):
    if not original.isdigit():
        return

    original_int = int(original)
    resp_original = session.get(url)
    if not resp_original or resp_original.status_code != 200:
        return

    test_id = str(original_int + 1) if original_int > 0 else "1"
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [test_id]
    test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(test_url)
    if not resp or resp.status_code != 200:
        return

    if not _responses_differ_meaningfully(resp_original.text, resp.text):
        return

    curl_original = build_curl(url)
    curl_test = build_curl(test_url)

    if _contains_pii(resp.text) and not _contains_pii(resp_original.text):
        session.add_finding(Finding(
            title="Insecure Direct Object Reference (IDOR)",
            severity=Severity.HIGH,
            description=(
                "The parameter '{param}' allows access to other users' data by changing the numeric ID. "
                "Response for ID {tid} contains PII (email addresses, phone numbers, or financial data) "
                "not present in the original response for ID {oid}, confirming unauthorized data access."
            ).format(param=param, tid=test_id, oid=original),
            evidence=(
                "Parameter: {param}\nOriginal ID: {oid}\nTest ID: {tid}\n"
                "Both returned HTTP 200 with different content.\n"
                "Test response contains PII patterns not in original."
            ).format(param=param, oid=original, tid=test_id),
            remediation=(
                "1. Implement server-side authorization checks on every data access.\n"
                "2. Use indirect references (UUIDs) instead of sequential IDs.\n"
                "3. Verify the authenticated user owns the requested resource."
            ),
            url=url,
            module="idor",
            cwe="CWE-639",
            confirmed=True,
            location="URL parameter '{}' in {}".format(param, parsed.path),
            parameter=param,
            request_method="GET",
            response_status=resp.status_code,
            curl_command="Original: {}\nModified: {}".format(curl_original, curl_test),
            reproduction_steps=(
                "1. Access: {url} (original ID: {oid})\n"
                "2. Change '{param}' to {tid}: {turl}\n"
                "3. Both URLs return HTTP 200 with different content.\n"
                "4. The modified response contains PII from another user.\n"
                "5. Run both:\n   {c1}\n   {c2}"
            ).format(url=url, oid=original, param=param, tid=test_id,
                     turl=test_url, c1=curl_original, c2=curl_test),
            developer_fix=(
                "File: Server-side handler for '{path}' that retrieves data by '{param}'.\n\n"
                "VULNERABLE:\n"
                "  data = db.query('SELECT * FROM records WHERE id = ?', [request.params['{param}']])\n"
                "  return data  # No auth check!\n\n"
                "SECURE:\n"
                "  data = db.query('SELECT * FROM records WHERE id = ? AND user_id = ?', [request.params['{param}'], current_user.id])\n"
                "  if not data: return 403\n\n"
                "Also consider using UUIDs instead of sequential integer IDs."
            ).format(path=parsed.path, param=param),
            affected_component="Data access in route handler for {}".format(parsed.path),
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            detection_method=_DETECTION,
        ))
    elif _contains_pii(resp.text):
        session.add_finding(Finding(
            title="Potential IDOR: Sequential ID Accessible",
            severity=Severity.MEDIUM,
            description="Parameter '{}' returns different data with PII when ID is changed from {} to {}.".format(param, original, test_id),
            evidence="Original ID: {}, Test ID: {}\nBoth returned HTTP 200 with different content containing PII.".format(original, test_id),
            remediation="Verify server-side authorization. Use UUIDs instead of sequential IDs.",
            url=url,
            module="idor",
            cwe="CWE-639",
            confirmed=False,
            location="URL parameter '{}' in {}".format(param, parsed.path),
            parameter=param,
            curl_command=curl_test,
            developer_fix="Add authorization checks to verify the authenticated user owns the requested resource before returning data.",
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            detection_method=_DETECTION,
        ))


def _check_path_idor(session, url):
    for pattern in ID_PATH_PATTERNS:
        match = re.search(pattern, url)
        if not match:
            continue

        original_id = match.group(1)
        original_int = int(original_id)

        resp_original = session.get(url)
        if not resp_original or resp_original.status_code != 200:
            continue

        test_id = str(original_int + 1) if original_int > 0 else "1"
        test_url = url[:match.start(1)] + test_id + url[match.end(1):]
        resp = session.get(test_url)
        if not resp or resp.status_code != 200:
            continue

        if _responses_differ_meaningfully(resp_original.text, resp.text) and _contains_pii(resp.text):
            session.add_finding(Finding(
                title="Potential IDOR via URL Path",
                severity=Severity.MEDIUM,
                description="URL path contains sequential ID that returns different data with PII when modified from {} to {}.".format(original_id, test_id),
                evidence="Original: {}\nModified: {}\nBoth returned HTTP 200 with different PII-containing content.".format(url, test_url),
                remediation="Implement authorization checks. Use non-guessable identifiers (UUIDs).",
                url=url,
                module="idor",
                cwe="CWE-639",
                confirmed=False,
                location="Sequential ID in URL path: {}".format(pattern),
                curl_command="curl -k '{}'".format(test_url),
                reproduction_steps=(
                    "1. Access original URL: {url}\n"
                    "2. Change the ID in the path to: {tid}\n"
                    "3. Access modified URL: {turl}\n"
                    "4. Both return HTTP 200 with different user data."
                ).format(url=url, tid=test_id, turl=test_url),
                developer_fix="Add server-side authorization to verify the requesting user owns the resource at the given path ID.",
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                detection_method=_DETECTION,
            ))
            return


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for Insecure Direct Object References (IDOR)...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param, values in params.items():
            if param.lower() in EXCLUDE_PARAMS:
                continue
            if param.lower() in ID_PARAMS or (values and values[0].isdigit()):
                _check_param_idor(session, url, param, values[0] if values else "")

        _check_path_idor(session, url)
