import re
import random
import string

import requests

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession

UPLOAD_PAYLOADS = [
    {"name": "PHP Web Shell", "filename": "test.php", "content": '<?php echo "VULNSCAN_UPLOAD_" . "CONFIRMED"; ?>', "content_type": "application/x-php", "indicator": "VULNSCAN_UPLOAD_CONFIRMED", "severity": Severity.CRITICAL, "desc": "PHP file execution"},
    {"name": "PHP Double Extension", "filename": "test.php.jpg", "content": '<?php echo "VULNSCAN_UPLOAD_" . "CONFIRMED"; ?>', "content_type": "image/jpeg", "indicator": "VULNSCAN_UPLOAD_CONFIRMED", "severity": Severity.CRITICAL, "desc": "Double extension bypass"},
    {"name": "PHP Null Byte", "filename": "test.php%00.jpg", "content": '<?php echo "VULNSCAN_UPLOAD_" . "CONFIRMED"; ?>', "content_type": "image/jpeg", "indicator": "VULNSCAN_UPLOAD_CONFIRMED", "severity": Severity.CRITICAL, "desc": "Null byte extension bypass"},
    {"name": "JSP Upload", "filename": "test.jsp", "content": '<%= "VULNSCAN_UPLOAD_" + "CONFIRMED" %>', "content_type": "application/octet-stream", "indicator": "VULNSCAN_UPLOAD_CONFIRMED", "severity": Severity.CRITICAL, "desc": "JSP file execution"},
    {"name": "ASP Upload", "filename": "test.asp", "content": '<% Response.Write("VULNSCAN_UPLOAD_" & "CONFIRMED") %>', "content_type": "application/octet-stream", "indicator": "VULNSCAN_UPLOAD_CONFIRMED", "severity": Severity.CRITICAL, "desc": "ASP file execution"},
    {"name": "SVG XSS", "filename": "test.svg", "content": '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert("VULNSCAN_XSS")</script></svg>', "content_type": "image/svg+xml", "indicator": 'alert("VULNSCAN_XSS")', "severity": Severity.HIGH, "desc": "SVG with embedded JavaScript"},
    {"name": "HTML Upload", "filename": "test.html", "content": '<html><body><script>document.write("VULNSCAN_UPLOAD_CONFIRMED")</script></body></html>', "content_type": "text/html", "indicator": "VULNSCAN_UPLOAD_CONFIRMED", "severity": Severity.HIGH, "desc": "HTML file with JavaScript"},
    {"name": ".htaccess Upload", "filename": ".htaccess", "content": 'AddType application/x-httpd-php .jpg', "content_type": "application/octet-stream", "indicator": None, "severity": Severity.CRITICAL, "desc": ".htaccess override"},
]

_DETECTION = (
    "Uploaded test files with dangerous extensions (.php, .jsp, .asp) and content types "
    "through discovered upload forms. Checked if files were stored in web-accessible "
    "locations and if server-side code execution occurred."
)


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for file upload vulnerabilities...")

    for form in session.forms:
        file_inputs = [inp for inp in form["inputs"] if inp.get("type") == "file"]
        if not file_inputs:
            continue

        logger.info(" [*] Found file upload form at {}".format(form['action']))

        for file_input in file_inputs:
            field_name = file_input.get("name", "file")
            other_data = {
                inp.get("name"): inp.get("value", "test")
                for inp in form["inputs"]
                if inp.get("name") and inp.get("type") != "file"
            }

            for payload in UPLOAD_PAYLOADS:
                marker = "".join(random.choices(string.ascii_lowercase, k=6))
                filename = payload["filename"].replace("test", "vstest_{}".format(marker))
                source_url = form.get("source_url", form["action"])

                files = {field_name: (filename, payload["content"], payload["content_type"])}
                resp = session.post(form["action"], files=files, data=other_data)
                if not resp or resp.status_code not in (200, 201, 301, 302):
                    continue

                upload_confirmed, uploaded_url = False, ""
                url_patterns = [
                    r'(?:src|href|url|path|file)\s*[=:]\s*["\']?([^"\'>\s]*{esc}[^"\'>\s]*)'.format(esc=re.escape(filename)),
                    r'["\']([^"\']*uploads?[^"\']*{esc}[^"\']*)["\']'.format(esc=re.escape(marker)),
                    r'["\']([^"\']*files?[^"\']*{esc}[^"\']*)["\']'.format(esc=re.escape(marker)),
                ]

                for pat in url_patterns:
                    match = re.search(pat, resp.text, re.IGNORECASE)
                    if match:
                        uploaded_url = match.group(1)
                        break

                if uploaded_url:
                    from urllib.parse import urljoin
                    full_url = urljoin(form["action"], uploaded_url)
                    file_resp = session.get(full_url)

                    if file_resp and payload["indicator"] and payload["indicator"] in file_resp.text:
                        upload_confirmed = True
                        ct = payload["content_type"]
                        curl_cmd = "curl -k -X POST '{}' -F '{}=@{};type={}'".format(
                            form['action'], field_name, filename, ct)
                        session.add_finding(Finding(
                            title="Unrestricted File Upload: {}".format(payload['name']),
                            severity=payload["severity"],
                            description=(
                                "The file upload at {action} accepts {desc} files and "
                                "the uploaded file is executable/accessible at {furl}. This enables "
                                "Remote Code Execution (RCE) - an attacker can upload a web shell and "
                                "take complete control of the server."
                            ).format(action=form['action'], desc=payload['desc'], furl=full_url),
                            evidence=(
                                "Upload Form: {action}\n"
                                "Field Name: {field}\n"
                                "Uploaded File: {fname}\n"
                                "Content-Type: {ct}\n"
                                "Accessible At: {furl}\n"
                                "Execution Confirmed: Content executed/rendered successfully"
                            ).format(action=form['action'], field=field_name, fname=filename,
                                     ct=payload['content_type'], furl=full_url),
                            remediation=(
                                "1. Validate file types server-side using magic bytes, not just extension.\n"
                                "2. Store uploads outside the web root.\n"
                                "3. Use random filenames, never preserve the original.\n"
                                "4. Set Content-Disposition: attachment for all downloads.\n"
                                "5. Implement file size limits.\n"
                                "6. Scan uploads for malware."
                            ),
                            url=source_url,
                            module="file_upload",
                            cwe="CWE-434",
                            confirmed=True,
                            location="File upload field '{}' at {}".format(field_name, form['action']),
                            parameter=field_name,
                            payload=filename,
                            request_method="POST",
                            response_status=resp.status_code,
                            curl_command=curl_cmd,
                            reproduction_steps=(
                                "1. Navigate to: {src}\n"
                                "2. Upload a file named '{fname}' with {desc} content.\n"
                                "3. The file is accepted (HTTP {status}).\n"
                                "4. Access the uploaded file at: {furl}\n"
                                "5. The server-side code executes, confirming RCE."
                            ).format(src=source_url, fname=filename, desc=payload['desc'],
                                     status=resp.status_code, furl=full_url),
                            developer_fix=(
                                "File: Upload handler at {action}\n\n"
                                "1. Validate file type by magic bytes:\n"
                                "   import magic\n"
                                "   mime = magic.from_buffer(file.read(2048), mime=True)\n"
                                "   ALLOWED = {{'image/jpeg', 'image/png', 'image/gif'}}\n"
                                "   if mime not in ALLOWED: reject()\n\n"
                                "2. Store outside web root:\n"
                                "   upload_dir = '/var/data/uploads/'  # Not in /var/www/\n\n"
                                "3. Rename files:\n"
                                "   filename = str(uuid4()) + '.jpg'  # Random name, safe extension"
                            ).format(action=form['action']),
                            affected_component="File upload handler at {}".format(form['action']),
                            references="https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                            detection_method=_DETECTION,
                        ))
                        return

                if not upload_confirmed and payload["filename"] == ".htaccess":
                    if resp.status_code in (200, 201):
                        reject_words = ["error", "invalid", "not allowed", "rejected",
                                        "failed", "denied", "forbidden", "unsupported"]
                        body_lower = resp.text.lower()
                        if not any(w in body_lower for w in reject_words):
                            session.add_finding(Finding(
                                title="File Upload Accepts .htaccess",
                                severity=Severity.HIGH,
                                description=".htaccess file was accepted by the upload handler, potentially allowing Apache configuration override.",
                                evidence="Uploaded .htaccess, server returned {} without error.".format(resp.status_code),
                                remediation="Block uploads of server configuration files (.htaccess, web.config, .env).",
                                url=source_url,
                                module="file_upload",
                                cwe="CWE-434",
                                confirmed=False,
                                location="File upload at {}".format(form['action']),
                                developer_fix="Add .htaccess, web.config, .env to your upload blocklist. Check filename before saving.",
                                detection_method=_DETECTION,
                            ))

            _check_size_limit(session, form, field_name, other_data)


def _check_size_limit(session, form, field_name, other_data):
    large_content = "A" * (10 * 1024 * 1024)
    files = {field_name: ("largefile.txt", large_content, "text/plain")}
    try:
        resp = session.post(form["action"], files=files, data=other_data)
        if resp and resp.status_code in (200, 201):
            source_url = form.get("source_url", form["action"])
            session.add_finding(Finding(
                title="No File Size Limit on Upload",
                severity=Severity.LOW,
                description="File upload accepts very large files (10MB+) without rejection, potentially enabling denial-of-service via disk exhaustion.",
                evidence="Uploaded 10MB file to {}, server returned {}.".format(form['action'], resp.status_code),
                remediation="Implement server-side file size limits (e.g., 5MB for images).",
                url=source_url,
                module="file_upload",
                cwe="CWE-770",
                confirmed=True,
                location="File upload at {}".format(form['action']),
                developer_fix=(
                    "Add file size validation:\n"
                    "  Python/Flask: app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024\n"
                    "  PHP: upload_max_filesize = 5M in php.ini\n"
                    "  Nginx: client_max_body_size 5m;\n"
                    "  Express: app.use(express.json({ limit: '5mb' }))"
                ),
                affected_component="File upload handler at {}".format(form['action']),
                detection_method=_DETECTION,
            ))
    except (requests.RequestException, ValueError) as e:
        logger.debug("file_upload _check_size_limit: operation failed: %s", e)
