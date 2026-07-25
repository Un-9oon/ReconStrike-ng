import re
import random
import string

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


def run(session: ScanSession) -> None:
    print("\n[*] Testing for file upload vulnerabilities...")

    for form in session.forms:
        file_inputs = [inp for inp in form["inputs"] if inp.get("type") == "file"]
        if not file_inputs:
            continue

        print(f"  [*] Found file upload form at {form['action']}")

        for file_input in file_inputs:
            field_name = file_input.get("name", "file")

            other_data = {}
            for inp in form["inputs"]:
                name = inp.get("name")
                if not name or inp.get("type") == "file":
                    continue
                other_data[name] = inp.get("value", "test")

            for payload in UPLOAD_PAYLOADS:
                marker = "".join(random.choices(string.ascii_lowercase, k=6))
                filename = payload["filename"].replace("test", f"vstest_{marker}")
                source_url = form.get("source_url", form["action"])

                files = {field_name: (filename, payload["content"], payload["content_type"])}
                resp = session.post(form["action"], files=files, data=other_data)
                if not resp:
                    continue

                if resp.status_code in (200, 201, 301, 302):
                    upload_confirmed = False
                    uploaded_url = ""

                    url_patterns = [
                        rf'(?:src|href|url|path|file)\s*[=:]\s*["\']?([^"\'>\s]*{re.escape(filename)}[^"\'>\s]*)',
                        rf'["\']([^"\']*uploads?[^"\']*{re.escape(marker)}[^"\']*)["\']',
                        rf'["\']([^"\']*files?[^"\']*{re.escape(marker)}[^"\']*)["\']',
                    ]

                    for pattern in url_patterns:
                        match = re.search(pattern, resp.text, re.IGNORECASE)
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
                            curl_cmd = f"curl -k -X POST '{form['action']}' -F '{field_name}=@{filename};type={ct}'"
                            session.add_finding(Finding(
                                title=f"Unrestricted File Upload: {payload['name']}",
                                severity=payload["severity"],
                                description=(
                                    f"The file upload at {form['action']} accepts {payload['desc']} files and "
                                    f"the uploaded file is executable/accessible at {full_url}. This enables "
                                    f"Remote Code Execution (RCE) - an attacker can upload a web shell and "
                                    f"take complete control of the server."
                                ),
                                evidence=(
                                    f"Upload Form: {form['action']}\n"
                                    f"Field Name: {field_name}\n"
                                    f"Uploaded File: {filename}\n"
                                    f"Content-Type: {payload['content_type']}\n"
                                    f"Accessible At: {full_url}\n"
                                    f"Execution Confirmed: Content executed/rendered successfully"
                                ),
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
                                location=f"File upload field '{field_name}' at {form['action']}",
                                parameter=field_name,
                                payload=filename,
                                request_method="POST",
                                response_status=resp.status_code,
                                curl_command=curl_cmd,
                                reproduction_steps=(
                                    f"1. Navigate to: {source_url}\n"
                                    f"2. Upload a file named '{filename}' with {payload['desc']} content.\n"
                                    f"3. The file is accepted (HTTP {resp.status_code}).\n"
                                    f"4. Access the uploaded file at: {full_url}\n"
                                    f"5. The server-side code executes, confirming RCE."
                                ),
                                developer_fix=(
                                    f"File: Upload handler at {form['action']}\n\n"
                                    f"1. Validate file type by magic bytes:\n"
                                    f"   import magic\n"
                                    f"   mime = magic.from_buffer(file.read(2048), mime=True)\n"
                                    f"   ALLOWED = {{'image/jpeg', 'image/png', 'image/gif'}}\n"
                                    f"   if mime not in ALLOWED: reject()\n\n"
                                    f"2. Store outside web root:\n"
                                    f"   upload_dir = '/var/data/uploads/'  # Not in /var/www/\n\n"
                                    f"3. Rename files:\n"
                                    f"   filename = str(uuid4()) + '.jpg'  # Random name, safe extension"
                                ),
                                affected_component=f"File upload handler at {form['action']}",
                                references="https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                                detection_method="Uploaded test files with dangerous extensions (.php, .jsp, .asp) and content types through discovered upload forms. Checked if files were stored in web-accessible locations and if server-side code execution occurred.",
                            ))
                            return

                    if not upload_confirmed and payload["filename"] == ".htaccess":
                        if resp.status_code in (200, 201):
                            error_indicators = ["error", "invalid", "not allowed", "rejected",
                                                 "failed", "denied", "forbidden", "unsupported"]
                            body_lower = resp.text.lower()
                            if not any(ind in body_lower for ind in error_indicators):
                                session.add_finding(Finding(
                                    title="File Upload Accepts .htaccess",
                                    severity=Severity.HIGH,
                                    description=".htaccess file was accepted by the upload handler, potentially allowing Apache configuration override.",
                                    evidence=f"Uploaded .htaccess, server returned {resp.status_code} without error.",
                                    remediation="Block uploads of server configuration files (.htaccess, web.config, .env).",
                                    url=source_url,
                                    module="file_upload",
                                    cwe="CWE-434",
                                    confirmed=False,
                                    location=f"File upload at {form['action']}",
                                    developer_fix="Add .htaccess, web.config, .env to your upload blocklist. Check filename before saving.",
                                    detection_method="Uploaded test files with dangerous extensions (.php, .jsp, .asp) and content types through discovered upload forms. Checked if files were stored in web-accessible locations and if server-side code execution occurred.",
                                ))

            _check_size_limit(session, form, field_name, other_data)


def _check_size_limit(session: ScanSession, form: dict, field_name: str, other_data: dict):
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
                evidence=f"Uploaded 10MB file to {form['action']}, server returned {resp.status_code}.",
                remediation="Implement server-side file size limits (e.g., 5MB for images).",
                url=source_url,
                module="file_upload",
                cwe="CWE-770",
                confirmed=True,
                location=f"File upload at {form['action']}",
                developer_fix=(
                    "Add file size validation:\n"
                    "  Python/Flask: app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024\n"
                    "  PHP: upload_max_filesize = 5M in php.ini\n"
                    "  Nginx: client_max_body_size 5m;\n"
                    "  Express: app.use(express.json({ limit: '5mb' }))"
                ),
                affected_component=f"File upload handler at {form['action']}",
                detection_method="Uploaded test files with dangerous extensions (.php, .jsp, .asp) and content types through discovered upload forms. Checked if files were stored in web-accessible locations and if server-side code execution occurred.",
            ))
    except Exception as e:
        logger.debug("file_upload _check_size_limit: operation failed: %s", e)
