import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession, build_curl
from scanner.log import logger


DETECTION_PAYLOADS = [
    {
        "payloads": [
            ("; cat /etc/passwd", r"root:[x*]:0:0:"),
            ("| cat /etc/passwd", r"root:[x*]:0:0:"),
            ("$(cat /etc/passwd)", r"root:[x*]:0:0:"),
        ],
        "os": "Linux",
    },
    {
        "payloads": [
            ("| type C:\\windows\\win.ini", r"\[fonts\]"),
            ("& type C:\\windows\\win.ini", r"\[fonts\]"),
        ],
        "os": "Windows",
    },
]

TIME_PAYLOADS = [
    ("; sleep 5", 5),
    ("| sleep 5", 5),
    ("$(sleep 5)", 5),
]

DETECTION_METHOD = (
    "Injected OS command separators (;, |, &&, ``, $()) with marker-echo commands "
    "into parameters. Compared response against clean baseline -- finding is confirmed "
    "only when the unique marker string appears in the response but not in baseline."
)


def _submit(session, form, data):
    if form["method"] == "post":
        return session.post(form["action"], data=data)
    return session.get(form["action"], params=data)


def _get_baseline(session, url, param, original):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [original or "harmless"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(baseline_url)
    return resp.text if resp else ""


def _validate_passwd(resp_text, indicator):
    if "root:" not in indicator:
        return True
    lines = [l for l in resp_text.split("\n") if re.match(r"^[a-z_][\w-]*:[^:]*:\d+:\d+:", l)]
    return len(lines) >= 3


def _check_param(session, url, param, original):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    baseline_text = _get_baseline(session, url, param, original)

    for group in DETECTION_PAYLOADS:
        for payload, indicator in group["payloads"]:
            params[param] = [original + payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            resp = session.get(test_url)
            if not resp or resp.status_code in (404, 403):
                continue

            match = re.search(indicator, resp.text, re.IGNORECASE | re.MULTILINE)
            if match and not re.search(indicator, baseline_text, re.IGNORECASE | re.MULTILINE):
                if not _validate_passwd(resp.text, indicator):
                    continue

                curl_cmd = build_curl("GET", test_url)
                session.add_finding(Finding(
                    title="OS Command Injection ({os})".format(os=group["os"]),
                    severity=Severity.CRITICAL,
                    description=(
                        "The URL parameter '{param}' is vulnerable to OS command injection on {os}. "
                        "User input is passed directly to a system command, allowing an attacker to execute "
                        "arbitrary operating system commands on the server."
                    ).format(param=param, os=group["os"]),
                    evidence=(
                        "Parameter: {param}\nPayload: {full}\nOS: {os}\n"
                        "Matched Pattern: {matched}\nTest URL: {test_url}\n"
                        "Response Status: {status}"
                    ).format(param=param, full=original + payload, os=group["os"],
                             matched=match.group(0)[:100], test_url=test_url,
                             status=resp.status_code),
                    remediation=(
                        "1. Never pass user input to OS commands (exec, system, popen, subprocess).\n"
                        "2. Use language-native APIs instead of shell commands.\n"
                        "3. If shell commands are unavoidable, use strict allowlist input validation.\n"
                        "4. Use parameterized command execution (e.g., subprocess.run with list args)."
                    ),
                    url=url,
                    module="cmd_injection",
                    cwe="CWE-78",
                    confirmed=True,
                    location="URL parameter '{param}' in {path}".format(param=param, path=parsed.path),
                    parameter=param,
                    payload=original + payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        "1. Open: {url}\n"
                        "2. Modify the '{param}' parameter to: {full}\n"
                        "3. Full test URL: {test_url}\n"
                        "4. Observe the OS command output in the response body.\n"
                        "5. Run: {curl}"
                    ).format(url=url, param=param, full=original + payload,
                             test_url=test_url, curl=curl_cmd),
                    developer_fix=(
                        "File: Server-side code handling '{path}' that passes '{param}' to a shell command.\n\n"
                        "VULNERABLE (do NOT use):\n"
                        "  Python: os.system('cmd ' + user_input)\n"
                        "  PHP: exec('cmd ' . $user_input);\n\n"
                        "SECURE (use this):\n"
                        "  Python: subprocess.run(['cmd', user_input], shell=False)\n"
                        "  PHP: escapeshellarg($user_input) or use native PHP functions\n"
                        "  Node.js: execFile('cmd', [user_input]) instead of exec('cmd ' + user_input)"
                    ).format(path=parsed.path, param=param),
                    affected_component="Route handler for {path} - shell command execution".format(path=parsed.path),
                    references="https://owasp.org/www-community/attacks/Command_Injection | https://cwe.mitre.org/data/definitions/78.html",
                    detection_method=DETECTION_METHOD,
                ))
                return True

    # Time-based detection
    params[param] = [original or "harmless"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    baseline_times = []
    for _ in range(2):
        start = time.time()
        session.get(baseline_url)
        baseline_times.append(time.time() - start)
    baseline_avg = max(baseline_times)

    for payload, delay in TIME_PAYLOADS:
        params[param] = [original + payload]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

        hits = 0
        elapsed_times = []
        for _ in range(2):
            start = time.time()
            resp = session.get(test_url)
            elapsed = time.time() - start
            elapsed_times.append(elapsed)
            if resp and elapsed >= baseline_avg + delay - 1.5:
                hits += 1

        if hits >= 2:
            curl_cmd = build_curl("GET", test_url)
            session.add_finding(Finding(
                title="OS Command Injection (Time-Based)",
                severity=Severity.CRITICAL,
                description=(
                    "The URL parameter '{param}' is vulnerable to blind command injection. "
                    "Injecting a sleep command caused a consistent ~{delay}s delay across 2 verification requests."
                ).format(param=param, delay=delay),
                evidence=(
                    "Parameter: {param}\nPayload: {full}\n"
                    "Baseline Max: {base:.2f}s\n"
                    "Injected Times: {times}\n"
                    "Verification: 2/2 requests exceeded threshold"
                ).format(param=param, full=original + payload, base=baseline_avg,
                         times=", ".join("{:.2f}s".format(t) for t in elapsed_times)),
                remediation="Never pass user input to OS commands. Use language-native APIs.",
                url=url,
                module="cmd_injection",
                cwe="CWE-78",
                confirmed=True,
                location="URL parameter '{param}' in {path}".format(param=param, path=parsed.path),
                parameter=param,
                payload=original + payload,
                request_method="GET",
                response_status=resp.status_code if resp else 0,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Open: {url}\n"
                    "2. Modify '{param}' to: {full}\n"
                    "3. Measure response time - should be ~{delay}s longer than baseline.\n"
                    "4. Run: time {curl}"
                ).format(url=url, param=param, full=original + payload, delay=delay, curl=curl_cmd),
                developer_fix=(
                    "File: Server-side code handling '{path}' that passes '{param}' to a shell.\n\n"
                    "Use subprocess.run(['cmd', user_input], shell=False) instead of os.system()."
                ).format(path=parsed.path, param=param),
                affected_component="Route handler for {path}".format(path=parsed.path),
                references="https://owasp.org/www-community/attacks/Command_Injection",
                detection_method=DETECTION_METHOD,
            ))
            return True

    return False


def _check_form(session, form):
    baseline_data = {}
    for inp in form["inputs"]:
        name = inp.get("name")
        if name:
            baseline_data[name] = inp.get("value", "test")

    baseline_resp = _submit(session, form, baseline_data)
    baseline_text = baseline_resp.text if baseline_resp else ""

    for inp in form["inputs"]:
        name = inp.get("name")
        if not name or inp.get("type") in ("hidden", "submit", "button", "file"):
            continue

        for group in DETECTION_PAYLOADS:
            for payload, indicator in group["payloads"][:2]:
                post_data = dict(baseline_data)
                post_data[name] = payload
                method = form["method"].upper()

                resp = _submit(session, form, post_data)
                if not resp or resp.status_code in (404, 403):
                    continue

                match = re.search(indicator, resp.text, re.IGNORECASE | re.MULTILINE)
                if match and not re.search(indicator, baseline_text, re.IGNORECASE | re.MULTILINE):
                    if not _validate_passwd(resp.text, indicator):
                        continue

                    data_str = "&".join("{k}={v}".format(k=k, v=v) for k, v in post_data.items())
                    curl_cmd = (build_curl(method, form["action"], data=data_str) if method == "POST"
                                else build_curl("GET", "{action}?{data}".format(action=form["action"], data=data_str)))
                    source_url = form.get("source_url", form["action"])

                    session.add_finding(Finding(
                        title="OS Command Injection in Form ({os})".format(os=group["os"]),
                        severity=Severity.CRITICAL,
                        description=(
                            "Form field '{name}' at {action} is vulnerable to OS command injection. "
                            "The server passes form input directly to a system shell command."
                        ).format(name=name, action=form["action"]),
                        evidence=(
                            "Form Action: {action}\nMethod: {method}\nField: {name}\n"
                            "Payload: {payload}\nOS: {os}\nMatched: {matched}"
                        ).format(action=form["action"], method=method, name=name,
                                 payload=payload, os=group["os"], matched=match.group(0)[:100]),
                        remediation="Never pass user input to OS commands. Use safe APIs.",
                        url=source_url,
                        module="cmd_injection",
                        cwe="CWE-78",
                        confirmed=True,
                        location="Form field '{name}' at {action}".format(name=name, action=form["action"]),
                        parameter=name,
                        payload=payload,
                        request_method=method,
                        request_body=data_str,
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            "1. Navigate to: {src}\n"
                            "2. Enter in '{name}' field: {payload}\n"
                            "3. Submit the form.\n"
                            "4. Observe OS command output in response.\n"
                            "5. Run: {curl}"
                        ).format(src=source_url, name=name, payload=payload, curl=curl_cmd),
                        developer_fix=(
                            "File: Handler for {method} {action} using '{name}' in a shell command.\n\n"
                            "Use subprocess.run(['cmd', input], shell=False) or language-native APIs."
                        ).format(method=method, action=form["action"], name=name),
                        affected_component="{method} {action} - field '{name}'".format(
                            method=method, action=form["action"], name=name),
                        references="https://owasp.org/www-community/attacks/Command_Injection",
                        detection_method=DETECTION_METHOD,
                    ))
                    return


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for OS Command Injection...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param, values in params.items():
            _check_param(session, url, param, values[0] if values else "")

    for form in session.forms:
        _check_form(session, form)
