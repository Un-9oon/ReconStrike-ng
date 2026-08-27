import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession, build_curl


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



def _get_baseline(session, url, param, original):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [original or "harmless"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(baseline_url)
    return resp.text if resp else ""


def _check_param(session: ScanSession, url: str, param: str, original: str):
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
                if "root:" in indicator:
                    lines = [l for l in resp.text.split("\n") if re.match(r"^[a-z_][\w-]*:[^:]*:\d+:\d+:", l)]
                    if len(lines) < 3:
                        continue

                curl_cmd = build_curl("GET", test_url)
                session.add_finding(Finding(
                    title=f"OS Command Injection ({group['os']})",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The URL parameter '{param}' is vulnerable to OS command injection on {group['os']}. "
                        f"User input is passed directly to a system command, allowing an attacker to execute "
                        f"arbitrary operating system commands on the server."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Payload: {original}{payload}\n"
                        f"OS: {group['os']}\n"
                        f"Matched Pattern: {match.group(0)[:100]}\n"
                        f"Test URL: {test_url}\n"
                        f"Response Status: {resp.status_code}"
                    ),
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
                    location=f"URL parameter '{param}' in {parsed.path}",
                    parameter=param,
                    payload=original + payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Open: {url}\n"
                        f"2. Modify the '{param}' parameter to: {original}{payload}\n"
                        f"3. Full test URL: {test_url}\n"
                        f"4. Observe the OS command output in the response body.\n"
                        f"5. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: Server-side code handling '{parsed.path}' that passes '{param}' to a shell command.\n\n"
                        f"VULNERABLE (do NOT use):\n"
                        f"  Python: os.system('cmd ' + user_input)\n"
                        f"  PHP: exec('cmd ' . $user_input);\n\n"
                        f"SECURE (use this):\n"
                        f"  Python: subprocess.run(['cmd', user_input], shell=False)\n"
                        f"  PHP: escapeshellarg($user_input) or use native PHP functions\n"
                        f"  Node.js: execFile('cmd', [user_input]) instead of exec('cmd ' + user_input)"
                    ),
                    affected_component=f"Route handler for {parsed.path} - shell command execution",
                    references="https://owasp.org/www-community/attacks/Command_Injection | https://cwe.mitre.org/data/definitions/78.html",
                    detection_method="Injected OS command separators (;, |, &&, ``, $()) with marker-echo commands into parameters. Compared response against clean baseline — finding is confirmed only when the unique marker string appears in the response but not in baseline.",
                ))
                return True

    baseline_times = []
    params[param] = [original or "harmless"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
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
                    f"The URL parameter '{param}' is vulnerable to blind command injection. "
                    f"Injecting a sleep command caused a consistent ~{delay}s delay across 2 verification requests."
                ),
                evidence=(
                    f"Parameter: {param}\n"
                    f"Payload: {original}{payload}\n"
                    f"Baseline Max: {baseline_avg:.2f}s\n"
                    f"Injected Times: {', '.join('{:.2f}s'.format(t) for t in elapsed_times)}\n"
                    f"Verification: 2/2 requests exceeded threshold"
                ),
                remediation="Never pass user input to OS commands. Use language-native APIs.",
                url=url,
                module="cmd_injection",
                cwe="CWE-78",
                confirmed=True,
                location=f"URL parameter '{param}' in {parsed.path}",
                parameter=param,
                payload=original + payload,
                request_method="GET",
                response_status=resp.status_code if resp else 0,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Open: {url}\n"
                    f"2. Modify '{param}' to: {original}{payload}\n"
                    f"3. Measure response time - should be ~{delay}s longer than baseline.\n"
                    f"4. Run: time {curl_cmd}"
                ),
                developer_fix=(
                    f"File: Server-side code handling '{parsed.path}' that passes '{param}' to a shell.\n\n"
                    f"Use subprocess.run(['cmd', user_input], shell=False) instead of os.system()."
                ),
                affected_component=f"Route handler for {parsed.path}",
                references="https://owasp.org/www-community/attacks/Command_Injection",
                detection_method="Injected OS command separators (;, |, &&, ``, $()) with marker-echo commands into parameters. Compared response against clean baseline — finding is confirmed only when the unique marker string appears in the response but not in baseline.",
            ))
            return True

    return False


def _check_form(session: ScanSession, form: dict):
    baseline_data = {}
    for inp in form["inputs"]:
        name = inp.get("name")
        if name:
            baseline_data[name] = inp.get("value", "test")

    if form["method"] == "post":
        baseline_resp = session.post(form["action"], data=baseline_data)
    else:
        baseline_resp = session.get(form["action"], params=baseline_data)
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

                if form["method"] == "post":
                    resp = session.post(form["action"], data=post_data)
                else:
                    resp = session.get(form["action"], params=post_data)

                if not resp or resp.status_code in (404, 403):
                    continue

                match = re.search(indicator, resp.text, re.IGNORECASE | re.MULTILINE)
                if match and not re.search(indicator, baseline_text, re.IGNORECASE | re.MULTILINE):
                    if "root:" in indicator:
                        lines = [l for l in resp.text.split("\n") if re.match(r"^[a-z_][\w-]*:[^:]*:\d+:\d+:", l)]
                        if len(lines) < 3:
                            continue

                    data_str = "&".join(f"{k}={v}" for k, v in post_data.items())
                    curl_cmd = build_curl(method, form["action"], data=data_str) if method == "POST" else build_curl("GET", f"{form['action']}?{data_str}")
                    source_url = form.get("source_url", form["action"])

                    session.add_finding(Finding(
                        title=f"OS Command Injection in Form ({group['os']})",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Form field '{name}' at {form['action']} is vulnerable to OS command injection. "
                            f"The server passes form input directly to a system shell command."
                        ),
                        evidence=(
                            f"Form Action: {form['action']}\n"
                            f"Method: {method}\n"
                            f"Field: {name}\n"
                            f"Payload: {payload}\n"
                            f"OS: {group['os']}\n"
                            f"Matched: {match.group(0)[:100]}"
                        ),
                        remediation="Never pass user input to OS commands. Use safe APIs.",
                        url=source_url,
                        module="cmd_injection",
                        cwe="CWE-78",
                        confirmed=True,
                        location=f"Form field '{name}' at {form['action']}",
                        parameter=name,
                        payload=payload,
                        request_method=method,
                        request_body=data_str,
                        response_status=resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Navigate to: {source_url}\n"
                            f"2. Enter in '{name}' field: {payload}\n"
                            f"3. Submit the form.\n"
                            f"4. Observe OS command output in response.\n"
                            f"5. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"File: Handler for {method} {form['action']} using '{name}' in a shell command.\n\n"
                            f"Use subprocess.run(['cmd', input], shell=False) or language-native APIs."
                        ),
                        affected_component=f"{method} {form['action']} - field '{name}'",
                        references="https://owasp.org/www-community/attacks/Command_Injection",
                        detection_method="Injected OS command separators (;, |, &&, ``, $()) with marker-echo commands into parameters. Compared response against clean baseline — finding is confirmed only when the unique marker string appears in the response but not in baseline.",
                    ))
                    return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for OS Command Injection...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param, values in params.items():
            original = values[0] if values else ""
            _check_param(session, url, param, original)

    for form in session.forms:
        _check_form(session, form)
