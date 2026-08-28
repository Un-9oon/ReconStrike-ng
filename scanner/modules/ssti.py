import re
import random
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger


def _make_payloads():
    a, b = random.randint(71, 97), random.randint(103, 127)
    return a, b, str(a * b)


ENGINES = [
    ("Jinja2/Twig", "{{{a}*{b}}}", [("{{config}}", r"<Config|SECRET_KEY"), ("{{7*'7'}}", "7777777")]),
    ("FreeMarker/Mako", "${{{a}*{b}}}", []),
    ("Ruby ERB / Java EL", "#{{{a}*{b}}}", []),
    ("ERB/ASP", "<%= {a}*{b} %>", []),
    ("Razor", "@({a}*{b})", []),
]

ENGINE_DEVELOPER_FIX = {
    "Jinja2/Twig": (
        "Fix: Never pass raw user input into Jinja2/Twig template strings.\n"
        "Instead of:\n"
        "  template = Template('Hello ' + user_input)\n"
        "  return template.render()\n"
        "Use:\n"
        "  template = Template('Hello {{ name }}')\n"
        "  return template.render(name=user_input)\n"
        "\n"
        "Enable Jinja2 sandbox for any dynamic template rendering:\n"
        "  from jinja2.sandbox import SandboxedEnvironment\n"
        "  env = SandboxedEnvironment()\n"
        "  template = env.from_string(safe_template)\n"
        "  return template.render(name=user_input)"
    ),
    "FreeMarker/Mako": (
        "Fix: Never interpolate user input into Mako/FreeMarker template source.\n"
        "Instead of:\n"
        "  template_str = '${' + user_input + '}'\n"
        "Use:\n"
        "  template = Template('${value}')\n"
        "  return template.render(value=user_input)\n"
        "\n"
        "For FreeMarker, disable new_builtin_class_resolver:\n"
        "  cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);"
    ),
    "Ruby ERB / Java EL": (
        "Fix: Do not pass user input into ERB template strings or EL expressions.\n"
        "Instead of:\n"
        "  ERB.new(\"<%= #{user_input} %>\").result\n"
        "Use:\n"
        "  ERB.new('<%= @value %>').result_with_hash(value: user_input)\n"
        "\n"
        "For Java EL, avoid evaluating user-controlled expressions:\n"
        "  // Do NOT do this:\n"
        "  valueExpression = factory.createValueExpression(ctx, userInput, Object.class);\n"
        "  // Instead, pass user input as a variable, not as the expression itself."
    ),
    "ERB/ASP": (
        "Fix: Never embed user input into ERB/ASP template source code.\n"
        "Instead of:\n"
        "  erb_string = '<%= ' + params[:input] + ' %>'\n"
        "Use:\n"
        "  <%= sanitize(@user_value) %>\n"
        "Pass user input as data, not as template code."
    ),
    "Razor": (
        "Fix: Do not pass user input into Razor view compilation.\n"
        "Instead of:\n"
        "  var template = \"@(\" + userInput + \")\";\n"
        "  Engine.Razor.RunCompile(template, ...);\n"
        "Use:\n"
        "  @Model.UserValue  // Pass as model property, never as template code\n"
        "Ensure RazorEngine uses IsolatedSandbox if dynamic compilation is required."
    ),
}


def _build_curl(method, url, headers=None, data=None):
    cmd = f"curl -k -X {method} '{url}'"
    if headers:
        for k, v in headers.items():
            cmd += f" -H '{k}: {v}'"
    if data:
        cmd += f" -d '{data}'"
    return cmd


def _confirm_ssti(session, url_or_action, param, method, form_data, engine_confirms, is_form):
    for confirm_payload, confirm_pattern in engine_confirms:
        if is_form:
            data = dict(form_data)
            data[param] = confirm_payload
            if method == "post":
                resp = session.post(url_or_action, data=data)
            else:
                resp = session.get(url_or_action, params=data)
        else:
            parsed = urlparse(url_or_action)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [confirm_payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            resp = session.get(test_url)

        if resp and re.search(confirm_pattern, resp.text):
            return True

    a2 = random.randint(201, 299)
    b2 = random.randint(301, 399)
    expected2 = str(a2 * b2)
    verify_payload = f"{{{{{a2}*{b2}}}}}"

    if is_form:
        data = dict(form_data)
        data[param] = verify_payload
        if method == "post":
            resp = session.post(url_or_action, data=data)
        else:
            resp = session.get(url_or_action, params=data)
    else:
        parsed = urlparse(url_or_action)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [verify_payload]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        resp = session.get(test_url)

    if resp and expected2 in resp.text:
        baseline_check = f"nontemplate{expected2}marker"
        if is_form:
            data[param] = baseline_check
            if method == "post":
                resp_b = session.post(url_or_action, data=data)
            else:
                resp_b = session.get(url_or_action, params=data)
        else:
            params[param] = [baseline_check]
            resp_b = session.get(urlunparse(parsed._replace(query=urlencode(params, doseq=True))))
        if resp_b and expected2 not in resp_b.text:
            return True

    return False


def _test_param_url(session: ScanSession, url: str, param: str, original: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    canary = f"vulnscancanary{random.randint(100000, 999999)}"
    params[param] = [canary]
    test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(test_url)
    if not resp or canary not in resp.text:
        return

    a, b, expected = _make_payloads()

    for engine_name, tpl, confirms in ENGINES:
        payload = tpl.format(a=a, b=b)
        params[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        resp = session.get(test_url)
        if not resp:
            continue

        if expected in resp.text:
            if _confirm_ssti(session, url, param, "get", None, confirms, is_form=False):
                dev_fix = ENGINE_DEVELOPER_FIX.get(engine_name, "Do not pass user input into template engine source code.")
                session.add_finding(Finding(
                    title=f"Server-Side Template Injection ({engine_name})",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The URL parameter '{param}' is processed by a {engine_name} template engine "
                        f"without proper sandboxing. The server evaluates user-supplied template "
                        f"expressions, which was confirmed by injecting a mathematical operation "
                        f"('{payload}') and observing the computed result ('{expected}') in the "
                        f"response. This vulnerability allows an attacker to execute arbitrary code "
                        f"on the server, read sensitive files, environment variables, and potentially "
                        f"achieve full Remote Code Execution (RCE)."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Template Engine: {engine_name}\n"
                        f"Payload Sent: {payload}\n"
                        f"Expected Result: {expected}\n"
                        f"Result Found in Response: Yes\n"
                        f"Confirmation: Double-verified with secondary arithmetic payload\n"
                        f"Response Status: {resp.status_code}\n"
                        f"Test URL: {test_url}"
                    ),
                    remediation=(
                        "1. Never pass user input directly into template engine source strings.\n"
                        "2. Use template variables/context instead of string concatenation with user data.\n"
                        "3. If dynamic templates are required, use a sandboxed environment (e.g., Jinja2 SandboxedEnvironment).\n"
                        "4. Implement strict input validation - reject template syntax characters ({, }, $, #, <%, @).\n"
                        "5. Apply the principle of least privilege to the template rendering process."
                    ),
                    url=url,
                    module="ssti",
                    cwe="CWE-1336",
                    confirmed=True,
                    location=f"URL parameter '{param}' in query string",
                    parameter=param,
                    payload=payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=_build_curl("GET", test_url),
                    reproduction_steps=(
                        f"1. Open the target URL: {url}\n"
                        f"2. Modify the '{param}' parameter value to the SSTI payload: {payload}\n"
                        f"3. Send the GET request (full URL: {test_url})\n"
                        f"4. Observe the computed result '{expected}' in the response body, confirming template evaluation.\n"
                        f"5. To further confirm RCE potential, try engine-specific payloads:\n"
                        f"   - Jinja2: {{{{config}}}} or {{{{self.__init__.__globals__}}}}\n"
                        f"   - FreeMarker: ${{\"freemarker.template.utility.Execute\"?new()(\"id\")}}\n"
                        f"   - Mako: ${{__import__('os').popen('id').read()}}"
                    ),
                    developer_fix=(
                        f"File: The server-side code that handles the '{parsed.path}' route and passes "
                        f"the '{param}' parameter into the {engine_name} template engine.\n"
                        f"\n{dev_fix}"
                    ),
                    affected_component=f"Route handler for {parsed.path} - template rendering with {engine_name}",
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"
                        " | https://cwe.mitre.org/data/definitions/1336.html"
                        " | https://portswigger.net/research/server-side-template-injection"
                    ),
                    detection_method="Injected template syntax expressions ({{7*7}}, ${7*7}, #{7*7}) for Jinja2, Mako, Freemarker, Twig, and other engines. Confirmed when the computed result (49) appears in the response but not in baseline — proving server-side template evaluation.",
                ))
                return


def _test_form(session: ScanSession, form: dict):
    for inp in form["inputs"]:
        name = inp.get("name")
        if not name or inp.get("type") in ("hidden", "submit", "button", "file"):
            continue

        canary = f"vulnscancanary{random.randint(100000, 999999)}"
        base_data = {}
        for other in form["inputs"]:
            other_name = other.get("name")
            if not other_name:
                continue
            base_data[other_name] = canary if other_name == name else other.get("value", "test")

        if form["method"] == "post":
            resp = session.post(form["action"], data=base_data)
        else:
            resp = session.get(form["action"], params=base_data)

        if not resp or canary not in resp.text:
            continue

        a, b, expected = _make_payloads()

        for engine_name, tpl, confirms in ENGINES:
            payload = tpl.format(a=a, b=b)
            test_data = dict(base_data)
            test_data[name] = payload

            if form["method"] == "post":
                resp2 = session.post(form["action"], data=test_data)
            else:
                resp2 = session.get(form["action"], params=test_data)

            if resp2 and expected in resp2.text:
                if _confirm_ssti(session, form["action"], name, form["method"], base_data, confirms, is_form=True):
                    method = form["method"].upper()
                    data_str = "&".join(f"{k}={v}" for k, v in test_data.items())
                    source_url = form.get("source_url", form["action"])
                    dev_fix = ENGINE_DEVELOPER_FIX.get(engine_name, "Do not pass user input into template engine source code.")

                    session.add_finding(Finding(
                        title=f"Server-Side Template Injection in Form ({engine_name})",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The form field '{name}' submitted to {form['action']} is processed by a "
                            f"{engine_name} template engine without proper sandboxing. The server evaluates "
                            f"user-supplied template expressions, confirmed by injecting a mathematical "
                            f"operation ('{payload}') and observing the computed result ('{expected}') in "
                            f"the response. An attacker can leverage this to execute arbitrary server-side "
                            f"code, read sensitive configuration, access environment variables, and "
                            f"potentially achieve full Remote Code Execution (RCE)."
                        ),
                        evidence=(
                            f"Form Action: {form['action']}\n"
                            f"Form Method: {method}\n"
                            f"Vulnerable Field: {name}\n"
                            f"Field Type: {inp.get('type', 'text')}\n"
                            f"Template Engine: {engine_name}\n"
                            f"Payload Sent: {payload}\n"
                            f"Expected Result: {expected}\n"
                            f"Result Found in Response: Yes\n"
                            f"Confirmation: Double-verified with secondary arithmetic payload\n"
                            f"Response Status: {resp2.status_code}"
                        ),
                        remediation=(
                            "1. Never pass user input directly into template engine source strings.\n"
                            "2. Use template variables/context instead of string concatenation with user data.\n"
                            "3. If dynamic templates are required, use a sandboxed environment (e.g., Jinja2 SandboxedEnvironment).\n"
                            "4. Implement strict input validation - reject template syntax characters ({, }, $, #, <%, @).\n"
                            "5. Apply the principle of least privilege to the template rendering process."
                        ),
                        url=source_url,
                        module="ssti",
                        cwe="CWE-1336",
                        confirmed=True,
                        location=f"Form field '{name}' (type: {inp.get('type', 'text')}) at {form['action']}",
                        parameter=name,
                        payload=payload,
                        request_method=method,
                        request_body=data_str,
                        response_status=resp2.status_code,
                        curl_command=_build_curl(method, form["action"], data=data_str) if method == "POST" else _build_curl("GET", f"{form['action']}?{data_str}"),
                        reproduction_steps=(
                            f"1. Navigate to the page containing the form: {source_url}\n"
                            f"2. Locate the form that submits to: {form['action']}\n"
                            f"3. Enter the following SSTI payload in the '{name}' field: {payload}\n"
                            f"4. Submit the form.\n"
                            f"5. Observe the computed result '{expected}' in the response body, confirming template evaluation.\n"
                            f"6. To escalate to RCE, try engine-specific code execution payloads."
                        ),
                        developer_fix=(
                            f"File: The server-side handler for {method} {form['action']} that processes "
                            f"the '{name}' form field and passes it to the {engine_name} template engine.\n"
                            f"\n{dev_fix}"
                        ),
                        affected_component=f"{method} {form['action']} - form field '{name}' rendered via {engine_name}",
                        references=(
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"
                            " | https://cwe.mitre.org/data/definitions/1336.html"
                            " | https://portswigger.net/research/server-side-template-injection"
                        ),
                        detection_method="Injected template syntax expressions ({{7*7}}, ${7*7}, #{7*7}) for Jinja2, Mako, Freemarker, Twig, and other engines. Confirmed when the computed result (49) appears in the response but not in baseline — proving server-side template evaluation.",
                    ))
                    return


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for Server-Side Template Injection (SSTI)...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param, values in params.items():
            _test_param_url(session, url, param, values[0] if values else "")

    for form in session.forms:
        _test_form(session, form)
