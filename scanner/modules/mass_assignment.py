import json
import re
from urllib.parse import urlparse

import requests

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession


EXTRA_PARAMS = [
    ("role", "admin", "Privilege escalation via role"),
    ("is_admin", "true", "Admin flag injection"),
    ("isAdmin", "true", "Admin flag injection (camelCase)"),
    ("admin", "true", "Admin flag injection (direct)"),
    ("verified", "true", "Verification bypass"),
    ("is_verified", "true", "Verification bypass (snake_case)"),
    ("active", "true", "Account activation bypass"),
    ("is_active", "true", "Account activation bypass (snake_case)"),
    ("email_verified", "true", "Email verification bypass"),
    ("approved", "true", "Approval bypass"),
    ("is_staff", "true", "Staff privilege escalation"),
    ("is_superuser", "true", "Superuser privilege escalation"),
    ("permissions", "admin", "Permission level override"),
    ("access_level", "admin", "Access level override"),
    ("user_type", "admin", "User type override"),
    ("group", "administrators", "Group membership injection"),
    ("status", "active", "Status override"),
    ("balance", "99999", "Balance manipulation"),
    ("price", "0", "Price manipulation"),
    ("discount", "100", "Discount manipulation"),
]

REFLECTION_PATTERNS = [
    (r'"role"\s*:\s*"admin"', "role set to admin"),
    (r'"is_?admin"\s*:\s*true', "admin flag set to true"),
    (r'"isAdmin"\s*:\s*true', "isAdmin set to true"),
    (r'"verified"\s*:\s*true', "verified flag set to true"),
    (r'"is_?verified"\s*:\s*true', "verified flag set to true"),
    (r'"is_?staff"\s*:\s*true', "staff flag set to true"),
    (r'"is_?superuser"\s*:\s*true', "superuser flag set to true"),
    (r'"permissions"\s*:\s*"admin"', "permissions set to admin"),
    (r'"access_level"\s*:\s*"admin"', "access level set to admin"),
    (r'"user_type"\s*:\s*"admin"', "user type set to admin"),
    (r'"balance"\s*:\s*99999', "balance manipulated"),
    (r'"price"\s*:\s*0', "price set to zero"),
    (r'"discount"\s*:\s*100', "discount set to 100"),
]

_REMEDIATION_FULL = (
    "1. Use an allowlist of permitted parameters on the server side.\n"
    "2. Never bind request data directly to model/database objects.\n"
    "3. Use DTOs (Data Transfer Objects) that only include expected fields.\n"
    "4. In Rails: use strong_parameters (params.require(:user).permit(:name, :email)).\n"
    "5. In Django: use serializer fields or form.cleaned_data only.\n"
    "6. In Express: explicitly pick allowed fields from req.body."
)

_REMEDIATION_SHORT = (
    "1. Implement strict parameter allowlisting on the server.\n"
    "2. Use DTOs that only expose permitted fields.\n"
    "3. Log and reject unexpected parameters."
)


def _build_curl(method, url, data=None, content_type=None):
    cmd = "curl -k -X {} '{}'".format(method, url)
    if content_type:
        cmd += " -H 'Content-Type: {}'".format(content_type)
    if data:
        cmd += " -d '{}'".format(data)
    return cmd


def _check_reflected(body, baseline_body, param, value):
    # direct reflection
    if value in body and (not baseline_body or value not in baseline_body):
        return True, "Value '{}' reflected in response".format(value)

    for pattern, desc in REFLECTION_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            if not baseline_body or not re.search(pattern, baseline_body, re.IGNORECASE):
                return True, desc

    # param=value in JSON structure
    jp = r'"{0}"\s*:\s*("{1}"|{1})'.format(re.escape(param), re.escape(value))
    if re.search(jp, body, re.IGNORECASE):
        if not baseline_body or not re.search(jp, baseline_body, re.IGNORECASE):
            return True, "Parameter '{}' reflected with value '{}' in JSON".format(param, value)

    return False, None


def _response_indicates_acceptance(baseline_resp, test_resp):
    if not baseline_resp or not test_resp:
        return False
    if test_resp.status_code in (200, 201, 302) and baseline_resp.status_code == test_resp.status_code:
        bl = len(baseline_resp.text)
        tl = len(test_resp.text)
        if bl > 0 and abs(tl - bl) / max(bl, 1) > 0.05:
            return True
    return False


def _extract_form_baseline(form):
    """Returns (action, inputs, source_url, baseline_data, existing_names) or None if not POST."""
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    if method != "post":
        return None
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)
    baseline_data = {inp["name"]: inp.get("value", "test") for inp in inputs if inp.get("name")}
    existing_names = {n.lower() for n in baseline_data}
    return action, inputs, source_url, baseline_data, existing_names


def _make_confirmed_finding(action, source_url, param, value, description,
                            indicator, existing_names, resp, payload_str,
                            curl_cmd, is_json=False):
    tag = "JSON" if is_json else "form"
    loc_prefix = "JSON body submitted to" if is_json else "Form submission to"
    title = "Mass Assignment via JSON - {}".format(description) if is_json else "Mass Assignment - {}".format(description)

    return Finding(
        title=title,
        severity=Severity.HIGH,
        description=(
            "The endpoint '{}' is vulnerable to mass assignment via {} body. "
            "When the extra parameter '{}={}' was injected, the server "
            "accepted and reflected it ({}). This allows modification of "
            "fields that should be protected from client-side manipulation."
        ).format(action, tag, param, value, indicator),
        evidence=(
            "Endpoint: {}\nInjected: {}={}\nDescription: {}\n"
            "Indicator: {}\nOriginal Fields: {}\nPayload: {}\n"
            "Response Status: {}"
        ).format(action, param, value, description, indicator,
                 ", ".join(existing_names), payload_str, resp.status_code),
        remediation=_REMEDIATION_FULL,
        url=source_url,
        module="mass_assignment",
        cwe="CWE-915",
        confirmed=True,
        location="{} {}".format(loc_prefix, action),
        parameter=param,
        payload=payload_str,
        request_method="POST",
        response_status=resp.status_code,
        curl_command=curl_cmd,
        reproduction_steps=(
            "1. Navigate to: {}\n"
            "2. Submit POST to {} with payload:\n   {}\n"
            "3. Observe '{}' reflected in the response.\n"
            "4. Run: {}"
        ).format(source_url, action, payload_str, param, curl_cmd),
        developer_fix=(
            "File: The handler for POST {action}.\n\n"
            "VULNERABLE pattern:\n"
            "  app.post('{action}', (req, res) => {{\n"
            "    User.update(req.body);  // All fields accepted!\n"
            "  }});\n\n"
            "SECURE pattern:\n"
            "  app.post('{action}', (req, res) => {{\n"
            "    const {{ name, email }} = req.body;\n"
            "    User.update({{ name, email }});\n"
            "  }});"
        ).format(action=action),
        affected_component="Parameter binding in handler for {}".format(action),
        references="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/ | https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        detection_method="Added extra parameter '{}={}' and detected it reflected in server response ({}).".format(param, value, indicator),
    )


def _make_potential_finding(action, source_url, param, value, description,
                            baseline_text, resp, payload_str, curl_cmd):
    return Finding(
        title="Potential Mass Assignment - {}".format(description),
        severity=Severity.MEDIUM,
        description=(
            "The endpoint '{}' may be vulnerable to mass assignment. "
            "When '{}={}' was added, the server response differed from "
            "baseline, suggesting the parameter was processed. Manual verification recommended."
        ).format(action, param, value),
        evidence=(
            "Endpoint: {}\nInjected: {}={}\nDescription: {}\n"
            "Baseline Length: {}\nTest Length: {}\nResponse Status: {}"
        ).format(action, param, value, description,
                 len(baseline_text), len(resp.text), resp.status_code),
        remediation=_REMEDIATION_SHORT,
        url=source_url,
        module="mass_assignment",
        cwe="CWE-915",
        confirmed=False,
        location="Form submission to {}".format(action),
        parameter=param,
        payload=payload_str,
        request_method="POST",
        response_status=resp.status_code,
        curl_command=curl_cmd,
        reproduction_steps=(
            "1. Navigate to: {}\n"
            "2. Add '{}={}' to the form submission.\n"
            "3. Compare response with normal submission.\n"
            "4. Run: {}"
        ).format(source_url, param, value, curl_cmd),
        developer_fix=(
            "File: The handler for POST {}.\n\n"
            "Use explicit field picking:\n"
            "  const allowed = ['name', 'email'];\n"
            "  const data = Object.fromEntries(\n"
            "    Object.entries(req.body).filter(([k]) => allowed.includes(k))\n"
            "  );"
        ).format(action),
        affected_component="Parameter binding in handler for {}".format(action),
        references="https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        detection_method="Added extra parameter '{}={}' and observed different response vs baseline.".format(param, value),
    )


def _coerce_json_value(value):
    """Cast string booleans/ints to native JSON types."""
    if value in ("true", "false"):
        return value == "true"
    return int(value) if value.isdigit() else value


def _test_form_encoded(session, form):
    parsed = _extract_form_baseline(form)
    if not parsed:
        return
    action, inputs, source_url, baseline_data, existing_names = parsed

    baseline_resp = session.post(action, data=baseline_data)
    if not baseline_resp:
        return
    baseline_text = baseline_resp.text

    for param, value, description in EXTRA_PARAMS:
        if param.lower() in existing_names:
            continue

        test_data = dict(baseline_data)
        test_data[param] = value

        try:
            resp = session.post(action, data=test_data)
        except (requests.RequestException, ValueError) as e:
            logger.debug("mass_assignment form-encoded: %s", e)
            continue

        if not resp or resp.status_code == 404:
            continue

        reflected, indicator = _check_reflected(resp.text, baseline_text, param, value)

        if reflected:
            data_str = "&".join("{}={}".format(k, v) for k, v in test_data.items())
            curl_cmd = _build_curl("POST", action, data=data_str)
            session.add_finding(_make_confirmed_finding(
                action, source_url, param, value, description,
                indicator, existing_names, resp, data_str, curl_cmd,
            ))
            return

        if _response_indicates_acceptance(baseline_resp, resp) and resp.status_code in (200, 201, 302):
            data_str = "&".join("{}={}".format(k, v) for k, v in test_data.items())
            curl_cmd = _build_curl("POST", action, data=data_str)
            session.add_finding(_make_potential_finding(
                action, source_url, param, value, description,
                baseline_text, resp, data_str, curl_cmd,
            ))
            return


def _test_form_json(session, form):
    parsed = _extract_form_baseline(form)
    if not parsed:
        return
    action, inputs, source_url, baseline_json, existing_names = parsed

    baseline_resp = session.post(action, json=baseline_json)
    if not baseline_resp:
        return
    baseline_text = baseline_resp.text

    for param, value, description in EXTRA_PARAMS:
        if param.lower() in existing_names:
            continue

        test_json = dict(baseline_json)
        test_json[param] = _coerce_json_value(value)

        try:
            resp = session.post(action, json=test_json)
        except (requests.RequestException, ValueError) as e:
            logger.debug("mass_assignment json: %s", e)
            continue

        if not resp or resp.status_code == 404:
            continue

        reflected, indicator = _check_reflected(resp.text, baseline_text, param, value)
        if not reflected:
            continue

        data_str = json.dumps(test_json)
        curl_cmd = _build_curl("POST", action, data=data_str, content_type="application/json")
        session.add_finding(_make_confirmed_finding(
            action, source_url, param, value, description,
            indicator, existing_names, resp, data_str, curl_cmd, is_json=True,
        ))
        return


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for Mass Assignment / Parameter Tampering...")

    for form in session.forms:
        _test_form_encoded(session, form)
        _test_form_json(session, form)
