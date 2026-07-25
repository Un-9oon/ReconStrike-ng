import json
import re
from urllib.parse import urlparse

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


def _build_curl(method, url, data=None, content_type=None):
    cmd = f"curl -k -X {method} '{url}'"
    if content_type:
        cmd += f" -H 'Content-Type: {content_type}'"
    if data:
        cmd += f" -d '{data}'"
    return cmd


def _check_reflected(body, baseline_body, param, value):
    """Check if the injected extra parameter is reflected in the response."""
    # Direct value reflection
    if value in body and (not baseline_body or value not in baseline_body):
        return True, f"Value '{value}' reflected in response"

    # Check known reflection patterns
    for pattern, description in REFLECTION_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            if not baseline_body or not re.search(pattern, baseline_body, re.IGNORECASE):
                return True, description

    # Check if param=value appears in a JSON-like structure
    json_pattern = rf'"{re.escape(param)}"\s*:\s*("{re.escape(value)}"|{re.escape(value)})'
    if re.search(json_pattern, body, re.IGNORECASE):
        if not baseline_body or not re.search(json_pattern, baseline_body, re.IGNORECASE):
            return True, f"Parameter '{param}' reflected with value '{value}' in JSON"

    return False, None


def _response_indicates_acceptance(baseline_resp, test_resp):
    """Check if the response suggests the extra parameter was accepted."""
    if not baseline_resp or not test_resp:
        return False

    # If extra params cause a different (successful) status
    if test_resp.status_code in (200, 201, 302) and baseline_resp.status_code == test_resp.status_code:
        bl = len(baseline_resp.text)
        tl = len(test_resp.text)
        if bl > 0 and abs(tl - bl) / max(bl, 1) > 0.05:
            return True

    return False


def _test_form_encoded(session, form):
    """Test form submissions with extra parameters (form-encoded)."""
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)
    parsed = urlparse(action)

    if method != "post":
        return

    # Build baseline data
    baseline_data = {}
    existing_names = set()
    for inp in inputs:
        name = inp.get("name")
        if name:
            baseline_data[name] = inp.get("value", "test")
            existing_names.add(name.lower())

    baseline_resp = session.post(action, data=baseline_data)
    if not baseline_resp:
        return
    baseline_text = baseline_resp.text

    for param, value, description in EXTRA_PARAMS:
        # Skip if the parameter already exists in the form
        if param.lower() in existing_names:
            continue

        test_data = dict(baseline_data)
        test_data[param] = value

        try:
            resp = session.post(action, data=test_data)
        except Exception:
            continue

        if not resp or resp.status_code in (404,):
            continue

        reflected, indicator = _check_reflected(resp.text, baseline_text, param, value)

        if reflected:
            data_str = "&".join(f"{k}={v}" for k, v in test_data.items())
            curl_cmd = _build_curl("POST", action, data=data_str)
            session.add_finding(Finding(
                title=f"Mass Assignment - {description}",
                severity=Severity.HIGH,
                description=(
                    f"The form endpoint '{action}' is vulnerable to mass assignment. "
                    f"When the extra parameter '{param}={value}' was added to the form "
                    f"submission (which was not part of the original form), the server "
                    f"accepted and reflected it ({indicator}). This allows an attacker to "
                    f"modify fields that should be protected from client-side manipulation."
                ),
                evidence=(
                    f"Form Action: {action}\n"
                    f"Form Method: POST\n"
                    f"Injected Parameter: {param}={value}\n"
                    f"Description: {description}\n"
                    f"Indicator: {indicator}\n"
                    f"Original Fields: {', '.join(existing_names)}\n"
                    f"Response Status: {resp.status_code}"
                ),
                remediation=(
                    "1. Use an allowlist of permitted parameters on the server side.\n"
                    "2. Never bind request data directly to model/database objects.\n"
                    "3. Use DTOs (Data Transfer Objects) that only include expected fields.\n"
                    "4. In Rails: use strong_parameters (params.require(:user).permit(:name, :email)).\n"
                    "5. In Django: use serializer fields or form.cleaned_data only.\n"
                    "6. In Express: explicitly pick allowed fields from req.body."
                ),
                url=source_url,
                module="mass_assignment",
                cwe="CWE-915",
                confirmed=True,
                location=f"Form submission to {action}",
                parameter=param,
                payload=f"{param}={value}",
                request_method="POST",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Navigate to: {source_url}\n"
                    f"2. Locate the form that submits to {action}\n"
                    f"3. Using a proxy or browser DevTools, add: {param}={value}\n"
                    f"4. Submit the form and observe the response.\n"
                    f"5. Look for: {indicator}\n"
                    f"6. Run: {curl_cmd}"
                ),
                developer_fix=(
                    f"File: The server-side handler for POST {action}.\n\n"
                    f"VULNERABLE pattern (do NOT use):\n"
                    f"  # Python/Django\n"
                    f"  user = User(**request.POST.dict())\n"
                    f"  # Rails\n"
                    f"  User.create(params[:user])\n"
                    f"  # Express\n"
                    f"  User.create(req.body)\n\n"
                    f"SECURE pattern:\n"
                    f"  # Python/Django\n"
                    f"  user = User(name=request.POST['name'], email=request.POST['email'])\n"
                    f"  # Rails\n"
                    f"  User.create(params.require(:user).permit(:name, :email))\n"
                    f"  # Express\n"
                    f"  const {{ name, email }} = req.body;\n"
                    f"  User.create({{ name, email }})"
                ),
                affected_component=f"Parameter binding in form handler for {action}",
                references="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/ | https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                detection_method=f"Added extra parameter '{param}={value}' to form submission and detected the value reflected in the server response ({indicator}).",
            ))
            return

        # Check for acceptance without direct reflection
        if _response_indicates_acceptance(baseline_resp, resp):
            # Also check for status code changes that indicate success
            if resp.status_code in (200, 201, 302):
                data_str = "&".join(f"{k}={v}" for k, v in test_data.items())
                curl_cmd = _build_curl("POST", action, data=data_str)
                session.add_finding(Finding(
                    title=f"Potential Mass Assignment - {description}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The form endpoint '{action}' may be vulnerable to mass assignment. "
                        f"When the extra parameter '{param}={value}' was added to the form "
                        f"submission, the server response differed from the baseline, suggesting "
                        f"the parameter was processed. Manual verification is recommended."
                    ),
                    evidence=(
                        f"Form Action: {action}\n"
                        f"Injected Parameter: {param}={value}\n"
                        f"Description: {description}\n"
                        f"Baseline Response Length: {len(baseline_text)}\n"
                        f"Test Response Length: {len(resp.text)}\n"
                        f"Response Status: {resp.status_code}"
                    ),
                    remediation=(
                        "1. Implement strict parameter allowlisting on the server.\n"
                        "2. Use DTOs that only expose permitted fields.\n"
                        "3. Log and reject unexpected parameters."
                    ),
                    url=source_url,
                    module="mass_assignment",
                    cwe="CWE-915",
                    confirmed=False,
                    location=f"Form submission to {action}",
                    parameter=param,
                    payload=f"{param}={value}",
                    request_method="POST",
                    response_status=resp.status_code,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Navigate to: {source_url}\n"
                        f"2. Add '{param}={value}' to the form submission.\n"
                        f"3. Compare the response with a normal submission.\n"
                        f"4. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        f"File: The handler for POST {action}.\n\n"
                        f"Use explicit field picking:\n"
                        f"  const allowed = ['name', 'email'];\n"
                        f"  const data = Object.fromEntries(\n"
                        f"    Object.entries(req.body).filter(([k]) => allowed.includes(k))\n"
                        f"  );"
                    ),
                    affected_component=f"Parameter binding in handler for {action}",
                    references="https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                    detection_method=f"Added extra parameter '{param}={value}' and observed different response compared to baseline, suggesting the parameter was processed.",
                ))
                return


def _test_form_json(session, form):
    """Test form submissions with extra parameters via JSON body."""
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)

    if method != "post":
        return

    # Build baseline JSON
    baseline_json = {}
    existing_names = set()
    for inp in inputs:
        name = inp.get("name")
        if name:
            baseline_json[name] = inp.get("value", "test")
            existing_names.add(name.lower())

    baseline_resp = session.post(action, json=baseline_json)
    if not baseline_resp:
        return
    baseline_text = baseline_resp.text

    for param, value, description in EXTRA_PARAMS:
        if param.lower() in existing_names:
            continue

        test_json = dict(baseline_json)
        # Use appropriate types for JSON
        if value in ("true", "false"):
            test_json[param] = value == "true"
        elif value.isdigit():
            test_json[param] = int(value)
        else:
            test_json[param] = value

        try:
            resp = session.post(action, json=test_json)
        except Exception:
            continue

        if not resp or resp.status_code in (404,):
            continue

        reflected, indicator = _check_reflected(resp.text, baseline_text, param, value)

        if reflected:
            data_str = json.dumps(test_json)
            curl_cmd = _build_curl("POST", action, data=data_str, content_type="application/json")
            session.add_finding(Finding(
                title=f"Mass Assignment via JSON - {description}",
                severity=Severity.HIGH,
                description=(
                    f"The endpoint '{action}' is vulnerable to mass assignment via JSON body. "
                    f"When the extra field '{param}' was added to the JSON payload, the server "
                    f"accepted and reflected it ({indicator}). This allows attackers to modify "
                    f"protected fields by adding them to API requests."
                ),
                evidence=(
                    f"Endpoint: {action}\n"
                    f"Injected Field: {param}\n"
                    f"Injected Value: {test_json[param]}\n"
                    f"Description: {description}\n"
                    f"Indicator: {indicator}\n"
                    f"Original Fields: {', '.join(existing_names)}\n"
                    f"Payload: {data_str}\n"
                    f"Response Status: {resp.status_code}"
                ),
                remediation=(
                    "1. Validate JSON payloads against a strict schema.\n"
                    "2. Use an allowlist of accepted fields for each endpoint.\n"
                    "3. Separate read-only fields from writable fields in the data model.\n"
                    "4. Use framework-level protections (serializers, strong params).\n"
                    "5. Log rejected fields for security monitoring."
                ),
                url=source_url,
                module="mass_assignment",
                cwe="CWE-915",
                confirmed=True,
                location=f"JSON body submitted to {action}",
                parameter=param,
                payload=data_str,
                request_method="POST",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Navigate to: {source_url}\n"
                    f"2. Submit a POST request to {action} with JSON:\n"
                    f"   {data_str}\n"
                    f"3. Observe '{param}' reflected in the response.\n"
                    f"4. Run: {curl_cmd}"
                ),
                developer_fix=(
                    f"File: The handler for POST {action}.\n\n"
                    f"VULNERABLE pattern:\n"
                    f"  app.post('{action}', (req, res) => {{\n"
                    f"    User.update(req.body);  // All fields accepted!\n"
                    f"  }});\n\n"
                    f"SECURE pattern:\n"
                    f"  app.post('{action}', (req, res) => {{\n"
                    f"    const {{ name, email }} = req.body;  // Only allowed fields\n"
                    f"    User.update({{ name, email }});\n"
                    f"  }});"
                ),
                affected_component=f"JSON body processing in handler for {action}",
                references="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/ | https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                detection_method=f"Added extra JSON field '{param}' to POST body and detected it reflected in the server response ({indicator}).",
            ))
            return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Mass Assignment / Parameter Tampering...")

    for form in session.forms:
        _test_form_encoded(session, form)
        _test_form_json(session, form)
