import re
from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger


CSRF_TOKEN_NAMES = {
    "csrf", "csrftoken", "csrf_token", "_csrf", "xsrf", "xsrf_token",
    "_xsrf", "authenticity_token", "__requestverificationtoken",
    "antiforgerytoken", "csrfmiddlewaretoken",
}

STATE_CHANGING_INDICATORS = [
    "password", "delete", "remove", "update", "edit",
    "create", "save", "modify", "change",
    "transfer", "upload", "config", "setting",
]


def _is_state_changing_form(form):
    if form["method"] != "post":
        return False
    action_path = urlparse(form["action"]).path.lower()
    input_names = [i.get("name", "").lower() for i in form["inputs"]]
    combined = action_path + " " + " ".join(input_names)
    return any(ind in combined for ind in STATE_CHANGING_INDICATORS)


def _has_csrf_token(form):
    for inp in form["inputs"]:
        name = (inp.get("name") or "").lower()
        normalized = name.replace("-", "").replace("_", "")
        if normalized in CSRF_TOKEN_NAMES or any(t in name for t in ("csrf", "xsrf", "authenticity_token")):
            return True
    return False


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for CSRF vulnerabilities...")

    for form in session.forms:
        if not _is_state_changing_form(form):
            continue
        if _has_csrf_token(form):
            continue

        resp = session.get(session.config.target)
        has_samesite = False
        if resp:
            for cookie in resp.cookies:
                attr = cookie.get_nonstandard_attr("SameSite") or ""
                if attr.lower() in ("strict", "lax"):
                    has_samesite = True
                    break

        if has_samesite:
            continue

        input_names = [i.get("name", "") for i in form["inputs"] if i.get("name")]
        source_url = form.get("source_url", form["action"])
        data_str = "&".join("{n}=test".format(n=n) for n in input_names)
        curl_cmd = "curl -k -X POST '{action}' -d '{data}'".format(action=form["action"], data=data_str)

        matched_kw = [ind for ind in STATE_CHANGING_INDICATORS
                      if ind in (urlparse(form["action"]).path.lower() + " " + " ".join(input_names).lower())]

        session.add_finding(Finding(
            title="Missing CSRF Protection on State-Changing Form",
            severity=Severity.MEDIUM,
            description=(
                "A POST form at {action} performs state-changing operations (detected keywords: "
                "{kw}) without CSRF token protection. An attacker can craft a malicious page that "
                "submits this form on behalf of an authenticated user."
            ).format(action=form["action"], kw=", ".join(matched_kw)),
            evidence=(
                "Form Action: {action}\n"
                "Method: POST\n"
                "Fields: {fields}\n"
                "CSRF Token: Not found\n"
                "SameSite Cookie: Not set"
            ).format(action=form["action"], fields=", ".join(input_names)),
            remediation=(
                "1. Add a CSRF token to all state-changing forms.\n"
                "2. Validate the token server-side on form submission.\n"
                "3. Set SameSite=Strict or SameSite=Lax on session cookies as defense-in-depth.\n"
                "4. Verify the Origin/Referer header matches your domain."
            ),
            url=source_url,
            module="csrf",
            cwe="CWE-352",
            confirmed=True,
            location="POST form at {action}".format(action=form["action"]),
            request_method="POST",
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Navigate to page containing the form: {src}\n"
                "2. Inspect the form that submits to: {action}\n"
                "3. Note that no CSRF token (hidden input) is present in the form.\n"
                "4. Create an HTML page with an auto-submitting form targeting {action}:\n"
                "   <form action=\"{action}\" method=\"POST\">\n"
                "{hidden_inputs}"
                "   </form><script>document.forms[0].submit()</script>\n"
                "5. When an authenticated user visits the attacker's page, the form auto-submits."
            ).format(
                src=source_url,
                action=form["action"],
                hidden_inputs="".join(
                    "     <input type=\"hidden\" name=\"{n}\" value=\"attacker_value\">\n".format(n=n)
                    for n in input_names
                ),
            ),
            developer_fix=(
                "File: The template rendering the form at {action} and its server-side handler.\n\n"
                "1. Add a hidden CSRF token field to the form:\n"
                "   <input type=\"hidden\" name=\"csrf_token\" value=\"{{{{ csrf_token }}}}\">\n\n"
                "2. Validate the token server-side:\n"
                "   Django: Uses {{% csrf_token %}} template tag automatically\n"
                "   Flask: from flask_wtf.csrf import CSRFProtect; csrf = CSRFProtect(app)\n"
                "   Express: Use csurf middleware\n"
                "   PHP: Generate token with bin2hex(random_bytes(32)), store in session, validate on POST\n\n"
                "3. Set SameSite on session cookies:\n"
                "   Set-Cookie: session=value; SameSite=Strict; Secure; HttpOnly"
            ).format(action=form["action"]),
            affected_component="POST {action}".format(action=form["action"]),
            references="https://owasp.org/www-community/attacks/csrf | https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            detection_method="Identified POST forms performing state-changing operations (password, delete, update, etc.) and checked for CSRF token hidden fields and SameSite cookie attributes. Missing both protections confirms CSRF vulnerability.",
        ))
