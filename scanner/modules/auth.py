import re
from urllib.parse import urljoin

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger


COMMON_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("administrator", "administrator"),
]

DETECTION_METHOD = (
    "Tested authentication mechanisms: checked login forms for HTTPS, tested for "
    "username enumeration via response differences, validated password policies, and "
    "attempted default credential combinations against common login endpoints."
)


def run(session: ScanSession) -> None:
    logger.info("\n[*] Checking authentication security...")
    _check_login_security(session)
    _check_session_security(session)
    _check_password_policy(session)
    _check_default_credentials(session)


def _check_login_security(session):
    login_paths = ["/login", "/signin", "/auth/login", "/user/login",
                   "/account/login", "/admin/login", "/admin"]

    for path in login_paths:
        url = urljoin(session.config.target, path)
        resp = session.get(url, allow_redirects=False)
        if not resp or resp.status_code not in (200, 301, 302):
            continue

        if resp.status_code in (301, 302):
            resp = session.get(url)
            if not resp:
                continue

        body = resp.text.lower()
        if not any(kw in body for kw in ["password", "login", "sign in", "username"]):
            continue

        # Check for HTTP form actions on HTTPS sites
        if session.config.target.startswith("https"):
            form_actions = re.findall(r'<form[^>]*action=["\']?(http://[^"\'>\s]+)', body, re.IGNORECASE)
            for action in form_actions:
                if action.startswith("http://"):
                    curl_cmd = "curl -kI '{url}'".format(url=url)
                    session.add_finding(Finding(
                        title="Login Form Submits Over HTTP",
                        severity=Severity.HIGH,
                        description="Login form at {url} submits credentials over unencrypted HTTP to {action}. Credentials can be intercepted via network sniffing.".format(url=url, action=action),
                        evidence="Login Page: {url}\nForm action: {action}\nProtocol: HTTP (unencrypted)".format(url=url, action=action),
                        remediation="Ensure login forms submit to HTTPS endpoints only.",
                        url=url,
                        module="auth",
                        cwe="CWE-319",
                        confirmed=True,
                        location="Login form action attribute at {url}".format(url=url),
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            "1. Navigate to: {url}\n"
                            "2. Inspect the login form's action attribute.\n"
                            "3. The form action points to an HTTP (not HTTPS) URL: {action}\n"
                            "4. Credentials are transmitted in cleartext."
                        ).format(url=url, action=action),
                        developer_fix=(
                            "Change the form action from http:// to https://:\n"
                            "  <form action=\"{fixed}\" method=\"POST\">\n"
                            "Or use a relative URL: <form action=\"/login\" method=\"POST\">\n"
                            "Also add HSTS header to prevent downgrade attacks."
                        ).format(fixed=action.replace("http://", "https://")),
                        affected_component="Login form at {url}".format(url=url),
                        references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
                        detection_method=DETECTION_METHOD,
                    ))

        from scanner.crawler import extract_forms
        forms = extract_forms(resp.text, url)
        for form in forms:
            if not any("pass" in (i.get("name") or "").lower() for i in form["inputs"]):
                continue

            post_data = {}
            for inp in form["inputs"]:
                name = inp.get("name", "")
                if not name:
                    continue
                name_l = name.lower()
                if any(k in name_l for k in ("user", "email", "login")):
                    post_data[name] = "invalid_user_test"
                elif "pass" in name_l:
                    post_data[name] = "invalid_pass_test"
                elif inp.get("value"):
                    post_data[name] = inp["value"]

            if form["method"] == "post":
                fail_resp = session.post(form["action"], data=post_data)
            else:
                fail_resp = session.get(form["action"], params=post_data)

            if not fail_resp:
                continue

            fail_body = fail_resp.text.lower()
            enum_patterns = [
                "user not found", "username not found", "account not found",
                "no account", "user does not exist", "invalid username",
                "email not found", "email not registered",
            ]
            for pattern in enum_patterns:
                if pattern in fail_body:
                    data_str = "&".join("{k}={v}".format(k=k, v=v) for k, v in post_data.items())
                    curl_cmd = "curl -k -X POST '{action}' -d '{data}'".format(action=form["action"], data=data_str)
                    session.add_finding(Finding(
                        title="Username Enumeration via Login Error",
                        severity=Severity.MEDIUM,
                        description=(
                            "Login error messages at {url} reveal whether a username/email exists in the system. "
                            "The error message '{pattern}' distinguishes between invalid users and wrong passwords, "
                            "allowing attackers to enumerate valid accounts."
                        ).format(url=url, pattern=pattern),
                        evidence=(
                            "Login URL: {url}\n"
                            "Error message contains: '{pattern}'\n"
                            "Test credentials: invalid_user_test / invalid_pass_test"
                        ).format(url=url, pattern=pattern),
                        remediation="Use generic error messages like 'Invalid credentials' that don't reveal whether the username exists.",
                        url=url,
                        module="auth",
                        cwe="CWE-204",
                        confirmed=True,
                        location="Login error response at {action}".format(action=form["action"]),
                        request_method="POST",
                        request_body=data_str,
                        response_status=fail_resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            "1. Navigate to: {url}\n"
                            "2. Enter a non-existent username and any password.\n"
                            "3. Submit the login form.\n"
                            "4. The error message contains '{pattern}', confirming the username doesn't exist.\n"
                            "5. Compare with a valid username - the error message differs.\n"
                            "6. Run: {curl}"
                        ).format(url=url, pattern=pattern, curl=curl_cmd),
                        developer_fix=(
                            "File: Login handler at {action}\n\n"
                            "VULNERABLE: 'User not found' / 'Wrong password' (reveals which is wrong)\n"
                            "SECURE: 'Invalid username or password' (same message for both cases)\n\n"
                            "Also ensure response timing is consistent for both cases to prevent timing-based enumeration."
                        ).format(action=form["action"]),
                        affected_component="Login handler at {action}".format(action=form["action"]),
                        references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
                        detection_method=DETECTION_METHOD,
                    ))
                    break
            break


def _check_session_security(session):
    from scanner.modules import session_security
    session_security.run(session)


def _check_password_policy(session):
    register_paths = ["/register", "/signup", "/sign-up", "/create-account", "/join"]

    for path in register_paths:
        url = urljoin(session.config.target, path)
        resp = session.get(url)
        if not resp or resp.status_code != 200:
            continue

        body = resp.text.lower()
        if not any(kw in body for kw in ["register", "sign up", "create account", "password"]):
            continue

        from scanner.crawler import extract_forms
        forms = extract_forms(resp.text, url)
        for form in forms:
            if not any("pass" in (i.get("name") or "").lower() for i in form["inputs"]):
                continue

            for inp in form["inputs"]:
                if "pass" in (inp.get("name") or "").lower():
                    input_tag = re.search(
                        r'<input[^>]*name=["\']?{name}[^>]*>'.format(name=re.escape(inp["name"])),
                        resp.text, re.IGNORECASE
                    )
                    if input_tag:
                        tag_str = input_tag.group(0)
                        if 'minlength' not in tag_str.lower() and 'pattern' not in tag_str.lower():
                            session.add_finding(Finding(
                                title="No Client-Side Password Strength Validation",
                                severity=Severity.INFO,
                                description="Registration form at {url} doesn't enforce password requirements client-side. Weak passwords may be accepted.".format(url=url),
                                evidence="Password field '{name}' lacks minlength/pattern attributes.\nForm action: {action}".format(name=inp["name"], action=form["action"]),
                                remediation="Enforce password policy both client-side (minlength, pattern) and server-side.",
                                url=url,
                                module="auth",
                                cwe="CWE-521",
                                confirmed=True,
                                location="Password field '{name}' in registration form at {url}".format(name=inp["name"], url=url),
                                curl_command="curl -k '{url}'".format(url=url),
                                developer_fix=(
                                    "Add client-side validation to the password field:\n"
                                    "  <input type=\"password\" name=\"{name}\" minlength=\"8\" "
                                    "pattern=\"(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{{8,}}\" required>\n\n"
                                    "Also enforce server-side: minimum 8 chars, mixed case, numbers, special chars."
                                ).format(name=inp["name"]),
                                affected_component="Registration form at {url}".format(url=url),
                                detection_method=DETECTION_METHOD,
                            ))
            break


def _fill_login_form(form, username, password):
    post_data = {}
    for inp in form["inputs"]:
        name = inp.get("name", "")
        if not name:
            continue
        name_l = name.lower()
        if any(k in name_l for k in ("user", "email", "login")):
            post_data[name] = username
        elif "pass" in name_l:
            post_data[name] = password
        elif inp.get("value"):
            post_data[name] = inp["value"]
    return post_data


def _submit_form(session, form, data):
    if form["method"] == "post":
        return session.post(form["action"], data=data, allow_redirects=True)
    return session.get(form["action"], params=data, allow_redirects=True)


def _check_default_credentials(session):
    if not session.config.auth_url:
        return

    resp = session.get(session.config.auth_url)
    if not resp:
        return

    from scanner.crawler import extract_forms
    forms = extract_forms(resp.text, session.config.auth_url)
    login_form = None
    for form in forms:
        if any("pass" in (i.get("name") or "").lower() for i in form["inputs"]):
            login_form = form
            break

    if not login_form:
        return

    fail_data = _fill_login_form(login_form, "vulnscan_invalid_user_xz9", "vulnscan_invalid_pass_xz9")
    fail_resp = _submit_form(session, login_form, fail_data)
    fail_text = fail_resp.text.lower() if fail_resp else ""

    logger.info(" [*] Testing for default credentials...")
    for username, password in COMMON_CREDS:
        post_data = _fill_login_form(login_form, username, password)
        resp = _submit_form(session, login_form, post_data)
        if not resp:
            continue

        success_forms = extract_forms(resp.text, login_form["action"])
        still_has_login = any(
            any("pass" in (i.get("name") or "").lower() for i in f["inputs"])
            for f in success_forms
        )
        if still_has_login:
            continue

        if resp.text.lower() != fail_text:
            data_str = "&".join("{k}={v}".format(k=k, v=v) for k, v in post_data.items())
            curl_cmd = "curl -k -X POST '{action}' -d '{data}'".format(action=login_form["action"], data=data_str)
            session.add_finding(Finding(
                title="Default Credentials: {user}/{pw}".format(user=username, pw=password),
                severity=Severity.CRITICAL,
                description=(
                    "The application accepts default credentials ({user}/{pw}). "
                    "This allows anyone with knowledge of common default passwords to gain unauthorized access."
                ).format(user=username, pw=password),
                evidence=(
                    "Login URL: {auth}\nUsername: {user}\nPassword: {pw}\n"
                    "Login succeeded - response no longer contains login form."
                ).format(auth=session.config.auth_url, user=username, pw=password),
                remediation=(
                    "1. Change all default credentials immediately.\n"
                    "2. Force password change on first login.\n"
                    "3. Implement account lockout after failed attempts.\n"
                    "4. Use strong password policy."
                ),
                url=session.config.auth_url,
                module="auth",
                cwe="CWE-798",
                confirmed=True,
                location="Login form at {action}".format(action=login_form["action"]),
                request_method="POST",
                request_body=data_str,
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    "1. Navigate to: {auth}\n"
                    "2. Enter username: {user}\n"
                    "3. Enter password: {pw}\n"
                    "4. Submit the login form.\n"
                    "5. Authentication succeeds.\n"
                    "6. Run: {curl}"
                ).format(auth=session.config.auth_url, user=username, pw=password, curl=curl_cmd),
                developer_fix=(
                    "1. Remove or change all default accounts:\n"
                    "   UPDATE users SET password = random_hash() WHERE username = '{user}';\n"
                    "2. Force password change on first login.\n"
                    "3. Add account lockout after 5 failed attempts."
                ).format(user=username),
                affected_component="Authentication system at {action}".format(action=login_form["action"]),
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials",
                detection_method=DETECTION_METHOD,
            ))
            return
