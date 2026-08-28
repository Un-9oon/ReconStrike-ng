import re
import time
import base64
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession


JAVA_MAGIC = "aced0005"
JAVA_MAGIC_B64 = "rO0AB"

PHP_PATTERNS = [
    re.compile(r'O:\d+:"[^"]+":'),
    re.compile(r'a:\d+:\{'),
    re.compile(r's:\d+:"[^"]*";'),
    re.compile(r'i:\d+;'),
]

PYTHON_PICKLE_INDICATORS = [
    b"\x80\x03", b"\x80\x04", b"\x80\x05",
    b"cos\n", b"cposix\n", b"c__builtin__",
]

DOTNET_VIEWSTATE_PATTERN = re.compile(
    r'<input[^>]*name=["\']__VIEWSTATE["\'][^>]*value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
DOTNET_VIEWSTATE_GENERATOR = re.compile(
    r'<input[^>]*name=["\']__VIEWSTATEGENERATOR["\'][^>]*value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

DESER_ERROR_PATTERNS = [
    (r"java\.io\.(InvalidClassException|StreamCorruptedException|ObjectStreamException)",
     "Java deserialization error"),
    (r"ClassNotFoundException.*readObject", "Java deserialization class not found"),
    (r"java\.io\.ObjectInputStream", "Java ObjectInputStream reference"),
    (r"org\.apache\.commons\.collections\.functors", "Apache Commons Collections (gadget chain)"),
    (r"ysoserial", "ysoserial reference"),
    (r"unserialize\(\).*error", "PHP unserialize error"),
    (r"__wakeup|__destruct|__toString", "PHP magic method reference"),
    (r"allowed_classes.*false", "PHP unserialize restricted classes"),
    (r"pickle\.(UnpicklingError|loads)", "Python pickle error"),
    (r"_pickle\.UnpicklingError", "Python C pickle error"),
    (r"cPickle", "Python cPickle reference"),
    (r"System\.Runtime\.Serialization", ".NET serialization error"),
    (r"ViewStateException", ".NET ViewState error"),
    (r"BinaryFormatter", ".NET BinaryFormatter reference"),
    (r"LosFormatter", ".NET LosFormatter reference"),
    (r"ObjectStateFormatter", ".NET ObjectStateFormatter reference"),
    (r"(de)?serializ(e|ation).*error", "Deserialization error message"),
]


def _looks_like_java_serial(value):
    if value.lower().startswith(JAVA_MAGIC):
        return True
    if value.startswith(JAVA_MAGIC_B64):
        return True
    try:
        decoded = base64.b64decode(value, validate=True)
        if decoded[:4] == bytes.fromhex(JAVA_MAGIC):
            return True
    except (ValueError, TypeError):
        pass
    return False


def _looks_like_php_serial(value):
    return any(p.search(value) for p in PHP_PATTERNS)


def _check_java_deserialization(session):
    target = session.config.target

    for url in list(session.crawled_urls)[:15]:
        parsed = urlparse(url)
        for param_name, values in parse_qs(parsed.query).items():
            for value in values:
                if _looks_like_java_serial(value):
                    _report_java_finding(session, url, param_name, value, "URL parameter")

    for cookie_name, cookie_value in session.session.cookies.items():
        if _looks_like_java_serial(cookie_value):
            _report_java_finding(session, target, cookie_name, cookie_value, "cookie")

    for url in list(session.crawled_urls)[:10]:
        resp = session.get(url)
        if not resp:
            continue
        for header_name in ("X-Session-Data", "X-Auth-Token", "Authorization"):
            header_val = resp.headers.get(header_name, "")
            if header_val and _looks_like_java_serial(header_val):
                _report_java_finding(session, url, header_name, header_val, "response header")


def _report_java_finding(session, url, param, value, location_type):
    short_value = value[:80] + "..." if len(value) > 80 else value
    curl_cmd = "curl -k -v '{}' 2>&1 | grep -i '{}'".format(url, param)

    session.add_finding(Finding(
        title="Java Serialized Object in {}: {}".format(location_type, param),
        severity=Severity.HIGH,
        description=(
            "Detected Java serialized data (magic bytes 0xACED0005 or Base64 'rO0AB') "
            "in {} '{}'. If the server deserializes this data using "
            "ObjectInputStream without validation, it may be vulnerable to Remote Code "
            "Execution via deserialization gadget chains (e.g., Apache Commons Collections)."
        ).format(location_type, param),
        evidence=(
            "URL: {}\nLocation: {} '{}'\nValue (truncated): {}\n"
            "Java serialization magic bytes detected."
        ).format(url, location_type, param, short_value),
        remediation=(
            "1. Avoid Java native serialization for untrusted data.\n"
            "2. Use JSON or other safe formats instead.\n"
            "3. If deserialization is required, use a look-ahead ObjectInputStream "
            "   that whitelists allowed classes.\n"
            "4. Remove vulnerable gadget libraries (Commons Collections < 4.1, etc.)."
        ),
        url=url,
        module="deserialization",
        cwe="CWE-502",
        confirmed=True,
        location="{}: {}".format(location_type, param),
        parameter=param,
        curl_command=curl_cmd,
        reproduction_steps=(
            "1. Identify Java serialized data in {} '{}' at {}\n"
            "2. The value begins with Java magic bytes (aced0005 / rO0AB)\n"
            "3. Use ysoserial to generate a payload for known gadget chains:\n"
            "   $ java -jar ysoserial.jar CommonsCollections1 'id' | base64\n"
            "4. Replace the {} value with the crafted payload\n"
            "5. Observe server behavior (RCE, errors, timing differences)"
        ).format(location_type, param, url, location_type),
        developer_fix=(
            "Replace Java native serialization with a safe alternative:\n\n"
            "// DANGEROUS - Do not use\n"
            "ObjectInputStream ois = new ObjectInputStream(input);\n"
            "Object obj = ois.readObject();  // arbitrary code execution\n\n"
            "// SAFE - Use JSON instead\n"
            "ObjectMapper mapper = new ObjectMapper();\n"
            "MyObject obj = mapper.readValue(input, MyObject.class);\n\n"
            "If you must deserialize, use a whitelist filter:\n"
            "ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(\n"
            "    \"com.myapp.model.*;!*\");\n"
            "ois.setObjectInputFilter(filter);"
        ),
        affected_component="Data deserialization",
        references=(
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests\n"
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html\n"
            "https://cwe.mitre.org/data/definitions/502.html"
        ),
        detection_method=(
            "Scanned {}s for Java serialization magic bytes "
            "(0xACED0005 hex / 'rO0AB' Base64). Found serialized Java object in '{}'."
        ).format(location_type, param),
    ))


def _check_php_deserialization(session):
    target = session.config.target

    for url in list(session.crawled_urls)[:15]:
        for param_name, values in parse_qs(urlparse(url).query).items():
            for value in values:
                if _looks_like_php_serial(value):
                    _report_php_finding(session, url, param_name, value, "URL parameter")

    for cookie_name, cookie_value in session.session.cookies.items():
        if _looks_like_php_serial(cookie_value):
            _report_php_finding(session, target, cookie_name, cookie_value, "cookie")
        try:
            decoded = base64.b64decode(cookie_value, validate=True).decode("utf-8", errors="ignore")
            if _looks_like_php_serial(decoded):
                _report_php_finding(session, target, cookie_name, decoded, "cookie (base64)")
        except (ValueError, TypeError):
            pass

    for form in session.forms[:10]:
        for inp in form.get("inputs", []):
            value, name = inp.get("value", ""), inp.get("name", "")
            if value and _looks_like_php_serial(value):
                _report_php_finding(
                    session, form.get("source_url", target),
                    name, value, "form hidden field",
                )


def _report_php_finding(session, url, param, value, location_type):
    short_value = value[:80] + "..." if len(value) > 80 else value

    session.add_finding(Finding(
        title="PHP Serialized Object in {}: {}".format(location_type, param),
        severity=Severity.HIGH,
        description=(
            "Detected PHP serialized data pattern in {} '{}'. "
            "If the application calls unserialize() on user-controlled data without "
            "restricting allowed classes, it may be vulnerable to PHP Object Injection, "
            "potentially leading to RCE via __wakeup/__destruct magic methods."
        ).format(location_type, param),
        evidence=(
            "URL: {}\nLocation: {} '{}'\nValue (truncated): {}\n"
            "PHP serialization pattern detected."
        ).format(url, location_type, param, short_value),
        remediation=(
            "1. Never unserialize() untrusted data.\n"
            "2. Use json_decode() instead.\n"
            "3. If unserialize is required, pass allowed_classes: false.\n"
            "4. Audit __wakeup, __destruct, __toString magic methods in all classes."
        ),
        url=url,
        module="deserialization",
        cwe="CWE-502",
        confirmed=True,
        location="{}: {}".format(location_type, param),
        parameter=param,
        curl_command="curl -k -v '{}'".format(url),
        reproduction_steps=(
            "1. Identify PHP serialized data in {} '{}' at {}\n"
            "2. The value matches PHP serialization patterns (O:, a:, s:, i:)\n"
            "3. Craft a PHP Object Injection payload targeting known gadget chains:\n"
            "   O:21:\"JDatabaseDriverMysqli\":0:{{}}\n"
            "4. Replace the parameter value and observe server behavior\n"
            "5. Use PHPGGC to generate framework-specific payloads"
        ).format(location_type, param, url),
        developer_fix=(
            "Replace unserialize() with JSON:\n\n"
            "// DANGEROUS\n"
            "$obj = unserialize($user_input);  // arbitrary object instantiation\n\n"
            "// SAFE\n"
            "$data = json_decode($user_input, true);\n\n"
            "// If unserialize is unavoidable, restrict classes:\n"
            "$obj = unserialize($input, ['allowed_classes' => false]);\n"
            "// Or whitelist:\n"
            "$obj = unserialize($input, ['allowed_classes' => ['SafeClass']]);"
        ),
        affected_component="PHP data deserialization",
        references=(
            "https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection\n"
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
        ),
        detection_method=(
            "Scanned {}s for PHP serialization patterns "
            "(O:N:\"class\", a:N:{{, s:N:\"\", i:N;). Found serialized PHP data in '{}'."
        ).format(location_type, param),
    ))


def _check_dotnet_viewstate(session):
    for url in list(session.crawled_urls)[:20]:
        resp = session.get(url)
        if not resp:
            continue

        body = resp.text or ""
        vs_match = DOTNET_VIEWSTATE_PATTERN.search(body)
        if not vs_match:
            continue

        viewstate = vs_match.group(1)
        generator_match = DOTNET_VIEWSTATE_GENERATOR.search(body)
        generator = generator_match.group(1) if generator_match else "N/A"

        is_encrypted, mac_enabled = True, True
        try:
            decoded = base64.b64decode(viewstate)
            if decoded[:2] == b"\xff\x01":
                is_encrypted = False
            if len(decoded) < 20:
                mac_enabled = False
        except (ValueError, TypeError):
            pass

        issues = []
        severity = Severity.INFO

        if not is_encrypted:
            issues.append("ViewState is not encrypted - data visible to client")
            severity = Severity.MEDIUM
        if not mac_enabled:
            issues.append("ViewState MAC validation may be disabled - tampering possible")
            severity = Severity.CRITICAL
        if viewstate and len(viewstate) > 10:
            issues.append("ViewState present - potential deserialization attack surface")
            if severity == Severity.INFO:
                severity = Severity.LOW

        if not issues:
            continue

        curl_cmd = "curl -k -s '{}' | grep -o '__VIEWSTATE[^\"]*\"[^\"]*\"'".format(url)

        session.add_finding(Finding(
            title="ASP.NET ViewState Deserialization Surface",
            severity=severity,
            description=(
                "The page at {} uses ASP.NET ViewState. "
                "{} "
                "If ViewState MAC validation is disabled or the machine key is compromised, "
                "an attacker can craft malicious ViewState payloads to achieve RCE via "
                "LosFormatter/ObjectStateFormatter deserialization."
            ).format(url, "Issues: {}.".format("; ".join(issues)) if issues else ""),
            evidence=(
                "URL: {}\n"
                "ViewState (first 100 chars): {}...\n"
                "ViewState Length: {} chars\n"
                "ViewStateGenerator: {}\n"
                "Encrypted: {}\n"
                "MAC likely enabled: {}"
            ).format(url, viewstate[:100], len(viewstate),
                     generator, is_encrypted, mac_enabled),
            remediation=(
                "1. Ensure ViewState MAC validation is enabled (default in .NET 4.5+).\n"
                "2. Encrypt ViewState with a strong machine key.\n"
                "3. Set ViewStateEncryptionMode=Always.\n"
                "4. Never store the machine key in web.config in source control.\n"
                "5. Consider eliminating ViewState where possible."
            ),
            url=url,
            module="deserialization",
            cwe="CWE-502",
            confirmed=not mac_enabled,
            location="__VIEWSTATE hidden field",
            curl_command=curl_cmd,
            reproduction_steps=(
                "1. Request {} and extract the __VIEWSTATE value\n"
                "2. Decode the base64 ViewState value\n"
                "3. If MAC is disabled, use ysoserial.net to craft a payload:\n"
                "   ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c 'cmd'\n"
                "4. Replace __VIEWSTATE value and submit the form\n"
                "5. Tool: https://github.com/0xACB/viewgen"
            ).format(url),
            developer_fix=(
                "Ensure ViewState protection in web.config:\n\n"
                "<system.web>\n"
                "  <pages viewStateEncryptionMode=\"Always\"\n"
                "         enableViewStateMac=\"true\" />\n"
                "  <machineKey validation=\"HMACSHA256\"\n"
                "             decryption=\"AES\"\n"
                "             validationKey=\"AutoGenerate,IsolateApps\"\n"
                "             decryptionKey=\"AutoGenerate,IsolateApps\" />\n"
                "</system.web>\n\n"
                "In .NET 4.5.2+, MAC validation cannot be disabled.\n"
                "Migrate to .NET 4.5.2+ if running an older version."
            ),
            affected_component="ASP.NET ViewState",
            references=(
                "https://owasp.org/www-community/attacks/Deserialization_of_untrusted_data\n"
                "https://swapneildash.medium.com/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817\n"
                "https://cwe.mitre.org/data/definitions/502.html"
            ),
            detection_method=(
                "Parsed HTML responses for __VIEWSTATE hidden fields. Decoded the "
                "base64 value to check for encryption and MAC validation status."
            ),
        ))


def _check_deserialization_errors(session):
    test_payloads = {
        "java_corrupt": base64.b64encode(bytes.fromhex("aced0005") + b"\x00" * 10).decode(),
        "php_corrupt": 'O:9:"FakeClass":0:{}',
        "php_array": 'a:1:{s:3:"key";s:5:"value";}',
    }

    for url in list(session.crawled_urls)[:10]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            continue

        for param_name in list(params.keys())[:3]:
            resp_baseline = session.get(url)
            if not resp_baseline:
                continue
            baseline_time = resp_baseline.elapsed.total_seconds()

            for payload_name, payload in test_payloads.items():
                new_params = dict(params)
                new_params[param_name] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))

                start = time.time()
                resp = session.get(test_url)
                elapsed = time.time() - start

                if not resp:
                    continue
                body = resp.text or ""

                # Check for deserialization error disclosure
                for pattern_str, error_desc in DESER_ERROR_PATTERNS:
                    match = re.search(pattern_str, body, re.IGNORECASE)
                    if not match:
                        continue

                    curl_cmd = "curl -k -s '{}' | grep -iE '{}'".format(test_url, pattern_str[:40])
                    session.add_finding(Finding(
                        title="Deserialization Error Disclosure: {}".format(error_desc),
                        severity=Severity.MEDIUM,
                        description=(
                            "Sending a {} payload to parameter '{}' "
                            "at {} triggered an error message revealing deserialization "
                            "internals: '{}'. This confirms the application "
                            "processes serialized data and may be vulnerable to "
                            "deserialization attacks."
                        ).format(payload_name, param_name, url, error_desc),
                        evidence=(
                            "URL: {}\nParameter: {}\nPayload Type: {}\n"
                            "Payload: {}\nError Pattern: {}\n"
                            "Matched Text: {}\nHTTP Status: {}"
                        ).format(test_url, param_name, payload_name,
                                 payload[:60], error_desc, match.group(), resp.status_code),
                        remediation=(
                            "1. Suppress detailed error messages in production.\n"
                            "2. Replace deserialization with safe alternatives (JSON).\n"
                            "3. Implement input validation before deserialization.\n"
                            "4. Use custom error pages that do not leak internals."
                        ),
                        url=url,
                        module="deserialization",
                        cwe="CWE-502",
                        confirmed=True,
                        location="Parameter: {}".format(param_name),
                        parameter=param_name,
                        payload=payload,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            "1. Send a {} payload to {}:\n"
                            "   {}\n"
                            "2. Observe the error response containing: {}\n"
                            "3. This confirms deserialization processing on the server\n"
                            "4. Run: {}"
                        ).format(payload_name, param_name, test_url, error_desc, curl_cmd),
                        developer_fix=(
                            "1. Disable verbose error messages in production:\n"
                            "   - PHP: display_errors = Off\n"
                            "   - Java: configure custom error pages in web.xml\n"
                            "   - .NET: <customErrors mode=\"On\" />\n\n"
                            "2. Replace deserialization:\n"
                            "   - Use json_decode() / JSON.parse() / ObjectMapper\n"
                            "   - Never deserialize untrusted input\n\n"
                            "3. If deserialization is required, whitelist allowed types."
                        ),
                        affected_component="Error handling / deserialization",
                        references=(
                            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html\n"
                            "https://cwe.mitre.org/data/definitions/502.html"
                        ),
                        detection_method=(
                            "Sent malformed serialized payloads ({}) to "
                            "parameter '{}' and matched error response against "
                            "known deserialization error patterns. Detected: {}."
                        ).format(payload_name, param_name, error_desc),
                    ))
                    break

                # Timing anomaly check
                time_diff = elapsed - baseline_time
                if time_diff > 3.0 and baseline_time < 2.0:
                    session.add_finding(Finding(
                        title="Deserialization Timing Anomaly: {}".format(param_name),
                        severity=Severity.LOW,
                        description=(
                            "Sending a {} payload to '{}' caused a "
                            "significant response time increase ({:.1f}s slower). "
                            "This may indicate server-side deserialization processing."
                        ).format(payload_name, param_name, time_diff),
                        evidence=(
                            "URL: {}\nParameter: {}\n"
                            "Baseline response time: {:.2f}s\n"
                            "Payload response time: {:.2f}s\n"
                            "Difference: {:.2f}s\nPayload type: {}"
                        ).format(url, param_name, baseline_time,
                                 elapsed, time_diff, payload_name),
                        remediation="Investigate the parameter for deserialization processing.",
                        url=url,
                        module="deserialization",
                        cwe="CWE-502",
                        confirmed=False,
                        location="Parameter: {}".format(param_name),
                        parameter=param_name,
                        payload=payload,
                        detection_method=(
                            "Compared response times between normal and serialized payloads "
                            "for parameter '{}'. Detected {:.1f}s anomaly."
                        ).format(param_name, time_diff),
                    ))


def _check_python_pickle(session):
    target = session.config.target

    for cookie_name, cookie_value in session.session.cookies.items():
        try:
            decoded = base64.b64decode(cookie_value, validate=True)
            for indicator in PYTHON_PICKLE_INDICATORS:
                if indicator not in decoded:
                    continue

                curl_cmd = "curl -k -v '{}' 2>&1 | grep -i 'set-cookie.*{}'".format(target, cookie_name)
                session.add_finding(Finding(
                    title="Python Pickle Object in Cookie: {}".format(cookie_name),
                    severity=Severity.HIGH,
                    description=(
                        "The cookie '{}' contains what appears to be Python "
                        "pickle serialized data. Python's pickle.loads() on untrusted data "
                        "allows arbitrary code execution via __reduce__ methods."
                    ).format(cookie_name),
                    evidence=(
                        "Cookie: {}\nValue (base64): {}...\n"
                        "Pickle indicator found: {!r}"
                    ).format(cookie_name, cookie_value[:80], indicator),
                    remediation=(
                        "1. Never use pickle.loads() on untrusted data.\n"
                        "2. Replace with JSON or other safe serialization.\n"
                        "3. Use hmac signing to verify data integrity before deserializing."
                    ),
                    url=target,
                    module="deserialization",
                    cwe="CWE-502",
                    confirmed=True,
                    location="Cookie: {}".format(cookie_name),
                    parameter=cookie_name,
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        "1. Decode the base64 value of cookie '{}'\n"
                        "2. Identify pickle protocol bytes in the decoded data\n"
                        "3. Craft a malicious pickle payload:\n"
                        "   import pickle, os\n"
                        "   class Exploit:\n"
                        "       def __reduce__(self):\n"
                        "           return (os.system, ('id',))\n"
                        "   payload = base64.b64encode(pickle.dumps(Exploit()))\n"
                        "4. Replace the cookie value and send the request"
                    ).format(cookie_name),
                    developer_fix=(
                        "Replace pickle with JSON:\n\n"
                        "# DANGEROUS\n"
                        "data = pickle.loads(base64.b64decode(cookie_value))  # RCE!\n\n"
                        "# SAFE\n"
                        "data = json.loads(base64.b64decode(cookie_value))\n\n"
                        "# If you need to sign data:\n"
                        "from itsdangerous import URLSafeSerializer\n"
                        "s = URLSafeSerializer(secret_key)\n"
                        "data = s.loads(cookie_value)  # signed + JSON"
                    ),
                    affected_component="Python session/cookie serialization",
                    references=(
                        "https://docs.python.org/3/library/pickle.html#restricting-globals\n"
                        "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
                    ),
                    detection_method=(
                        "Base64-decoded cookie '{}' and scanned for "
                        "Python pickle protocol bytes and opcodes."
                    ).format(cookie_name),
                ))
                break
        except (ValueError, TypeError):
            pass


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for insecure deserialization...")

    _check_java_deserialization(session)
    _check_php_deserialization(session)
    _check_python_pickle(session)
    _check_dotnet_viewstate(session)
    _check_deserialization_errors(session)
