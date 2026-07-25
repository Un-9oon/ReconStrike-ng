import base64
import json
import re
import hashlib
import hmac

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession


def _decode_jwt_part(part: str) -> dict | None:
    padding = 4 - len(part) % 4
    if padding != 4:
        part += "=" * padding
    try:
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)
    except Exception as e:
        logger.debug("jwt _decode_jwt_part: base64/JSON decode failed: %s", e)
        return None


def _extract_jwts(text: str) -> list[str]:
    pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
    return re.findall(pattern, text)


def _forge_none_alg(header_b64: str, payload_b64: str) -> str:
    header = _decode_jwt_part(header_b64)
    if not header:
        return ""
    header["alg"] = "none"
    new_header = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"{new_header}.{payload_b64}."


def _forge_weak_secret(header_b64: str, payload_b64: str) -> list[tuple[str, str]]:
    weak_secrets = [
        "secret", "password", "123456", "key", "test", "admin",
        "jwt_secret", "changeme", "mysecret", "default",
        "your-256-bit-secret", "shhhhh", "supersecret",
    ]
    results = []
    for secret in weak_secrets:
        msg = f"{header_b64}.{payload_b64}".encode()
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        results.append((secret, f"{header_b64}.{payload_b64}.{sig}"))
    return results


def run(session: ScanSession) -> None:
    print("\n[*] Checking for JWT vulnerabilities...")

    all_jwts = set()
    jwt_locations = {}

    for url in session.crawled_urls:
        resp = session.get(url)
        if not resp:
            continue

        for header_name in ["Authorization", "Set-Cookie", "X-Auth-Token", "X-Access-Token"]:
            header_val = resp.headers.get(header_name, "")
            tokens = _extract_jwts(header_val)
            for t in tokens:
                all_jwts.add(t)
                jwt_locations[t] = f"Header: {header_name} @ {url}"

        body_tokens = _extract_jwts(resp.text)
        for t in body_tokens:
            all_jwts.add(t)
            jwt_locations.setdefault(t, f"Body @ {url}")

    if not all_jwts:
        return

    for token in all_jwts:
        parts = token.split(".")
        if len(parts) < 2:
            continue

        header = _decode_jwt_part(parts[0])
        payload = _decode_jwt_part(parts[1])
        location = jwt_locations.get(token, "Unknown")
        token_url = location.split(" @ ")[-1] if " @ " in location else session.config.target

        if not header or not payload:
            continue

        alg = header.get("alg", "")
        if alg.lower() == "none":
            session.add_finding(Finding(
                title="JWT Algorithm Set to 'none'",
                severity=Severity.CRITICAL,
                description="A JWT token uses algorithm 'none', meaning the signature is not verified. Any user can forge tokens with arbitrary claims.",
                evidence=f"Location: {location}\nHeader: {json.dumps(header)}\nPayload: {json.dumps(payload)}",
                remediation="Always enforce a strong algorithm (RS256, ES256). Reject 'none' algorithm.",
                url=token_url,
                module="jwt",
                cwe="CWE-345",
                confirmed=True,
                location=f"JWT token found in {location}",
                curl_command=f"curl -k -H 'Authorization: Bearer {token[:60]}...' '{token_url}'",
                developer_fix=(
                    "Configure your JWT library to reject 'none' algorithm:\n"
                    "  Python (PyJWT): jwt.decode(token, key, algorithms=['RS256'])  # Explicit allowlist\n"
                    "  Node.js: jwt.verify(token, key, { algorithms: ['RS256'] })\n"
                    "  Java: .requireAlgorithm('RS256')"
                ),
                affected_component="JWT verification logic",
                references="https://cwe.mitre.org/data/definitions/345.html",
                detection_method="Extracted JWT tokens from responses/cookies and decoded without verification. Tested for: \'none\' algorithm acceptance, weak HMAC secrets via dictionary attack, sensitive data in payload, and missing/excessive expiration claims.",
            ))

        if alg in ("HS256", "HS384", "HS512"):
            none_token = _forge_none_alg(parts[0], parts[1])
            if none_token:
                for url in list(session.crawled_urls)[:5]:
                    resp = session.get(url, headers={"Authorization": f"Bearer {none_token}"})
                    if resp and resp.status_code == 200:
                        resp_orig = session.get(url, headers={"Authorization": f"Bearer {token}"})
                        if resp_orig and resp.text == resp_orig.text:
                            session.add_finding(Finding(
                                title="JWT 'none' Algorithm Accepted",
                                severity=Severity.CRITICAL,
                                description=(
                                    "The server accepts JWT tokens with algorithm set to 'none', completely bypassing "
                                    "signature verification. An attacker can forge any JWT claims (user ID, role, permissions) "
                                    "without knowing the secret key."
                                ),
                                evidence=(
                                    f"Original token accepted at: {url}\n"
                                    f"Forged 'none' alg token also accepted.\n"
                                    f"Forged token: {none_token[:80]}...\n"
                                    f"Both responses were identical (HTTP 200)."
                                ),
                                remediation="Reject 'none' algorithm in JWT verification. Use an explicit algorithm whitelist.",
                                url=url,
                                module="jwt",
                                cwe="CWE-345",
                                confirmed=True,
                                location=f"JWT verification at {url}",
                                payload=none_token[:100],
                                curl_command=f"curl -k -H 'Authorization: Bearer {none_token[:60]}...' '{url}'",
                                reproduction_steps=(
                                    f"1. Capture a valid JWT token from: {location}\n"
                                    f"2. Decode the header, change 'alg' to 'none'.\n"
                                    f"3. Remove the signature (third part).\n"
                                    f"4. Send the forged token to: {url}\n"
                                    f"5. The server accepts it as valid."
                                ),
                                developer_fix=(
                                    "Specify allowed algorithms explicitly:\n"
                                    "  Python: jwt.decode(token, secret, algorithms=['HS256'])\n"
                                    "  Node.js: jwt.verify(token, secret, { algorithms: ['HS256'] })\n"
                                    "  Never use jwt.decode() without algorithm validation."
                                ),
                                affected_component="JWT token verification",
                                references="https://portswigger.net/web-security/jwt",
                                detection_method="Extracted JWT tokens from responses/cookies and decoded without verification. Tested for: \'none\' algorithm acceptance, weak HMAC secrets via dictionary attack, sensitive data in payload, and missing/excessive expiration claims.",
                            ))
                            break

            for secret, forged in _forge_weak_secret(parts[0], parts[1]):
                if len(parts) >= 3 and parts[2]:
                    forged_sig = forged.split(".")[-1]
                    if forged_sig == parts[2]:
                        session.add_finding(Finding(
                            title=f"JWT Signed with Weak Secret: '{secret}'",
                            severity=Severity.CRITICAL,
                            description=(
                                f"The JWT token is signed with the easily guessable secret '{secret}'. "
                                f"An attacker can forge tokens with arbitrary claims (user ID, admin role) "
                                f"using this known secret."
                            ),
                            evidence=(
                                f"Secret Found: {secret}\n"
                                f"Location: {location}\n"
                                f"Algorithm: {alg}\n"
                                f"Payload: {json.dumps(payload)}"
                            ),
                            remediation="Use a strong, randomly generated secret (256+ bits). Rotate secrets regularly.",
                            url=token_url,
                            module="jwt",
                            cwe="CWE-321",
                            confirmed=True,
                            location=f"JWT token in {location}",
                            payload=f"Secret: {secret}",
                            reproduction_steps=(
                                f"1. Extract JWT from: {location}\n"
                                f"2. The token uses {alg} algorithm.\n"
                                f"3. Sign a forged payload with secret '{secret}'.\n"
                                f"4. The signature matches, confirming the weak secret.\n"
                                f"5. Use this to forge tokens with admin privileges."
                            ),
                            developer_fix=(
                                f"Replace the weak secret with a strong random key:\n"
                                f"  Python: import secrets; JWT_SECRET = secrets.token_hex(32)\n"
                                f"  Store in environment variable, not in code:\n"
                                f"    JWT_SECRET = os.environ['JWT_SECRET']\n"
                                f"  Or use asymmetric keys (RS256) instead of shared secrets."
                            ),
                            affected_component="JWT signing configuration",
                            references="https://portswigger.net/web-security/jwt",
                            detection_method="Extracted JWT tokens from responses/cookies and decoded without verification. Tested for: \'none\' algorithm acceptance, weak HMAC secrets via dictionary attack, sensitive data in payload, and missing/excessive expiration claims.",
                        ))
                        break

        if payload:
            sensitive_keys = ["password", "secret", "ssn", "credit_card", "api_key"]
            found_sensitive = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_keys)]
            if found_sensitive:
                session.add_finding(Finding(
                    title="JWT Contains Sensitive Data",
                    severity=Severity.MEDIUM,
                    description=(
                        f"JWT payload contains sensitive fields: {', '.join(found_sensitive)}. "
                        f"JWT payloads are only base64-encoded, not encrypted - anyone can decode and read them."
                    ),
                    evidence=f"Sensitive fields: {found_sensitive}\nLocation: {location}",
                    remediation="Don't store sensitive data in JWT payloads. Use encrypted JWTs (JWE) if needed.",
                    url=token_url,
                    module="jwt",
                    cwe="CWE-311",
                    confirmed=True,
                    location=f"JWT payload in {location}",
                    developer_fix=(
                        "Remove sensitive fields from JWT payload. Store them server-side instead:\n"
                        "  # Instead of putting password/secrets in JWT:\n"
                        "  payload = {'user_id': user.id, 'role': user.role, 'exp': expiry}\n"
                        "  # Fetch sensitive data server-side using user_id"
                    ),
                    references="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                    detection_method="Extracted JWT tokens from responses/cookies and decoded without verification. Tested for: \'none\' algorithm acceptance, weak HMAC secrets via dictionary attack, sensitive data in payload, and missing/excessive expiration claims.",
                ))

            exp = payload.get("exp")
            if exp and isinstance(exp, (int, float)):
                import time
                if exp - time.time() > 86400 * 30:
                    session.add_finding(Finding(
                        title="JWT Has Excessive Expiration",
                        severity=Severity.LOW,
                        description=f"JWT token has expiration more than 30 days from now. Long-lived tokens increase the window for token theft and abuse.",
                        evidence=f"Expiration timestamp: {exp} (>30 days)\nLocation: {location}",
                        remediation="Use short-lived tokens (15-60 minutes) with refresh token rotation.",
                        url=token_url,
                        module="jwt",
                        cwe="CWE-613",
                        confirmed=True,
                        location=f"JWT 'exp' claim in {location}",
                        developer_fix="Set short expiration: payload['exp'] = datetime.utcnow() + timedelta(minutes=15). Use refresh tokens for longer sessions.",
                        detection_method="Extracted JWT tokens from responses/cookies and decoded without verification. Tested for: \'none\' algorithm acceptance, weak HMAC secrets via dictionary attack, sensitive data in payload, and missing/excessive expiration claims.",
                    ))
            elif "exp" not in payload:
                session.add_finding(Finding(
                    title="JWT Missing Expiration Claim",
                    severity=Severity.MEDIUM,
                    description="JWT token has no 'exp' claim, meaning it never expires. A stolen token grants permanent access.",
                    evidence=f"No 'exp' field in payload.\nLocation: {location}\nPayload keys: {list(payload.keys())}",
                    remediation="Always include an 'exp' claim in JWT tokens.",
                    url=token_url,
                    module="jwt",
                    cwe="CWE-613",
                    confirmed=True,
                    location=f"JWT payload in {location}",
                    developer_fix="Add expiration to JWT payload:\n  payload['exp'] = datetime.utcnow() + timedelta(hours=1)\n  payload['iat'] = datetime.utcnow()",
                    references="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                    detection_method="Extracted JWT tokens from responses/cookies and decoded without verification. Tested for: \'none\' algorithm acceptance, weak HMAC secrets via dictionary attack, sensitive data in payload, and missing/excessive expiration claims.",
                ))
