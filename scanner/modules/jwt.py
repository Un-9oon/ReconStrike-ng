import base64
import json
import re
import hashlib
import hmac
import time

from scanner.log import logger
from scanner.core import Finding, Severity, ScanSession

_DETECTION = (
    "Extracted JWT tokens from responses/cookies and decoded without verification. "
    "Tested for: 'none' algorithm acceptance, weak HMAC secrets via dictionary attack, "
    "sensitive data in payload, and missing/excessive expiration claims."
)


def _decode_jwt_part(part):
    padding = 4 - len(part) % 4
    if padding != 4:
        part += "=" * padding
    try:
        return json.loads(base64.urlsafe_b64decode(part))
    except (ValueError, TypeError, KeyError) as e:
        logger.debug("jwt _decode_jwt_part: base64/JSON decode failed: %s", e)
        return None


def _extract_jwts(text):
    return re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', text)


def _forge_none_alg(header_b64, payload_b64):
    header = _decode_jwt_part(header_b64)
    if not header:
        return ""
    header["alg"] = "none"
    new_header = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return "{}.{}.".format(new_header, payload_b64)


def _forge_weak_secret(header_b64, payload_b64):
    weak_secrets = [
        "secret", "password", "123456", "key", "test", "admin",
        "jwt_secret", "changeme", "mysecret", "default",
        "your-256-bit-secret", "shhhhh", "supersecret",
    ]
    results = []
    msg = "{}.{}".format(header_b64, payload_b64).encode()
    for secret in weak_secrets:
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        results.append((secret, "{}.{}.{}".format(header_b64, payload_b64, sig)))
    return results


def run(session: ScanSession) -> None:
    logger.info("\n[*] Checking for JWT vulnerabilities...")

    all_jwts = set()
    jwt_locations = {}

    for url in session.crawled_urls:
        resp = session.get(url)
        if not resp:
            continue

        for header_name in ["Authorization", "Set-Cookie", "X-Auth-Token", "X-Access-Token"]:
            for t in _extract_jwts(resp.headers.get(header_name, "")):
                all_jwts.add(t)
                jwt_locations[t] = "Header: {} @ {}".format(header_name, url)

        for t in _extract_jwts(resp.text):
            all_jwts.add(t)
            jwt_locations.setdefault(t, "Body @ {}".format(url))

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

        # alg: none already set in the token
        if alg.lower() == "none":
            session.add_finding(Finding(
                title="JWT Algorithm Set to 'none'",
                severity=Severity.CRITICAL,
                description="A JWT token uses algorithm 'none', meaning the signature is not verified. Any user can forge tokens with arbitrary claims.",
                evidence="Location: {}\nHeader: {}\nPayload: {}".format(location, json.dumps(header), json.dumps(payload)),
                remediation="Always enforce a strong algorithm (RS256, ES256). Reject 'none' algorithm.",
                url=token_url,
                module="jwt",
                cwe="CWE-345",
                confirmed=True,
                location="JWT token found in {}".format(location),
                curl_command="curl -k -H 'Authorization: Bearer {}...' '{}'".format(token[:60], token_url),
                developer_fix=(
                    "Configure your JWT library to reject 'none' algorithm:\n"
                    "  Python (PyJWT): jwt.decode(token, key, algorithms=['RS256'])  # Explicit allowlist\n"
                    "  Node.js: jwt.verify(token, key, { algorithms: ['RS256'] })\n"
                    "  Java: .requireAlgorithm('RS256')"
                ),
                affected_component="JWT verification logic",
                references="https://cwe.mitre.org/data/definitions/345.html",
                detection_method=_DETECTION,
            ))

        # Test none-alg bypass on HMAC tokens
        if alg in ("HS256", "HS384", "HS512"):
            none_token = _forge_none_alg(parts[0], parts[1])
            if none_token:
                for url in list(session.crawled_urls)[:5]:
                    resp = session.get(url, headers={"Authorization": "Bearer {}".format(none_token)})
                    if not resp or resp.status_code != 200:
                        continue
                    resp_orig = session.get(url, headers={"Authorization": "Bearer {}".format(token)})
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
                                "Original token accepted at: {url}\n"
                                "Forged 'none' alg token also accepted.\n"
                                "Forged token: {tok}...\n"
                                "Both responses were identical (HTTP 200)."
                            ).format(url=url, tok=none_token[:80]),
                            remediation="Reject 'none' algorithm in JWT verification. Use an explicit algorithm whitelist.",
                            url=url,
                            module="jwt",
                            cwe="CWE-345",
                            confirmed=True,
                            location="JWT verification at {}".format(url),
                            payload=none_token[:100],
                            curl_command="curl -k -H 'Authorization: Bearer {}...' '{}'".format(none_token[:60], url),
                            reproduction_steps=(
                                "1. Capture a valid JWT token from: {loc}\n"
                                "2. Decode the header, change 'alg' to 'none'.\n"
                                "3. Remove the signature (third part).\n"
                                "4. Send the forged token to: {url}\n"
                                "5. The server accepts it as valid."
                            ).format(loc=location, url=url),
                            developer_fix=(
                                "Specify allowed algorithms explicitly:\n"
                                "  Python: jwt.decode(token, secret, algorithms=['HS256'])\n"
                                "  Node.js: jwt.verify(token, secret, { algorithms: ['HS256'] })\n"
                                "  Never use jwt.decode() without algorithm validation."
                            ),
                            affected_component="JWT token verification",
                            references="https://portswigger.net/web-security/jwt",
                            detection_method=_DETECTION,
                        ))
                        break

            # Weak secret brute-force
            for secret, forged in _forge_weak_secret(parts[0], parts[1]):
                if len(parts) >= 3 and parts[2]:
                    if forged.split(".")[-1] == parts[2]:
                        session.add_finding(Finding(
                            title="JWT Signed with Weak Secret: '{}'".format(secret),
                            severity=Severity.CRITICAL,
                            description=(
                                "The JWT token is signed with the easily guessable secret '{}'. "
                                "An attacker can forge tokens with arbitrary claims (user ID, admin role) "
                                "using this known secret."
                            ).format(secret),
                            evidence=(
                                "Secret Found: {secret}\nLocation: {loc}\n"
                                "Algorithm: {alg}\nPayload: {pay}"
                            ).format(secret=secret, loc=location, alg=alg, pay=json.dumps(payload)),
                            remediation="Use a strong, randomly generated secret (256+ bits). Rotate secrets regularly.",
                            url=token_url,
                            module="jwt",
                            cwe="CWE-321",
                            confirmed=True,
                            location="JWT token in {}".format(location),
                            payload="Secret: {}".format(secret),
                            reproduction_steps=(
                                "1. Extract JWT from: {loc}\n"
                                "2. The token uses {alg} algorithm.\n"
                                "3. Sign a forged payload with secret '{secret}'.\n"
                                "4. The signature matches, confirming the weak secret.\n"
                                "5. Use this to forge tokens with admin privileges."
                            ).format(loc=location, alg=alg, secret=secret),
                            developer_fix=(
                                "Replace the weak secret with a strong random key:\n"
                                "  Python: import secrets; JWT_SECRET = secrets.token_hex(32)\n"
                                "  Store in environment variable, not in code:\n"
                                "    JWT_SECRET = os.environ['JWT_SECRET']\n"
                                "  Or use asymmetric keys (RS256) instead of shared secrets."
                            ),
                            affected_component="JWT signing configuration",
                            references="https://portswigger.net/web-security/jwt",
                            detection_method=_DETECTION,
                        ))
                        break

        if not payload:
            continue

        # Sensitive data in payload
        sensitive_keys = ["password", "secret", "ssn", "credit_card", "api_key"]
        found_sensitive = [k for k in payload if any(s in k.lower() for s in sensitive_keys)]
        if found_sensitive:
            session.add_finding(Finding(
                title="JWT Contains Sensitive Data",
                severity=Severity.MEDIUM,
                description=(
                    "JWT payload contains sensitive fields: {}. "
                    "JWT payloads are only base64-encoded, not encrypted - anyone can decode and read them."
                ).format(", ".join(found_sensitive)),
                evidence="Sensitive fields: {}\nLocation: {}".format(found_sensitive, location),
                remediation="Don't store sensitive data in JWT payloads. Use encrypted JWTs (JWE) if needed.",
                url=token_url,
                module="jwt",
                cwe="CWE-311",
                confirmed=True,
                location="JWT payload in {}".format(location),
                developer_fix=(
                    "Remove sensitive fields from JWT payload. Store them server-side instead:\n"
                    "  # Instead of putting password/secrets in JWT:\n"
                    "  payload = {'user_id': user.id, 'role': user.role, 'exp': expiry}\n"
                    "  # Fetch sensitive data server-side using user_id"
                ),
                references="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                detection_method=_DETECTION,
            ))

        # Expiration checks
        exp = payload.get("exp")
        if exp and isinstance(exp, (int, float)):
            if exp - time.time() > 86400 * 30:
                session.add_finding(Finding(
                    title="JWT Has Excessive Expiration",
                    severity=Severity.LOW,
                    description="JWT token has expiration more than 30 days from now. Long-lived tokens increase the window for token theft and abuse.",
                    evidence="Expiration timestamp: {} (>30 days)\nLocation: {}".format(exp, location),
                    remediation="Use short-lived tokens (15-60 minutes) with refresh token rotation.",
                    url=token_url,
                    module="jwt",
                    cwe="CWE-613",
                    confirmed=True,
                    location="JWT 'exp' claim in {}".format(location),
                    developer_fix="Set short expiration: payload['exp'] = datetime.utcnow() + timedelta(minutes=15). Use refresh tokens for longer sessions.",
                    detection_method=_DETECTION,
                ))
        elif "exp" not in payload:
            session.add_finding(Finding(
                title="JWT Missing Expiration Claim",
                severity=Severity.MEDIUM,
                description="JWT token has no 'exp' claim, meaning it never expires. A stolen token grants permanent access.",
                evidence="No 'exp' field in payload.\nLocation: {}\nPayload keys: {}".format(location, list(payload.keys())),
                remediation="Always include an 'exp' claim in JWT tokens.",
                url=token_url,
                module="jwt",
                cwe="CWE-613",
                confirmed=True,
                location="JWT payload in {}".format(location),
                developer_fix="Add expiration to JWT payload:\n  payload['exp'] = datetime.utcnow() + timedelta(hours=1)\n  payload['iat'] = datetime.utcnow()",
                references="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                detection_method=_DETECTION,
            ))
