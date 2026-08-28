from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger


CORS_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]


def run(session: ScanSession) -> None:
    logger.info("\n[*] Testing for CORS misconfiguration...")

    for url in list(session.crawled_urls)[:20]:
        for origin in CORS_ORIGINS:
            resp = session.get(url, headers={"Origin": origin})
            if not resp:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if not acao:
                continue

            curl_cmd = "curl -k -H 'Origin: {origin}' -I '{url}'".format(origin=origin, url=url)

            if acao == "*" and acac.lower() == "true":
                _report(session, url, origin, acao, acac, curl_cmd,
                        title="CORS: Wildcard with Credentials",
                        severity=Severity.HIGH,
                        desc=(
                            "The server returns Access-Control-Allow-Origin: * with "
                            "Access-Control-Allow-Credentials: true. This is a browser-rejected "
                            "combination but indicates a fundamental CORS misconfiguration."
                        ),
                        fix=(
                            "Never set Access-Control-Allow-Origin: * when credentials are needed.\n"
                            "Use a whitelist of trusted origins:\n"
                            "  allowed = ['https://app.example.com']\n"
                            "  origin = request.headers.get('Origin')\n"
                            "  if origin in allowed:\n"
                            "      response.headers['Access-Control-Allow-Origin'] = origin\n"
                            "      response.headers['Access-Control-Allow-Credentials'] = 'true'"
                        ))
                return

            if acao == origin and origin not in ("null",):
                if acac.lower() == "true":
                    _report(session, url, origin, acao, acac, curl_cmd,
                            title="CORS: Arbitrary Origin Reflected with Credentials",
                            severity=Severity.HIGH,
                            desc=(
                                "The server reflects the attacker-controlled Origin header '{origin}' "
                                "in Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials: true. "
                                "This allows any website to make credentialed cross-origin requests and "
                                "read the response, enabling data theft from authenticated users."
                            ).format(origin=origin),
                            fix=(
                                "Validate Origin against a whitelist of trusted domains:\n"
                                "  ALLOWED_ORIGINS = {'https://app.example.com', 'https://admin.example.com'}\n"
                                "  origin = request.headers.get('Origin', '')\n"
                                "  if origin in ALLOWED_ORIGINS:\n"
                                "      response.headers['Access-Control-Allow-Origin'] = origin\n"
                                "      response.headers['Access-Control-Allow-Credentials'] = 'true'\n"
                                "Do NOT reflect the Origin header without validation."
                            ))
                    return
                else:
                    _report(session, url, origin, acao, acac, curl_cmd,
                            title="CORS: Arbitrary Origin Reflected",
                            severity=Severity.MEDIUM,
                            desc=(
                                "The server reflects the attacker-controlled Origin header '{origin}' "
                                "but does not set Allow-Credentials. This limits the impact but "
                                "indicates the CORS policy is misconfigured."
                            ).format(origin=origin),
                            fix="Validate Origin against a strict whitelist of trusted domains before reflecting it.")
                    return

            if acao == "null" and origin == "null":
                _report(session, url, origin, acao, acac, curl_cmd,
                        title="CORS: Null Origin Allowed",
                        severity=Severity.MEDIUM,
                        desc=(
                            "The server trusts the 'null' origin. An attacker can trigger a null origin "
                            "using sandboxed iframes or data: URIs to bypass CORS restrictions."
                        ),
                        fix="Remove 'null' from your CORS origin whitelist. Never trust the null origin.",
                        extra_steps=(
                            "1. Send a request with Origin: null\n"
                            "2. Server responds with Access-Control-Allow-Origin: null\n"
                            "3. Attacker uses <iframe sandbox> to trigger null origin.\n"
                            "4. Run: {curl_cmd}"
                        ).format(curl_cmd=curl_cmd))
                return


def _report(session, url, origin, acao, acac, curl_cmd, title, severity, desc, fix,
            extra_steps=None):
    evidence = "URL: {url}\nOrigin Sent: {origin}\nAccess-Control-Allow-Origin: {acao}".format(
        url=url, origin=origin, acao=acao)
    if acac:
        evidence += "\nAccess-Control-Allow-Credentials: {acac}".format(acac=acac)

    steps = extra_steps or (
        "1. Send a request to {url} with header: Origin: {origin}\n"
        "2. Observe the response headers.\n"
        "3. Run: {curl_cmd}"
    ).format(url=url, origin=origin, curl_cmd=curl_cmd)

    session.add_finding(Finding(
        title=title,
        severity=severity,
        description=desc,
        evidence=evidence,
        remediation="Validate the Origin header against a strict whitelist of trusted domains.",
        url=url,
        module="cors",
        cwe="CWE-942",
        confirmed=True,
        location="CORS headers on {url}".format(url=url),
        curl_command=curl_cmd,
        reproduction_steps=steps,
        developer_fix=fix,
        affected_component="CORS configuration",
        references="https://portswigger.net/web-security/cors",
        detection_method="Sent requests with crafted Origin headers (evil.com, attacker.com, null) and inspected Access-Control-Allow-Origin and Access-Control-Allow-Credentials response headers. Misconfigurations like wildcard or origin reflection with credentials are flagged.",
    ))
