import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger


WEAK_CIPHERS = {"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"}


def run(session: ScanSession) -> None:
    parsed = urlparse(session.config.target)
    hostname = parsed.netloc.split(":")[0]

    if parsed.scheme != "https":
        session.add_finding(Finding(
            title="Site Not Using HTTPS",
            severity=Severity.HIGH,
            description="The target is served over plain HTTP. All traffic including credentials, session tokens, and user data is transmitted unencrypted and can be intercepted.",
            evidence=f"URL scheme: {parsed.scheme}\nTarget: {session.config.target}",
            remediation="Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS.",
            url=session.config.target,
            module="ssl",
            cwe="CWE-319",
            confirmed=True,
            location="Web server protocol configuration",
            curl_command=f"curl -I '{session.config.target}'",
            reproduction_steps=(
                f"1. The target URL uses http:// scheme: {session.config.target}\n"
                f"2. All traffic is unencrypted and visible to network attackers."
            ),
            developer_fix=(
                "1. Obtain a TLS certificate (free via Let's Encrypt):\n"
                "   certbot --nginx -d yourdomain.com\n"
                "2. Redirect HTTP to HTTPS:\n"
                "   Nginx: return 301 https://$host$request_uri;\n"
                "   Apache: Redirect permanent / https://yourdomain.com/\n"
                "3. Add HSTS header: Strict-Transport-Security: max-age=31536000"
            ),
            affected_component="Web server TLS configuration",
            references="https://letsencrypt.org/getting-started/",
            detection_method="Performed TLS handshake analysis checking: protocol version (TLS 1.2+ required), certificate validity and expiration, hostname verification, and cipher suite strength. Uses Python\'s ssl module for direct socket-level inspection.",
        ))
        return

    logger.info("\n[*] Checking SSL/TLS configuration...")
    port = parsed.port or 443
    test_cmd = f"openssl s_client -connect {hostname}:{port}"

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=session.config.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

                if protocol in ("TLSv1", "TLSv1.1"):
                    session.add_finding(Finding(
                        title=f"Deprecated TLS Version: {protocol}",
                        severity=Severity.HIGH,
                        description=f"Server negotiated {protocol} which is deprecated and has known vulnerabilities (BEAST, POODLE).",
                        evidence=f"Negotiated protocol: {protocol}\nHost: {hostname}:{port}",
                        remediation="Disable TLSv1.0 and TLSv1.1. Use TLSv1.2 or TLSv1.3 only.",
                        url=session.config.target,
                        module="ssl",
                        cwe="CWE-326",
                        confirmed=True,
                        location=f"TLS configuration on {hostname}:{port}",
                        curl_command=test_cmd,
                        developer_fix=(
                            f"Nginx: ssl_protocols TLSv1.2 TLSv1.3;\n"
                            f"Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
                            f"HAProxy: ssl-min-ver TLSv1.2"
                        ),
                        affected_component="TLS protocol configuration",
                        references="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                        detection_method="Performed TLS handshake analysis checking: protocol version (TLS 1.2+ required), certificate validity and expiration, hostname verification, and cipher suite strength. Uses Python\'s ssl module for direct socket-level inspection.",
                    ))

                if cert:
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (not_after - datetime.now(timezone.utc)).days

                    if days_left < 0:
                        session.add_finding(Finding(
                            title="SSL Certificate Expired",
                            severity=Severity.CRITICAL,
                            description=f"The SSL certificate expired {abs(days_left)} days ago. Browsers will show security warnings and users cannot safely connect.",
                            evidence=f"Expiry: {cert['notAfter']} ({abs(days_left)} days ago)\nHost: {hostname}",
                            remediation="Renew the SSL certificate immediately.",
                            url=session.config.target,
                            module="ssl",
                            cwe="CWE-295",
                            confirmed=True,
                            location=f"SSL certificate on {hostname}:{port}",
                            curl_command=f"echo | {test_cmd} 2>/dev/null | openssl x509 -noout -dates",
                            developer_fix="Renew certificate: certbot renew\nOr: certbot certonly --nginx -d yourdomain.com",
                            affected_component="SSL certificate",
                            detection_method="Performed TLS handshake analysis checking: protocol version (TLS 1.2+ required), certificate validity and expiration, hostname verification, and cipher suite strength. Uses Python\'s ssl module for direct socket-level inspection.",
                        ))
                    elif days_left < 30:
                        session.add_finding(Finding(
                            title="SSL Certificate Expiring Soon",
                            severity=Severity.MEDIUM,
                            description=f"The SSL certificate expires in {days_left} days. If not renewed, the site will become inaccessible via HTTPS.",
                            evidence=f"Expiry: {cert['notAfter']} ({days_left} days remaining)\nHost: {hostname}",
                            remediation="Renew the SSL certificate before expiration. Set up auto-renewal.",
                            url=session.config.target,
                            module="ssl",
                            cwe="CWE-295",
                            confirmed=True,
                            location=f"SSL certificate on {hostname}:{port}",
                            developer_fix="Set up auto-renewal: certbot renew --deploy-hook 'systemctl reload nginx'\nAdd to crontab: 0 0 * * * certbot renew",
                            affected_component="SSL certificate",
                            detection_method="Performed TLS handshake analysis checking: protocol version (TLS 1.2+ required), certificate validity and expiration, hostname verification, and cipher suite strength. Uses Python\'s ssl module for direct socket-level inspection.",
                        ))

                    subject = dict(x[0] for x in cert.get("subject", []))
                    cert_names = [subject.get("commonName", "")] + [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                    if not any(_match_hostname(hostname, n) for n in cert_names):
                        session.add_finding(Finding(
                            title="SSL Certificate Hostname Mismatch",
                            severity=Severity.HIGH,
                            description=f"The certificate does not match the target hostname '{hostname}'. Browsers will reject the connection.",
                            evidence=f"Hostname: {hostname}\nCertificate names: {cert_names}",
                            remediation="Obtain a certificate that covers the target hostname.",
                            url=session.config.target,
                            module="ssl",
                            cwe="CWE-295",
                            confirmed=True,
                            location=f"SSL certificate CN/SAN on {hostname}",
                            developer_fix=f"Reissue certificate with correct hostname:\n  certbot certonly --nginx -d {hostname}",
                            affected_component="SSL certificate subject",
                            detection_method="Performed TLS handshake analysis checking: protocol version (TLS 1.2+ required), certificate validity and expiration, hostname verification, and cipher suite strength. Uses Python\'s ssl module for direct socket-level inspection.",
                        ))

                if cipher:
                    cipher_name = cipher[0]
                    for weak in WEAK_CIPHERS:
                        if weak in cipher_name.upper():
                            session.add_finding(Finding(
                                title=f"Weak SSL Cipher: {cipher_name}",
                                severity=Severity.HIGH,
                                description=f"Server negotiated weak cipher suite '{cipher_name}'. This may allow decryption of traffic.",
                                evidence=f"Cipher: {cipher_name}\nProtocol: {protocol}\nHost: {hostname}:{port}",
                                remediation="Disable weak cipher suites. Use only strong ciphers (AES-GCM, ChaCha20).",
                                url=session.config.target,
                                module="ssl",
                                cwe="CWE-326",
                                confirmed=True,
                                location=f"Cipher suite on {hostname}:{port}",
                                developer_fix=(
                                    "Nginx: ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384';\n"
                                    "Apache: SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
                                ),
                                affected_component="TLS cipher suite configuration",
                                detection_method="Performed TLS handshake analysis checking: protocol version (TLS 1.2+ required), certificate validity and expiration, hostname verification, and cipher suite strength. Uses Python\'s ssl module for direct socket-level inspection.",
                            ))
                            break

    except ssl.SSLCertVerificationError as e:
        session.add_finding(Finding(
            title="SSL Certificate Verification Failed",
            severity=Severity.HIGH,
            description="The SSL certificate could not be verified. This may indicate a self-signed, expired, or improperly configured certificate.",
            evidence=str(e),
            remediation="Use a valid certificate from a trusted CA (e.g., Let's Encrypt).",
            url=session.config.target,
            module="ssl",
            cwe="CWE-295",
            confirmed=True,
            location=f"SSL certificate on {hostname}:{port}",
            developer_fix="Obtain a trusted certificate: certbot certonly --nginx -d yourdomain.com",
            affected_component="SSL certificate chain",
            detection_method="Performed TLS handshake analysis checking: protocol version (TLS 1.2+ required), certificate validity and expiration, hostname verification, and cipher suite strength. Uses Python\'s ssl module for direct socket-level inspection.",
        ))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.warning(f" [!] SSL check failed: {e}")

    _check_deprecated_protocols(session, hostname, port)


def _check_deprecated_protocols(session: ScanSession, hostname: str, port: int):
    for proto_name, proto_const in [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = proto_const
            ctx.maximum_version = proto_const
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    session.add_finding(Finding(
                        title=f"Server Accepts Deprecated {proto_name}",
                        severity=Severity.MEDIUM,
                        description=f"Server still accepts connections via deprecated {proto_name}. This protocol has known vulnerabilities.",
                        evidence=f"Successfully connected to {hostname}:{port} with {proto_name}",
                        remediation=f"Disable {proto_name} on the server. Use TLSv1.2+ only.",
                        url=session.config.target,
                        module="ssl",
                        cwe="CWE-326",
                        confirmed=True,
                        location=f"TLS protocol support on {hostname}:{port}",
                        curl_command=f"openssl s_client -connect {hostname}:{port} -{proto_name.lower().replace('.', '_')}",
                        developer_fix=(
                            f"Nginx: ssl_protocols TLSv1.2 TLSv1.3;\n"
                            f"Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1"
                        ),
                        affected_component="TLS protocol configuration",
                        detection_method="Performed TLS handshake analysis checking: protocol version (TLS 1.2+ required), certificate validity and expiration, hostname verification, and cipher suite strength. Uses Python\'s ssl module for direct socket-level inspection.",
                    ))
        except (ssl.SSLError, socket.error, OSError):
            pass


def _match_hostname(hostname: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")
    return hostname == pattern
