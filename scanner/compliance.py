from scanner.core import ScanSession, Severity, Finding
from scanner.log import logger

OWASP_TOP_10 = {
    "A01:2021 Broken Access Control": {
        "modules": ["idor", "directory", "misconfig"],
        "cwes": ["CWE-639", "CWE-548", "CWE-284", "CWE-601", "CWE-942"],
    },
    "A02:2021 Cryptographic Failures": {
        "modules": ["ssl", "headers"],
        "cwes": ["CWE-319", "CWE-326", "CWE-295", "CWE-311", "CWE-614"],
    },
    "A03:2021 Injection": {
        "modules": ["sqli", "xss", "cmdi", "ssti", "lfi", "xxe"],
        "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-1336", "CWE-98", "CWE-611"],
    },
    "A04:2021 Insecure Design": {
        "modules": ["auth", "csrf"],
        "cwes": ["CWE-352", "CWE-521", "CWE-204"],
    },
    "A05:2021 Security Misconfiguration": {
        "modules": ["misconfig", "headers", "directory", "fingerprint"],
        "cwes": ["CWE-16", "CWE-200", "CWE-1021", "CWE-644", "CWE-113"],
    },
    "A06:2021 Vulnerable Components": {
        "modules": ["fingerprint"],
        "cwes": ["CWE-1104"],
    },
    "A07:2021 Auth Failures": {
        "modules": ["auth", "jwt"],
        "cwes": ["CWE-798", "CWE-345", "CWE-321", "CWE-613"],
    },
    "A08:2021 Data Integrity Failures": {
        "modules": ["jwt", "csrf"],
        "cwes": ["CWE-345", "CWE-352"],
    },
    "A09:2021 Logging & Monitoring": {"modules": [], "cwes": []},
    "A10:2021 SSRF": {"modules": ["ssrf"], "cwes": ["CWE-918"]},
}

PCI_DSS_CHECKS = {
    "6.5.1 Injection Flaws": ["sqli", "cmdi", "lfi", "ssti", "xxe"],
    "6.5.2 Buffer Overflows": [],
    "6.5.3 Insecure Cryptographic Storage": ["ssl", "info"],
    "6.5.4 Insecure Communications": ["ssl", "headers"],
    "6.5.5 Improper Error Handling": ["info"],
    "6.5.7 XSS": ["xss"],
    "6.5.8 Improper Access Control": ["idor", "directory", "auth"],
    "6.5.9 CSRF": ["csrf"],
    "6.5.10 Broken Auth": ["auth", "jwt"],
}


def generate_compliance_report(session: ScanSession) -> dict:
    report = {"owasp": {}, "pci_dss": {}}

    for category, info in OWASP_TOP_10.items():
        findings = [f for f in session.findings
                    if f.module in info["modules"] or f.cwe in info["cwes"]]
        max_sev = max((f.severity for f in findings), key=lambda s: s.score, default=None)
        report["owasp"][category] = {
            "status": "FAIL" if findings else "PASS",
            "finding_count": len(findings),
            "max_severity": max_sev.value if max_sev else None,
            "findings": findings,
        }

    for requirement, modules in PCI_DSS_CHECKS.items():
        findings = [f for f in session.findings if f.module in modules]
        report["pci_dss"][requirement] = {
            "status": "FAIL" if findings else "PASS",
            "finding_count": len(findings),
            "findings": findings,
        }

    return report


def print_compliance_summary(report: dict):
    logger.info("=" * 60)
    logger.info("OWASP TOP 10 (2021) COMPLIANCE")
    logger.info("=" * 60)

    passed = 0
    for category, data in report["owasp"].items():
        if data["status"] == "PASS":
            passed += 1
            logger.info("  PASS  %s", category)
        else:
            logger.info("  FAIL  %s (%d findings, max: %s)", category, data["finding_count"], data["max_severity"])

    logger.info("Score: %d/%d categories passing", passed, len(report["owasp"]))

    logger.info("=" * 60)
    logger.info("PCI DSS v4.0 RELEVANT CHECKS")
    logger.info("=" * 60)

    pci_passed = 0
    for req, data in report["pci_dss"].items():
        if data["status"] == "PASS":
            pci_passed += 1
            logger.info("  PASS  %s", req)
        else:
            logger.info("  FAIL  %s (%d findings)", req, data["finding_count"])

    logger.info("Score: %d/%d requirements passing", pci_passed, len(report["pci_dss"]))


def generate_compliance_html(report: dict, target: str) -> str:
    import html as html_mod
    severity_colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706",
        "LOW": "#2563eb", "INFO": "#6b7280",
    }

    owasp_rows = ""
    for category, data in report["owasp"].items():
        status_color = "#22c55e" if data["status"] == "PASS" else "#dc2626"
        sev_html = ""
        if data["max_severity"]:
            sev_color = severity_colors.get(data["max_severity"], "#6b7280")
            sev_html = '<span style="color:{};font-weight:600;">{}</span>'.format(sev_color, data["max_severity"])
        owasp_rows += """
        <tr>
            <td style="color:{};font-weight:700;">{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
        </tr>""".format(status_color, data['status'], html_mod.escape(category), data['finding_count'], sev_html)

    pci_rows = ""
    for req, data in report["pci_dss"].items():
        status_color = "#22c55e" if data["status"] == "PASS" else "#dc2626"
        pci_rows += """
        <tr>
            <td style="color:{};font-weight:700;">{}</td>
            <td>{}</td>
            <td>{}</td>
        </tr>""".format(status_color, data['status'], html_mod.escape(req), data['finding_count'])

    owasp_pass = sum(1 for d in report["owasp"].values() if d["status"] == "PASS")
    pci_pass = sum(1 for d in report["pci_dss"].values() if d["status"] == "PASS")

    table_style = 'style="width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;"'
    header_style = 'style="background:#0f172a;"'
    th_base = 'style="padding:10px 16px;text-align:left;color:#94a3b8;'

    return """
    <h2 class="section-title">OWASP Top 10 (2021) Compliance &mdash; {owasp_pass}/{owasp_total}</h2>
    <div style="overflow-x:auto;margin-bottom:24px;">
    <table {table_style}>
        <thead><tr {header_style}>
            <th {th}width:60px;">Status</th>
            <th {th}">Category</th>
            <th {th}width:80px;">Findings</th>
            <th {th}width:80px;">Severity</th>
        </tr></thead>
        <tbody>{owasp_rows}</tbody>
    </table></div>

    <h2 class="section-title">PCI DSS v4.0 Compliance &mdash; {pci_pass}/{pci_total}</h2>
    <div style="overflow-x:auto;margin-bottom:24px;">
    <table {table_style}>
        <thead><tr {header_style}>
            <th {th}width:60px;">Status</th>
            <th {th}">Requirement</th>
            <th {th}width:80px;">Findings</th>
        </tr></thead>
        <tbody>{pci_rows}</tbody>
    </table></div>
    """.format(
        owasp_pass=owasp_pass, owasp_total=len(report['owasp']),
        pci_pass=pci_pass, pci_total=len(report['pci_dss']),
        table_style=table_style, header_style=header_style,
        th=th_base, owasp_rows=owasp_rows, pci_rows=pci_rows,
    )
