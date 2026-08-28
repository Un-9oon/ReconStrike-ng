import os
from datetime import datetime, timezone

from fpdf import FPDF

from scanner.core import ScanSession, Severity, Finding
from scanner import __version__

SEVERITY_COLORS = {
    "CRITICAL": (139, 0, 0),
    "HIGH": (255, 0, 0),
    "MEDIUM": (255, 255, 0),
    "LOW": (0, 128, 0),
    "INFO": (107, 114, 128),
}

PASS_COLOR = (34, 197, 94)
FAIL_COLOR = (220, 38, 38)


def _sanitize(text: str) -> str:
    return (text
            .replace("—", "-")
            .replace("–", "-")
            .replace("‘", "'")
            .replace("’", "'")
            .replace("“", '"')
            .replace("”", '"')
            .replace("…", "...")
            .replace("•", "*")
            .encode("latin-1", errors="replace").decode("latin-1"))


class ReconStrikePDF(FPDF):
    def __init__(self, target: str):
        super().__init__()
        self.target = target
        self.set_auto_page_break(auto=True, margin=20)

    def cell(self, w=None, h=None, text="", *args, **kwargs):
        return super().cell(w, h, _sanitize(str(text)) if text else text, *args, **kwargs)

    def multi_cell(self, w, h=None, text="", *args, **kwargs):
        return super().multi_cell(w, h, _sanitize(str(text)) if text else text, *args, **kwargs)

    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(120, 120, 120)
        super().cell(0, 6, f"ReconStrike v{__version__} - Security Assessment Report", align="L")
        super().cell(0, 6, _sanitize(self.target[:60]), align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        super().cell(0, 10, f"Page {self.page_no()}/{{nb}} - Confidential - For authorized use only", align="C")

    def _section_title(self, title: str):
        self.ln(6)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(15, 23, 42)
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(59, 130, 246)
        self.set_line_width(0.6)
        self.line(10, self.get_y(), 80, self.get_y())
        self.set_line_width(0.2)
        self.ln(4)

    def _subsection_title(self, title: str):
        self.ln(3)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(30, 41, 59)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def _severity_badge(self, severity_str: str, x: float = None, y: float = None):
        color = SEVERITY_COLORS.get(severity_str, (107, 114, 128))
        if x is not None:
            self.set_xy(x, y)
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        w = self.get_string_width(severity_str) + 6
        self.cell(w, 5, severity_str, fill=True, align="C")
        self.set_text_color(0, 0, 0)

    def _key_value(self, key: str, value: str):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 100, 100)
        self.cell(40, 6, key + ":", align="L")
        self.set_font("Helvetica", "", 10)
        self.set_text_color(15, 23, 42)
        self.cell(0, 6, value, new_x="LMARGIN", new_y="NEXT")

    def _stat_box(self, x, y, w, h, label, value, color=(59, 130, 246)):
        self.set_xy(x, y)
        self.set_draw_color(*color)
        self.set_line_width(0.4)
        self.rect(x, y, w, h)
        self.set_line_width(0.2)
        self.set_xy(x, y + 3)
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(*color)
        self.cell(w, 10, str(value), align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_xy(x, y + 14)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(100, 100, 100)
        self.cell(w, 5, label, align="C")

    def _table_header(self, columns: list[tuple[str, float]]):
        self.set_fill_color(241, 245, 249)
        self.set_text_color(71, 85, 105)
        self.set_font("Helvetica", "B", 9)
        for col_name, col_width in columns:
            self.cell(col_width, 7, col_name, border=1, fill=True, align="C")
        self.ln()

    def _table_row(self, values: list[tuple[str, float]], fill: bool = False):
        if fill:
            self.set_fill_color(248, 250, 252)
        self.set_text_color(30, 41, 59)
        self.set_font("Helvetica", "", 9)
        for val, w in values:
            self.cell(w, 6, val[:int(w / 1.8)], border=1, fill=fill, align="L")
        self.ln()
def generate_pdf_report(session: ScanSession, output_path: str, compliance_data: dict = None) -> str:
    output_path = os.path.realpath(output_path)
    findings = sorted(session.findings, key=lambda f: f.severity.score, reverse=True)
    duration = (session.end_time or 0) - (session.start_time or 0)
    now = datetime.now(timezone.utc)

    severity_counts = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}

    risk_score = _calculate_risk_score(findings)
    risk_label = _risk_label(risk_score)

    pdf = ReconStrikePDF(session.config.target)
    pdf.alias_nb_pages()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(15, 23, 42)
    pdf.ln(15)
    pdf.cell(0, 15, "Security Assessment Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, "ReconStrike — Advanced Web & Network Vulnerability Assessment", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    pdf.set_draw_color(59, 130, 246)
    pdf.set_line_width(0.8)
    pdf.line(60, pdf.get_y(), 150, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(10)

    pdf._key_value("Target", session.config.target)
    pdf._key_value("Date", now.strftime("%B %d, %Y at %H:%M UTC"))
    pdf._key_value("Duration", f"{duration:.0f} seconds")
    pdf._key_value("URLs Scanned", str(len(session.crawled_urls)))
    pdf._key_value("Forms Found", str(len(session.forms)))
    pdf._key_value("Modules Run", str(len(session.config.scan_modules)))
    pdf._key_value("Total Findings", f"{len(findings)} ({sum(1 for f in findings if f.confirmed)} confirmed)")
    pdf.ln(4)

    y = pdf.get_y()
    box_w = 36
    gap = 2
    start_x = 10
    stats = [
        ("CRITICAL", severity_counts["CRITICAL"], SEVERITY_COLORS["CRITICAL"]),
        ("HIGH", severity_counts["HIGH"], SEVERITY_COLORS["HIGH"]),
        ("MEDIUM", severity_counts["MEDIUM"], SEVERITY_COLORS["MEDIUM"]),
        ("LOW", severity_counts["LOW"], SEVERITY_COLORS["LOW"]),
        ("INFO", severity_counts["INFO"], SEVERITY_COLORS["INFO"]),
    ]
    for i, (label, value, color) in enumerate(stats):
        pdf._stat_box(start_x + i * (box_w + gap), y, box_w, 22, label, value, color)
    pdf.set_y(y + 28)
    pdf.ln(2)
    risk_color = _risk_color(risk_score)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*risk_color)
    pdf.cell(0, 10, f"Overall Risk Score: {risk_score}/100 ({risk_label})", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)

    # Risk bar
    bar_x = 40
    bar_w = 130
    bar_y = pdf.get_y() + 2
    pdf.set_fill_color(226, 232, 240)
    pdf.rect(bar_x, bar_y, bar_w, 5, style="F")
    fill_w = bar_w * risk_score / 100
    pdf.set_fill_color(*risk_color)
    pdf.rect(bar_x, bar_y, fill_w, 5, style="F")
    pdf.ln(12)
    pdf._section_title("1. Executive Summary")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(51, 65, 85)

    total = len(findings)
    confirmed = sum(1 for f in findings if f.confirmed)
    modules_run = len(session.config.scan_modules)

    summary_text = (
        f"A comprehensive security assessment was performed against {session.config.target} "
        f"on {now.strftime('%B %d, %Y')}. The assessment scanned {len(session.crawled_urls)} URLs "
        f"and {len(session.forms)} forms using {modules_run} security testing modules over "
        f"{duration:.0f} seconds.\n\n"
        f"The assessment identified {total} security findings ({confirmed} confirmed), "
        f"resulting in an overall risk score of {risk_score}/100 ({risk_label}). "
    )

    if severity_counts["CRITICAL"]:
        summary_text += (
            f"\n\nCRITICAL: {severity_counts['CRITICAL']} critical vulnerability(ies) require "
            f"immediate remediation as they pose a direct risk of system compromise or data breach."
        )
    if severity_counts["HIGH"]:
        summary_text += (
            f"\n\nHIGH: {severity_counts['HIGH']} high-severity issue(s) should be addressed "
            f"as a priority in the next remediation cycle."
        )
    if not severity_counts["CRITICAL"] and not severity_counts["HIGH"]:
        summary_text += (
            "\n\nNo critical or high-severity vulnerabilities were identified. "
            "The application demonstrates a reasonable security baseline."
        )

    pdf.multi_cell(0, 5, summary_text)
    pdf.ln(4)
    pdf._section_title("2. Findings Overview")

    columns = [("Severity", 22), ("Title", 80), ("Module", 22), ("CWE", 20), ("Status", 20), ("URL", 26)]
    pdf._table_header(columns)

    for i, f in enumerate(findings):
        if pdf.get_y() > 260:
            pdf.add_page()
            pdf._table_header(columns)
        sev_color = SEVERITY_COLORS.get(f.severity.value, (0, 0, 0))
        pdf.set_text_color(*sev_color)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(22, 6, f.severity.value, border=1, align="C")
        pdf.set_text_color(30, 41, 59)
        pdf.set_font("Helvetica", "", 9)
        title_trunc = f.title[:48] + "..." if len(f.title) > 48 else f.title
        pdf.cell(80, 6, title_trunc, border=1)
        pdf.cell(22, 6, f.module[:12], border=1, align="C")
        pdf.cell(20, 6, f.cwe if f.cwe else "-", border=1, align="C")
        if f.confirmed:
            pdf.set_text_color(*PASS_COLOR)
            pdf.cell(20, 6, "Confirmed", border=1, align="C")
        else:
            pdf.set_text_color(*SEVERITY_COLORS["MEDIUM"])
            pdf.cell(20, 6, "Tentative", border=1, align="C")
        pdf.set_text_color(100, 100, 100)
        pdf.set_font("Helvetica", "", 7)
        from urllib.parse import urlparse
        url_short = urlparse(f.url).path[:16] or "/"
        pdf.cell(26, 6, url_short, border=1, align="C")
        pdf.ln()
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(0, 0, 0)
    pdf._section_title("3. Detailed Findings")

    for idx, f in enumerate(findings, 1):
        if pdf.get_y() > 220:
            pdf.add_page()

        # Finding header bar
        sev_color = SEVERITY_COLORS.get(f.severity.value, (0, 0, 0))
        y_start = pdf.get_y()
        pdf.set_fill_color(*sev_color)
        pdf.rect(10, y_start, 3, 8, style="F")

        pdf.set_xy(15, y_start)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(15, 23, 42)
        conf_str = " [CONFIRMED]" if f.confirmed else " [TENTATIVE]"
        pdf.cell(0, 8, f"{idx}. [{f.severity.value}] {f.title}{conf_str}", new_x="LMARGIN", new_y="NEXT")

        # Meta line
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(100, 100, 100)
        meta_parts = [f"Module: {f.module}"]
        if f.cwe:
            meta_parts.append(f"CWE: {f.cwe}")
        meta_parts.append(f"URL: {f.url[:70]}")
        pdf.cell(0, 5, " | ".join(meta_parts), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

        # Description
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(0, 5, "DESCRIPTION", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(51, 65, 85)
        pdf.multi_cell(0, 4.5, f.description)
        pdf.ln(2)

        # Vulnerability details
        if f.location or f.parameter or f.payload:
            if pdf.get_y() > 250:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(71, 85, 105)
            pdf.cell(0, 5, "VULNERABILITY DETAILS", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(51, 65, 85)
            if f.location:
                pdf._key_value("Location", f.location[:90])
            if f.parameter:
                pdf._key_value("Parameter", f.parameter)
            if f.payload:
                pdf._key_value("Payload", f.payload[:90])
            if f.request_method:
                pdf._key_value("Method", f.request_method)
            if f.response_status:
                pdf._key_value("Status", str(f.response_status))
            if f.affected_component:
                pdf._key_value("Component", f.affected_component[:90])
            pdf.ln(2)

        # Detection method
        if f.detection_method:
            if pdf.get_y() > 250:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(99, 102, 241)
            pdf.cell(0, 5, "HOW IT WAS FOUND", new_x="LMARGIN", new_y="NEXT")
            pdf.set_fill_color(245, 243, 255)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(67, 56, 202)
            pdf.multi_cell(0, 4, f.detection_method, fill=True)
            pdf.ln(2)

        # Evidence
        if pdf.get_y() > 250:
            pdf.add_page()
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(0, 5, "EVIDENCE", new_x="LMARGIN", new_y="NEXT")
        pdf.set_fill_color(241, 245, 249)
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(30, 41, 59)
        evidence_text = f.evidence[:500]
        evidence_lines = evidence_text.split("\n")
        for line in evidence_lines[:10]:
            if pdf.get_y() > 270:
                pdf.add_page()
            pdf.cell(0, 4, "  " + line[:100], fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

        # cURL command
        if f.curl_command:
            if pdf.get_y() > 250:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(71, 85, 105)
            pdf.cell(0, 5, "REPRODUCE WITH CURL", new_x="LMARGIN", new_y="NEXT")
            pdf.set_fill_color(240, 253, 244)
            pdf.set_font("Courier", "", 7)
            pdf.set_text_color(22, 101, 52)
            for line in f.curl_command.split("\n")[:3]:
                pdf.cell(0, 4, "  " + line[:110], fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

        # Reproduction steps
        if f.reproduction_steps:
            if pdf.get_y() > 240:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(71, 85, 105)
            pdf.cell(0, 5, "REPRODUCTION STEPS", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(51, 65, 85)
            for line in f.reproduction_steps.split("\n")[:8]:
                if pdf.get_y() > 270:
                    pdf.add_page()
                pdf.cell(0, 4, "  " + line[:100], new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

        # Developer fix
        if f.developer_fix:
            if pdf.get_y() > 230:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(34, 139, 34)
            pdf.cell(0, 5, "DEVELOPER FIX GUIDE", new_x="LMARGIN", new_y="NEXT")
            pdf.set_fill_color(240, 253, 244)
            pdf.set_font("Courier", "", 7)
            pdf.set_text_color(22, 101, 52)
            for line in f.developer_fix.split("\n")[:12]:
                if pdf.get_y() > 270:
                    pdf.add_page()
                pdf.cell(0, 4, "  " + line[:110], fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

        # Remediation
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(0, 5, "REMEDIATION", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(34, 139, 34)
        pdf.multi_cell(0, 4.5, f.remediation)

        # References
        if f.references:
            pdf.ln(1)
            pdf.set_font("Helvetica", "I", 7)
            pdf.set_text_color(100, 100, 200)
            pdf.cell(0, 4, "Refs: " + f.references[:120], new_x="LMARGIN", new_y="NEXT")

        pdf.ln(4)
    if compliance_data:
        pdf.add_page()
        pdf._section_title("4. Compliance Mapping")

        # OWASP
        pdf._subsection_title("OWASP Top 10 (2021)")
        owasp_cols = [("Status", 18), ("Category", 90), ("Findings", 22), ("Max Severity", 30)]
        pdf._table_header(owasp_cols)

        owasp_pass = 0
        for category, data in compliance_data["owasp"].items():
            if pdf.get_y() > 260:
                pdf.add_page()
                pdf._table_header(owasp_cols)
            status = data["status"]
            color = PASS_COLOR if status == "PASS" else FAIL_COLOR
            pdf.set_text_color(*color)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(18, 6, status, border=1, align="C")
            pdf.set_text_color(30, 41, 59)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(90, 6, category[:55], border=1)
            pdf.cell(22, 6, str(data["finding_count"]), border=1, align="C")
            sev = data.get("max_severity") or "-"
            if sev != "-":
                sev_c = SEVERITY_COLORS.get(sev, (0, 0, 0))
                pdf.set_text_color(*sev_c)
                pdf.set_font("Helvetica", "B", 9)
            pdf.cell(30, 6, sev, border=1, align="C")
            pdf.ln()
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 9)
            if status == "PASS":
                owasp_pass += 1

        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 10)
        owasp_total = len(compliance_data["owasp"])
        score_color = PASS_COLOR if owasp_pass >= 7 else FAIL_COLOR if owasp_pass <= 3 else SEVERITY_COLORS["MEDIUM"]
        pdf.set_text_color(*score_color)
        pdf.cell(0, 7, f"OWASP Score: {owasp_pass}/{owasp_total} categories passing", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # PCI DSS
        pdf._subsection_title("PCI DSS v4.0")
        pci_cols = [("Status", 18), ("Requirement", 112), ("Findings", 22)]
        pdf._table_header(pci_cols)

        pci_pass = 0
        for req, data in compliance_data["pci_dss"].items():
            if pdf.get_y() > 260:
                pdf.add_page()
                pdf._table_header(pci_cols)
            status = data["status"]
            color = PASS_COLOR if status == "PASS" else FAIL_COLOR
            pdf.set_text_color(*color)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(18, 6, status, border=1, align="C")
            pdf.set_text_color(30, 41, 59)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(112, 6, req, border=1)
            pdf.cell(22, 6, str(data["finding_count"]), border=1, align="C")
            pdf.ln()
            if status == "PASS":
                pci_pass += 1

        pdf.ln(3)
        pci_total = len(compliance_data["pci_dss"])
        score_color = PASS_COLOR if pci_pass >= 7 else FAIL_COLOR if pci_pass <= 3 else SEVERITY_COLORS["MEDIUM"]
        pdf.set_text_color(*score_color)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, f"PCI DSS Score: {pci_pass}/{pci_total} requirements passing", new_x="LMARGIN", new_y="NEXT")
    summary_num = "4" if not compliance_data else "5"
    pdf.add_page()
    pdf._section_title(f"{summary_num}. Findings Summary")

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(51, 65, 85)
    total = len(findings)
    confirmed = sum(1 for f in findings if f.confirmed)
    pdf.multi_cell(0, 5, (
        f"This section provides a consolidated view of all {total} findings "
        f"({confirmed} confirmed, {total - confirmed} tentative) discovered during the assessment."
    ))
    pdf.ln(4)

    sum_cols = [("No.", 10), ("Severity", 22), ("Title", 75), ("Module", 22), ("Status", 18), ("Location", 43)]
    pdf._table_header(sum_cols)

    for i, f in enumerate(findings, 1):
        if pdf.get_y() > 260:
            pdf.add_page()
            pdf._table_header(sum_cols)
        sev_color = SEVERITY_COLORS.get(f.severity.value, (0, 0, 0))
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(10, 6, str(i), border=1, align="C")
        pdf.set_text_color(*sev_color)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(22, 6, f.severity.value, border=1, align="C")
        pdf.set_text_color(30, 41, 59)
        pdf.set_font("Helvetica", "", 8)
        title_t = f.title[:45] + "..." if len(f.title) > 45 else f.title
        pdf.cell(75, 6, title_t, border=1)
        pdf.cell(22, 6, f.module[:12], border=1, align="C")
        if f.confirmed:
            pdf.set_text_color(*PASS_COLOR)
        else:
            pdf.set_text_color(*SEVERITY_COLORS["MEDIUM"])
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(18, 6, "Confirmed" if f.confirmed else "Tentative", border=1, align="C")
        pdf.set_text_color(100, 100, 100)
        pdf.set_font("Helvetica", "", 7)
        loc = (f.location[:25] if f.location else f.url[:25])
        pdf.cell(43, 6, loc, border=1)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)

    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, f"Total Findings: {total}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sum(1 for f in findings if f.severity.value == sev_name)
        if count:
            pdf.set_text_color(*SEVERITY_COLORS[sev_name])
            pdf.cell(0, 6, f"  {sev_name}: {count}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, f"  Confirmed: {confirmed} | Tentative: {total - confirmed}", new_x="LMARGIN", new_y="NEXT")
    section_num = str(int(summary_num) + 1)
    pdf.add_page()
    pdf._section_title(f"{section_num}. Methodology")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(51, 65, 85)
    pdf.multi_cell(0, 5, (
        f"This assessment was conducted using ReconStrike v{__version__}, an automated vulnerability "
        "assessment framework. The tool employs the following techniques to ensure accuracy "
        "and eliminate false positives:\n\n"
        "Baseline Comparison: For all injection tests (SQLi, XSS, SSTI, LFI, Command Injection, "
        "XXE, SSRF), the scanner first captures a baseline response without any payload, then "
        "compares it to the injected response. Only NEW indicators are flagged.\n\n"
        "Double Verification: Time-based blind injection checks require 2/2 successful delay "
        "measurements with window-based timing validation.\n\n"
        "Structural Validation: Content-based detections require structural markers (e.g., "
        "/etc/passwd must contain 3+ properly formatted lines, not just a regex match).\n\n"
        "Context-Aware Analysis: XSS detection uses context-specific payloads and filters "
        "reflections in safe contexts (HTML comments, textarea, title tags).\n\n"
        "Per-Object Inspection: Cookie security flags are checked per-cookie using the response "
        "object, not by parsing raw headers.\n\n"
        "Soft-404 Detection: Directory scanning detects custom 404 pages that return HTTP 200 "
        "and filters them using content similarity analysis."
    ))

    pdf.ln(5)
    pdf._subsection_title("Modules Executed")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(51, 65, 85)
    for mod in session.config.scan_modules:
        pdf.cell(0, 5, f"  - {mod}", new_x="LMARGIN", new_y="NEXT")
    next_num = int(section_num) + 1
    pdf.ln(8)
    pdf._section_title(f"{next_num}. Disclaimer")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(51, 65, 85)
    pdf.multi_cell(0, 5, (
        "This report is generated by an automated security assessment tool and is intended "
        "for authorized security testing purposes only. While the tool employs multiple "
        "verification techniques to minimize false positives, automated scanning cannot "
        "replace a thorough manual penetration test.\n\n"
        "The findings in this report represent the state of the target at the time of "
        "scanning. Vulnerabilities may have been introduced or remediated since the scan. "
        "It is recommended to re-scan after applying fixes to verify remediation.\n\n"
        "This report is confidential and should be handled according to your organization's "
        "information security policies."
    ))

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True, mode=0o700)
    pdf.output(output_path)
    os.chmod(output_path, 0o600)
    return output_path
def _calculate_risk_score(findings: list) -> int:
    if not findings:
        return 0
    max_score = 0
    scores = {"CRITICAL": 100, "HIGH": 74, "MEDIUM": 49, "LOW": 24, "INFO": 0}
    for f in findings:
        base = scores[f.severity.value]
        if f.confirmed and base > 0:
            bump = {"HIGH": 74, "MEDIUM": 49, "LOW": 24}.get(f.severity.value, base)
            if bump == base and f.severity.value != "CRITICAL":
                pass
        score = base
        if score > max_score:
            max_score = score
    return max_score
def _risk_label(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"
def _risk_color(score: int) -> tuple:
    if score >= 75:
        return (139, 0, 0)
    if score >= 50:
        return (255, 0, 0)
    if score >= 25:
        return (255, 255, 0)
    if score > 0:
        return (0, 128, 0)
    return (107, 114, 128)
