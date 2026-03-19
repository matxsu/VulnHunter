import os
import io
from datetime import datetime
from app.models.scan import ScanResult, Severity

# Severity color mapping
SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def generate_markdown(result: ScanResult) -> str:
    """Generate a full Markdown report from a ScanResult."""
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration = result.duration_seconds
    duration_str = f"{duration:.1f}s" if duration else "N/A"

    lines += [
        "# VulnHunter — Security Assessment Report",
        "",
        f"> Generated: {now}  ",
        f"> Scan ID: `{result.scan_id}`  ",
        f"> Target: `{result.target_url}`  ",
        f"> Status: **{result.status.value.upper()}**  ",
        f"> Duration: {duration_str}  ",
        f"> Pages crawled: {result.pages_crawled}  ",
        f"> Requests sent: {result.requests_sent}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    counts = result.severity_counts
    total = len(result.vulnerabilities)

    if total == 0:
        lines.append("✅ **No vulnerabilities detected** during this scan.")
    else:
        lines += [
            f"**{total} vulnerabilities** were identified during the automated scan.",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in SEVERITY_ORDER:
            c = counts.get(sev.value, 0)
            if c > 0:
                lines.append(f"| {SEVERITY_EMOJI[sev]} {sev.value.capitalize()} | {c} |")

    lines += ["", "---", "", "## Vulnerability Details", ""]

    if not result.vulnerabilities:
        lines.append("_No vulnerabilities found._")
    else:
        sorted_vulns = sorted(
            result.vulnerabilities,
            key=lambda v: SEVERITY_ORDER.index(v.severity)
        )
        for i, vuln in enumerate(sorted_vulns, 1):
            emoji = SEVERITY_EMOJI.get(vuln.severity, "⚪")
            lines += [
                f"### {i}. {emoji} {vuln.vuln_type.value}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **ID** | `{vuln.id}` |",
                f"| **Severity** | {vuln.severity.value.capitalize()} |",
                f"| **CVSS Score** | {vuln.cvss_score} |",
                f"| **URL** | `{vuln.url}` |",
            ]
            if vuln.parameter:
                lines.append(f"| **Parameter** | `{vuln.parameter}` |")
            if vuln.payload:
                safe_payload = vuln.payload.replace("|", "\\|")
                lines.append(f"| **Payload** | `{safe_payload}` |")
            lines += [
                "",
                f"**CVSS Vector:** `{vuln.cvss_vector}`",
                "",
                "**Description:**",
                "",
                f"> {vuln.description}",
                "",
            ]
            if vuln.evidence:
                lines += [
                    "**Evidence:**",
                    "",
                    f"```\n{vuln.evidence}\n```",
                    "",
                ]
            lines += [
                "**Remediation:**",
                "",
                f"{vuln.remediation}",
                "",
                "---",
                "",
            ]

    lines += [
        "## Scan Metadata",
        "",
        f"- **Scanner:** VulnHunter v1.0",
        f"- **Started:** {result.started_at.isoformat() if result.started_at else 'N/A'}",
        f"- **Completed:** {result.completed_at.isoformat() if result.completed_at else 'N/A'}",
        f"- **Duration:** {duration_str}",
        "",
        "---",
        "*This report was generated automatically by VulnHunter. "
        "Manual verification is recommended before acting on findings.*",
    ]

    return "\n".join(lines)


def generate_pdf(result: ScanResult) -> bytes:
    """Generate PDF report using reportlab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table,
            TableStyle, HRFlowable, PageBreak
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
    except ImportError:
        raise RuntimeError("reportlab is required for PDF generation: pip install reportlab")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    style_normal = styles["Normal"]
    style_normal.fontName = "Helvetica"
    style_normal.fontSize = 10

    style_h1 = ParagraphStyle(
        "H1", parent=styles["Heading1"],
        fontSize=20, spaceAfter=12,
        textColor=colors.HexColor("#0f172a"),
    )
    style_h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=14, spaceAfter=8, spaceBefore=12,
        textColor=colors.HexColor("#1e40af"),
    )
    style_h3 = ParagraphStyle(
        "H3", parent=styles["Heading3"],
        fontSize=12, spaceAfter=6, spaceBefore=8,
        textColor=colors.HexColor("#374151"),
    )
    style_code = ParagraphStyle(
        "Code", parent=style_normal,
        fontName="Courier", fontSize=8,
        backColor=colors.HexColor("#f3f4f6"),
        textColor=colors.HexColor("#111827"),
        leftIndent=10, rightIndent=10,
        spaceBefore=4, spaceAfter=4,
    )

    SEV_COLORS = {
        "critical": colors.HexColor("#dc2626"),
        "high":     colors.HexColor("#ea580c"),
        "medium":   colors.HexColor("#ca8a04"),
        "low":      colors.HexColor("#2563eb"),
        "info":     colors.HexColor("#6b7280"),
    }

    story = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration = result.duration_seconds
    duration_str = f"{duration:.1f}s" if duration else "N/A"

    # Title
    story.append(Paragraph("VulnHunter", style_h1))
    story.append(Paragraph("Automated Security Assessment Report", style_h2))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1e40af")))
    story.append(Spacer(1, 12))

    # Metadata table
    meta_data = [
        ["Generated", now],
        ["Scan ID", result.scan_id],
        ["Target", result.target_url],
        ["Status", result.status.value.upper()],
        ["Duration", duration_str],
        ["Pages Crawled", str(result.pages_crawled)],
        ["Requests Sent", str(result.requests_sent)],
    ]
    meta_table = Table(meta_data, colWidths=[4*cm, 13*cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    # Summary
    story.append(Paragraph("Executive Summary", style_h2))
    total = len(result.vulnerabilities)
    counts = result.severity_counts

    if total == 0:
        story.append(Paragraph("✅ No vulnerabilities detected during this scan.", style_normal))
    else:
        story.append(Paragraph(f"<b>{total} vulnerabilities</b> identified.", style_normal))
        story.append(Spacer(1, 8))

        sev_data = [["Severity", "Count", "Risk Level"]]
        for sev in SEVERITY_ORDER:
            c = counts.get(sev.value, 0)
            if c > 0:
                sev_data.append([sev.value.capitalize(), str(c), sev.value.upper()])

        sev_table = Table(sev_data, colWidths=[5*cm, 3*cm, 9*cm])
        sev_style = [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
        ]
        for row_i, row in enumerate(sev_data[1:], 1):
            sev_name = row[0].lower()
            bg = SEV_COLORS.get(sev_name, colors.HexColor("#f8fafc"))
            sev_style.append(("BACKGROUND", (0, row_i), (-1, row_i), bg))
            sev_style.append(("TEXTCOLOR", (0, row_i), (-1, row_i), colors.white))
        sev_table.setStyle(TableStyle(sev_style))
        story.append(sev_table)

    story.append(Spacer(1, 20))
    story.append(Paragraph("Vulnerability Details", style_h2))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 8))

    sorted_vulns = sorted(
        result.vulnerabilities,
        key=lambda v: SEVERITY_ORDER.index(v.severity)
    )

    for i, vuln in enumerate(sorted_vulns, 1):
        sev_color = SEV_COLORS.get(vuln.severity.value, colors.gray)

        # Vuln header
        story.append(Paragraph(
            f"{i}. {vuln.vuln_type.value}",
            style_h3
        ))

        badge_data = [[
            Paragraph(f"<b>{vuln.severity.value.upper()}</b>", ParagraphStyle(
                "badge", parent=style_normal,
                textColor=colors.white, fontSize=9,
            )),
            Paragraph(f"CVSS: <b>{vuln.cvss_score}</b>", style_normal),
            Paragraph(f"ID: <b>{vuln.id}</b>", style_normal),
        ]]
        badge_table = Table(badge_data, colWidths=[4*cm, 4*cm, 9*cm])
        badge_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), sev_color),
            ("BACKGROUND", (1, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ]))
        story.append(badge_table)
        story.append(Spacer(1, 6))

        # Details table
        detail_rows = [["URL", vuln.url]]
        if vuln.parameter:
            detail_rows.append(["Parameter", vuln.parameter])
        if vuln.payload:
            detail_rows.append(["Payload", vuln.payload[:80]])
        detail_rows.append(["CVSS Vector", vuln.cvss_vector])

        detail_table = Table(detail_rows, colWidths=[3.5*cm, 13.5*cm])
        detail_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("FONTNAME", (1, 0), (1, -1), "Courier"),
            ("FONTSIZE", (1, 0), (1, -1), 8),
        ]))
        story.append(detail_table)
        story.append(Spacer(1, 6))

        story.append(Paragraph("<b>Description:</b>", style_normal))
        story.append(Paragraph(vuln.description, style_normal))
        story.append(Spacer(1, 4))

        if vuln.evidence:
            story.append(Paragraph("<b>Evidence:</b>", style_normal))
            story.append(Paragraph(vuln.evidence, style_code))
            story.append(Spacer(1, 4))

        story.append(Paragraph("<b>Remediation:</b>", style_normal))
        story.append(Paragraph(vuln.remediation, style_normal))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 10))

    # Footer
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e40af")))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "<i>This report was generated automatically by VulnHunter v1.0. "
        "Manual verification is recommended before acting on findings.</i>",
        ParagraphStyle("footer", parent=style_normal, fontSize=8,
                       textColor=colors.HexColor("#6b7280"))
    ))

    doc.build(story)
    return buffer.getvalue()