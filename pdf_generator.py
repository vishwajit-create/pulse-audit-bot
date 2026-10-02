import os
import html
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from config import REPORTS_DIR
from models import ForensicDossier

def generate_forensic_pdf(dossier: ForensicDossier) -> Path:
    """
    Generates a professional, print-ready Cyber Forensic PDF Dossier using ReportLab.
    """
    filename = f"forensic_report_{dossier.subject_type.lower()}_{dossier.subject_value.replace('.', '_')}_{dossier.case_id}.pdf"
    # sanitize filename
    filename = "".join(c for c in filename if c.isalnum() or c in "._-")
    pdf_path = REPORTS_DIR / filename

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        alignment=0
    )
    subtitle_style = ParagraphStyle(
        "DocSubTitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b")
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=4
    )
    cell_bold = ParagraphStyle(
        "CellBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1e293b")
    )
    cell_text = ParagraphStyle(
        "CellText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#334155")
    )
    mono_style = ParagraphStyle(
        "MonoText",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#0f172a")
    )

    elements = []

    # 1. Header Banner
    header_data = [
        [
            Paragraph("🛡️ <b>CYBER FORENSIC INCIDENT DOSSIER</b>", title_style),
            Paragraph(f"<b>CASE REF:</b> {dossier.case_id}<br/><b>DATE:</b> {dossier.generated_at}", subtitle_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[380, 160])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(header_table)
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563eb"), spaceAfter=10))

    # 2. Executive Threat Gauge & Summary Card
    severity = dossier.threat.severity
    if severity == "CRITICAL":
        badge_color = colors.HexColor("#dc2626")
    elif severity == "HIGH":
        badge_color = colors.HexColor("#ea580c")
    elif severity == "MEDIUM":
        badge_color = colors.HexColor("#ca8a04")
    elif severity == "LOW":
        badge_color = colors.HexColor("#0284c7")
    else:
        badge_color = colors.HexColor("#16a34a")

    summary_data = [
        [
            Paragraph("<b>Target Subject:</b>", cell_bold),
            Paragraph(f"<b>{dossier.subject_type}:</b> {dossier.subject_value}", cell_text),
            Paragraph("<b>Threat Severity:</b>", cell_bold),
            Paragraph(f"<font color='{badge_color.hexval()}'><b>{severity} ({dossier.threat.risk_score}/100)</b></font>", cell_bold),
        ],
        [
            Paragraph("<b>First Observed:</b>", cell_bold),
            Paragraph(dossier.first_seen, cell_text),
            Paragraph("<b>Last Observed:</b>", cell_bold),
            Paragraph(dossier.last_seen, cell_text),
        ],
        [
            Paragraph("<b>Total Actions:</b>", cell_bold),
            Paragraph(str(dossier.total_events), cell_text),
            Paragraph("<b>Messages Dispatched:</b>", cell_bold),
            Paragraph(str(dossier.total_messages), cell_text),
        ],
        [
            Paragraph("<b>Aliases (Handles):</b>", cell_bold),
            Paragraph(", ".join(dossier.aliases_used) if dossier.aliases_used else "None", cell_text),
            Paragraph("<b>Rooms / Targets:</b>", cell_bold),
            Paragraph(", ".join(dossier.targets_accessed) if dossier.targets_accessed else "None", cell_text),
        ]
    ]

    summary_table = Table(summary_data, colWidths=[110, 160, 110, 160])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 10))

    # 3. Network Reconnaissance & Attribution
    elements.append(Paragraph("1. Network Attribution & Geolocation", section_heading))
    intel = dossier.ip_intel
    if intel:
        abuse_text = f"{intel.abuse_confidence_score}%" if intel.abuse_confidence_score is not None else "Not Queried / Free Plan"
        net_data = [
            [Paragraph("<b>IP Address</b>", cell_bold), Paragraph(intel.ip, mono_style),
             Paragraph("<b>Country & City</b>", cell_bold), Paragraph(f"{intel.country} ({intel.country_code}) / {intel.city}", cell_text)],
            [Paragraph("<b>Region / State</b>", cell_bold), Paragraph(intel.region_name, cell_text),
             Paragraph("<b>Postal / ZIP</b>", cell_bold), Paragraph(intel.zip_code or "N/A", cell_text)],
            [Paragraph("<b>Coordinates</b>", cell_bold), Paragraph(f"Lat: {intel.latitude}, Lon: {intel.longitude}", mono_style),
             Paragraph("<b>Timezone</b>", cell_bold), Paragraph(intel.timezone or "N/A", cell_text)],
            [Paragraph("<b>ISP Provider</b>", cell_bold), Paragraph(intel.isp, cell_text),
             Paragraph("<b>Organization</b>", cell_bold), Paragraph(intel.org, cell_text)],
            [Paragraph("<b>Autonomous System</b>", cell_bold), Paragraph(intel.asn, cell_text),
             Paragraph("<b>Abuse Score</b>", cell_bold), Paragraph(abuse_text, cell_text)],
        ]
    else:
        net_data = [[Paragraph("No IP intelligence available for this subject.", cell_text)]]

    net_table = Table(net_data, colWidths=[110, 160, 110, 160])
    net_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
    ]))
    elements.append(net_table)
    elements.append(Spacer(1, 10))

    # 4. Client Hardware & Browser Fingerprint
    elements.append(Paragraph("2. Client Hardware & Browser Fingerprint", section_heading))
    fp = dossier.fingerprint
    if fp:
        bot_flag = "⚠️ YES (Automated Script/Bot)" if fp.is_bot else "No (Standard Browser)"
        device_type = "Mobile" if fp.is_mobile else ("Tablet" if fp.is_tablet else "Desktop / PC")
        fp_data = [
            [Paragraph("<b>Operating System</b>", cell_bold), Paragraph(html.escape(f"{fp.os_family} {fp.os_version}".strip()), cell_text),
             Paragraph("<b>Browser Software</b>", cell_bold), Paragraph(html.escape(f"{fp.browser_family} {fp.browser_version}".strip()), cell_text)],
            [Paragraph("<b>Device Class</b>", cell_bold), Paragraph(device_type, cell_text),
             Paragraph("<b>Bot Detection</b>", cell_bold), Paragraph(bot_flag, cell_bold if fp.is_bot else cell_text)],
            [Paragraph("<b>Raw User-Agent</b>", cell_bold), Paragraph(html.escape(fp.raw_user_agent[:180]), mono_style), "", ""]
        ]
        fp_table = Table(fp_data, colWidths=[110, 160, 110, 160])
        fp_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('SPAN', (1,2), (3,2)),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(fp_table)
    else:
        elements.append(Paragraph("No browser or device telemetry recorded.", cell_text))
    elements.append(Spacer(1, 10))

    # 5. Detected Exploit Signatures & Anomaly Explanations
    elements.append(Paragraph("3. Detected Threat Signatures & Rule Violations", section_heading))
    if dossier.threat.indicators:
        threat_rows = [
            [Paragraph("<b>Indicator Flag</b>", cell_bold), Paragraph("<b>Forensic Analysis & Matched Rule</b>", cell_bold)]
        ]
        for ind, exp in zip(dossier.threat.indicators, dossier.threat.explanations):
            threat_rows.append([
                Paragraph(f"<font color='red'><b>{html.escape(ind)}</b></font>", cell_bold),
                Paragraph(html.escape(exp), cell_text)
            ])
        threat_table = Table(threat_rows, colWidths=[140, 400])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#fee2e2")),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#fff1f2")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#fca5a5")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#fecaca")),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(threat_table)
    else:
        elements.append(Paragraph("✅ No malicious exploit signatures or anomalous security flags observed.", cell_text))
    elements.append(Spacer(1, 10))

    # 6. Chronological Activity Log (Evidence Audit Trail)
    elements.append(Paragraph("4. Chronological Evidence Audit Trail", section_heading))
    log_rows = [
        [
            Paragraph("<b>Timestamp (UTC)</b>", cell_bold),
            Paragraph("<b>Event</b>", cell_bold),
            Paragraph("<b>Sender</b>", cell_bold),
            Paragraph("<b>Target</b>", cell_bold),
            Paragraph("<b>Payload / Content</b>", cell_bold),
        ]
    ]

    for ev in dossier.events[-30:]:  # Last 30 events for the evidence table
        msg_preview = ev.message[:120] + "..." if len(ev.message) > 120 else ev.message
        if ev.is_flagged or ev.flags:
            msg_preview = f"🚩 {msg_preview}"
        log_rows.append([
            Paragraph(html.escape(ev.timestamp[:19].replace("T", " ")), mono_style),
            Paragraph(html.escape(ev.event_type), cell_text),
            Paragraph(html.escape(ev.sender), cell_text),
            Paragraph(html.escape(ev.target), cell_text),
            Paragraph(html.escape(msg_preview), mono_style),
        ])

    log_table = Table(log_rows, colWidths=[90, 65, 75, 80, 230])
    log_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('LEFTPADDING', (0,0), (-1,-1), 3),
        ('RIGHTPADDING', (0,0), (-1,-1), 3),
    ]))
    elements.append(log_table)
    elements.append(Spacer(1, 12))

    # Footer note
    footer_text = Paragraph(
        "<i>Chain of Custody Notice: This automated audit document contains digitally preserved forensic evidence generated directly from server event telemetry. Verify timestamps against Render deployment logs for corroboration.</i>",
        subtitle_style
    )
    elements.append(footer_text)

    doc.build(elements)
    return pdf_path
