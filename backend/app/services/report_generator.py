import io
from datetime import datetime, timezone
from html import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)


class ReportGenerator:
    """
    Forensic Threat Report Generator producing exportable PDF reports
    from scan result telemetry and grounded AI explanations.
    """

    @classmethod
    def generate_pdf(cls, scan_data: dict) -> bytes:
        if not isinstance(scan_data, dict):
            if hasattr(scan_data, "model_dump"):
                scan_data = scan_data.model_dump()
            elif hasattr(scan_data, "dict"):
                scan_data = scan_data.dict()
            else:
                scan_data = {}

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0F172A"),
        )

        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#2563EB"),
        )

        timestamp_style = ParagraphStyle(
            "ReportTimestamp",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#64748B"),
            alignment=2,
        )

        section_heading = ParagraphStyle(
            "SectionHeading",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=10,
            spaceAfter=6,
        )

        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
        )

        target_style = ParagraphStyle(
            "TargetPayload",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#0F172A"),
            backColor=colors.HexColor("#F8FAFC"),
            borderPadding=8,
            spaceBefore=4,
            spaceAfter=8,
        )

        table_header_style = ParagraphStyle(
            "TableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=colors.white,
        )

        table_cell_style = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#1E293B"),
        )

        table_cell_bold = ParagraphStyle(
            "TableCellBold",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#0F172A"),
        )

        story = []

        # 1. BRANDED HEADER
        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        header_data = [
            [
                Paragraph("<b>CYBERGUARDIAN</b>", subtitle_style),
                Paragraph(f"Generated: {timestamp_str}", timestamp_style),
            ],
            [
                Paragraph("Forensic Threat Analysis Report", title_style),
                Paragraph("", timestamp_style),
            ],
        ]

        header_table = Table(header_data, colWidths=[360, 180])
        header_table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("SPAN", (0, 1), (1, 1)),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        story.append(header_table)
        story.append(Spacer(1, 8))
        story.append(
            HRFlowable(
                width="100%",
                thickness=2,
                color=colors.HexColor("#2563EB"),
                spaceBefore=2,
                spaceAfter=12,
            )
        )

        # Telemetry extraction
        risk_assessment = scan_data.get("risk_assessment", {})
        if not isinstance(risk_assessment, dict) and hasattr(risk_assessment, "model_dump"):
            risk_assessment = risk_assessment.model_dump()
        elif not isinstance(risk_assessment, dict):
            risk_assessment = {}

        score = risk_assessment.get("score", 0)
        level = str(risk_assessment.get("level", "LOW")).upper()
        triggers = risk_assessment.get("triggers", [])

        explanation = scan_data.get("explanation", {})
        if not isinstance(explanation, dict) and hasattr(explanation, "model_dump"):
            explanation = explanation.model_dump()
        elif not isinstance(explanation, dict):
            explanation = {}

        summary = explanation.get("summary", "No AI summary available.")
        why_flagged = explanation.get("why_flagged", [])
        recommended_actions = explanation.get("recommended_actions", [])
        educational_tip = explanation.get("educational_tip", "")

        evidence = scan_data.get("evidence", {})
        if not isinstance(evidence, dict) and hasattr(evidence, "model_dump"):
            evidence = evidence.model_dump()
        elif not isinstance(evidence, dict):
            evidence = {}

        target_payload = (
            scan_data.get("target")
            or scan_data.get("url")
            or scan_data.get("message")
            or evidence.get("extracted_text")
            or evidence.get("final_url")
            or "Unknown Target Payload"
        )

        scan_type = scan_data.get("scan_type")
        if not scan_type:
            if "url" in scan_data or "final_url" in evidence:
                scan_type = "URL Scan"
            elif "message" in scan_data or "urgency_detected" in evidence:
                scan_type = "Phishing Message Scan"
            elif "has_qr_code" in evidence:
                scan_type = "QR Code Scan"
            else:
                scan_type = "Threat Intelligence Scan"

        # 2. TARGET PAYLOAD & RISK OVERVIEW
        story.append(Paragraph(f"<b>Target Payload ({scan_type})</b>", section_heading))
        story.append(Paragraph(escape(str(target_payload)), target_style))
        story.append(Spacer(1, 8))

        level_colors = {
            "CRITICAL": (colors.HexColor("#991B1B"), colors.HexColor("#FEE2E2")),
            "HIGH": (colors.HexColor("#DC2626"), colors.HexColor("#FEF2F2")),
            "MEDIUM": (colors.HexColor("#D97706"), colors.HexColor("#FFFBEB")),
            "LOW": (colors.HexColor("#059669"), colors.HexColor("#ECFDF5")),
        }
        text_color, bg_color = level_colors.get(
            level, (colors.HexColor("#059669"), colors.HexColor("#ECFDF5"))
        )

        badge_style = ParagraphStyle(
            "BadgeStyle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=text_color,
            alignment=1,
        )

        score_style = ParagraphStyle(
            "ScoreStyle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0F172A"),
            alignment=1,
        )

        meta_label_style = ParagraphStyle(
            "MetaLabel",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748B"),
            alignment=1,
        )

        trig_style = ParagraphStyle(
            "TrigCount",
            parent=badge_style,
            fontSize=13,
            textColor=colors.HexColor("#1E293B"),
        )

        risk_table_data = [
            [
                Paragraph("THREAT RISK SCORE", meta_label_style),
                Paragraph("SEVERITY LEVEL", meta_label_style),
                Paragraph("RISK TRIGGERS FIRED", meta_label_style),
            ],
            [
                Paragraph(f"<b>{score} / 100</b>", score_style),
                Paragraph(f"<b>{level}</b>", badge_style),
                Paragraph(f"<b>{len(triggers)} Trigger(s)</b>", trig_style),
            ],
        ]

        risk_table = Table(risk_table_data, colWidths=[180, 180, 180])
        risk_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
                    ("INNERGRID", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("BACKGROUND", (1, 1), (1, 1), bg_color),
                ]
            )
        )
        story.append(risk_table)
        story.append(Spacer(1, 14))

        # 3. AI SUMMARY & KEY EVIDENCE BREAKDOWN
        story.append(Paragraph("AI Threat Explanation & Executive Summary", section_heading))

        summary_p = Paragraph(escape(summary), body_style)
        summary_table = Table([[summary_p]], colWidths=[540])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#BFDBFE")),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ]
            )
        )
        story.append(summary_table)
        story.append(Spacer(1, 10))

        if why_flagged:
            story.append(Paragraph("<b>Key Threat Evidence Indicators</b>", body_style))
            story.append(Spacer(1, 4))
            for item in why_flagged:
                bullet_p = Paragraph(
                    f"• <font color='#DC2626'><b>[FLAG]</b></font> {escape(item)}",
                    body_style,
                )
                story.append(bullet_p)
                story.append(Spacer(1, 3))
            story.append(Spacer(1, 10))

        # 4. HEURISTIC THREAT FACTOR TABLES
        story.append(Paragraph("Heuristic Telemetry & Risk Factor Breakdown", section_heading))

        factor_rows = [
            [
                Paragraph("Threat Factor / Test", table_header_style),
                Paragraph("Observation / Telemetry Detail", table_header_style),
                Paragraph("Status", table_header_style),
            ]
        ]

        def add_factor_row(factor_name, detail_str, is_flagged):
            status_html = (
                "<font color='#DC2626'><b>FLAGGED</b></font>"
                if is_flagged
                else "<font color='#059669'><b>PASS / CLEAN</b></font>"
            )
            factor_rows.append(
                [
                    Paragraph(escape(factor_name), table_cell_bold),
                    Paragraph(escape(str(detail_str)), table_cell_style),
                    Paragraph(status_html, table_cell_style),
                ]
            )

        if triggers:
            add_factor_row("Risk Engine Triggers", ", ".join(triggers), is_flagged=True)
        else:
            add_factor_row("Risk Engine Triggers", "No risk triggers activated", is_flagged=False)

        if "domain_age_days" in evidence:
            d_age = evidence.get("domain_age_days")
            d_str = f"{d_age} days" if d_age is not None else "Unknown / Unresolved"
            add_factor_row(
                "Domain Registration Age",
                d_str,
                is_flagged=(d_age is not None and d_age < 30),
            )

        if "ssl_valid" in evidence:
            ssl_v = evidence.get("ssl_valid", False)
            issuer = evidence.get("ssl_issuer")
            ssl_str = f"Valid Certificate ({issuer})" if ssl_v and issuer else ("Valid Certificate" if ssl_v else "Invalid / Self-Signed / Expired")
            add_factor_row("SSL/TLS Encryption", ssl_str, is_flagged=not ssl_v)

        if "redirect_count" in evidence:
            reds = evidence.get("redirect_count", 0)
            add_factor_row("HTTP Redirect Chain", f"{reds} redirect hop(s)", is_flagged=(reds > 2))

        if "suspicious_tld" in evidence:
            susp_tld = evidence.get("suspicious_tld", False)
            add_factor_row("Top-Level Domain (TLD) Risk", "High-risk TLD detected" if susp_tld else "Standard TLD", is_flagged=susp_tld)

        if "brand_impersonation" in evidence:
            b_imp = evidence.get("brand_impersonation", False)
            add_factor_row("Brand Impersonation Test", "Typosquatting/Brand spoofing detected" if b_imp else "No impersonation detected", is_flagged=b_imp)

        if "urgency_detected" in evidence:
            urg = evidence.get("urgency_detected", False)
            add_factor_row("Psychological Urgency Tactics", "Coercive urgency language found" if urg else "Normal communication tone", is_flagged=urg)

        if "financial_lures_detected" in evidence:
            fin = evidence.get("financial_lures_detected", False)
            add_factor_row("Financial Lure Detection", "Banking/Monetary payment lure detected" if fin else "No financial lure detected", is_flagged=fin)

        threat_intel = evidence.get("threat_intel") or {}
        safe_hit = evidence.get("safe_browsing_hit", False) or threat_intel.get("flagged", False)
        add_factor_row(
            "Threat Intelligence Feeds",
            "Matched malicious entry in URLhaus/Google Safe Browsing" if safe_hit else "Clean across active threat intelligence feeds",
            is_flagged=safe_hit,
        )

        factor_table = Table(factor_rows, colWidths=[160, 260, 120])
        factor_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#94A3B8")),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ]
            )
        )
        story.append(factor_table)
        story.append(Spacer(1, 14))

        # 5. ACTIONABLE SAFEGUARDS & REMEDIATION
        safeguards_block = []
        safeguards_block.append(Paragraph("Actionable Safeguards & Remediation Steps", section_heading))

        if recommended_actions:
            for action in recommended_actions:
                act_p = Paragraph(
                    f"<b>[ACTION]</b> {escape(action)}",
                    body_style,
                )
                safeguards_block.append(act_p)
                safeguards_block.append(Spacer(1, 4))

        if educational_tip:
            safeguards_block.append(Spacer(1, 6))
            tip_p = Paragraph(
                f"<b>Educational Tip:</b> {escape(educational_tip)}",
                ParagraphStyle(
                    "TipStyle",
                    parent=body_style,
                    textColor=colors.HexColor("#1E3A8A"),
                ),
            )
            tip_table = Table([[tip_p]], colWidths=[540])
            tip_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#FCD34D")),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            safeguards_block.append(tip_table)

        story.append(KeepTogether(safeguards_block))

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

