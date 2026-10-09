import os
import uuid
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from flask import current_app, has_app_context

from app.utils.masking import mask_sensitive_value


def generate_privacy_report(document_name, file_type, risk_result, findings=None):
    findings = findings or []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if has_app_context():
        output_dir = current_app.config["REPORT_FOLDER"]
    else:
        project_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        output_dir = os.path.join(project_dir, "instance", "reports")
    os.makedirs(output_dir, exist_ok=True)

    report_name = f"privacy_report_{uuid.uuid4().hex}.pdf"
    report_path = os.path.join(output_dir, report_name)

    doc = SimpleDocTemplate(report_path, pagesize=letter)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=18, leading=22, spaceAfter=20)
    heading_style = ParagraphStyle("ReportHeading", fontName="Helvetica-Bold", fontSize=11, leading=14, spaceAfter=8, textColor=colors.HexColor("#1f2937"))
    body_style = ParagraphStyle("ReportBody", parent=styles["BodyText"], fontSize=9, leading=12)

    content = []
    content.append(Paragraph("Privacy Risk Report", title_style))
    content.append(Paragraph(f"Document Filename: {document_name}", body_style))
    content.append(Paragraph(f"File Type: {file_type}", body_style))
    content.append(Paragraph(f"Scan Date/Time: {now}", body_style))
    content.append(Paragraph(f"Overall Privacy Risk Score: {risk_result.get('total_score', 0)}", body_style))
    content.append(Paragraph(f"Risk Level: {risk_result.get('risk_level', 'Low')}", body_style))
    content.append(Spacer(1, 0.2 * inch))

    categories = [category for category, count in risk_result.get("detected_category_summary", {}).items() if count > 0]
    content.append(Paragraph("Detected Categories", heading_style))
    content.append(Paragraph(", ".join(categories) if categories else "No sensitive categories detected.", body_style))
    content.append(Paragraph(f"Number of Findings: {len(findings)}", body_style))
    content.append(Spacer(1, 0.2 * inch))

    if findings:
        rows = [["Category", "Masked Value", "Confidence", "Evidence"]]
        for item in findings:
            rows.append([
                item.get("type", "unknown"),
                mask_sensitive_value(item.get("type", "unknown"), item.get("value", "")),
                str(item.get("confidence", "0.0")),
                item.get("evidence", "Detected by pattern match")[:80],
            ])

        table = Table(rows, colWidths=[1.3 * inch, 2.3 * inch, 0.8 * inch, 2.2 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]))
        content.append(table)
    else:
        content.append(Paragraph("No sensitive findings were detected.", body_style))

    content.append(Spacer(1, 0.2 * inch))
    content.append(Paragraph("Score Contribution by Category", heading_style))
    category_rows = [["Category", "Contribution"]]
    for category, contribution in risk_result.get("score_contribution_of_each_category", {}).items():
        if contribution > 0:
            category_rows.append([category, str(contribution)])
    if len(category_rows) == 1:
        category_rows.append(["No contributions", "0"])
    category_table = Table(category_rows, colWidths=[2.6 * inch, 2.0 * inch])
    category_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))
    content.append(category_table)
    content.append(Spacer(1, 0.2 * inch))

    content.append(Paragraph("Risk Explanation", heading_style))
    for explanation in risk_result.get("explanations", ["No sensitive findings were detected."]):
        content.append(Paragraph(f"- {explanation}", body_style))

    doc.build(content)
    return report_name
