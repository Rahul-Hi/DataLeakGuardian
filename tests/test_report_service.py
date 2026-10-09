from io import BytesIO

import fitz
import os

from app import create_app
from app.services.report_service import generate_privacy_report


def _make_pdf_bytes(text):
    pdf = fitz.open()
    page = pdf.new_page()
    page.insert_text((72, 72), text, fontsize=16)
    stream = BytesIO()
    pdf.save(stream)
    pdf.close()
    stream.seek(0)
    return stream.read()


def test_generate_privacy_report_successfully():
    risk_result = {
        "total_score": 55,
        "risk_level": "High",
        "detected_category_summary": {"aadhaar": 1, "phone": 1},
        "score_contribution_of_each_category": {"aadhaar": 30, "phone": 15, "email": 0, "pan": 0, "bank_account": 0, "ifsc": 0, "dob": 0, "pin": 0},
        "explanations": ["Aadhaar detected 1 time(s); contributed 30 points.", "Phone detected 1 time(s); contributed 15 points."],
    }
    findings = [
        {"type": "aadhaar", "value": "1234 5678 9012", "confidence": 0.95, "evidence": "Aadhaar detected"},
        {"type": "phone", "value": "+91 98765 43210", "confidence": 0.92, "evidence": "Phone detected"},
    ]

    report_name = generate_privacy_report("sample.pdf", "PDF", risk_result, findings)

    assert report_name.endswith(".pdf")
    assert "privacy_report_" in report_name


def test_report_contains_risk_information_and_masks_sensitive_values():
    risk_result = {
        "total_score": 30,
        "risk_level": "Moderate",
        "detected_category_summary": {"email": 1},
        "score_contribution_of_each_category": {"email": 10, "aadhaar": 0, "pan": 0, "bank_account": 0, "ifsc": 0, "phone": 0, "dob": 0, "pin": 0},
        "explanations": ["Email detected 1 time(s); contributed 10 points."],
    }
    findings = [{"type": "email", "value": "alice@example.com", "confidence": 0.98, "evidence": "Email detected"}]

    report_name = generate_privacy_report("sample.pdf", "PDF", risk_result, findings)
    report_path = os.path.join(create_app().config["REPORT_FOLDER"], report_name)

    assert report_name.endswith(".pdf")
    assert report_path.endswith(".pdf")

    with open(report_path, "rb") as report_file:
        pdf_bytes = report_file.read()
    assert pdf_bytes.startswith(b"%PDF")
    assert b"alice@example.com" not in pdf_bytes
    assert b"example.com" not in pdf_bytes


def test_empty_no_findings_report_is_generated():
    risk_result = {
        "total_score": 0,
        "risk_level": "Low",
        "detected_category_summary": {"email": 0, "aadhaar": 0, "pan": 0, "bank_account": 0, "ifsc": 0, "phone": 0, "dob": 0, "pin": 0},
        "score_contribution_of_each_category": {"email": 0, "aadhaar": 0, "pan": 0, "bank_account": 0, "ifsc": 0, "phone": 0, "dob": 0, "pin": 0},
        "explanations": ["No sensitive findings were detected."],
    }

    report_name = generate_privacy_report("empty.pdf", "PDF", risk_result, [])

    assert report_name.endswith(".pdf")
    report_path = os.path.join(create_app().config["REPORT_FOLDER"], report_name)
    pdf_doc = fitz.open(report_path)
    extracted_text = "\n".join(page.get_text("text") for page in pdf_doc)
    pdf_doc.close()

    assert "No sensitive findings were detected." in extracted_text
