from pathlib import Path

import fitz
import pytest

from app.services.detection_service import detect_sensitive_data
from app.services.extraction_service import extract_text_from_file


@pytest.fixture
def sample_dir(tmp_path):
    sample_dir = tmp_path / "detection_samples"
    sample_dir.mkdir()
    return sample_dir


def _create_text_pdf(path, text):
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text, fontsize=16)
    doc.save(path)
    doc.close()


@pytest.mark.parametrize(
    "doc_text, category, expected_value",
    [
        ("Aadhaar: 1234 5678 9012", "aadhaar", "1234 5678 9012"),
        ("PAN: ABCDE1234F", "pan", "ABCDE1234F"),
        ("Account No: 1234567890", "bank_account", "1234567890"),
        ("IFSC: SBIN0001234", "ifsc", "SBIN0001234"),
        ("Phone: +91 98765 43210", "phone", "+91 98765 43210"),
        ("Email: alice@example.com", "email", "alice@example.com"),
        ("DOB: 12/05/1998", "dob", "12/05/1998"),
        ("PIN: 110001", "pin", "110001"),
    ],
)
def test_detection_positive_cases(sample_dir, doc_text, category, expected_value):
    pdf_path = sample_dir / f"{category}_sample.pdf"
    _create_text_pdf(pdf_path, doc_text)

    extracted = extract_text_from_file(pdf_path)
    findings = detect_sensitive_data(extracted)

    assert any(item["type"] == category and expected_value in item["value"] for item in findings)
    assert all(set(item.keys()) >= {"type", "value", "position", "confidence", "evidence"} for item in findings if item["type"] == category)


@pytest.mark.parametrize(
    "text, category",
    [
        ("Reference ID: 1234 5678 9012", "aadhaar"),
        ("PAN code: ABCD123", "pan"),
        ("Invoice: 1234567890", "bank_account"),
        ("Bank code: ABCD1234", "ifsc"),
        ("Reference: 12345 67890", "phone"),
        ("Domain: example.com", "email"),
        ("Date: 99/99/9999", "dob"),
        ("Serial: 110001", "pin"),
    ],
)
def test_detection_negative_false_positive_cases(text, category):
    findings = detect_sensitive_data(text)
    assert all(item["type"] != category for item in findings)


def test_detects_sensitive_data_in_extracted_text_from_pdf(sample_dir):
    doc_text = "Customer Name: Alice Johnson\nAadhaar: 1234 5678 9012\nEmail: alice@example.com"
    pdf_path = sample_dir / "mixed_sample.pdf"
    _create_text_pdf(pdf_path, doc_text)

    extracted = extract_text_from_file(pdf_path)
    findings = detect_sensitive_data(extracted)

    detected = {item["type"] for item in findings}
    assert "aadhaar" in detected
    assert "email" in detected


def test_detects_contextual_snippets():
    text = "Account record verification. Email: user.leak@company.org in employee database."
    findings = detect_sensitive_data(text)

    email_findings = [f for f in findings if f["type"] == "email"]
    assert len(email_findings) == 1
    item = email_findings[0]
    assert "context_snippet" in item
    assert "[MATCH]" in item["context_snippet"]
    assert "Email:" in item["context_snippet"]
    assert "employee" in item["context_snippet"]

