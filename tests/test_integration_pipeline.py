from io import BytesIO

import fitz

from auth_helpers import create_authenticated_test_client


def _make_pdf_bytes(text):
    pdf = fitz.open()
    page = pdf.new_page()
    page.insert_text((72, 72), text, fontsize=16)
    stream = BytesIO()
    pdf.save(stream)
    pdf.close()
    stream.seek(0)
    return stream.read()


def test_upload_and_analysis_pipeline_integration():
    _, client, _ = create_authenticated_test_client()

    payload = (
        "Customer Name: Alice Johnson\n"
        "Aadhaar: 1234 5678 9012\n"
        "Phone: +91 98765 43210\n"
        "Email: alice@example.com\n"
        "PAN: ABCDE1234F\n"
        "PIN: 110001"
    )

    response = client.post(
        "/",
        data={"file": (BytesIO(_make_pdf_bytes(payload)), "sample_mixed.pdf")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)

    assert "sample_mixed.pdf" in html
    assert "Analysis Result" in html
    assert "Total risk score" in html
    assert "Risk level" in html
    assert "aadhaar" in html.lower() or "Aadhaar" in html
    assert "phone" in html.lower() or "Phone" in html
    assert "email" in html.lower() or "Email" in html
    assert "1234 5678 9012" not in html
    assert "9876543210" not in html
    assert "alice@example.com" not in html


def test_rejects_invalid_upload_in_integration_flow():
    _, client, _ = create_authenticated_test_client()

    response = client.post(
        "/",
        data={"file": (BytesIO(b"not a valid file"), "bad.txt")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Only PDF, PNG, JPG, and JPEG files are allowed" in html


def test_contextual_snippets_are_safely_masked_and_remediations_rendered():
    _, client, _ = create_authenticated_test_client()

    payload = (
        "Document Record.\n"
        "Customer Aadhaar: 1234 5678 9012 registered for access.\n"
        "Contact Email: confidential@corp.test registered for alerts."
    )

    response = client.post(
        "/",
        data={"file": (BytesIO(_make_pdf_bytes(payload)), "snippet_test.pdf")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)

    # Contextual snippet checks
    assert "Context Preview" in html
    assert "XXXX XXXX 9012" in html
    assert "co" in html and "@corp.test" in html

    # Absolute safe masking assertion: raw PII never leaks into snippet or HTML
    assert "1234 5678 9012" not in html
    assert "confidential@corp.test" not in html

    # Actionable remediation guidance rendered
    assert "Actionable Remediation & Redaction Guidance" in html
    assert "UIDAI" in html or "Aadhaar" in html

