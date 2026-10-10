import os
from pathlib import Path

import fitz
import pytest
from PIL import Image, ImageDraw, ImageFont

from app.services.extraction_service import extract_text_from_file


@pytest.fixture
def sample_dir(tmp_path):
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    return sample_dir


def _create_text_pdf(path, text):
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text, fontsize=16)
    doc.save(path)
    doc.close()


def _create_image_with_text(path, text):
    image = Image.new("RGB", (1000, 300), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    draw.text((50, 100), text, fill="black", font=font)
    image.save(path)


def _create_scanned_pdf_from_image(path, image_path):
    doc = fitz.open()
    page = doc.new_page()
    page.insert_image(page.rect, filename=str(image_path))
    doc.save(path)
    doc.close()


def test_extracts_text_from_text_based_pdf(sample_dir):
    pdf_path = sample_dir / "text_sample.pdf"
    expected_text = "Customer Name: Alice Johnson"
    _create_text_pdf(pdf_path, expected_text)

    extracted = extract_text_from_file(pdf_path)

    assert expected_text.lower() in extracted.lower()


def test_extracts_text_from_image_ocr(sample_dir):
    image_path = sample_dir / "image_sample.png"
    expected_text = "PAN: ABCDE1234F"
    _create_image_with_text(image_path, expected_text)

    extracted = extract_text_from_file(image_path)

    assert "ABCD" in extracted.upper() or "PAN" in extracted.upper()


def test_ocr_fallback_for_scanned_pdf(sample_dir):
    image_path = sample_dir / "scanned_source.png"
    expected_text = "Aadhaar 1234 5678 9012"
    _create_image_with_text(image_path, expected_text)

    scanned_pdf_path = sample_dir / "scanned_sample.pdf"
    _create_scanned_pdf_from_image(scanned_pdf_path, image_path)

    extracted = extract_text_from_file(scanned_pdf_path)

    assert "Aadhaar" in extracted or "1234" in extracted


def test_rejects_unsupported_file_types(sample_dir):
    unsupported_path = sample_dir / "notes.txt"
    unsupported_path.write_text("This is a text file.", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported file type|Document is empty or unreadable"):
        extract_text_from_file(unsupported_path)


def test_rejects_empty_or_unreadable_documents(sample_dir):
    empty_path = sample_dir / "empty.pdf"
    empty_path.write_bytes(b"")

    with pytest.raises(ValueError, match="Document is empty or unreadable"):
        extract_text_from_file(empty_path)


# ----------------------------------------------------------------------
# GEMINI VISION OCR FALLBACK TESTS (MOCKED)
# ----------------------------------------------------------------------

def _mock_gemini_response(text="Income Tax Department PAN: ABCDE1234F"):
    import json
    return json.dumps({
        "candidates": [
            {
                "content": {
                    "parts": [{"text": text}]
                }
            }
        ]
    }).encode("utf-8")


def test_tesseract_preferred_when_available(monkeypatch, sample_dir):
    """Verify that when Tesseract is available, it is chosen first without calling Gemini."""
    image_path = sample_dir / "tess_test.png"
    _create_image_with_text(image_path, "PAN ABCDE1234F")

    monkeypatch.setattr("app.services.extraction_service.is_tesseract_available", lambda: True)
    gemini_called = False

    def fake_gemini(*args, **kwargs):
        nonlocal gemini_called
        gemini_called = True
        return "Gemini Text"

    monkeypatch.setattr("app.services.extraction_service._call_gemini_vision_ocr", fake_gemini)
    text = extract_text_from_file(image_path)
    assert not gemini_called
    assert "PAN" in text.upper() or "ABCD" in text.upper()


def test_gemini_fallback_when_tesseract_unavailable(monkeypatch, sample_dir):
    """Verify Gemini OCR is invoked when Tesseract is missing and GEMINI_API_KEY is set."""
    image_path = sample_dir / "gemini_test.png"
    _create_image_with_text(image_path, "Dummy Image")

    monkeypatch.setattr("app.services.extraction_service.is_tesseract_available", lambda: False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-mock-api-key")

    mock_resp = _mock_gemini_response("Government of India Aadhaar 9876 5432 1098")

    class MockHTTPResponse:
        def read(self):
            return mock_resp
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: MockHTTPResponse())

    extracted = extract_text_from_file(image_path)
    assert "Aadhaar 9876 5432 1098" in extracted


def test_gemini_ocr_supported_image_mime_types(monkeypatch):
    """Verify that PNG, JPG, and JPEG pass appropriate MIME types to the Gemini API."""
    from app.services.extraction_service import _extract_image_text

    monkeypatch.setattr("app.services.extraction_service.is_tesseract_available", lambda: False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-mock-api-key")

    captured_mime = []

    def fake_call(raw_bytes, mime_type):
        captured_mime.append(mime_type)
        return "Extracted Content"

    monkeypatch.setattr("app.services.extraction_service._call_gemini_vision_ocr", fake_call)

    dummy_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    _extract_image_text(dummy_bytes, "png")
    assert captured_mime[-1] == "image/png"

    _extract_image_text(dummy_bytes, "jpg")
    assert captured_mime[-1] == "image/jpeg"

    _extract_image_text(dummy_bytes, "jpeg")
    assert captured_mime[-1] == "image/jpeg"


def test_gemini_fallback_for_scanned_pdf(monkeypatch, sample_dir):
    """Verify scanned (image-only) PDFs use Gemini when Tesseract is missing and key is set."""
    img_path = sample_dir / "pdf_page.png"
    _create_image_with_text(img_path, "Scanned Page")
    pdf_path = sample_dir / "scanned_doc.pdf"
    _create_scanned_pdf_from_image(pdf_path, img_path)

    monkeypatch.setattr("app.services.extraction_service.is_tesseract_available", lambda: False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-mock-api-key")

    mock_resp = _mock_gemini_response("Bank Account: 12345678901234 IFSC: HDFC0001234")

    class MockHTTPResponse:
        def read(self):
            return mock_resp
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: MockHTTPResponse())

    extracted = extract_text_from_file(pdf_path)
    assert "HDFC0001234" in extracted


def test_error_when_neither_tesseract_nor_gemini_key_available(monkeypatch, sample_dir):
    """Verify clear actionable error is raised when neither Tesseract nor GEMINI_API_KEY is available."""
    image_path = sample_dir / "no_engine.png"
    _create_image_with_text(image_path, "Text")

    monkeypatch.setattr("app.services.extraction_service.is_tesseract_available", lambda: False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    with pytest.raises(ValueError, match="OCR engine .* is not installed .* and GEMINI_API_KEY is not configured"):
        extract_text_from_file(image_path)


def test_gemini_rate_limit_429_handling(monkeypatch):
    """Verify HTTP 429 returns an actionable rate-limit message."""
    import urllib.error
    from app.services.extraction_service import _call_gemini_vision_ocr

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def mock_429(*args, **kwargs):
        raise urllib.error.HTTPError(
            url="https://api", code=429, msg="Too Many Requests", hdrs={}, fp=None
        )

    monkeypatch.setattr("urllib.request.urlopen", mock_429)

    with pytest.raises(ValueError, match="rate limit reached"):
        _call_gemini_vision_ocr(b"dummy_bytes", "image/png")


def test_gemini_auth_error_handling(monkeypatch):
    """Verify HTTP 401/403 returns an actionable authentication error."""
    import urllib.error
    from app.services.extraction_service import _call_gemini_vision_ocr

    monkeypatch.setenv("GEMINI_API_KEY", "invalid-key")

    def mock_401(*args, **kwargs):
        raise urllib.error.HTTPError(
            url="https://api", code=401, msg="Unauthorized", hdrs={}, fp=None
        )

    monkeypatch.setattr("urllib.request.urlopen", mock_401)

    with pytest.raises(ValueError, match="authentication failed or invalid configuration"):
        _call_gemini_vision_ocr(b"dummy_bytes", "image/png")


def test_gemini_network_timeout_handling(monkeypatch):
    """Verify network timeout returns an actionable timeout message."""
    import socket
    from app.services.extraction_service import _call_gemini_vision_ocr

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def mock_timeout(*args, **kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr("urllib.request.urlopen", mock_timeout)

    with pytest.raises(ValueError, match="timed out or network unavailable"):
        _call_gemini_vision_ocr(b"dummy_bytes", "image/png")


def test_gemini_empty_or_malformed_response_handling(monkeypatch):
    """Verify empty/malformed responses fail safely without silent false positives."""
    import json
    from app.services.extraction_service import _call_gemini_vision_ocr

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Malformed empty candidates
    class MockEmpty:
        def read(self):
            return json.dumps({"candidates": []}).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: MockEmpty())

    with pytest.raises(ValueError, match="returned no content"):
        _call_gemini_vision_ocr(b"dummy_bytes", "image/png")


def test_gemini_extracted_text_flows_into_pii_detection_and_masking(monkeypatch, sample_dir):
    """Verify text from Gemini flows seamlessly into Aadhaar/PAN regex detection and masking."""
    from app.services.detection_service import detect_sensitive_data
    from app.utils.masking import mask_sensitive_value

    image_path = sample_dir / "card.png"
    _create_image_with_text(image_path, "Card image")

    monkeypatch.setattr("app.services.extraction_service.is_tesseract_available", lambda: False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Simulated OCR extraction with Indian PAN and Aadhaar
    synthetic_ocr = "INCOME TAX DEPARTMENT PAN: ABCDE1234F Aadhaar: 3675 9834 6012"
    mock_resp = _mock_gemini_response(synthetic_ocr)

    class MockResp:
        def read(self):
            return mock_resp
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: MockResp())

    extracted = extract_text_from_file(image_path)
    findings = detect_sensitive_data(extracted)
    assert len(findings) >= 2

    pan_finding = next((f for f in findings if f["type"] == "pan"), None)
    assert pan_finding is not None
    assert pan_finding["value"] == "ABCDE1234F"

    masked_pan = mask_sensitive_value(pan_finding["type"], pan_finding["value"])
    assert masked_pan == "XXXXX1234F"
