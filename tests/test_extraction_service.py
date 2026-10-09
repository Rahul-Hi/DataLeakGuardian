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
