import os
import re
from pathlib import Path

import fitz
import pytesseract
from PIL import Image, ImageFilter, ImageOps

TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if os.path.exists(TESSERACT_PATH):
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH


def normalize_extracted_text(text):
    if text is None:
        return ""

    cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = re.sub(r"[ \t]+\n", "\n", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    cleaned = re.sub(r" \n", "\n", cleaned)
    return cleaned.strip()


def _prepare_image(image):
    image = image.convert("L")
    image = ImageOps.autocontrast(image)
    image = image.filter(ImageFilter.SHARPEN)
    return image


def _ocr_image(image_path):
    with Image.open(image_path) as image:
        processed = _prepare_image(image.convert("RGB"))
        text = pytesseract.image_to_string(processed, config="--psm 6")
    return normalize_extracted_text(text)


def _ocr_pdf_page(page):
    pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
    image = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    processed = _prepare_image(image)
    text = pytesseract.image_to_string(processed, config="--psm 6")
    return normalize_extracted_text(text)


def _extract_pdf_text(file_path):
    try:
        document = fitz.open(file_path)
    except Exception as exc:
        raise ValueError("Document is unreadable or corrupted.") from exc

    try:
        pages = []
        for page in document:
            page_text = normalize_extracted_text(page.get_text("text"))
            if page_text:
                pages.append(page_text)

        combined_text = "\n\n".join(pages).strip()

        if len(combined_text) < 20:
            ocr_pages = []
            for page in document:
                ocr_text = _ocr_pdf_page(page)
                if ocr_text:
                    ocr_pages.append(ocr_text)

            combined_text = "\n\n".join(ocr_pages).strip()

        if not combined_text:
            raise ValueError("Document is empty or unreadable.")

        return combined_text
    finally:
        document.close()


def _extract_image_text(file_path):
    try:
        text = _ocr_image(file_path)
    except Exception as exc:
        raise ValueError("Document is empty or unreadable.") from exc

    if not text:
        raise ValueError("Document is empty or unreadable.")

    return text


def extract_text_from_file(file_path, file_type=None):
    path = Path(file_path)
    if not path.exists() or path.stat().st_size == 0:
        raise ValueError("Document is empty or unreadable.")

    detected_type = (file_type or path.suffix.lower().lstrip(".")).lower()

    if detected_type not in {"pdf", "png", "jpg", "jpeg"}:
        raise ValueError("Unsupported file type.")

    if detected_type == "pdf":
        return _extract_pdf_text(str(path))
    return _extract_image_text(str(path))
