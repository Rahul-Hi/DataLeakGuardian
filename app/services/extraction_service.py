import io
import os
import re
import shutil
from pathlib import Path

import fitz
import pytesseract
from PIL import Image, ImageFilter, ImageOps

TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if os.path.exists(TESSERACT_PATH):
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH


def is_tesseract_available() -> bool:
    """Check whether the Tesseract OCR binary is installed and accessible."""
    cmd = getattr(pytesseract.pytesseract, "tesseract_cmd", "tesseract")
    if cmd and cmd != "tesseract":
        if os.path.isfile(cmd):
            return True
        if shutil.which(cmd):
            return True
    if shutil.which("tesseract"):
        return True
    if os.path.isfile(TESSERACT_PATH):
        return True
    return False


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


def _ocr_image(image_input):
    if isinstance(image_input, (bytes, bytearray)):
        img_ctx = Image.open(io.BytesIO(image_input))
    else:
        img_ctx = Image.open(image_input)

    with img_ctx as image:
        processed = _prepare_image(image.convert("RGB"))
        text = pytesseract.image_to_string(processed, config="--psm 6")
    return normalize_extracted_text(text)


def _ocr_pdf_page(page):
    pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
    image = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    processed = _prepare_image(image)
    text = pytesseract.image_to_string(processed, config="--psm 6")
    return normalize_extracted_text(text)


def _get_gemini_api_key() -> str:
    """Safely retrieves the Gemini API key from environment without exposing it in logs."""
    return os.environ.get("GEMINI_API_KEY", "").strip()


def _call_gemini_vision_ocr(image_bytes: bytes, mime_type: str = "image/png") -> str:
    """
    Calls the Google Gemini API to extract raw text from image bytes.
    Enforces in-memory processing, strict OCR prompt, timeouts, and safe error handling.
    """
    import base64
    import json
    import socket
    import urllib.error
    import urllib.request

    api_key = _get_gemini_api_key()
    if not api_key:
        raise ValueError(
            "OCR engine (Tesseract) is not installed on this server and GEMINI_API_KEY is not configured. "
            "Images and scanned documents cannot be processed. "
            "Please upload a digital text PDF or paste text directly."
        )

    model = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite").strip() or "gemini-3.5-flash-lite"
    timeout_sec = float(os.environ.get("GEMINI_TIMEOUT_SECONDS", "8.0"))

    # Convert image bytes to Base64 inline data
    b64_data = base64.b64encode(image_bytes).decode("ascii")

    # Strict OCR instruction: extract verbatim text only
    system_instruction = (
        "You are an OCR transcription engine. Extract all visible text from this document image "
        "exactly as written, preserving layout, spacing, and numbers. "
        "Do not explain, summarize, sanitize, categorize, or redact any data. "
        "Return ONLY the transcribed text."
    )

    request_payload = {
        "contents": [
            {
                "parts": [
                    {"text": system_instruction},
                    {
                        "inlineData": {
                            "mimeType": mime_type,
                            "data": b64_data,
                        }
                    },
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.0,
            "maxOutputTokens": 8192,
        },
    }

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    req_data = json.dumps(request_payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=req_data,
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
            "User-Agent": "DataLeakGuardian-OCR/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as response:
            resp_body = response.read().decode("utf-8")
            data = json.loads(resp_body)
    except urllib.error.HTTPError as err:
        if err.code == 429:
            raise ValueError("OCR service rate limit reached. Please wait a moment and try again.") from err
        if err.code in (400, 401, 403):
            raise ValueError("OCR service authentication failed or invalid configuration.") from err
        if err.code == 404:
            raise ValueError(
                f"OCR service model '{model}' was not found or is unavailable for this API key (HTTP 404). "
                "Please verify the GEMINI_MODEL setting."
            ) from err
        raise ValueError(f"OCR service request failed (HTTP {err.code}). Please try again.") from err
    except (urllib.error.URLError, socket.timeout, TimeoutError) as err:
        raise ValueError("OCR service request timed out or network unavailable. Please try again.") from err
    except Exception as err:
        raise ValueError("OCR service returned an unreadable response.") from err

    # Parse response structure safely
    candidates = data.get("candidates")
    if not candidates or not isinstance(candidates, list):
        raise ValueError("OCR engine returned no content for this document.")

    content = candidates[0].get("content", {})
    parts = content.get("parts", [])
    extracted_chunks = []
    for part in parts:
        if isinstance(part, dict) and "text" in part:
            extracted_chunks.append(part["text"])

    raw_text = "".join(extracted_chunks).strip()
    if not raw_text:
        raise ValueError("Document appears to be blank or contains no legible text.")

    return normalize_extracted_text(raw_text)


def _extract_pdf_text(source):
    try:
        if isinstance(source, (bytes, bytearray)):
            document = fitz.open(stream=source, filetype="pdf")
        else:
            document = fitz.open(source)
    except Exception as exc:
        raise ValueError("Document is unreadable or corrupted.") from exc

    try:
        pages = []
        for page in document:
            page_text = normalize_extracted_text(page.get_text("text"))
            if page_text:
                pages.append(page_text)

        combined_text = "\n\n".join(pages).strip()

        # If digital text is missing or extremely sparse (< 20 chars), attempt OCR
        if len(combined_text) < 20:
            if is_tesseract_available():
                ocr_pages = []
                for page in document:
                    ocr_text = _ocr_pdf_page(page)
                    if ocr_text:
                        ocr_pages.append(ocr_text)
                combined_text = "\n\n".join(ocr_pages).strip()
            elif _get_gemini_api_key():
                ocr_pages = []
                for page in document:
                    pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                    page_png_bytes = pix.tobytes("png")
                    ocr_text = _call_gemini_vision_ocr(page_png_bytes, "image/png")
                    if ocr_text:
                        ocr_pages.append(ocr_text)
                combined_text = "\n\n".join(ocr_pages).strip()
            else:
                raise ValueError(
                    "OCR engine (Tesseract) is not installed on this server and GEMINI_API_KEY is not configured. "
                    "Scanned PDFs and image-only documents cannot be processed. "
                    "Please upload a digital text PDF or paste text directly."
                )

        if not combined_text:
            raise ValueError("Document is empty or unreadable.")

        return combined_text
    finally:
        document.close()


def _extract_image_text(source, file_type="png"):
    if is_tesseract_available():
        try:
            text = _ocr_image(source)
        except Exception as exc:
            raise ValueError("Document is empty or unreadable.") from exc

        if not text:
            raise ValueError("Document is empty or unreadable.")
        return text

    if _get_gemini_api_key():
        if isinstance(source, (bytes, bytearray)):
            raw_bytes = bytes(source)
        else:
            raw_bytes = Path(source).read_bytes()

        mime_lookup = {
            "png": "image/png",
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
        }
        mime_type = mime_lookup.get(file_type.lower().lstrip("."), "image/png")
        return _call_gemini_vision_ocr(raw_bytes, mime_type)

    raise ValueError(
        "OCR engine (Tesseract) is not installed on this server and GEMINI_API_KEY is not configured. "
        "Images cannot be processed without OCR. "
        "Please upload a digital text PDF or paste text directly."
    )


def extract_text_from_file(file_source, file_type=None):
    if isinstance(file_source, (bytes, bytearray)):
        if len(file_source) == 0:
            raise ValueError("Document is empty or unreadable.")
        detected_type = (file_type or "").lower().lstrip(".")
        if detected_type not in {"pdf", "png", "jpg", "jpeg"}:
            raise ValueError("Unsupported file type.")
        if detected_type == "pdf":
            return _extract_pdf_text(file_source)
        return _extract_image_text(file_source, detected_type)

    path = Path(file_source)
    if not path.exists() or path.stat().st_size == 0:
        raise ValueError("Document is empty or unreadable.")

    detected_type = (file_type or path.suffix.lower().lstrip(".")).lower()

    if detected_type not in {"pdf", "png", "jpg", "jpeg"}:
        raise ValueError("Unsupported file type.")

    if detected_type == "pdf":
        return _extract_pdf_text(str(path))
    return _extract_image_text(str(path), detected_type)
