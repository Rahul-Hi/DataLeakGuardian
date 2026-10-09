import io
import shutil
from pathlib import Path
from unittest.mock import patch

import fitz
import pytest
from flask import Flask
from PIL import Image

from app import create_app
from app.database import is_postgres
from app.services.extraction_service import (
    extract_text_from_file,
    is_tesseract_available,
)
from app.services.storage_service import (
    LocalStorageBackend,
    get_storage,
)
from auth_helpers import create_authenticated_test_client


def _csrf_token(client, path="/"):
    response = client.get(path)
    html = response.get_data(as_text=True)
    marker = 'name="csrf_token" value="'
    start = html.find(marker)
    assert start != -1
    start += len(marker)
    end = html.find('"', start)
    return html[start:end]


def _make_digital_pdf(text: str) -> bytes:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text, fontsize=14)
    stream = io.BytesIO()
    doc.save(stream)
    doc.close()
    return stream.getvalue()


def _make_scanned_image_bytes(text: str = "Scanned invoice") -> bytes:
    img = Image.new("RGB", (200, 100), color=(255, 255, 255))
    stream = io.BytesIO()
    img.save(stream, format="PNG")
    return stream.getvalue()


def _make_scanned_pdf_bytes() -> bytes:
    img_bytes = _make_scanned_image_bytes()
    doc = fitz.open()
    page = doc.new_page(width=300, height=300)
    page.insert_image(page.rect, stream=img_bytes)
    stream = io.BytesIO()
    doc.save(stream)
    doc.close()
    return stream.getvalue()


# ----------------------------------------------------------------------
# 1. VERCEL ENTRY POINT TESTS
# ----------------------------------------------------------------------

def test_vercel_entrypoint_can_be_imported():
    """Verify api/index.py exports module-level 'app' without duplicating initialization."""
    import api.index

    assert hasattr(api.index, "app")
    assert isinstance(api.index.app, Flask)
    assert "web" in api.index.app.blueprints
    assert api.index.app.config.get("MAX_CONTENT_LENGTH") == 4 * 1024 * 1024


def test_vercel_entrypoint_preserves_application_factory(tmp_path):
    """Verify application factory can still create independent test app instances."""
    test_db = tmp_path / "factory_test.db"
    app = create_app({"TESTING": True, "DATABASE_PATH": str(test_db)})
    assert isinstance(app, Flask)
    assert app.config["TESTING"] is True


# ----------------------------------------------------------------------
# 2. UPLOAD LIMIT BOUNDARY TESTS
# ----------------------------------------------------------------------

def test_upload_size_enforcement_boundary():
    """Verify files below, at, and above the 4 MB limit are handled correctly."""
    app, client, _ = create_authenticated_test_client()

    # 1. Below limit (small valid digital PDF) -> accepted
    valid_pdf = _make_digital_pdf("Valid PDF document within normal limits.")
    res_valid = client.post(
        "/",
        data={
            "csrf_token": _csrf_token(client, "/"),
            "file": (io.BytesIO(valid_pdf), "valid.pdf"),
        },
        content_type="multipart/form-data",
    )
    assert res_valid.status_code == 200
    assert "File size exceeds" not in res_valid.get_data(as_text=True)

    # 2. Strictly above limit -> rejected with 413 and clear error
    oversized_data = b"%PDF-1.4\n" + (b"0" * (4 * 1024 * 1024 + 10))
    res_oversized = client.post(
        "/",
        data={
            "csrf_token": _csrf_token(client, "/"),
            "file": (io.BytesIO(oversized_data), "too_large.pdf"),
        },
        content_type="multipart/form-data",
    )
    assert res_oversized.status_code == 413
    assert "File size exceeds the 4 MB limit." in res_oversized.get_data(as_text=True)


def test_text_scanner_size_limit_enforcement():
    """Verify text scanner also enforces 4 MB limit."""
    app, client, _ = create_authenticated_test_client()

    large_text = "x" * (4 * 1024 * 1024 + 100)
    response = client.post(
        "/scan-text",
        data={
            "csrf_token": _csrf_token(client, "/"),
            "text_content": large_text,
        },
        follow_redirects=True,
    )
    html = response.get_data(as_text=True)
    assert "Text content exceeds the 4 MB limit." in html or "exceeds" in html.lower()


# ----------------------------------------------------------------------
# 3. OCR GRACEFUL HANDLING TESTS
# ----------------------------------------------------------------------

def test_missing_tesseract_image_upload_returns_actionable_error():
    """When Tesseract is missing, image uploads must return an actionable message, not HTTP 500."""
    app, client, _ = create_authenticated_test_client()

    img_data = _make_scanned_image_bytes()

    with patch("app.services.extraction_service.is_tesseract_available", return_value=False):
        response = client.post(
            "/",
            data={
                "csrf_token": _csrf_token(client, "/"),
                "file": (io.BytesIO(img_data), "photo.png"),
            },
            content_type="multipart/form-data",
        )

    # Must be handled gracefully (HTTP 200 with flash message), NEVER unhandled 500
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "OCR engine (Tesseract) is not installed on this server" in html
    assert "Images cannot be processed without OCR" in html


def test_missing_tesseract_scanned_pdf_returns_actionable_error():
    """When Tesseract is missing, scanned (image-only) PDFs must return an actionable message."""
    app, client, _ = create_authenticated_test_client()

    scanned_pdf = _make_scanned_pdf_bytes()

    with patch("app.services.extraction_service.is_tesseract_available", return_value=False):
        response = client.post(
            "/",
            data={
                "csrf_token": _csrf_token(client, "/"),
                "file": (io.BytesIO(scanned_pdf), "scanned_doc.pdf"),
            },
            content_type="multipart/form-data",
        )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "OCR engine (Tesseract) is not installed on this server" in html
    assert "Scanned PDFs and image-only documents cannot be processed" in html


def test_digital_pdf_extracts_cleanly_without_tesseract():
    """Digital PDFs extract text directly via PyMuPDF without ever invoking or needing Tesseract."""
    expected_text = "This is a digital text PDF containing sensitive info: test@example.com and Aadhaar 1234 5678 9012."
    pdf_bytes = _make_digital_pdf(expected_text)

    # Even if Tesseract is completely missing, digital PDF extraction MUST succeed
    with patch("app.services.extraction_service.is_tesseract_available", return_value=False):
        extracted = extract_text_from_file(pdf_bytes, "pdf")

    assert "digital text PDF" in extracted
    assert "test@example.com" in extracted


# ----------------------------------------------------------------------
# 4. ENVIRONMENT & LOCAL DEV BEHAVIOR TESTS
# ----------------------------------------------------------------------

def test_local_development_behavior_default():
    """Verify local development preserves SQLite and LocalStorageBackend by default."""
    with patch.dict("os.environ", {}, clear=True):
        assert not is_postgres()
        storage = get_storage()
        assert isinstance(storage, LocalStorageBackend)


def test_production_r2_storage_configuration_validation():
    """Verify STORAGE_BACKEND=r2 fails fast if credentials are missing and never silently falls back."""
    # 1. Explicit STORAGE_BACKEND='r2' with missing credentials
    with patch.dict("os.environ", {"STORAGE_BACKEND": "r2"}, clear=True):
        with pytest.raises(ValueError, match="Incomplete Cloudflare R2 configuration"):
            get_storage()

    # 2. Incomplete R2 credentials without STORAGE_BACKEND
    with patch.dict("os.environ", {"R2_BUCKET_NAME": "my-bucket"}, clear=True):
        with pytest.raises(ValueError, match="Incomplete Cloudflare R2 configuration"):
            get_storage()


def test_production_postgres_detection():
    """Verify DATABASE_URL pointing to PostgreSQL is detected accurately."""
    with patch.dict("os.environ", {"DATABASE_URL": "postgresql://usr:pwd@ep-xyz.neon.tech/db"}, clear=True):
        assert is_postgres()


# ----------------------------------------------------------------------
# 5. PRODUCTION SECRET-KEY VALIDATION TESTS
# ----------------------------------------------------------------------

def test_production_startup_fails_when_flask_secret_key_is_absent(monkeypatch):
    """Verify production startup fails fast when FLASK_SECRET_KEY is missing or empty."""
    monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)

    # 1. Via FLASK_ENV=production
    monkeypatch.setenv("FLASK_ENV", "production")
    with pytest.raises(ValueError, match="FLASK_SECRET_KEY environment variable is missing or empty"):
        create_app()

    # 2. Via VERCEL=1
    monkeypatch.delenv("FLASK_ENV", raising=False)
    monkeypatch.setenv("VERCEL", "1")
    with pytest.raises(ValueError, match="FLASK_SECRET_KEY environment variable is missing or empty"):
        create_app()

    # 3. Via explicit config PRODUCTION=True
    monkeypatch.delenv("VERCEL", raising=False)
    with pytest.raises(ValueError, match="FLASK_SECRET_KEY environment variable is missing or empty"):
        create_app({"PRODUCTION": True})


def test_production_startup_succeeds_when_flask_secret_key_is_set(monkeypatch):
    """Verify production startup succeeds when FLASK_SECRET_KEY and DATABASE_URL are properly set."""
    from unittest.mock import patch
    strong_secret = "f4c9a87d6e5b4c3a210987654321fedcba0987654321fedcba0987654321fedc"
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("FLASK_SECRET_KEY", strong_secret)
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@ep-test.neon.tech/neondb?sslmode=require")

    with patch("app.__init__.init_db"):
        app = create_app()
    assert app.config["SECRET_KEY"] == strong_secret


def test_local_development_startup_succeeds_without_production_secret(monkeypatch):
    """Verify local development continues to work without requiring a production secret."""
    monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)
    monkeypatch.delenv("FLASK_ENV", raising=False)
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("VERCEL_ENV", raising=False)

    app = create_app({"TESTING": True})
    assert app.config.get("SECRET_KEY") is not None
    assert len(app.config["SECRET_KEY"]) > 0


# ----------------------------------------------------------------------
# 6. PRODUCTION DATABASE_URL VALIDATION TESTS
# ----------------------------------------------------------------------

def test_production_startup_fails_when_database_url_is_absent(monkeypatch):
    """Verify production startup fails fast when DATABASE_URL is missing."""
    strong_secret = "a" * 64
    monkeypatch.setenv("FLASK_SECRET_KEY", strong_secret)
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ValueError, match="DATABASE_URL environment variable is missing or empty"):
        create_app()


def test_production_startup_fails_when_database_url_is_not_postgresql(monkeypatch):
    """Verify production startup fails fast when DATABASE_URL does not identify a PostgreSQL connection."""
    strong_secret = "b" * 64
    monkeypatch.setenv("FLASK_SECRET_KEY", strong_secret)
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///local.db")

    with pytest.raises(ValueError, match="DATABASE_URL must be a PostgreSQL connection URL"):
        create_app()


def test_production_startup_succeeds_when_database_url_is_postgresql(monkeypatch):
    """Verify production startup succeeds when DATABASE_URL is a valid PostgreSQL URI."""
    strong_secret = "c" * 64
    monkeypatch.setenv("FLASK_SECRET_KEY", strong_secret)
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@ep-test.neon.tech/neondb?sslmode=require")

    # create_app() will try to init_db() in non-production... but in production we skip it.
    # However, psycopg.connect() would fail without a real server, so we patch init_db.
    from unittest.mock import patch
    with patch("app.__init__.init_db"):
        app = create_app()
    assert app is not None


def test_local_development_startup_succeeds_without_database_url(monkeypatch):
    """Verify local development startup does not require DATABASE_URL."""
    monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)
    monkeypatch.delenv("FLASK_ENV", raising=False)
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("VERCEL_ENV", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    app = create_app({"TESTING": True})
    assert app is not None


# ----------------------------------------------------------------------
# 7. PRODUCTION STORAGE BACKEND GUARD TESTS
# ----------------------------------------------------------------------

def test_production_storage_fails_without_storage_backend_configured(monkeypatch):
    """Verify get_storage() fails fast in a production environment when STORAGE_BACKEND is not configured."""
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("STORAGE_BACKEND", raising=False)
    monkeypatch.delenv("R2_BUCKET_NAME", raising=False)
    monkeypatch.delenv("R2_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("R2_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("R2_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("R2_ACCOUNT_ID", raising=False)

    with pytest.raises(ValueError, match="STORAGE_BACKEND environment variable is not configured"):
        get_storage()


def test_local_development_storage_defaults_to_local_backend(monkeypatch):
    """Verify get_storage() returns LocalStorageBackend when no production indicators are set."""
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("FLASK_ENV", raising=False)
    monkeypatch.delenv("STORAGE_BACKEND", raising=False)
    monkeypatch.delenv("R2_BUCKET_NAME", raising=False)
    monkeypatch.delenv("R2_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("R2_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("R2_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("R2_ACCOUNT_ID", raising=False)

    storage = get_storage()
    assert isinstance(storage, LocalStorageBackend)
