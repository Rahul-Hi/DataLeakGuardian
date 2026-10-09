import logging
from io import BytesIO
from pathlib import Path

import fitz
from werkzeug.datastructures import FileStorage

from app import create_app
from app.database import get_db
from app.services.upload_service import save_uploaded_file
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


def test_oversized_upload_is_rejected():
    _, client, _ = create_authenticated_test_client()

    response = client.post(
        "/",
        data={"file": (BytesIO(b"x" * (5 * 1024 * 1024 + 1)), "large.pdf")},
        content_type="multipart/form-data",
    )

    html = response.get_data(as_text=True)
    assert response.status_code == 413
    assert "File size exceeds the 5 MB limit." in html


def test_unsupported_extension_is_rejected():
    _, client, _ = create_authenticated_test_client()

    response = client.post(
        "/",
        data={"file": (BytesIO(b"some text"), "notes.txt")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Only PDF, PNG, JPG, and JPEG files are allowed." in html


def test_corrupted_or_invalid_file_is_rejected():
    _, client, _ = create_authenticated_test_client()

    response = client.post(
        "/",
        data={"file": (BytesIO(b"not a real pdf"), "broken.pdf")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "corrupted or invalid" in html.lower()


def test_path_traversal_filename_is_sanitized():
    app = create_app()
    with app.app_context():
        file_storage = FileStorage(
            stream=BytesIO(_make_pdf_bytes("Safe Name: 1234 5678 9012")),
            filename="../../../../evil.pdf",
            content_type="application/pdf",
        )
        result = save_uploaded_file(file_storage)

    assert result["original_name"] == "evil.pdf"
    assert ".." not in result["file_name"]
    assert result["file_name"].endswith(".pdf")


def test_arbitrary_report_access_is_denied():
    app = create_app()
    client = app.test_client()

    response = client.get("/report/../../app/__init__.py")

    assert response.status_code in {403, 404}


def test_sensitive_values_not_in_logs_or_responses(caplog):
    _, client, _ = create_authenticated_test_client()

    with caplog.at_level(logging.INFO):
        response = client.post(
            "/",
            data={
                "file": (
                    BytesIO(
                        _make_pdf_bytes(
                            "Aadhaar: 1234 5678 9012\nEmail: alice@example.com\nPhone: +91 98765 43210"
                        )
                    ),
                    "sensitive.pdf",
                )
            },
            content_type="multipart/form-data",
        )

    html = response.get_data(as_text=True)
    assert "1234 5678 9012" not in html
    assert "alice@example.com" not in html
    assert "+91 98765 43210" not in html
    assert "1234 5678 9012" not in caplog.text
    assert "alice@example.com" not in caplog.text
    assert "+91 98765 43210" not in caplog.text


def test_masking_still_works_for_html_response():
    _, client, _ = create_authenticated_test_client()

    response = client.post(
        "/",
        data={
            "file": (
                BytesIO(
                    _make_pdf_bytes(
                        "Aadhaar: 1234 5678 9012\nEmail: alice@example.com\nPhone: +91 98765 43210"
                    )
                ),
                "sensitive.pdf",
            )
        },
        content_type="multipart/form-data",
    )

    html = response.get_data(as_text=True)
    assert "XXXX XXXX 9012" in html or "XXXX" in html
    assert "alice@example.com" not in html
    assert "+91 98765 43210" not in html


def test_valid_upload_still_works():
    _, client, _ = create_authenticated_test_client()

    response = client.post(
        "/",
        data={"file": (BytesIO(_make_pdf_bytes("Customer Name: Alice Johnson")), "valid.pdf")},
        content_type="multipart/form-data",
    )

    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Analysis Result" in html
    assert "valid.pdf" in html


def test_secret_key_environment_override_takes_precedence(monkeypatch):
    monkeypatch.setenv("FLASK_SECRET_KEY", "env-override-secret")
    app = create_app()

    assert app.config["SECRET_KEY"] == "env-override-secret"


def test_secret_key_fallback_is_stable_across_restarts(monkeypatch):
    monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)

    first = create_app().config["SECRET_KEY"]
    second = create_app().config["SECRET_KEY"]

    assert first == second


def test_runtime_entrypoint_keeps_debug_disabled_and_loopback_only():
    run_py = Path(__file__).resolve().parents[1] / "run.py"
    source = run_py.read_text(encoding="utf-8")

    assert "debug=False" in source
    assert 'host="127.0.0.1"' in source


def test_create_app_preserves_existing_user_and_scan_history():
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})

    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            ("Persisted User", "persist@example.test", "placeholder-hash"),
        )
        user_id = db.execute(
            "SELECT id FROM users WHERE email = ?", ("persist@example.test",)
        ).fetchone()["id"]
        db.execute(
            """
            INSERT INTO documents (
                user_id, original_name, file_name, file_type, file_size, stored_path,
                status, total_score, risk_level, finding_count, findings_json, risk_json,
                report_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                "persisted.pdf",
                "persisted_scan.pdf",
                "pdf",
                256,
                "uploads/persisted_scan.pdf",
                "completed",
                80,
                "medium",
                3,
                "[]",
                "{}",
                "persisted_report.pdf",
            ),
        )
        db.commit()

    restarted = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})
    with restarted.app_context():
        db = get_db()
        persisted = db.execute(
            "SELECT COUNT(*) AS count FROM documents WHERE file_name = ?",
            ("persisted_scan.pdf",),
        ).fetchone()["count"]
        assert persisted == 1

        user_exists = db.execute(
            "SELECT COUNT(*) AS count FROM users WHERE email = ?",
            ("persist@example.test",),
        ).fetchone()["count"]
        assert user_exists == 1

        db.execute("DELETE FROM documents WHERE file_name = ?", ("persisted_scan.pdf",))
        db.execute("DELETE FROM users WHERE email = ?", ("persist@example.test",))
        db.commit()


def test_secure_cookies_and_security_headers_are_enabled():
    app = create_app()
    client = app.test_client()

    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["SESSION_COOKIE_SECURE"] is True

    response = client.get("/login")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert response.headers["Content-Security-Policy"] == (
        "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
    )
