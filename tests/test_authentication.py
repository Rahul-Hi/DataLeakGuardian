import os
import re
import uuid
from io import BytesIO
from pathlib import Path

import fitz
from werkzeug.security import check_password_hash

from app import create_app
from app.database import get_db


def _make_pdf_bytes(text):
    pdf = fitz.open()
    page = pdf.new_page()
    page.insert_text((72, 72), text, fontsize=14)
    stream = BytesIO()
    pdf.save(stream)
    pdf.close()
    stream.seek(0)
    return stream.read()


def _csrf_token(client, path):
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match
    return match.group(1).decode()


def _new_app_client():
    config = {"TESTING": True, "WTF_CSRF_ENABLED": True}
    if os.environ.get("DATABASE_PATH"):
        config["DATABASE_PATH"] = os.environ["DATABASE_PATH"]
    app = create_app(config)
    return app, app.test_client()


def _register(app, client, name="Test User", email=None, password="correct-horse-77"):
    email = email or f"user-{uuid.uuid4().hex}@example.test"
    response = client.post(
        "/register",
        data={"csrf_token": _csrf_token(client, "/register"), "name": name, "email": email, "password": password},
    )
    with app.app_context():
        user = get_db().execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    return email, user["id"] if user else None, response


def _login(client, email, password="correct-horse-77"):
    return client.post(
        "/login",
        data={"csrf_token": _csrf_token(client, "/login"), "email": email, "password": password},
    )


def _cleanup_users(app, *user_ids):
    with app.app_context():
        db = get_db()
        for user_id in user_ids:
            if user_id is None:
                continue
            scans = db.execute("SELECT file_name, report_name FROM documents WHERE user_id = ?", (user_id,)).fetchall()
            for scan in scans:
                for folder, filename in (("UPLOAD_FOLDER", scan["file_name"]), ("REPORT_FOLDER", scan["report_name"])):
                    if filename and Path(filename).name == filename:
                        (Path(app.config[folder]) / filename).unlink(missing_ok=True)
            db.execute("DELETE FROM documents WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()


def _upload_pdf(client, filename="owned.pdf"):
    response = client.post(
        "/",
        data={
            "csrf_token": _csrf_token(client, "/"),
            "file": (BytesIO(_make_pdf_bytes("Email: owner@example.com")), filename),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert b"Analysis Result" in response.data
    return response


def test_registration_stores_hashed_password():
    app, client = _new_app_client()
    email = f"register-{uuid.uuid4().hex}@example.test"
    try:
        email, user_id, response = _register(app, client, "Taylor Example", email)
        assert response.status_code == 302
        assert response.location.endswith("/login")
        with app.app_context():
            user = get_db().execute("SELECT name, email, password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
        assert user["name"] == "Taylor Example"
        assert user["email"] == email
        assert user["password_hash"] != "correct-horse-77"
        assert check_password_hash(user["password_hash"], "correct-horse-77")
    finally:
        with app.app_context():
            user = get_db().execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        _cleanup_users(app, user["id"] if user else None)


def test_duplicate_email_registration_is_rejected():
    app, client = _new_app_client()
    email = f"duplicate-{uuid.uuid4().hex}@example.test"
    try:
        _, user_id, first = _register(app, client, email=email)
        duplicate = client.post(
            "/register",
            data={"csrf_token": _csrf_token(client, "/register"), "name": "Second User", "email": email, "password": "another-password-88"},
        )
        assert first.status_code == 302
        assert duplicate.status_code == 200
        assert b"An account with that email already exists." in duplicate.data
        with app.app_context():
            count = get_db().execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,)).fetchone()[0]
        assert count == 1
    finally:
        with app.app_context():
            user = get_db().execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        _cleanup_users(app, user["id"] if user else None)


def test_login_accepts_valid_credentials_and_invalid_login_is_clear():
    app, client = _new_app_client()
    email, user_id, registration = _register(app, client)
    try:
        assert registration.status_code == 302
        invalid = _login(client, email, "wrong-password-99")
        assert invalid.status_code == 200
        assert b"Invalid email or password." in invalid.data
        assert b"wrong-password-99" not in invalid.data
        valid = _login(client, email)
        assert valid.status_code == 302
        assert valid.location.endswith("/dashboard")
        dashboard = client.get("/dashboard")
        assert dashboard.status_code == 200
        assert b"Test User" in dashboard.data
    finally:
        _cleanup_users(app, user_id)


def test_unauthenticated_users_cannot_open_scan_pages():
    app, client = _new_app_client()
    for path in ("/", "/dashboard", "/history", "/history/1", "/history/1/report"):
        response = client.get(path)
        assert response.status_code == 302
        assert response.location.endswith("/login")


def test_authenticated_upload_is_assigned_to_current_user():
    app, client = _new_app_client()
    email, user_id, _ = _register(app, client)
    try:
        assert _login(client, email).status_code == 302
        _upload_pdf(client)
        with app.app_context():
            scan = get_db().execute(
                "SELECT user_id, status, findings_json FROM documents WHERE original_name = 'owned.pdf' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        assert scan["user_id"] == user_id
        assert scan["status"] == "completed"
        assert "owner@example.com" not in scan["findings_json"]
    finally:
        _cleanup_users(app, user_id)


def test_user_cannot_view_download_or_delete_another_users_scan():
    app, owner_client = _new_app_client()
    owner_email, owner_id, _ = _register(app, owner_client, name="Owner")
    other_client = app.test_client()
    other_email, other_id, _ = _register(app, other_client, name="Other")
    try:
        assert _login(owner_client, owner_email).status_code == 302
        _upload_pdf(owner_client, "private-to-owner.pdf")
        with app.app_context():
            scan = get_db().execute(
                "SELECT * FROM documents WHERE user_id = ? AND original_name = 'private-to-owner.pdf' ORDER BY id DESC LIMIT 1",
                (owner_id,),
            ).fetchone()
            scan_id = scan["id"]
            report_name = scan["report_name"]
        assert _login(other_client, other_email).status_code == 302

        assert other_client.get(f"/history/{scan_id}").status_code == 404
        assert other_client.get(f"/history/{scan_id}/report").status_code == 404
        denied_delete = other_client.post(
            f"/history/{scan_id}/delete", data={"csrf_token": _csrf_token(other_client, "/")}
        )
        assert denied_delete.status_code == 404
        with app.app_context():
            assert get_db().execute("SELECT id FROM documents WHERE id = ?", (scan_id,)).fetchone() is not None
        assert (Path(app.config["REPORT_FOLDER"]) / report_name).is_file()
    finally:
        _cleanup_users(app, owner_id, other_id)


def test_logout_clears_authenticated_session():
    app, client = _new_app_client()
    email, user_id, _ = _register(app, client)
    try:
        assert _login(client, email).status_code == 302
        with client.session_transaction() as auth_session:
            assert "user_id" in auth_session
        response = client.post("/logout", data={"csrf_token": _csrf_token(client, "/dashboard")})
        assert response.status_code == 302
        assert response.location.endswith("/login")
        with client.session_transaction() as auth_session:
            assert "user_id" not in auth_session
        assert client.get("/").location.endswith("/login")
    finally:
        _cleanup_users(app, user_id)


def test_csrf_required_for_auth_upload_and_delete_posts():
    app, client = _new_app_client()
    assert client.post("/register", data={"name": "No Token", "email": "csrf@example.test", "password": "password-123"}).status_code == 400
    assert client.post("/login", data={"email": "csrf@example.test", "password": "password-123"}).status_code == 400

    email, user_id, _ = _register(app, client)
    try:
        assert _login(client, email).status_code == 302
        assert client.post(
            "/", data={"file": (BytesIO(_make_pdf_bytes("No token")), "csrf.pdf")}, content_type="multipart/form-data"
        ).status_code == 400
        _upload_pdf(client, "csrf-delete.pdf")
        with app.app_context():
            scan = get_db().execute(
                "SELECT id FROM documents WHERE user_id = ? AND original_name = 'csrf-delete.pdf' ORDER BY id DESC LIMIT 1",
                (user_id,),
            ).fetchone()
        assert client.post(f"/history/{scan['id']}/delete").status_code == 400
        assert client.post("/logout").status_code == 400
    finally:
        _cleanup_users(app, user_id)
