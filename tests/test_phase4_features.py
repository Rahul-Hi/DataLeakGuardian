import csv
import io
import json
import uuid
from io import BytesIO

import fitz
import pytest

from app import create_app
from app.database import get_db
from auth_helpers import create_authenticated_test_client


def _make_pdf_bytes(text):
    pdf = fitz.open()
    page = pdf.new_page()
    page.insert_text((72, 72), text, fontsize=14)
    stream = BytesIO()
    pdf.save(stream)
    pdf.close()
    stream.seek(0)
    return stream.read()


def _csrf_token(client, path="/dashboard"):
    response = client.get(path)
    import re
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match
    return match.group(1).decode()


# -------------------------------------------------------------
# 1. DIRECT TEXT SCANNER TESTS
# -------------------------------------------------------------

def test_direct_text_scanner_detects_and_masks_sensitive_data():
    app, client, user_id = create_authenticated_test_client()
    raw_snippet = (
        "Sensitive customer dispatch:\n"
        "Name: John Doe\n"
        "Aadhaar Number: 1234 5678 9012\n"
        "Primary Email: secret@enterprise.test\n"
        "Emergency Contact: +91 98765 43210"
    )

    response = client.post(
        "/scan-text",
        data={
            "csrf_token": _csrf_token(client, "/"),
            "snippet_name": "customer_support_note",
            "text_content": raw_snippet,
        },
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)

    # Result inspection
    assert "Analysis Result" in html
    assert "customer_support_note.txt" in html
    assert "XXXX XXXX 9012" in html
    assert "se" in html and "@enterprise.test" in html
    # Raw values NEVER exposed
    assert "1234 5678 9012" not in html
    assert "secret@enterprise.test" not in html
    assert "+91 98765 43210" not in html

    # History integration
    with app.app_context():
        scan = get_db().execute(
            "SELECT * FROM documents WHERE user_id = ? AND original_name = 'customer_support_note.txt'",
            (user_id,),
        ).fetchone()
        assert scan is not None
        assert scan["file_type"] == "txt"
        assert scan["finding_count"] >= 2
        assert scan["status"] == "completed"


def test_direct_text_scanner_handles_empty_and_whitespace():
    app, client, _ = create_authenticated_test_client()

    response = client.post(
        "/scan-text",
        data={"csrf_token": _csrf_token(client, "/"), "text_content": "   \n\t  "},
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Please enter or paste text to analyze." in html


def test_direct_text_scanner_rejects_oversized_text():
    app, client, _ = create_authenticated_test_client()

    large_text = "a" * (5 * 1024 * 1024 + 10)
    response = client.post(
        "/scan-text",
        data={"csrf_token": _csrf_token(client, "/"), "text_content": large_text},
        follow_redirects=True,
    )
    # Either 413 from Flask MAX_CONTENT_LENGTH or 200 with validation flash
    assert response.status_code in (200, 413)
    html = response.get_data(as_text=True)
    assert "limit" in html.lower() or "5 mb" in html.lower()


# -------------------------------------------------------------
# 2. CSV AND JSON EXPORT TESTS
# -------------------------------------------------------------

def test_json_and_csv_exports_contain_masked_values_and_metadata():
    app, client, user_id = create_authenticated_test_client()
    raw_text = "Employee PAN: ABCDE1234F, DOB: 14/08/1990, Phone: +91 98765 43210"

    scan_response = client.post(
        "/scan-text",
        data={
            "csrf_token": _csrf_token(client, "/"),
            "snippet_name": "tax_record",
            "text_content": raw_text,
        },
    )
    assert scan_response.status_code == 200

    with app.app_context():
        scan = get_db().execute(
            "SELECT id FROM documents WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,)
        ).fetchone()
        scan_id = scan["id"]

    # --- JSON Export ---
    json_resp = client.get(f"/history/{scan_id}/export/json")
    assert json_resp.status_code == 200
    assert json_resp.mimetype == "application/json"
    assert "attachment; filename=" in json_resp.headers.get("Content-Disposition", "")

    json_data = json.loads(json_resp.get_data(as_text=True))
    assert json_data["scan_id"] == scan_id
    assert json_data["filename"] == "tax_record.txt"
    assert json_data["total_risk_score"] > 0
    assert "findings" in json_data
    assert len(json_data["findings"]) > 0

    # Ensure zero raw PII leaks into JSON export
    raw_json_str = json_resp.get_data(as_text=True)
    assert "ABCDE1234F" not in raw_json_str
    assert "+91 98765 43210" not in raw_json_str
    assert "XXXXX1234F" in raw_json_str

    # --- CSV Export ---
    csv_resp = client.get(f"/history/{scan_id}/export/csv")
    assert csv_resp.status_code == 200
    assert csv_resp.mimetype == "text/csv"
    assert "attachment; filename=" in csv_resp.headers.get("Content-Disposition", "")

    csv_text = csv_resp.get_data(as_text=True)
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    header = rows[0]
    assert "Scan ID" in header
    assert "Masked Sensitive Value" in header
    assert "Risk Level" in header

    # Ensure zero raw PII leaks into CSV export
    assert "ABCDE1234F" not in csv_text
    assert "+91 98765 43210" not in csv_text
    assert "XXXXX1234F" in csv_text


def test_cross_user_export_authorization_denied():
    app, client1, user1_id = create_authenticated_test_client()
    
    # Create distinct second user
    with app.app_context():
        db = get_db()
        email2 = f"user2_{uuid.uuid4().hex[:8]}@example.test"
        from werkzeug.security import generate_password_hash
        cur = db.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            ("User Two", email2, generate_password_hash("pass12345678")),
        )
        db.commit()
        user2_id = cur.lastrowid

    client2 = app.test_client()
    with client2.session_transaction() as sess:
        sess["user_id"] = user2_id

    try:
        scan_resp = client1.post(
            "/scan-text",
            data={
                "csrf_token": _csrf_token(client1, "/"),
                "snippet_name": "user1_secret",
                "text_content": "Aadhaar: 1234 5678 9012",
            },
        )
        assert scan_resp.status_code == 200
        with app.app_context():
            scan = get_db().execute(
                "SELECT id FROM documents WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user1_id,)
            ).fetchone()
            user1_scan_id = scan["id"]

        # User 2 tries to download User 1's JSON and CSV exports
        assert client2.get(f"/history/{user1_scan_id}/export/json").status_code == 404
        assert client2.get(f"/history/{user1_scan_id}/export/csv").status_code == 404
    finally:
        with app.app_context():
            db = get_db()
            db.execute("DELETE FROM users WHERE id = ?", (user2_id,))
            db.commit()


# -------------------------------------------------------------
# 3. SCAN HISTORY SEARCH, FILTER & PAGINATION TESTS
# -------------------------------------------------------------

def test_scan_history_search_by_filename():
    app, client, user_id = create_authenticated_test_client()

    token = uuid.uuid4().hex[:6]
    fn1 = f"alpha_report_{token}.txt"
    fn2 = f"beta_invoice_{token}.txt"

    client.post("/scan-text", data={"csrf_token": _csrf_token(client, "/"), "snippet_name": fn1, "text_content": "Phone: +91 98765 43210"})
    client.post("/scan-text", data={"csrf_token": _csrf_token(client, "/"), "snippet_name": fn2, "text_content": "Email: test@example.com"})

    # Search for alpha
    resp_alpha = client.get(f"/history?search=alpha_report_{token}")
    assert resp_alpha.status_code == 200
    html_alpha = resp_alpha.get_data(as_text=True)
    assert fn1 in html_alpha
    assert fn2 not in html_alpha

    # Search for beta
    resp_beta = client.get(f"/history?search=beta_invoice_{token}")
    assert resp_beta.status_code == 200
    html_beta = resp_beta.get_data(as_text=True)
    assert fn2 in html_beta
    assert fn1 not in html_beta


def test_scan_history_filter_by_risk_level():
    app, client, user_id = create_authenticated_test_client()

    token = uuid.uuid4().hex[:6]
    clean_fn = f"clean_doc_{token}.txt"
    critical_fn = f"critical_doc_{token}.txt"

    client.post("/scan-text", data={"csrf_token": _csrf_token(client, "/"), "snippet_name": clean_fn, "text_content": "Clean company policy text without PII"})
    client.post(
        "/scan-text",
        data={
            "csrf_token": _csrf_token(client, "/"),
            "snippet_name": critical_fn,
            "text_content": "Aadhaar: 1234 5678 9012\nPAN: ABCDE1234F\nAccount: 1234567890\nPhone: +91 98765 43210",
        },
    )

    # Filter Low risk
    low_resp = client.get(f"/history?search={token}&risk=Low")
    assert low_resp.status_code == 200
    low_html = low_resp.get_data(as_text=True)
    assert clean_fn in low_html
    assert critical_fn not in low_html

    # Filter Critical risk
    crit_resp = client.get(f"/history?search={token}&risk=Critical")
    assert crit_resp.status_code == 200
    crit_html = crit_resp.get_data(as_text=True)
    assert critical_fn in crit_html
    assert clean_fn not in crit_html


# -------------------------------------------------------------
# 4. ACCOUNT PROFILE & PASSWORD MANAGEMENT TESTS
# -------------------------------------------------------------

def test_profile_view_displays_authenticated_user_info():
    app, client, user_id = create_authenticated_test_client()
    resp = client.get("/profile")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "User Information" in html
    assert "Update Password" in html
    with app.app_context():
        user = get_db().execute("SELECT name, email FROM users WHERE id = ?", (user_id,)).fetchone()
        assert user["name"] in html
        assert user["email"] in html


def test_password_update_flow_and_reauthentication():
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})
    with app.app_context():
        db = get_db()
        test_email = f"pwd_user_{uuid.uuid4().hex[:8]}@example.test"
        from werkzeug.security import generate_password_hash, check_password_hash
        cur = db.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            ("Password Test User", test_email, generate_password_hash("original-pass-1234")),
        )
        db.commit()
        user_id = cur.lastrowid

    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = user_id

    try:
        # 1. Reject incorrect current password
        bad_current = client.post(
            "/profile",
            data={
                "csrf_token": _csrf_token(client, "/profile"),
                "current_password": "wrong-current-password",
                "new_password": "brand-new-password-123",
                "confirm_password": "brand-new-password-123",
            },
            follow_redirects=True,
        )
        assert bad_current.status_code == 200
        assert "Current password is incorrect." in bad_current.get_data(as_text=True)

        # 2. Reject mismatched confirmation
        mismatched = client.post(
            "/profile",
            data={
                "csrf_token": _csrf_token(client, "/profile"),
                "current_password": "original-pass-1234",
                "new_password": "brand-new-password-123",
                "confirm_password": "brand-new-password-456",
            },
            follow_redirects=True,
        )
        assert mismatched.status_code == 200
        assert "New password and confirmation do not match." in mismatched.get_data(as_text=True)

        # 3. Reject too short new password
        too_short = client.post(
            "/profile",
            data={
                "csrf_token": _csrf_token(client, "/profile"),
                "current_password": "original-pass-1234",
                "new_password": "short",
                "confirm_password": "short",
            },
            follow_redirects=True,
        )
        assert too_short.status_code == 200
        assert "New password must be at least 8 characters long." in too_short.get_data(as_text=True)

        # 4. Successful password update
        success_resp = client.post(
            "/profile",
            data={
                "csrf_token": _csrf_token(client, "/profile"),
                "current_password": "original-pass-1234",
                "new_password": "brand-new-secure-password-2026",
                "confirm_password": "brand-new-secure-password-2026",
            },
            follow_redirects=True,
        )
        assert success_resp.status_code == 200
        assert "Your password has been successfully updated." in success_resp.get_data(as_text=True)

        # Verify database hash was updated
        with app.app_context():
            user = get_db().execute("SELECT email, password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
            assert check_password_hash(user["password_hash"], "brand-new-secure-password-2026")
            assert not check_password_hash(user["password_hash"], "original-pass-1234")

        # Verify user can log in with new password
        client.post("/logout", data={"csrf_token": _csrf_token(client, "/dashboard")})
        new_login = client.post(
            "/login",
            data={
                "csrf_token": _csrf_token(client, "/login"),
                "email": user["email"],
                "password": "brand-new-secure-password-2026",
            },
            follow_redirects=True,
        )
        assert new_login.status_code == 200
        assert "Privacy Dashboard" in new_login.get_data(as_text=True)
    finally:
        with app.app_context():
            get_db().execute("DELETE FROM users WHERE id = ?", (user_id,))
            get_db().commit()
