import json
from pathlib import Path
import re
import shutil
import uuid
from io import BytesIO

import fitz

from app.database import get_db
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


def _create_scan(client, text="Email: history@example.com"):
    filename = f"history_{uuid.uuid4().hex[:10]}.pdf"
    response = client.post(
        "/",
        data={"file": (BytesIO(_make_pdf_bytes(text)), filename)},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    app = client.application
    with app.app_context():
        scan = get_db().execute(
            "SELECT * FROM documents WHERE original_name = ? ORDER BY id DESC LIMIT 1", (filename,)
        ).fetchone()
        return filename, dict(scan)


def _remove_scan(client, scan_id):
    response = client.post(f"/history/{scan_id}/delete")
    assert response.status_code == 302


def test_completed_scan_history_and_dashboard_statistics():
    app, client, user_id = create_authenticated_test_client()
    with app.app_context():
        before = get_db().execute(
            "SELECT COUNT(*) AS total, SUM(risk_level = 'Low') AS low FROM documents WHERE user_id = ? AND status = 'completed'",
            (user_id,),
        ).fetchone()
        before_total = before["total"]
        before_low = before["low"] or 0

    filename, scan = _create_scan(client)
    try:
        assert scan["status"] == "completed"
        assert scan["total_score"] == 10
        assert scan["risk_level"] == "Low"
        assert scan["finding_count"] == 1
        assert scan["uploaded_at"]
        assert "history@example.com" not in scan["findings_json"]
        assert json.loads(scan["findings_json"])[0]["value"] != "history@example.com"

        history_response = client.get("/history")
        assert history_response.status_code == 200
        assert filename in history_response.get_data(as_text=True)

        dashboard_html = client.get("/dashboard").get_data(as_text=True)
        assert re.search(rf'Total documents scanned</div><div class="stat-value">{before_total + 1}</div>', dashboard_html)
        assert re.search(rf'Low risk</div><div class="stat-value text-success">{before_low + 1}</div>', dashboard_html)
        assert filename in dashboard_html
    finally:
        _remove_scan(client, scan["id"])


def test_dashboard_counts_each_risk_level():
    app, client, user_id = create_authenticated_test_client()
    levels = [(10, "Low"), (30, "Moderate"), (60, "High"), (80, "Critical")]
    with app.app_context():
        db = get_db()
        before = db.execute(
            "SELECT risk_level, COUNT(*) AS count FROM documents WHERE user_id = ? AND status = 'completed' GROUP BY risk_level",
            (user_id,),
        ).fetchall()
        counts = {row["risk_level"]: row["count"] for row in before}
        inserted_ids = []
        for score, level in levels:
            token = uuid.uuid4().hex
            cursor = db.execute(
                """INSERT INTO documents (
                    user_id, original_name, file_name, file_type, file_size, stored_path, status,
                    total_score, risk_level, finding_count, findings_json, risk_json
                ) VALUES (?, ?, ?, 'pdf', 0, '', 'completed', ?, ?, 0, '[]', '{}')""",
                (user_id, f"dashboard_{token}.pdf", f"{token}.pdf", score, level),
            )
            inserted_ids.append(cursor.lastrowid)
        db.commit()

    try:
        html = client.get("/dashboard").get_data(as_text=True)
        expected = {
            "Low": counts.get("Low", 0) + 1,
            "Moderate": counts.get("Moderate", 0) + 1,
            "High": counts.get("High", 0) + 1,
            "Critical": counts.get("Critical", 0) + 1,
        }
        assert re.search(rf'Low risk</div><div class="stat-value text-success">{expected["Low"]}</div>', html)
        assert re.search(rf'Moderate risk</div><div class="stat-value text-warning-emphasis">{expected["Moderate"]}</div>', html)
        assert re.search(rf'High risk</div><div class="stat-value risk-high-text">{expected["High"]}</div>', html)
        assert re.search(rf'Critical risk</div><div class="stat-value text-danger">{expected["Critical"]}</div>', html)
    finally:
        with app.app_context():
            db = get_db()
            db.executemany("DELETE FROM documents WHERE id = ?", [(scan_id,) for scan_id in inserted_ids])
            db.commit()


def test_previous_result_can_be_viewed():
    app, client, _ = create_authenticated_test_client()
    filename, scan = _create_scan(client, "Aadhaar: 1234 5678 9012")
    try:
        response = client.get(f"/history/{scan['id']}")
        html = response.get_data(as_text=True)
        assert response.status_code == 200
        assert filename in html
        assert "Analysis Result" in html
        assert "XXXX XXXX 9012" in html
        assert "1234 5678 9012" not in html
    finally:
        _remove_scan(client, scan["id"])


def test_previous_report_can_be_downloaded():
    app, client, _ = create_authenticated_test_client()
    _, scan = _create_scan(client)
    try:
        response = client.get(f"/history/{scan['id']}/report")
        assert response.status_code == 200
        assert response.mimetype == "application/pdf"
        assert response.data.startswith(b"%PDF")
        assert client.get(f"/static/reports/{scan['report_name']}").status_code == 404
        assert client.get(f"/static/uploads/{scan['file_name']}").status_code == 404
    finally:
        _remove_scan(client, scan["id"])


def test_deleting_scan_removes_record_and_artifacts():
    app, client, _ = create_authenticated_test_client()
    filename, scan = _create_scan(client)
    upload_path = Path(app.config["UPLOAD_FOLDER"]) / scan["file_name"]
    report_path = Path(app.config["REPORT_FOLDER"]) / scan["report_name"]
    legacy_upload_path = Path(app.root_path) / "static" / "uploads" / scan["file_name"]
    legacy_report_path = Path(app.root_path) / "static" / "reports" / scan["report_name"]
    assert upload_path.is_file()
    legacy_upload_path.parent.mkdir(parents=True, exist_ok=True)
    legacy_report_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(upload_path, legacy_upload_path)
    shutil.copy2(report_path, legacy_report_path)

    response = client.post(f"/history/{scan['id']}/delete", follow_redirects=True)
    assert response.status_code == 200
    assert "Scan and associated files deleted." in response.get_data(as_text=True)
    assert filename not in client.get("/history").get_data(as_text=True)
    assert not upload_path.exists()
    assert not report_path.exists()
    assert not legacy_upload_path.exists()
    assert not legacy_report_path.exists()
    with app.app_context():
        assert get_db().execute("SELECT id FROM documents WHERE id = ?", (scan["id"],)).fetchone() is None


def test_unknown_scan_cannot_be_viewed_downloaded_or_deleted():
    app, client, _ = create_authenticated_test_client()

    assert client.get("/history/999999999").status_code == 404
    assert client.get("/history/999999999/report").status_code == 404
    assert client.post("/history/999999999/delete").status_code == 404
    assert client.get("/report/../../app/__init__.py").status_code == 404


def test_legacy_static_artifact_paths_are_not_public():
    app, client, _ = create_authenticated_test_client()
    upload_probe = Path(app.root_path) / "static" / "uploads" / f"probe_{uuid.uuid4().hex}.pdf"
    report_probe = Path(app.root_path) / "static" / "reports" / f"probe_{uuid.uuid4().hex}.pdf"
    upload_probe.parent.mkdir(parents=True, exist_ok=True)
    report_probe.parent.mkdir(parents=True, exist_ok=True)
    upload_probe.write_bytes(b"private upload probe")
    report_probe.write_bytes(b"private report probe")
    try:
        assert client.get(f"/static/uploads/{upload_probe.name}").status_code == 404
        assert client.get(f"/static/reports/{report_probe.name}").status_code == 404
    finally:
        upload_probe.unlink(missing_ok=True)
        report_probe.unlink(missing_ok=True)
