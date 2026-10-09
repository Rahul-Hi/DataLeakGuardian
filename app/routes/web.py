import os
import json
import re
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.database import get_db
from app.services.detection_service import detect_sensitive_data
from app.services.extraction_service import extract_text_from_file
from app.services.report_service import generate_privacy_report
from app.services.risk_service import calculate_privacy_risk
from app.services.upload_service import cleanup_stale_files, save_uploaded_file
from app.utils.masking import mask_sensitive_value

web_bp = Blueprint("web", __name__)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("web.login"))
        return view(*args, **kwargs)

    return wrapped_view


@web_bp.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id") is not None:
        return redirect(url_for("web.dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or len(name) > 120:
            flash("Enter a name no longer than 120 characters.", "danger")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                    (name, email, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                flash("An account with that email already exists.", "danger")
            else:
                flash("Account created. Please sign in.", "success")
                return redirect(url_for("web.login"))

    return render_template("register.html")


@web_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id") is not None:
        return redirect(url_for("web.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT id, password_hash FROM users WHERE email = ?", (email,)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "danger")
        else:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("web.dashboard"))

    return render_template("login.html")


@web_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("web.login"))


def _scan_path(folder_config, filename):
    if not filename or os.path.basename(filename) != filename:
        return None
    return _path_in_directory(current_app.config[folder_config], filename)


def _path_in_directory(directory, filename):
    if not filename or os.path.basename(filename) != filename:
        return None
    base = Path(directory).resolve()
    path = (base / filename).resolve()
    if path.parent != base:
        return None
    return path


def _get_scan(scan_id):
    scan = get_db().execute(
        "SELECT * FROM documents WHERE id = ? AND user_id = ? AND status = 'completed'",
        (scan_id, session["user_id"]),
    ).fetchone()
    if scan is None:
        abort(404)
    return scan


def _result_context(scan):
    risk_result = json.loads(scan["risk_json"] or "{}")
    findings = json.loads(scan["findings_json"] or "[]")
    return {
        "file_name": scan["original_name"],
        "file_type": scan["file_type"].upper(),
        "total_score": scan["total_score"],
        "risk_level": scan["risk_level"],
        "findings": findings,
        "finding_count": scan["finding_count"],
        "detected_categories": [
            category for category, count in risk_result.get("detected_category_summary", {}).items() if count > 0
        ],
        "category_contributions": risk_result.get("score_contribution_of_each_category", {}),
        "explanations": risk_result.get("explanations", []),
        "scan_id": scan["id"],
    }


@web_bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if uploaded_file is None or uploaded_file.filename == "":
            flash("Please choose a file to upload.", "danger")
            return render_template("upload.html")

        try:
            file_info = save_uploaded_file(uploaded_file)
            stored_path = os.path.abspath(os.path.join(current_app.config["UPLOAD_FOLDER"], file_info["file_name"]))
            extracted_text = extract_text_from_file(stored_path, file_info["file_type"])
            findings = detect_sensitive_data(extracted_text)
            risk_result = calculate_privacy_risk(findings)
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("upload.html")
        except Exception:
            flash("Unable to process this file. Please upload a valid PDF or image.", "danger")
            return render_template("upload.html")

        masked_findings = []
        for item in findings:
            masked_findings.append(
                {
                    "type": item["type"],
                    "value": mask_sensitive_value(item["type"], item["value"]),
                    "confidence": item.get("confidence"),
                }
            )
        report_name = generate_privacy_report(
            file_info["original_name"],
            file_info["file_type"].upper(),
            risk_result,
            masked_findings,
        )

        db = get_db()
        cursor = db.execute(
            """
            INSERT INTO documents (
                user_id, original_name, file_name, file_type, file_size, stored_path, status,
                total_score, risk_level, finding_count, findings_json, risk_json, report_name
            ) VALUES (?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?)
            """,
            (
                session["user_id"],
                file_info["original_name"],
                file_info["file_name"],
                file_info["file_type"],
                file_info["file_size"],
                file_info["stored_path"],
                risk_result["total_score"],
                risk_result["risk_level"],
                len(masked_findings),
                json.dumps(masked_findings),
                json.dumps(risk_result),
                report_name,
            ),
        )
        db.commit()
        scan = _get_scan(cursor.lastrowid)
        cleanup_stale_files()
        return render_template("result.html", **_result_context(scan), report_name=report_name)

    return render_template("upload.html")


@web_bp.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    stats = db.execute(
        """
        SELECT COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN risk_level = 'Low' THEN 1 ELSE 0 END), 0) AS low,
            COALESCE(SUM(CASE WHEN risk_level = 'Moderate' THEN 1 ELSE 0 END), 0) AS moderate,
            COALESCE(SUM(CASE WHEN risk_level = 'High' THEN 1 ELSE 0 END), 0) AS high,
            COALESCE(SUM(CASE WHEN risk_level = 'Critical' THEN 1 ELSE 0 END), 0) AS critical
        FROM documents WHERE user_id = ? AND status = 'completed'
        """,
        (session["user_id"],),
    ).fetchone()
    recent_scans = db.execute(
        "SELECT id, original_name, uploaded_at, total_score, risk_level, finding_count FROM documents "
        "WHERE user_id = ? AND status = 'completed' ORDER BY uploaded_at DESC, id DESC LIMIT 5",
        (session["user_id"],),
    ).fetchall()
    return render_template("dashboard.html", stats=stats, recent_scans=recent_scans)


@web_bp.route("/history")
@login_required
def history():
    scans = get_db().execute(
        "SELECT id, original_name, uploaded_at, total_score, risk_level, finding_count FROM documents "
        "WHERE user_id = ? AND status = 'completed' ORDER BY uploaded_at DESC, id DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template("history.html", scans=scans)


@web_bp.route("/history/<int:scan_id>")
@login_required
def view_scan(scan_id):
    scan = _get_scan(scan_id)
    return render_template("result.html", **_result_context(scan), report_name=scan["report_name"])


@web_bp.route("/history/<int:scan_id>/report")
@login_required
def download_report(scan_id):
    scan = _get_scan(scan_id)
    report_path = _scan_path("REPORT_FOLDER", scan["report_name"])
    if report_path is None or not report_path.is_file() or report_path.suffix.lower() != ".pdf":
        return "Not Found", 404
    return send_from_directory(current_app.config["REPORT_FOLDER"], report_path.name, as_attachment=True)


@web_bp.route("/history/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    scan = _get_scan(scan_id)
    upload_path = _scan_path("UPLOAD_FOLDER", scan["file_name"])
    report_path = _scan_path("REPORT_FOLDER", scan["report_name"])
    legacy_upload_path = _path_in_directory(
        os.path.join(current_app.root_path, "static", "uploads"), scan["file_name"]
    )
    legacy_report_path = _path_in_directory(
        os.path.join(current_app.root_path, "static", "reports"), scan["report_name"]
    )
    db = get_db()
    db.execute("DELETE FROM documents WHERE id = ?", (scan_id,))
    db.commit()
    for path in (upload_path, report_path, legacy_upload_path, legacy_report_path):
        if path is not None:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                current_app.logger.warning("Could not remove scan artifact: %s", path.name)
    flash("Scan and associated files deleted.", "success")
    return redirect(url_for("web.history"))


@web_bp.route("/static/uploads/<path:filename>")
@web_bp.route("/static/reports/<path:filename>")
def deny_legacy_static_artifacts(filename):
    abort(404)
