import csv
import io
import math
import os
import json
import re
import sqlite3
import uuid
from functools import wraps
from pathlib import Path

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
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


@web_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = get_db().execute("SELECT id, name, email FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user is None:
        session.clear()
        return redirect(url_for("web.login"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        user_auth = get_db().execute(
            "SELECT password_hash FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()

        if not check_password_hash(user_auth["password_hash"], current_password):
            flash("Current password is incorrect.", "danger")
        elif len(new_password) < 8:
            flash("New password must be at least 8 characters long.", "danger")
        elif new_password != confirm_password:
            flash("New password and confirmation do not match.", "danger")
        else:
            db = get_db()
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_password), session["user_id"]),
            )
            db.commit()
            flash("Your password has been successfully updated.", "success")
            return redirect(url_for("web.profile"))

    return render_template("profile.html", user=user)


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
    remediations = risk_result.get("remediations")
    if not remediations:
        from app.services.risk_service import get_remediations_for_categories

        cats = [k for k, v in risk_result.get("detected_category_summary", {}).items() if v > 0]
        remediations = get_remediations_for_categories(cats)

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
        "remediations": remediations,
        "scan_id": scan["id"],
    }


def _process_findings_and_save(original_name, file_name, file_type, file_size, stored_path, text_content):
    findings = detect_sensitive_data(text_content)
    risk_result = calculate_privacy_risk(findings)

    masked_findings = []
    for item in findings:
        masked_val = mask_sensitive_value(item["type"], item["value"])
        snippet = item.get("context_snippet", "")
        if "[MATCH]" in snippet:
            safe_snippet = snippet.replace("[MATCH]", f" {masked_val} ")
        elif snippet:
            safe_snippet = snippet.replace(item["value"], masked_val)
        else:
            safe_snippet = f"... {masked_val} ..."

        # Safe secondary sweep: ensure any other raw finding in the snippet is also masked
        for other in findings:
            raw_other = other.get("value", "")
            if raw_other and raw_other in safe_snippet:
                safe_snippet = safe_snippet.replace(
                    raw_other, mask_sensitive_value(other["type"], raw_other)
                )

        safe_snippet = re.sub(r"\s+", " ", safe_snippet).strip()

        masked_findings.append(
            {
                "type": item["type"],
                "value": masked_val,
                "confidence": item.get("confidence"),
                "evidence": item.get("evidence"),
                "context_snippet": safe_snippet,
            }
        )

    report_name = generate_privacy_report(
        original_name,
        file_type.upper(),
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
            original_name,
            file_name,
            file_type,
            file_size,
            stored_path,
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
    return scan, report_name


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
            scan, report_name = _process_findings_and_save(
                original_name=file_info["original_name"],
                file_name=file_info["file_name"],
                file_type=file_info["file_type"],
                file_size=file_info["file_size"],
                stored_path=file_info["stored_path"],
                text_content=extracted_text,
            )
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("upload.html")
        except Exception:
            flash("Unable to process this file. Please upload a valid PDF or image.", "danger")
            return render_template("upload.html")

        cleanup_stale_files()
        return render_template("result.html", **_result_context(scan), report_name=report_name)

    return render_template("upload.html")


@web_bp.route("/scan-text", methods=["POST"])
@login_required
def scan_text():
    text_content = request.form.get("text_content", "")
    if not text_content or not text_content.strip():
        flash("Please enter or paste text to analyze.", "danger")
        return redirect(url_for("web.index", mode="text"))

    raw_text = text_content.strip()
    byte_size = len(raw_text.encode("utf-8"))
    if byte_size > 5 * 1024 * 1024:
        flash("Text content exceeds the 5 MB limit.", "danger")
        return redirect(url_for("web.index", mode="text"))

    snippet_name = request.form.get("snippet_name", "").strip()
    if not snippet_name or len(snippet_name) > 100:
        snippet_name = "Text-Snippet.txt"
    elif not snippet_name.lower().endswith(".txt"):
        snippet_name = f"{snippet_name}.txt"

    token = uuid.uuid4().hex
    safe_filename = f"text_{token}.txt"
    stored_path = f"uploads/{safe_filename}"
    abs_stored_path = os.path.join(current_app.config["UPLOAD_FOLDER"], safe_filename)
    try:
        with open(abs_stored_path, "w", encoding="utf-8") as f:
            f.write(raw_text)
    except OSError:
        flash("Unable to save snippet for processing.", "danger")
        return redirect(url_for("web.index", mode="text"))

    try:
        scan, report_name = _process_findings_and_save(
            original_name=snippet_name,
            file_name=safe_filename,
            file_type="txt",
            file_size=byte_size,
            stored_path=stored_path,
            text_content=raw_text,
        )
    except Exception:
        flash("Unable to process text snippet.", "danger")
        return redirect(url_for("web.index", mode="text"))

    return render_template("result.html", **_result_context(scan), report_name=report_name)


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

    category_totals = {
        "aadhaar": 0,
        "pan": 0,
        "bank_account": 0,
        "ifsc": 0,
        "phone": 0,
        "email": 0,
        "dob": 0,
        "pin": 0,
    }
    docs_for_categories = db.execute(
        "SELECT risk_json FROM documents WHERE user_id = ? AND status = 'completed'",
        (session["user_id"],),
    ).fetchall()
    for row in docs_for_categories:
        try:
            rdata = json.loads(row["risk_json"] or "{}")
            summary = rdata.get("detected_category_summary", {})
            for cat, cnt in summary.items():
                if cat in category_totals:
                    category_totals[cat] += cnt
        except Exception:
            pass

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_scans=recent_scans,
        category_totals=category_totals,
    )


@web_bp.route("/history")
@login_required
def history():
    search = request.args.get("search", "").strip()
    risk_filter = request.args.get("risk", "").strip()
    sort_by = request.args.get("sort", "date_desc").strip()

    valid_risks = {"Low", "Moderate", "High", "Critical"}
    query = "SELECT id, original_name, uploaded_at, total_score, risk_level, finding_count FROM documents WHERE user_id = ? AND status = 'completed'"
    params = [session["user_id"]]

    if search:
        query += " AND original_name LIKE ?"
        params.append(f"%{search}%")

    if risk_filter in valid_risks:
        query += " AND risk_level = ?"
        params.append(risk_filter)

    sort_options = {
        "date_desc": "uploaded_at DESC, id DESC",
        "date_asc": "uploaded_at ASC, id ASC",
        "score_desc": "total_score DESC, id DESC",
        "score_asc": "total_score ASC, id ASC",
        "findings_desc": "finding_count DESC, id DESC",
    }
    order_clause = sort_options.get(sort_by, "uploaded_at DESC, id DESC")
    query += f" ORDER BY {order_clause}"

    db = get_db()
    total_count = db.execute(
        re.sub(r"^SELECT.*?FROM", "SELECT COUNT(*) FROM", query.split(" ORDER BY")[0]),
        params,
    ).fetchone()[0]

    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    per_page = 20
    total_pages = max(1, math.ceil(total_count / per_page))
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page

    query += " LIMIT ? OFFSET ?"
    params.extend([per_page, offset])

    scans = db.execute(query, params).fetchall()
    return render_template(
        "history.html",
        scans=scans,
        search=search,
        risk_filter=risk_filter,
        sort_by=sort_by,
        page=page,
        total_pages=total_pages,
        total_count=total_count,
    )


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


@web_bp.route("/history/<int:scan_id>/export/json")
@login_required
def export_scan_json(scan_id):
    scan = _get_scan(scan_id)
    context = _result_context(scan)

    export_payload = {
        "scan_id": scan["id"],
        "filename": scan["original_name"],
        "file_type": scan["file_type"].upper(),
        "scan_timestamp": scan["uploaded_at"],
        "total_risk_score": scan["total_score"],
        "risk_level": scan["risk_level"],
        "finding_count": scan["finding_count"],
        "detected_categories": context["detected_categories"],
        "category_contributions": context["category_contributions"],
        "score_explanations": context["explanations"],
        "remediation_guidance": context["remediations"],
        "findings": context["findings"],
    }

    clean_basename = re.sub(r"[^\w\-.]", "_", scan["original_name"]).rstrip(".")
    filename = f"scan_{scan['id']}_{clean_basename}_findings.json"
    response = Response(
        json.dumps(export_payload, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
    return response


@web_bp.route("/history/<int:scan_id>/export/csv")
@login_required
def export_scan_csv(scan_id):
    scan = _get_scan(scan_id)
    context = _result_context(scan)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID",
        "Document Name",
        "Risk Level",
        "Total Risk Score",
        "Finding Index",
        "Category",
        "Masked Sensitive Value",
        "Confidence",
        "Matched Rule Evidence",
        "Context Snippet",
    ])

    findings = context["findings"]
    if findings:
        for idx, item in enumerate(findings, start=1):
            writer.writerow([
                scan["id"],
                scan["original_name"],
                scan["risk_level"],
                scan["total_score"],
                idx,
                item.get("type", ""),
                item.get("value", ""),
                item.get("confidence", "high"),
                item.get("evidence", ""),
                item.get("context_snippet", ""),
            ])
    else:
        writer.writerow([
            scan["id"],
            scan["original_name"],
            scan["risk_level"],
            scan["total_score"],
            0,
            "None",
            "No sensitive data detected",
            "N/A",
            "Clean document",
            "N/A",
        ])

    clean_basename = re.sub(r"[^\w\-.]", "_", scan["original_name"]).rstrip(".")
    filename = f"scan_{scan['id']}_{clean_basename}_findings.csv"
    response = Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
    return response


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

