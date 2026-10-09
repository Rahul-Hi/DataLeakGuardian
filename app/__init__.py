import os
import secrets
import shutil
from pathlib import Path

from flask import Flask, g, render_template, session
from werkzeug.exceptions import RequestEntityTooLarge
from flask_wtf.csrf import CSRFProtect

from app.database import close_db, get_db, init_db
from app.routes import web_bp


def _migrate_legacy_artifacts(app):
    legacy_uploads = Path(app.root_path) / "static" / "uploads"
    legacy_reports = Path(app.root_path) / "static" / "reports"
    upload_folder = Path(app.config["UPLOAD_FOLDER"])
    report_folder = Path(app.config["REPORT_FOLDER"])
    scans = get_db().execute(
        "SELECT id, file_name, stored_path, report_name FROM documents WHERE status = 'completed'"
    ).fetchall()

    for scan in scans:
        upload_name = scan["file_name"]
        if upload_name and Path(upload_name).name == upload_name:
            old_upload = legacy_uploads / upload_name
            new_upload = upload_folder / upload_name
            if old_upload.is_file() and not new_upload.exists():
                try:
                    shutil.copy2(old_upload, new_upload)
                except OSError:
                    app.logger.warning("Could not migrate legacy upload for scan %s", scan["id"])
            if new_upload.is_file() and scan["stored_path"] != f"uploads/{upload_name}":
                get_db().execute(
                    "UPDATE documents SET stored_path = ? WHERE id = ?",
                    (f"uploads/{upload_name}", scan["id"]),
                )

        report_name = scan["report_name"]
        if report_name and Path(report_name).name == report_name:
            old_report = legacy_reports / report_name
            new_report = report_folder / report_name
            if old_report.is_file() and not new_report.exists():
                try:
                    shutil.copy2(old_report, new_report)
                except OSError:
                    app.logger.warning("Could not migrate legacy report for scan %s", scan["id"])
    get_db().commit()


csrf = CSRFProtect()


def create_app(config=None):
    app = Flask(__name__)

    os.makedirs(app.instance_path, exist_ok=True)
    secret_key_path = Path(app.instance_path) / "secret_key.txt"
    secret_key = os.environ.get("FLASK_SECRET_KEY")
    if not secret_key:
        if secret_key_path.exists():
            secret_key = secret_key_path.read_text(encoding="utf-8").strip()
        else:
            secret_key = secrets.token_hex(32)
            try:
                secret_key_path.write_text(secret_key, encoding="utf-8")
                secret_key_path.chmod(0o600)
            except OSError:
                app.logger.warning("Could not persist Flask secret key; using a process-local key.")

    app.config["SECRET_KEY"] = secret_key
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
    app.config["UPLOAD_FOLDER"] = os.path.join(app.instance_path, "uploads")
    app.config["REPORT_FOLDER"] = os.path.join(app.instance_path, "reports")
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["REPORT_FOLDER"], exist_ok=True)
    app.config["ALLOWED_EXTENSIONS"] = {"pdf", "png", "jpg", "jpeg"}
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = True
    if config:
        app.config.update(config)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["REPORT_FOLDER"], exist_ok=True)
    csrf.init_app(app)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'")
        return response

    @app.before_request
    def load_current_user():
        user_id = session.get("user_id")
        g.current_user = None
        if user_id is not None:
            g.current_user = get_db().execute(
                "SELECT id, name, email FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if g.current_user is None:
                session.clear()

    @app.context_processor
    def inject_current_user():
        return {"current_user": g.get("current_user")}

    @app.errorhandler(RequestEntityTooLarge)
    def handle_too_large(error):
        return render_template("upload.html", error_message="File size exceeds the 5 MB limit."), 413

    app.register_blueprint(web_bp)
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()
        _migrate_legacy_artifacts(app)

    return app
