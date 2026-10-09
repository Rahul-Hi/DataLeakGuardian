import os
import tempfile
from pathlib import Path
from werkzeug.security import generate_password_hash

from app import create_app
from app.database import get_db

TEST_EMAIL = "route-tests@example.test"


def get_default_test_db_path() -> str:
    env_db = os.environ.get("DATABASE_PATH")
    if env_db:
        return env_db
    fallback_dir = Path(tempfile.gettempdir()) / "dlg_isolated_test_env"
    fallback_dir.mkdir(parents=True, exist_ok=True)
    return str(fallback_dir / "isolated_test_app.db")


def create_authenticated_test_client(custom_config=None):
    config = {
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "DATABASE_PATH": get_default_test_db_path(),
    }
    if os.environ.get("UPLOAD_FOLDER"):
        config["UPLOAD_FOLDER"] = os.environ["UPLOAD_FOLDER"]
    if os.environ.get("REPORT_FOLDER"):
        config["REPORT_FOLDER"] = os.environ["REPORT_FOLDER"]

    if custom_config:
        config.update(custom_config)

    app = create_app(config)
    with app.app_context():
        db = get_db()
        row = db.execute("SELECT id FROM users WHERE email = ?", (TEST_EMAIL,)).fetchone()
        if row is None:
            cursor = db.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                ("Route Test User", TEST_EMAIL, generate_password_hash("test-only-password")),
            )
            db.commit()
            user_id = cursor.lastrowid
        else:
            user_id = row["id"]

    client = app.test_client()
    with client.session_transaction() as auth_session:
        auth_session["user_id"] = user_id
    return app, client, user_id
