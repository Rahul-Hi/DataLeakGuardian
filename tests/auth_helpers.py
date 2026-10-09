from werkzeug.security import generate_password_hash

from app import create_app
from app.database import get_db


TEST_EMAIL = "route-tests@example.test"


def create_authenticated_test_client():
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})
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
