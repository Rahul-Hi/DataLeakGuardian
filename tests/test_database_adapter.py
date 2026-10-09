import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import pytest

from app import create_app
from tests.auth_helpers import create_authenticated_test_client
from app.database import (
    DualRow,
    IntegrityError,
    PostgresConnectionWrapper,
    PostgresCursorWrapper,
    close_db,
    dual_row_factory,
    get_db,
    get_db_path,
    is_postgres,
    translate_placeholders,
)

try:
    import psycopg
    from psycopg import IntegrityError as PostgresIntegrityError
except ImportError:
    psycopg = None
    PostgresIntegrityError = None


def test_database_defaults_to_sqlite(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert not is_postgres()
    assert str(get_db_path()).endswith("app.db")


def test_is_postgres_detection(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/testdb")
    assert is_postgres()
    monkeypatch.setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/testdb")
    assert is_postgres()
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert not is_postgres()


def test_sqlite_isolation_in_testing_mode():
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})
    with app.app_context():
        assert not is_postgres()
        db = get_db()
        row = db.execute("SELECT 1 AS num").fetchone()
        assert row["num"] == 1


def test_translate_placeholders_basic():
    sql = "SELECT id, email FROM users WHERE email = ? AND name = ?"
    translated = translate_placeholders(sql)
    assert translated == "SELECT id, email FROM users WHERE email = %s AND name = %s"


def test_translate_placeholders_preserves_literals_and_comments():
    # String literal with ?
    sql = "SELECT * FROM users WHERE status = 'pending?' AND email = ?"
    assert translate_placeholders(sql) == "SELECT * FROM users WHERE status = 'pending?' AND email = %s"

    # Escaped single quotes
    sql = "SELECT * FROM users WHERE note = 'It''s fine?' AND id = ?"
    assert translate_placeholders(sql) == "SELECT * FROM users WHERE note = 'It''s fine?' AND id = %s"

    # Line comment with ?
    sql = "SELECT id FROM users WHERE id = ? -- what is this? \n AND x = ?"
    assert translate_placeholders(sql) == "SELECT id FROM users WHERE id = %s -- what is this? \n AND x = %s"

    # Block comment with ?
    sql = "SELECT id FROM users WHERE id = ? /* comment? */ AND active = ?"
    assert translate_placeholders(sql) == "SELECT id FROM users WHERE id = %s /* comment? */ AND active = %s"


def test_dual_row_access():
    names = ["id", "username", "email"]
    values = [42, "guardian", "guardian@example.test"]
    row = DualRow(names, values)

    # Key / dict access
    assert row["id"] == 42
    assert row["username"] == "guardian"
    assert row["email"] == "guardian@example.test"
    assert row.get("email") == "guardian@example.test"
    assert row.get("missing", "default") == "default"
    assert "username" in row
    assert "missing" not in row

    # Sequence / index access
    assert row[0] == 42
    assert row[1] == "guardian"
    assert row[2] == "guardian@example.test"

    # Iteration and conversions
    assert list(row.keys()) == ["id", "username", "email"]
    assert tuple(row.values()) == (42, "guardian", "guardian@example.test")
    assert dict(row) == {"id": 42, "username": "guardian", "email": "guardian@example.test"}


class FakePsycopgCursor:
    def __init__(self):
        self.executed = []
        self.description = None
        self.rowcount = 0
        self._fetchone_data = None
        self.closed = False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        if "RETURNING id" in sql:
            self._fetchone_data = (101,)
            self.description = [type("Col", (), {"name": "id"})()]

    def executemany(self, sql, params_seq):
        self.executed.append((sql, params_seq))

    def fetchone(self):
        val = self._fetchone_data
        self._fetchone_data = None
        return val

    def fetchall(self):
        return []

    def fetchmany(self, size=None):
        return []

    def __iter__(self):
        return iter([])

    def close(self):
        self.closed = True


class FakePsycopgConnection:
    def __init__(self):
        self.committed = False
        self.rolled_back = False
        self.closed = False
        self.cursor_instance = FakePsycopgCursor()

    def cursor(self):
        return self.cursor_instance

    def execute(self, sql, params=None):
        return self.cursor_instance.execute(sql, params)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def test_postgres_cursor_wrapper_insert_returning_id():
    fake_cursor = FakePsycopgCursor()
    wrapper = PostgresCursorWrapper(fake_cursor)

    wrapper.execute(
        "INSERT INTO documents (user_id, original_name) VALUES (?, ?)",
        (1, "test.pdf"),
    )

    # Query was translated and RETURNING id appended
    executed_sql, executed_params = fake_cursor.executed[0]
    assert executed_sql == "INSERT INTO documents (user_id, original_name) VALUES (%s, %s) RETURNING id"
    assert executed_params == (1, "test.pdf")
    # lastrowid was captured transparently
    assert wrapper.lastrowid == 101
    # fetchone on auto-returning insert returns None
    assert wrapper.fetchone() is None


def test_postgres_cursor_wrapper_does_not_double_append_returning():
    fake_cursor = FakePsycopgCursor()
    wrapper = PostgresCursorWrapper(fake_cursor)

    wrapper.execute(
        "INSERT INTO documents (user_id) VALUES (?) RETURNING id",
        (1,),
    )
    executed_sql, _ = fake_cursor.executed[0]
    assert executed_sql.count("RETURNING") == 1


def test_postgres_cursor_wrapper_executemany_and_fetch():
    fake_cursor = FakePsycopgCursor()
    wrapper = PostgresCursorWrapper(fake_cursor)

    wrapper.executemany("DELETE FROM documents WHERE id = ?", [(10,), (20,)])
    assert fake_cursor.executed[0][0] == "DELETE FROM documents WHERE id = %s"
    assert fake_cursor.executed[0][1] == [(10,), (20,)]
    assert wrapper.fetchall() == []
    assert wrapper.fetchmany(5) == []
    assert list(iter(wrapper)) == []

    # Test context manager closes cursor
    with wrapper:
        pass
    assert fake_cursor.closed


def test_postgres_connection_wrapper_lifecycle():
    fake_conn = FakePsycopgConnection()
    wrapper = PostgresConnectionWrapper(fake_conn)

    cur = wrapper.execute("SELECT id FROM users WHERE email = ?", ("test@example.com",))
    assert cur is not None
    assert fake_conn.cursor_instance.executed[0][0] == "SELECT id FROM users WHERE email = %s"

    wrapper.commit()
    assert fake_conn.committed

    wrapper.rollback()
    assert fake_conn.rolled_back

    wrapper.close()
    assert fake_conn.closed


def test_postgres_connection_context_manager():
    # Success commits
    fake_conn = FakePsycopgConnection()
    wrapper = PostgresConnectionWrapper(fake_conn)
    with wrapper:
        wrapper.execute("UPDATE users SET name = %s", ("New",))
    assert fake_conn.committed

    # Exception rolls back
    fake_conn2 = FakePsycopgConnection()
    wrapper2 = PostgresConnectionWrapper(fake_conn2)
    with pytest.raises(ValueError):
        with wrapper2:
            raise ValueError("Test error")
    assert fake_conn2.rolled_back


def test_flask_teardown_closes_postgres_connection():
    app = create_app({"TESTING": True})
    fake_conn = FakePsycopgConnection()
    wrapper = PostgresConnectionWrapper(fake_conn)

    with app.app_context():
        from flask import g

        g.db = wrapper
        assert not fake_conn.closed

    # Once context exits, teardown runs close_db()
    assert fake_conn.closed


def test_integrity_error_normalization():
    # Verify sqlite3.IntegrityError is caught by normalized IntegrityError
    with pytest.raises(IntegrityError):
        raise sqlite3.IntegrityError("UNIQUE constraint failed")

    # If psycopg is available, verify Postgres IntegrityError is also caught
    if PostgresIntegrityError is not None:
        with pytest.raises(IntegrityError):
            raise PostgresIntegrityError("duplicate key value violates unique constraint")


def test_init_db_postgres_branching(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/testdb")
    fake_conn = FakePsycopgConnection()

    monkeypatch.setattr(
        "app.database.PostgresConnectionWrapper",
        lambda url: PostgresConnectionWrapper(fake_conn),
    )

    from app.database import init_db

    init_db()

    assert fake_conn.closed
    assert fake_conn.committed
    assert any("CREATE TABLE IF NOT EXISTS users" in sql for sql, _ in fake_conn.cursor_instance.executed)


def test_live_postgresql_integration_if_configured():
    test_pg_url = os.environ.get("TEST_POSTGRESQL_URL")
    if not test_pg_url:
        pytest.skip(
            "TEST_POSTGRESQL_URL is not configured; skipping live PostgreSQL end-to-end integration tests."
        )

    if psycopg is None:
        pytest.skip("psycopg is not installed.")

    # Real live test against configured PostgreSQL server
    wrapper = PostgresConnectionWrapper(test_pg_url)
    try:
        schema_path = Path(__file__).resolve().parent.parent / "database" / "schema_postgres.sql"
        wrapper._conn.execute(schema_path.read_text(encoding="utf-8"))
        wrapper.commit()

        # Test insert and lastrowid
        cur = wrapper.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            ("PG Test", "pgtest@example.test", "hash123"),
        )
        wrapper.commit()
        user_id = cur.lastrowid
        assert user_id is not None

        # Test row fetching and DualRow
        row = wrapper.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,)).fetchone()
        assert row["name"] == "PG Test"
        assert row[0] == user_id
        assert row[1] == "PG Test"

        # Test duplicate integrity error
        with pytest.raises(IntegrityError):
            wrapper.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                ("PG Test 2", "pgtest@example.test", "hash456"),
            )
        wrapper.rollback()

        # Clean up
        wrapper.execute("DELETE FROM users WHERE id = ?", (user_id,))
        wrapper.commit()
    finally:
        wrapper.close()


def test_export_scan_json_with_sqlite_string_timestamp():
    """Verify JSON export safely handles SQLite string timestamps and preserves value."""
    app, client, user_id = create_authenticated_test_client()
    with app.app_context():
        db = get_db()
        cur = db.execute(
            """
            INSERT INTO documents (
                user_id, original_name, file_name, file_type, file_size, stored_path, status,
                total_score, risk_level, finding_count, findings_json, risk_json, report_name,
                uploaded_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                "sqlite_test.txt",
                "sqlite_test.txt",
                "txt",
                100,
                "uploads/sqlite_test.txt",
                25,
                "Low",
                1,
                json.dumps([{"type": "email", "value": "t***@example.test"}]),
                json.dumps({"detected_category_summary": {"email": 1}}),
                "report_1.pdf",
                "2026-10-09 14:30:00",
            ),
        )
        db.commit()
        scan_id = cur.lastrowid

    response = client.get(f"/history/{scan_id}/export/json")
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    data = json.loads(response.get_data(as_text=True))
    assert data["scan_id"] == scan_id
    assert data["filename"] == "sqlite_test.txt"
    assert data["scan_timestamp"] == "2026-10-09 14:30:00"
    assert data["total_risk_score"] == 25
    assert data["risk_level"] == "Low"
    assert len(data["findings"]) == 1


def test_export_scan_json_with_postgres_datetime_timestamp(monkeypatch):
    """Verify JSON export safely normalizes and serializes Python datetime objects returned by PostgreSQL."""
    app, client, user_id = create_authenticated_test_client()
    pg_timestamp = datetime(2026, 10, 9, 14, 30, 0, tzinfo=timezone.utc)

    # Insert baseline document
    with app.app_context():
        db = get_db()
        cur = db.execute(
            """
            INSERT INTO documents (
                user_id, original_name, file_name, file_type, file_size, stored_path, status,
                total_score, risk_level, finding_count, findings_json, risk_json, report_name
            ) VALUES (?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                "pg_test.txt",
                "pg_test.txt",
                "txt",
                100,
                "uploads/pg_test.txt",
                45,
                "Moderate",
                0,
                "[]",
                "{}",
                "report_2.pdf",
            ),
        )
        db.commit()
        scan_id = cur.lastrowid

    # Intercept _get_scan to supply a datetime object for uploaded_at (representative of psycopg)
    import app.routes.web as web_module
    original_get_scan = web_module._get_scan

    def mock_get_scan(sid):
        row = dict(original_get_scan(sid))
        row["uploaded_at"] = pg_timestamp
        return row

    monkeypatch.setattr(web_module, "_get_scan", mock_get_scan)

    response = client.get(f"/history/{scan_id}/export/json")
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    data = json.loads(response.get_data(as_text=True))
    assert data["scan_id"] == scan_id
    assert data["filename"] == "pg_test.txt"
    assert data["scan_timestamp"] == pg_timestamp.isoformat()
    assert data["total_risk_score"] == 45
    assert data["risk_level"] == "Moderate"
