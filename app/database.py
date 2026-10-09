import sqlite3
from pathlib import Path

from flask import g

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "app.db"
SCHEMA_PATH = BASE_DIR / "database" / "schema.sql"


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        existing_columns = {row[1] for row in conn.execute("PRAGMA table_info(documents)")}
        migrations = {
            "user_id": "INTEGER REFERENCES users(id) ON DELETE RESTRICT",
            "total_score": "INTEGER",
            "risk_level": "TEXT",
            "finding_count": "INTEGER NOT NULL DEFAULT 0",
            "findings_json": "TEXT NOT NULL DEFAULT '[]'",
            "risk_json": "TEXT NOT NULL DEFAULT '{}'",
            "report_name": "TEXT",
        }
        for column, definition in migrations.items():
            if column not in existing_columns:
                conn.execute(f"ALTER TABLE documents ADD COLUMN {column} {definition}")
