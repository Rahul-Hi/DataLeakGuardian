import os
import re
import sqlite3
from pathlib import Path

from flask import current_app, g, has_app_context

try:
    import psycopg
    from psycopg import IntegrityError as PostgresIntegrityError

    IntegrityError = (sqlite3.IntegrityError, PostgresIntegrityError)
except ImportError:
    psycopg = None
    PostgresIntegrityError = sqlite3.IntegrityError
    IntegrityError = sqlite3.IntegrityError

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "app.db"
SCHEMA_PATH = BASE_DIR / "database" / "schema.sql"
SCHEMA_POSTGRES_PATH = BASE_DIR / "database" / "schema_postgres.sql"


def get_database_url():
    if has_app_context() and current_app.config.get("DATABASE_URL"):
        return current_app.config["DATABASE_URL"]
    return os.environ.get("DATABASE_URL")


def is_postgres():
    url = get_database_url()
    return bool(url and (url.startswith("postgres://") or url.startswith("postgresql://")))


def get_db_path():
    if has_app_context() and current_app.config.get("DATABASE_PATH"):
        return Path(current_app.config["DATABASE_PATH"])
    env_path = os.environ.get("DATABASE_PATH")
    if env_path:
        return Path(env_path)
    return DB_PATH


def translate_placeholders(sql: str) -> str:
    """Safely replace '?' parameter placeholders with '%s' for PostgreSQL/psycopg,
    ignoring '?' characters that occur inside string literals or SQL comments.
    """
    tokens = []
    i = 0
    n = len(sql)
    while i < n:
        char = sql[i]
        # Line comment (-- ...)
        if char == "-" and i + 1 < n and sql[i + 1] == "-":
            end = sql.find("\n", i + 2)
            if end == -1:
                tokens.append(sql[i:])
                break
            tokens.append(sql[i : end + 1])
            i = end + 1
        # Block comment (/* ... */)
        elif char == "/" and i + 1 < n and sql[i + 1] == "*":
            end = sql.find("*/", i + 2)
            if end == -1:
                tokens.append(sql[i:])
                break
            tokens.append(sql[i : end + 2])
            i = end + 2
        # Single-quoted string literal ('...')
        elif char == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                    else:
                        j += 1
                        break
                elif sql[j] == "\\":
                    j += 2
                else:
                    j += 1
            tokens.append(sql[i:j])
            i = j
        # Double-quoted identifier ("...")
        elif char == '"':
            j = i + 1
            while j < n:
                if sql[j] == '"':
                    if j + 1 < n and sql[j + 1] == '"':
                        j += 2
                    else:
                        j += 1
                        break
                elif sql[j] == "\\":
                    j += 2
                else:
                    j += 1
            tokens.append(sql[i:j])
            i = j
        elif char == "?":
            tokens.append("%s")
            i += 1
        else:
            tokens.append(char)
            i += 1
    return "".join(tokens)


class DualRow(dict):
    """Dict-like and tuple-like row object matching sqlite3.Row behavior."""

    def __init__(self, names, values):
        super().__init__(zip(names, values))
        self._values = tuple(values)
        self._names = tuple(names)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)

    def __iter__(self):
        return iter(self._names)

    def keys(self):
        return self._names

    def values(self):
        return self._values

    def items(self):
        return zip(self._names, self._values)


def dual_row_factory(cursor):
    desc = cursor.description
    if not desc:
        return lambda values: values
    names = tuple(col.name for col in desc)

    def make_row(values):
        return DualRow(names, values)

    return make_row


class PostgresCursorWrapper:
    """Wraps a psycopg cursor to provide SQLite-compatible lastrowid and interface."""

    def __init__(self, cursor):
        self._cursor = cursor
        self.lastrowid = None
        self._appended_returning = False

    @property
    def description(self):
        return self._cursor.description

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def execute(self, query, params=None):
        sql = translate_placeholders(query)
        self.lastrowid = None
        self._appended_returning = False

        if re.match(r"^\s*INSERT\s+INTO\s+", sql, re.IGNORECASE):
            if not re.search(r"\bRETURNING\b", sql, re.IGNORECASE):
                sql = sql.rstrip().rstrip(";") + " RETURNING id"
                self._appended_returning = True

        if params is None:
            self._cursor.execute(sql)
        else:
            self._cursor.execute(sql, params)

        if self._appended_returning:
            try:
                row = self._cursor.fetchone()
                if row is not None:
                    self.lastrowid = row[0]
            except Exception:
                self.lastrowid = None

        return self

    def executemany(self, query, params_seq):
        sql = translate_placeholders(query)
        self.lastrowid = None
        self._appended_returning = False
        self._cursor.executemany(sql, params_seq)
        return self

    def fetchone(self):
        if self._appended_returning:
            return None
        return self._cursor.fetchone()

    def fetchall(self):
        if self._appended_returning:
            return []
        return self._cursor.fetchall()

    def fetchmany(self, size=None):
        if self._appended_returning:
            return []
        if size is None:
            return self._cursor.fetchmany()
        return self._cursor.fetchmany(size)

    def close(self):
        return self._cursor.close()

    def __iter__(self):
        if self._appended_returning:
            return iter([])
        return iter(self._cursor)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class PostgresConnectionWrapper:
    """Wraps a psycopg connection to provide a unified database API."""

    def __init__(self, connection_or_url):
        if isinstance(connection_or_url, str):
            if psycopg is None:
                raise RuntimeError("psycopg is required for PostgreSQL connections.")
            url = connection_or_url
            if url.startswith("postgres://"):
                url = "postgresql://" + url[len("postgres://") :]
            self._conn = psycopg.connect(url, row_factory=dual_row_factory)
        else:
            self._conn = connection_or_url

    def cursor(self):
        return PostgresCursorWrapper(self._conn.cursor())

    def execute(self, query, params=None):
        cursor = self.cursor()
        cursor.execute(query, params)
        return cursor

    def executemany(self, query, params_seq):
        cursor = self.cursor()
        cursor.executemany(query, params_seq)
        return cursor

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()

    @property
    def closed(self):
        return self._conn.closed

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()


def get_db():
    if "db" not in g:
        if is_postgres():
            g.db = PostgresConnectionWrapper(get_database_url())
        else:
            db_path = get_db_path()
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            g.db = conn
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(db_path=None):
    if db_path is None and is_postgres():
        url = get_database_url()
        conn = PostgresConnectionWrapper(url)
        try:
            schema_sql = SCHEMA_POSTGRES_PATH.read_text(encoding="utf-8")
            conn._conn.execute(schema_sql)
            conn.commit()
        finally:
            conn.close()
        return

    path = Path(db_path) if db_path else get_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
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
