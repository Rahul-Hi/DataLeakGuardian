CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    original_name TEXT NOT NULL,
    file_name TEXT NOT NULL UNIQUE,
    file_type TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    stored_path TEXT NOT NULL,
    uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'uploaded',
    total_score INTEGER,
    risk_level TEXT,
    finding_count INTEGER NOT NULL DEFAULT 0,
    findings_json TEXT NOT NULL DEFAULT '[]',
    risk_json TEXT NOT NULL DEFAULT '{}',
    report_name TEXT
);
