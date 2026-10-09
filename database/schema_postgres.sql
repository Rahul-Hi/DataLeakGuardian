-- Data Leak Guardian Schema for PostgreSQL
-- Compatible with Neon, Supabase, and standard PostgreSQL 14+

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    original_name VARCHAR(255) NOT NULL,
    file_name VARCHAR(255) NOT NULL UNIQUE,
    file_type VARCHAR(50) NOT NULL,
    file_size BIGINT NOT NULL,
    stored_path TEXT NOT NULL,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) NOT NULL DEFAULT 'uploaded',
    total_score INTEGER,
    risk_level VARCHAR(50),
    finding_count INTEGER NOT NULL DEFAULT 0,
    findings_json TEXT NOT NULL DEFAULT '[]',
    risk_json TEXT NOT NULL DEFAULT '{}',
    report_name VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_documents_user_status ON documents(user_id, status);
CREATE INDEX IF NOT EXISTS idx_documents_uploaded_at ON documents(uploaded_at DESC);
