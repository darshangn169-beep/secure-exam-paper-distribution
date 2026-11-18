"""
database.py
-----------
SQLite database setup for users, papers (encrypted metadata) and access logs.
"""

import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = "exam_system.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,              -- 'admin' or 'center'
            entity_key TEXT NOT NULL         -- maps to keys/<entity_key>_public.pem
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS papers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            subject TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            enc_file_path TEXT NOT NULL,     -- path to AES-encrypted PDF on disk
            aes_key_enc BLOB NOT NULL,       -- AES key, RSA-encrypted with center's public key
            nonce BLOB NOT NULL,             -- AES-EAX nonce
            tag BLOB NOT NULL,               -- AES-EAX authentication tag
            signature BLOB NOT NULL,         -- RSA signature of SHA-256 hash (by admin)
            sha256_hash TEXT NOT NULL,       -- hex digest, stored for display/reference
            exam_datetime TEXT NOT NULL,     -- paper cannot be decrypted before this
            uploaded_by TEXT NOT NULL,
            center_username TEXT NOT NULL,
            uploaded_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            paper_id INTEGER,
            username TEXT,
            action TEXT,          -- 'decrypt_attempt'
            status TEXT,          -- 'success' / 'failure'
            reason TEXT,
            timestamp TEXT
        )
    """)

    # Seed demo users if not already present
    demo_users = [
        ("admin", "admin123", "admin", "admin"),
        ("center1", "center123", "center", "center1"),
        ("center2", "center123", "center", "center2"),
    ]
    for username, password, role, entity_key in demo_users:
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone() is None:
            cur.execute(
                "INSERT INTO users (username, password_hash, role, entity_key) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), role, entity_key),
            )

    conn.commit()
    conn.close()


def log_access(paper_id, username, action, status, reason, timestamp):
    conn = get_db()
    conn.execute(
        "INSERT INTO access_logs (paper_id, username, action, status, reason, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (paper_id, username, action, status, reason, timestamp),
    )
    conn.commit()
    conn.close()
