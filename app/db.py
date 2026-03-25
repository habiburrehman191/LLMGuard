import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "logs" / "llmguard.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt TEXT NOT NULL,
            retrieved_document TEXT,
            action TEXT NOT NULL,
            blocked INTEGER NOT NULL,
            reason TEXT NOT NULL,
            risk_score REAL NOT NULL,
            response TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def insert_log(prompt, retrieved_document, action, blocked, reason, risk_score, response):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO logs (
            prompt,
            retrieved_document,
            action,
            blocked,
            reason,
            risk_score,
            response
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        prompt,
        retrieved_document,
        action,
        int(blocked),
        reason,
        risk_score,
        response
    ))

    conn.commit()
    conn.close()