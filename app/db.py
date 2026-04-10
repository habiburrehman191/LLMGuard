from __future__ import annotations

import json
import sqlite3

from app.config import get_settings


def get_connection() -> sqlite3.Connection:
    db_path = get_settings().db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(db_path)


def init_db() -> None:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt TEXT NOT NULL,
            retrieved_document TEXT,
            retrieved_sources TEXT,
            retrieved_chunks TEXT,
            action TEXT NOT NULL,
            label TEXT,
            blocked INTEGER NOT NULL,
            reason TEXT NOT NULL,
            rule_score REAL,
            semantic_score REAL,
            ml_score REAL,
            rule_label TEXT,
            semantic_label TEXT,
            ml_label TEXT,
            risk_score REAL NOT NULL,
            response TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    existing_columns = {
        row[1]
        for row in cursor.execute("PRAGMA table_info(logs)").fetchall()
    }
    for column_name, column_type in (
        ("retrieved_sources", "TEXT"),
        ("retrieved_chunks", "TEXT"),
        ("label", "TEXT"),
        ("rule_score", "REAL"),
        ("semantic_score", "REAL"),
        ("ml_score", "REAL"),
        ("rule_label", "TEXT"),
        ("semantic_label", "TEXT"),
        ("ml_label", "TEXT"),
    ):
        if column_name not in existing_columns:
            cursor.execute(f"ALTER TABLE logs ADD COLUMN {column_name} {column_type}")

    conn.commit()
    conn.close()


def insert_log(
    prompt: str,
    retrieved_document: str | None,
    retrieved_sources: list[str] | None,
    retrieved_chunks: list[dict[str, object]] | None,
    action: str,
    label: str,
    blocked: bool,
    reason: str,
    rule_score: float,
    semantic_score: float,
    ml_score: float,
    rule_label: str,
    semantic_label: str,
    ml_label: str,
    risk_score: float,
    response: str | None,
) -> None:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO logs (
            prompt,
            retrieved_document,
            retrieved_sources,
            retrieved_chunks,
            action,
            label,
            blocked,
            reason,
            rule_score,
            semantic_score,
            ml_score,
            rule_label,
            semantic_label,
            ml_label,
            risk_score,
            response
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            prompt,
            retrieved_document,
            json.dumps(retrieved_sources or []),
            json.dumps(retrieved_chunks or []),
            action,
            label,
            int(blocked),
            reason,
            rule_score,
            semantic_score,
            ml_score,
            rule_label,
            semantic_label,
            ml_label,
            risk_score,
            response,
        ),
    )

    conn.commit()
    conn.close()
