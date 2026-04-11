from __future__ import annotations

import json
import sqlite3
from collections import Counter
from typing import Any

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


def _decode_json_column(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def fetch_recent_logs(limit: int = 25) -> list[dict[str, Any]]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    rows = cursor.execute(
        """
        SELECT
            id,
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
            response,
            created_at
        FROM logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()

    records: list[dict[str, Any]] = []
    for row in rows:
        record = dict(row)
        record["blocked"] = bool(record["blocked"])
        record["retrieved_sources"] = _decode_json_column(record["retrieved_sources"], [])
        record["retrieved_chunks"] = _decode_json_column(record["retrieved_chunks"], [])
        records.append(record)

    return records


def fetch_dashboard_metrics(limit: int = 50) -> dict[str, Any]:
    recent_logs = fetch_recent_logs(limit=limit)
    conn = get_connection()
    cursor = conn.cursor()
    total_queries = cursor.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    label_rows = cursor.execute(
        "SELECT COALESCE(label, 'unknown') AS bucket, COUNT(*) FROM logs GROUP BY COALESCE(label, 'unknown')"
    ).fetchall()
    action_rows = cursor.execute(
        "SELECT COALESCE(action, 'unknown') AS bucket, COUNT(*) FROM logs GROUP BY COALESCE(action, 'unknown')"
    ).fetchall()
    conn.close()

    label_counts = Counter({row[0]: row[1] for row in label_rows})
    action_counts = Counter({row[0]: row[1] for row in action_rows})
    risk_history = [
        {
            "id": record["id"],
            "timestamp": record["created_at"],
            "risk_score": float(record.get("risk_score") or 0.0),
            "label": record.get("label") or "unknown",
            "action": record.get("action") or "unknown",
        }
        for record in reversed(recent_logs)
    ]

    return {
        "total_queries": total_queries,
        "label_counts": dict(label_counts),
        "action_counts": dict(action_counts),
        "recent_logs": recent_logs,
        "risk_history": risk_history,
    }
