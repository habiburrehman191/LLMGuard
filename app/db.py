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
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS demo_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario TEXT,
            mode TEXT NOT NULL,
            prompt TEXT NOT NULL,
            action TEXT NOT NULL,
            label TEXT NOT NULL,
            blocked INTEGER NOT NULL,
            risk_score REAL NOT NULL,
            threat_source TEXT,
            tool_name TEXT,
            tool_allowed INTEGER,
            qwen_called INTEGER,
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS access_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt TEXT NOT NULL,
            user_role TEXT NOT NULL,
            user_id TEXT,
            session_id TEXT,
            document_id TEXT,
            title TEXT,
            classification TEXT,
            source_path TEXT,
            allowed INTEGER NOT NULL,
            reason TEXT,
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
        ("threat_source", "TEXT"),
        ("tool_name", "TEXT"),
        ("tool_allowed", "INTEGER"),
        ("output_firewall_action", "TEXT"),
        ("canary_markers", "TEXT"),
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
    threat_source: str | None = None,
    tool_name: str | None = None,
    tool_allowed: bool | None = None,
    output_firewall_action: str | None = None,
    canary_markers: list[str] | None = None,
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
            , threat_source
            , tool_name
            , tool_allowed
            , output_firewall_action
            , canary_markers
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            threat_source,
            tool_name,
            None if tool_allowed is None else int(tool_allowed),
            output_firewall_action,
            json.dumps(canary_markers or []),
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
            threat_source,
            tool_name,
            tool_allowed,
            output_firewall_action,
            canary_markers,
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
        record["canary_markers"] = _decode_json_column(record.get("canary_markers"), [])
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
    demo_rows = cursor.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN label = 'safe' THEN 1 ELSE 0 END) AS safe_queries,
            SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) AS blocked_attacks,
            SUM(CASE WHEN tool_allowed = 0 AND tool_name IS NOT NULL THEN 1 ELSE 0 END) AS tool_calls_blocked,
            SUM(CASE WHEN threat_source = 'retrieved_content' AND blocked = 1 THEN 1 ELSE 0 END) AS document_injection_attempts,
            SUM(CASE WHEN threat_source IN ('tool_call', 'prompt') AND prompt LIKE '%student%' AND blocked = 1 THEN 1 ELSE 0 END) AS data_exfiltration_attempts
        FROM demo_events
        """
    ).fetchone()
    uoh_demo_rows = cursor.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN mode = 'protected' AND blocked = 1 THEN 1 ELSE 0 END) AS protected_blocks,
            SUM(CASE WHEN mode = 'unprotected' AND risk_score >= 0.5 THEN 1 ELSE 0 END) AS unprotected_risky_outputs,
            SUM(CASE WHEN tool_allowed = 0 AND tool_name IS NOT NULL THEN 1 ELSE 0 END) AS tool_calls_blocked,
            SUM(CASE WHEN threat_source = 'retrieved_content' AND blocked = 1 THEN 1 ELSE 0 END) AS retrieved_injection_attempts
        FROM demo_events
        WHERE scenario LIKE 'uoh_%'
        """
    ).fetchone()
    zero_trust_rows = cursor.execute(
        """
        SELECT
            SUM(CASE WHEN blocked = 1 AND threat_source = 'prompt' THEN 1 ELSE 0 END) AS prompt_blocks,
            SUM(CASE WHEN blocked = 1 AND threat_source = 'access_control' THEN 1 ELSE 0 END) AS access_blocks,
            SUM(CASE WHEN blocked = 1 AND threat_source = 'tool_call' THEN 1 ELSE 0 END) AS tool_blocks,
            SUM(CASE WHEN blocked = 1 AND threat_source = 'output_firewall' THEN 1 ELSE 0 END) AS output_blocks,
            SUM(CASE WHEN canary_markers IS NOT NULL AND canary_markers != '[]' THEN 1 ELSE 0 END) AS canary_attempts,
            SUM(CASE WHEN reason LIKE '%role-bypass%' OR reason LIKE '%bypass access control%' OR reason LIKE '%override portal permissions%' THEN 1 ELSE 0 END) AS role_bypass_attempts
        FROM logs
        """
    ).fetchone()
    unauthorized_retrieval_count = cursor.execute(
        "SELECT COUNT(*) FROM access_events WHERE allowed = 0"
    ).fetchone()[0]
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
        "demo_metrics": {
            "total": demo_rows[0] or 0,
            "safe_queries": demo_rows[1] or 0,
            "blocked_attacks": demo_rows[2] or 0,
            "tool_calls_blocked": demo_rows[3] or 0,
            "document_injection_attempts": demo_rows[4] or 0,
            "data_exfiltration_attempts": demo_rows[5] or 0,
        },
        "uoh_demo_metrics": {
            "total": uoh_demo_rows[0] or 0,
            "protected_blocks": uoh_demo_rows[1] or 0,
            "unprotected_risky_outputs": uoh_demo_rows[2] or 0,
            "tool_calls_blocked": uoh_demo_rows[3] or 0,
            "retrieved_injection_attempts": uoh_demo_rows[4] or 0,
        },
        "zero_trust_metrics": {
            "prompt_firewall_blocks": zero_trust_rows[0] or 0,
            "access_policy_blocks": zero_trust_rows[1] or 0,
            "tool_firewall_blocks": zero_trust_rows[2] or 0,
            "output_firewall_blocks": zero_trust_rows[3] or 0,
            "canary_leakage_attempts": zero_trust_rows[4] or 0,
            "unauthorized_retrieval_attempts": unauthorized_retrieval_count or 0,
            "role_bypass_attempts": zero_trust_rows[5] or 0,
        },
    }


def insert_demo_event(
    *,
    scenario: str | None,
    mode: str,
    prompt: str,
    action: str,
    label: str,
    blocked: bool,
    risk_score: float,
    threat_source: str | None,
    tool_name: str | None,
    tool_allowed: bool | None,
    qwen_called: bool | None,
    reason: str | None,
) -> None:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO demo_events (
                scenario,
                mode,
                prompt,
                action,
                label,
                blocked,
                risk_score,
                threat_source,
                tool_name,
                tool_allowed,
                qwen_called,
                reason
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scenario,
                mode,
                prompt,
                action,
                label,
                int(blocked),
                risk_score,
                threat_source,
                tool_name,
                None if tool_allowed is None else int(tool_allowed),
                None if qwen_called is None else int(qwen_called),
                reason,
            ),
        )
        conn.commit()
    except sqlite3.OperationalError as exc:
        conn.close()
        if "no such table: demo_events" not in str(exc).lower():
            raise
        init_db()
        insert_demo_event(
            scenario=scenario,
            mode=mode,
            prompt=prompt,
            action=action,
            label=label,
            blocked=blocked,
            risk_score=risk_score,
            threat_source=threat_source,
            tool_name=tool_name,
            tool_allowed=tool_allowed,
            qwen_called=qwen_called,
            reason=reason,
        )
        return
    conn.close()


def insert_access_event(
    *,
    prompt: str,
    user_role: str,
    user_id: str | None,
    session_id: str | None,
    document_id: str | None,
    title: str | None,
    classification: str | None,
    source_path: str | None,
    allowed: bool,
    reason: str | None,
) -> None:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO access_events (
                prompt,
                user_role,
                user_id,
                session_id,
                document_id,
                title,
                classification,
                source_path,
                allowed,
                reason
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                prompt,
                user_role,
                user_id,
                session_id,
                document_id,
                title,
                classification,
                source_path,
                int(allowed),
                reason,
            ),
        )
        conn.commit()
    except sqlite3.OperationalError as exc:
        conn.close()
        if "no such table: access_events" not in str(exc).lower():
            raise
        init_db()
        insert_access_event(
            prompt=prompt,
            user_role=user_role,
            user_id=user_id,
            session_id=session_id,
            document_id=document_id,
            title=title,
            classification=classification,
            source_path=source_path,
            allowed=allowed,
            reason=reason,
        )
        return
    conn.close()
