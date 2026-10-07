"""Synthetic Events preview only; all writes are fixed to an ignored QA directory."""
import os
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
PREVIEW = ROOT / "reports" / "ui" / "security-events" / "preview"
PREVIEW.mkdir(parents=True, exist_ok=True)
os.environ["LLMGUARD_DB_PATH"] = str(PREVIEW / "llmguard.db")
os.environ["LLMGUARD_TESTBED_DATABASE_URL"] = "sqlite:///" + (PREVIEW / "auth.db").as_posix()

from app.application_registry import UNIVERSITY_APPLICATION_ID, bootstrap_default_application, register_application
from app.db import init_db
from app.security_events import record_security_event


def fixture(mode):
    if mode not in {"events", "empty"}:
        raise ValueError("Choose serve/events/empty.")
    init_db()
    bootstrap_default_application()
    with sqlite3.connect(PREVIEW / "llmguard.db") as db:
        # This connection can only open this helper's fixed synthetic preview DB.
        for table in ("security_incident_status_audit", "security_incident_events", "security_incidents", "security_events"):
            db.execute(f"DELETE FROM {table}")
    if mode == "empty":
        return
    register_application(organization_name="Synthetic QA", organization_slug="synthetic-qa",
                         application_id="synthetic-qa-events", name="Synthetic QA Application",
                         slug="synthetic-qa-events", environment="test", status="registered", channels=("public",))
    cases = [
        ("public", "input", "INPUT_FIREWALL", "safe", "low", .02, "allow"),
        ("student", "input", "PROMPT_INJECTION", "malicious", "high", .96, "block"),
        ("employee", "context", "INDIRECT_PROMPT_INJECTION", "malicious", "critical", .84, "quarantine"),
        ("student", "output", "SENSITIVE_OUTPUT", "suspicious", "medium", .61, "sanitize"),
        ("public", "input", "SESSION_RESTRICTION", "session_risk", "high", .62, "session_restrict"),
        ("employee", "output", "PROTECTION_BYPASS", "bypassed", "none", None, "bypass"),
        ("integration", "integration", "INTEGRATION_VALIDATION_FAILURE", "error", "high", None, "reject"),
        ("employee", "context", "CROSS_CHUNK_DETECTION", "malicious", "high", .91, "block"),
    ]
    for index, (channel, stage, event_type, classification, severity, risk_score, action) in enumerate(cases):
        record_security_event(application_id=UNIVERSITY_APPLICATION_ID, channel=channel, stage=stage,
                              event_type=event_type, classification=classification, severity=severity,
                              risk_score=risk_score, action=action,
                              request_id=f"synthetic-events-qa-{index}-" + "x" * 170)
    record_security_event(application_id="synthetic-qa-events", channel="public", stage="input",
                          event_type="INPUT_FIREWALL", classification="safe", severity="low",
                          risk_score=0, action="log")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode == "serve":
        from app.auth import seed_development_users
        from app.database import SessionLocal, init_database
        import uvicorn
        init_database()
        with SessionLocal() as db:
            seed_development_users(db)
        fixture("events")
        uvicorn.run("app.main:app", host="127.0.0.1", port=8767)
    else:
        fixture(mode)
