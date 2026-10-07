"""Optional browser preview; fixtures and both SQLite stores are QA-only."""
import json
import os
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
PREVIEW = ROOT / "reports" / "ui" / "security-incidents" / "preview"
PREVIEW.mkdir(parents=True, exist_ok=True)
os.environ["LLMGUARD_DB_PATH"] = str(PREVIEW / "llmguard.db")
os.environ["LLMGUARD_TESTBED_DATABASE_URL"] = "sqlite:///" + (PREVIEW / "auth.db").as_posix()

from app.application_registry import UNIVERSITY_APPLICATION_ID, bootstrap_default_application, register_application
from app.db import init_db
from app.security_events import list_incidents, record_security_event, update_incident_status
from dataclasses import asdict


def fixture(mode):
    if mode not in {"incidents", "empty"}:
        raise ValueError("Choose serve/incidents/empty.")
    init_db()
    bootstrap_default_application()
    with sqlite3.connect(PREVIEW / "llmguard.db") as db:
        for table in ("security_incident_status_audit", "security_incident_events", "security_incidents", "security_events"):
            db.execute(f"DELETE FROM {table}")
    if mode == "incidents":
        register_application(organization_name="Synthetic QA", organization_slug="synthetic-incidents-qa",
                             application_id="synthetic-incidents-qa", name="Synthetic QA Application",
                             slug="synthetic-incidents-qa", environment="test", status="registered", channels=("public",))
        cases = [(UNIVERSITY_APPLICATION_ID, "high", "OPEN", "input"),
                 (UNIVERSITY_APPLICATION_ID, "critical", "ACKNOWLEDGED", "context"),
                 (UNIVERSITY_APPLICATION_ID, "high", "RESOLVED", "input"),
                 ("synthetic-incidents-qa", "high", "OPEN", "input")]
        for index, (app_id, severity, state, stage) in enumerate(cases):
            request_id = f"synthetic-incidents-{index}-" + "x" * 150
            record_security_event(application_id=app_id, request_id=request_id, channel="public", stage=stage,
                                  event_type="SESSION_RESTRICTION" if index == 3 else "CONTEXT_FIREWALL" if stage == "context" else "INPUT_FIREWALL",
                                  classification="session_risk" if index == 3 else "malicious", severity=severity,
                                  action="session_restrict" if index == 3 else "quarantine" if stage == "context" else "block", risk_score=.97)
            incident = list_incidents(application_id=app_id)[0]
            if state != "OPEN":
                update_incident_status(incident.incident_id, new_status=state, actor="synthetic-qa")
            if index == 0:
                record_security_event(application_id=app_id, request_id=request_id, channel="public", stage="output",
                                      event_type="OUTPUT_FIREWALL", classification="malicious", severity="high", action="block", risk_score=.97)
    (PREVIEW.parent / "fixture.json").write_text(json.dumps([asdict(i) for i in list_incidents()], indent=2), encoding="utf-8")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode == "serve":
        from app.auth import seed_development_users
        from app.database import SessionLocal, init_database
        import uvicorn
        init_database()
        with SessionLocal() as db:
            seed_development_users(db)
        fixture("incidents")
        uvicorn.run("app.main:app", host="127.0.0.1", port=8768)
    else:
        fixture(mode)
