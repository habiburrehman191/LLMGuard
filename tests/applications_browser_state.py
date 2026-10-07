"""State fixtures for the isolated Applications browser preview only."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DB = ROOT / "reports" / "ui" / "applications-preview" / "llmguard.db"
if Path(os.environ.get("LLMGUARD_DB_PATH", "")).resolve() != EXPECTED_DB.resolve():
    raise RuntimeError("This helper only accepts reports/ui/applications-preview/llmguard.db.")
mode = sys.argv[1] if len(sys.argv) == 2 else ""
if mode not in {"pending", "protected", "degraded", "bypassed", "disconnected", "empty"}:
    raise RuntimeError("Choose pending/protected/degraded/bypassed/disconnected/empty.")

from app.application_registry import UNIVERSITY_APPLICATION_ID, bootstrap_default_application, list_applications
from app.integration_health import record_heartbeat
from app.protection_control import record_guard_stage_success, set_protection_enabled

if {app.application_id for app in list_applications()} - {UNIVERSITY_APPLICATION_ID}:
    raise RuntimeError("Preview contains unexpected applications; refusing to change fixtures.")
with sqlite3.connect(EXPECTED_DB) as db:
    db.execute("DELETE FROM application_guard_health WHERE application_id = ?", (UNIVERSITY_APPLICATION_ID,))
    db.execute("DELETE FROM integration_health WHERE application_id = ?", (UNIVERSITY_APPLICATION_ID,))
    if mode == "empty":
        for table in ("application_channels", "application_protection", "application_protection_audit", "applications"):
            db.execute(f"DELETE FROM {table} WHERE application_id = ?", (UNIVERSITY_APPLICATION_ID,))
        db.commit()
        sys.exit(0)

bootstrap_default_application()
set_protection_enabled(UNIVERSITY_APPLICATION_ID, enabled=True, actor="synthetic-browser-qa",
                       reason="Synthetic Applications presentation fixture")
if mode != "pending":
    record_heartbeat(application_id=UNIVERSITY_APPLICATION_ID, environment="development",
                     application_version="synthetic-qa-app", integration_version="synthetic-qa-integration",
                     channels=("public", "student", "employee"),
                     received_at=datetime.now(timezone.utc) - timedelta(days=1) if mode == "disconnected" else None)
    stages = ("input",) if mode == "degraded" else ("input", "context", "output")
    for stage in stages:
        record_guard_stage_success(UNIVERSITY_APPLICATION_ID, stage)
    if mode == "bypassed":
        set_protection_enabled(UNIVERSITY_APPLICATION_ID, enabled=False, actor="synthetic-browser-qa",
                               reason="Synthetic bypass presentation fixture")
