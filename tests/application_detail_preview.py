"""Isolated synthetic Application Detail preview/fixtures; never opens production DBs."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
PREVIEW = ROOT / "reports" / "ui" / "application-detail" / "preview"
PREVIEW.mkdir(parents=True, exist_ok=True)
os.environ["LLMGUARD_DB_PATH"] = str(PREVIEW / "llmguard.db")
os.environ["LLMGUARD_TESTBED_DATABASE_URL"] = "sqlite:///" + (PREVIEW / "auth.db").as_posix()
os.environ["LLMGUARD_HEARTBEAT_TIMEOUT_SECONDS"] = "3600"

from app.application_registry import UNIVERSITY_APPLICATION_ID, bootstrap_default_application
from app.db import init_db
from app.integration_health import record_heartbeat
from app.protection_control import record_guard_stage_success


def fixture(mode):
    if mode not in {"reset", "pending", "protected", "degraded", "disconnected"}:
        raise ValueError("Choose serve/reset/pending/protected/degraded/disconnected.")
    init_db()
    bootstrap_default_application()
    with sqlite3.connect(PREVIEW / "llmguard.db") as db:
        if mode == "reset":
            for table in ("api_credentials", "application_protection_audit"):
                db.execute(f"DELETE FROM {table} WHERE application_id = ?", (UNIVERSITY_APPLICATION_ID,))
            db.execute("UPDATE application_protection SET protection_enabled = 1 WHERE application_id = ?", (UNIVERSITY_APPLICATION_ID,))
        for table in ("application_guard_health", "integration_health"):
            db.execute(f"DELETE FROM {table} WHERE application_id = ?", (UNIVERSITY_APPLICATION_ID,))
    if mode in {"reset", "pending"}:
        return
    record_heartbeat(application_id=UNIVERSITY_APPLICATION_ID, environment="development",
                     application_version="synthetic-qa-app", integration_version="synthetic-qa-integration",
                     channels=("public", "student", "employee"),
                     received_at=datetime.now(timezone.utc) - timedelta(days=1) if mode == "disconnected" else None)
    for stage in (("input",) if mode == "degraded" else ("input", "context", "output")):
        record_guard_stage_success(UNIVERSITY_APPLICATION_ID, stage)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode == "serve":
        from app.auth import seed_development_users
        from app.database import SessionLocal, init_database
        import uvicorn
        init_database()
        with SessionLocal() as db:
            seed_development_users(db)
        fixture("protected")
        uvicorn.run("app.main:app", host="127.0.0.1", port=8766)
    else:
        fixture(mode)
