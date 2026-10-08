"""Synthetic dashboard browser fixtures; refuses to seed the application database."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DB = ROOT / "reports" / "ui" / "dashboard-preview" / "llmguard.db"
if Path(os.environ.get("LLMGUARD_DB_PATH", "")).resolve() != EXPECTED_DB.resolve():
    raise RuntimeError("Set LLMGUARD_DB_PATH to reports/ui/dashboard-preview/llmguard.db only.")

from app.application_registry import UNIVERSITY_APPLICATION_ID, register_application
from app.db import init_db
from app.integration_health import record_heartbeat
from app.protection_control import record_guard_stage_success
from app.security_events import record_security_event

init_db()
register_application(organization_name="Synthetic QA", organization_slug="synthetic-qa",
                     application_id="synthetic-empty", name="Synthetic Empty Application",
                     slug="synthetic-empty", environment="test", status="active", channels=("public",))
record_heartbeat(application_id=UNIVERSITY_APPLICATION_ID, environment="development",
                 application_version="synthetic-qa-app", integration_version="synthetic-qa-integration",
                 channels=("public", "student", "employee"))
for stage in ("input", "context", "output"):
    record_guard_stage_success(UNIVERSITY_APPLICATION_ID, stage)
for i, (stage, action, category, risk) in enumerate([
    ("input", "allow", "safe", .02), ("input", "block", "malicious", .9),
    ("context", "quarantine", "malicious", .8), ("output", "sanitize", "suspicious", .5),
    ("input", "allow", "safe", None), ("input", "block", "malicious", .7),
]):
    record_security_event(application_id=UNIVERSITY_APPLICATION_ID, channel="public",
                          request_id=f"synthetic-dashboard-qa-{i}", stage=stage,
                          event_type=stage.upper() + "_FIREWALL", classification=category,
                          severity="high" if category == "malicious" else "low",
                          action=action, risk_score=risk)
