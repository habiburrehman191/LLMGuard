from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.application_registry import UNIVERSITY_APPLICATION_ID, bootstrap_default_application, register_application
from app.auth import seed_development_users
from app.config import reset_settings_cache
from app.database import Base, get_db
from app.db import init_db
from app.integration_health import record_heartbeat
from app.protection_control import record_guard_stage_success, set_protection_enabled
from app.security_events import get_security_overview, record_security_event


class DashboardFrontendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("LLMGUARD_DB_PATH")
        os.environ["LLMGUARD_DB_PATH"] = str(Path(self.temp.name) / "dashboard.db")
        reset_settings_cache()
        init_db()
        bootstrap_default_application()
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)
        with self.sessions() as db:
            seed_development_users(db)
        from app.main import app
        self.app = app
        def auth_db():
            with self.sessions() as db:
                yield db
        app.dependency_overrides[get_db] = auth_db
        self.client = TestClient(app)
        self.assertEqual(200, self.client.post("/auth/login", json={"username": "admin1", "password": "Admin@123"}).status_code)

    def tearDown(self):
        self.app.dependency_overrides.pop(get_db, None)
        self.client.close()
        self.engine.dispose()
        if self.previous is None:
            os.environ.pop("LLMGUARD_DB_PATH", None)
        else:
            os.environ["LLMGUARD_DB_PATH"] = self.previous
        reset_settings_cache()
        self.temp.cleanup()

    def page(self, application_id=UNIVERSITY_APPLICATION_ID):
        response = self.client.get("/admin/dashboard", params={"application_id": application_id})
        self.assertEqual(200, response.status_code)
        return response.text

    def heartbeat(self, *, old=False):
        record_heartbeat(application_id=UNIVERSITY_APPLICATION_ID, environment="development",
                         application_version=None, integration_version=None,
                         channels=("public", "student", "employee"),
                         received_at=datetime.now(timezone.utc) - timedelta(days=1) if old else None)

    def record(self, *, request_id, action="allow", stage="input", classification="safe", risk=None,
               application_id=UNIVERSITY_APPLICATION_ID, event_type="INPUT_FIREWALL"):
        return record_security_event(application_id=application_id, channel="public", request_id=request_id,
                                     stage=stage, event_type=event_type, classification=classification,
                                     severity="high" if classification == "malicious" else "low",
                                     action=action, risk_score=risk)

    def test_empty_dashboard_has_seven_truthful_stages_and_one_shell(self):
        html = self.page()
        self.assertIn("No security activity yet", html)
        self.assertIn("No security events yet", html)
        self.assertIn("0 / 3", html)
        self.assertIn("state-integration_pending", html)
        self.assertIn(
            '<div class="protection-gauge-copy"><span>Verified guard stages</span><strong>0 / 3</strong>',
            html,
        )
        self.assertIn("<small>Integration Pending</small>", html)
        self.assertIn('data-protection-state="INTEGRATION_PENDING"', html)
        self.assertEqual(7, html.count('data-runtime-stage='))
        self.assertEqual(7, html.count('data-runtime-checkpoint='))
        self.assertEqual(7, html.count('data-stage-status="Not reported"'))
        self.assertEqual(1, html.count('class="console-header"'))
        self.assertIn("Channels: public, student, employee", html)
        self.assertNotIn("ApplicationChannelRecord(", html)
        self.assertIn("qwen3:1.7b", html)
        self.assertIn('data-application-logo="university-of-haripur"', html)
        self.assertIn('src="/static/branding/university-of-haripur-logo.png"', html)
        for unsupported in ("gpt-4o-mini", "Pinecone", "ChromaDB", "PCAP", "100% Verified", "Simulate Prompt Attack"):
            self.assertNotIn(unsupported, html)
        self.assertNotRegex(html, r'data-stage-status="[^"]*ms')
        self.assertNotIn("tailwind", html.lower())

    def test_real_runtime_states_and_partial_guard_readiness_render(self):
        self.heartbeat()
        record_guard_stage_success(UNIVERSITY_APPLICATION_ID, "input")
        html = self.page()
        self.assertIn("state-degraded", html)
        self.assertIn("1 / 3", html)
        self.assertIn("<small>Degraded</small>", html)
        self.assertEqual(1, html.count('data-stage-status="READY"'))
        for stage in ("context", "output"):
            record_guard_stage_success(UNIVERSITY_APPLICATION_ID, stage)
        protected_html = self.page()
        self.assertIn("state-protected", protected_html)
        self.assertIn("3 / 3", protected_html)
        self.assertIn("<small>Protected</small>", protected_html)
        set_protection_enabled(UNIVERSITY_APPLICATION_ID, enabled=False, actor="synthetic-dashboard-test",
                               reason="Synthetic local bypass rendering check")
        self.assertEqual(3, self.page().count('data-stage-status="BYPASSED"'))
        self.heartbeat(old=True)
        self.assertIn("state-disconnected", self.page())

    def test_stored_events_populate_chart_summary_and_recorded_stage_status(self):
        self.record(request_id="synthetic-safe")
        self.record(request_id="synthetic-block", action="block", classification="malicious", risk=.9)
        quarantine = self.record(request_id="synthetic-context", stage="context", action="quarantine",
                                 classification="malicious", risk=.8, event_type="CONTEXT_FIREWALL")
        self.record(request_id="synthetic-output", stage="output", action="sanitize", classification="suspicious",
                    risk=None, event_type="OUTPUT_FIREWALL")
        html = self.page()
        overview = get_security_overview(application_id=UNIVERSITY_APPLICATION_ID)
        self.assertIn('<span>Blocked</span><strong>1</strong><small>Last 24h</small>', html)
        self.assertIn('<span>Quarantined</span><strong>1</strong><small>Last 24h</small>', html)
        self.assertIn(f'<span>Open Incidents</span><strong>{overview.open_incidents}</strong><small>Current</small>', html)
        self.assertIn('<span>Safe Requests</span><strong>1</strong><small>Recent input requests</small>', html)
        self.assertIn('data-stage-status="BLOCK"', html)
        self.assertIn('data-stage-status="QUARANTINE"', html)
        self.assertIn('data-stage-status="SANITIZE"', html)
        self.assertIn(quarantine.created_at, html)
        self.assertIn("Risk: 90%", html)
        self.assertIn("Risk: Not scored", html)
        self.assertEqual(4, html.count("data-security-event"))
        self.assertIn("Action counts · latest 4 events within 24h", html)
        self.assertIn("request_id=synthetic-context", html)

    def test_selector_scopes_events_and_empty_application_without_fake_activity(self):
        register_application(organization_name="Synthetic QA", organization_slug="synthetic-qa",
                             application_id="synthetic-empty", name="Synthetic Empty Application",
                             slug="synthetic-empty", environment="test", status="active", channels=("public",))
        self.record(request_id="only-first-application", action="block", classification="malicious")
        html = self.page("synthetic-empty")
        self.assertIn('value="synthetic-empty" selected', html)
        self.assertNotIn('data-application-logo="university-of-haripur"', html)
        self.assertIn('method="get" action="/admin/dashboard"', html)
        self.assertNotIn("only-first-application", html)
        self.assertIn("No security events yet", html)
        self.assertNotIn('data-activity-action="block"', html)

    def test_recent_rows_are_capped_and_safe_requests_are_distinct_not_stage_totals(self):
        self.record(request_id="same-safe-request")
        self.record(request_id="same-safe-request", event_type="SESSION_POLICY")
        self.record(request_id="same-safe-request", stage="output", event_type="OUTPUT_FIREWALL")
        html = self.page()
        self.assertIn('<span>Safe Requests</span><strong>1</strong>', html)
        for i in range(8):
            self.record(request_id=f"synthetic-{i}", action="block", classification="malicious")
        html = self.page()
        self.assertEqual(5, html.count("data-security-event"))
        self.assertIn("latest 6 events within 24h", html)
        self.assertIn('<span>Blocked</span><strong>8</strong>', html)

    def test_unknown_stored_action_is_counted_without_inventing_classification(self):
        self.record(request_id="synthetic-custom", action="review")
        html = self.page()
        self.assertIn('data-activity-action="other"', html)
        self.assertIn('data-stage-status="REVIEW"', html)
        self.assertIn("Other actions", html)


if __name__ == "__main__":
    unittest.main()
