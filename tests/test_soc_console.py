from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.application_registry import UNIVERSITY_APPLICATION_ID, bootstrap_default_application
from app.auth import hash_password, seed_development_users
from app.config import reset_settings_cache
from app.database import Base, get_db
from app.db import init_db
from app.models import PortalScope, User, UserRole
from app.security_events import list_incidents, record_security_event


class SocConsoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._temp_dir.name) / "llmguard.db"
        self._previous_db_path = os.environ.get("LLMGUARD_DB_PATH")
        os.environ["LLMGUARD_DB_PATH"] = str(self.db_path)
        reset_settings_cache()
        init_db()
        bootstrap_default_application()

        self.auth_engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.auth_engine)
        self.auth_session = sessionmaker(bind=self.auth_engine, expire_on_commit=False)
        with self.auth_session() as db:
            seed_development_users(db)
            db.add(
                User(
                    username="security-read-only",
                    password_hash=hash_password("Employee@123"),
                    role=UserRole.employee,
                    portal_scope=PortalScope.admin,
                    synthetic_ref="SYNTHETIC-SOC-READ-ONLY",
                    is_active=True,
                )
            )
            db.commit()

        from app.main import app

        def isolated_auth_db():
            with self.auth_session() as db:
                yield db

        self.app = app
        self.app.dependency_overrides[get_db] = isolated_auth_db
        self.client = TestClient(self.app)
        self._login("admin1", "Admin@123")

    def tearDown(self) -> None:
        self.app.dependency_overrides.pop(get_db, None)
        self.client.close()
        self.auth_engine.dispose()
        if self._previous_db_path is None:
            os.environ.pop("LLMGUARD_DB_PATH", None)
        else:
            os.environ["LLMGUARD_DB_PATH"] = self._previous_db_path
        reset_settings_cache()
        self._temp_dir.cleanup()

    def _login(self, username: str, password: str) -> None:
        self.client.cookies.clear()
        response = self.client.post(
            "/auth/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(200, response.status_code)

    def _record(
        self,
        *,
        request_id: str,
        channel: str = "public",
        stage: str = "input",
        event_type: str = "INPUT_FIREWALL",
        classification: str = "safe",
        severity: str = "low",
        risk_score: float | None = 0.05,
        action: str = "allow",
        source_id: str | None = None,
        chunk_id: str | None = None,
    ):
        return record_security_event(
            application_id=UNIVERSITY_APPLICATION_ID,
            channel=channel,
            request_id=request_id,
            stage=stage,
            event_type=event_type,
            classification=classification,
            severity=severity,
            risk_score=risk_score,
            action=action,
            source_id=source_id,
            chunk_id=chunk_id,
        )

    def test_empty_state_pages_render_without_placeholder_events(self) -> None:
        expectations = {
            "/admin/security-dashboard": "No unified security events have been recorded.",
            "/admin/soc/events": "No events match the selected filters.",
            "/admin/soc/incidents": "No incidents match the selected filters.",
            "/admin/soc/quarantine": "No quarantine events have been recorded.",
            "/admin/soc/trace": "Enter a request ID",
        }
        for path, message in expectations.items():
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(200, response.status_code)
                self.assertIn(message, response.text)

    def test_overview_metrics_are_derived_from_real_events(self) -> None:
        self._record(request_id="safe-event")
        self._record(
            request_id="suspicious-event",
            classification="suspicious",
            severity="medium",
            risk_score=0.55,
            action="sanitize",
        )
        self._record(
            request_id="malicious-event",
            classification="malicious",
            severity="high",
            risk_score=0.96,
            action="block",
        )
        self._record(
            request_id="session-event",
            event_type="SESSION_RESTRICTION",
            classification="session_risk",
            severity="high",
            risk_score=0.62,
            action="session_restrict",
        )

        response = self.client.get("/admin/security-dashboard")

        self.assertEqual(200, response.status_code)
        self.assertIn("<span>Total recent events</span><strong>4</strong>", response.text)
        self.assertIn("<span>Suspicious</span><strong>1</strong>", response.text)
        self.assertIn("<span>Malicious</span><strong>1</strong>", response.text)
        self.assertIn("<span>Blocked</span><strong>1</strong>", response.text)
        self.assertIn("<span>Session restricted</span><strong>1</strong>", response.text)
        self.assertIn("University of Haripur AI System", response.text)
        self.assertIn("public", response.text)

    def test_live_event_filters_and_bypass_distinction(self) -> None:
        self._record(request_id="public-safe-visible")
        self._record(
            request_id="employee-malicious-visible",
            channel="employee",
            classification="malicious",
            severity="high",
            risk_score=0.99,
            action="block",
        )
        self._record(
            request_id="bypass-visible",
            event_type="PROTECTION_BYPASS",
            classification="bypassed",
            severity="none",
            risk_score=None,
            action="bypass",
        )
        self._record(
            request_id="integration-failure-visible",
            channel="integration",
            stage="integration",
            event_type="INTEGRATION_VALIDATION_FAILURE",
            classification="suspicious",
            severity="medium",
            risk_score=None,
            action="reject",
        )

        filtered = self.client.get(
            "/admin/soc/events",
            params={"channel": "employee", "action": "block"},
        )
        self.assertEqual(200, filtered.status_code)
        self.assertIn("employee-malicious-visible", filtered.text)
        self.assertNotIn("public-safe-visible", filtered.text)
        self.assertNotIn("bypass-visible", filtered.text)

        all_events = self.client.get("/admin/soc/events")
        self.assertIn('class="soc-state-bypassed"', all_events.text)
        self.assertIn("bypassed", all_events.text)
        self.assertIn('class="soc-state-failure"', all_events.text)
        self.assertIn("INTEGRATION_VALIDATION_FAILURE", all_events.text)

    def test_incident_detail_correlation_and_lifecycle_are_real(self) -> None:
        request_id = "incident-console-trace"
        self._record(
            request_id=request_id,
            classification="malicious",
            severity="high",
            risk_score=0.97,
            action="block",
        )
        self._record(
            request_id=request_id,
            stage="context",
            event_type="CONTEXT_FIREWALL",
            classification="malicious",
            severity="critical",
            risk_score=1.0,
            action="quarantine",
            source_id="safe-source-reference",
            chunk_id="safe-chunk-reference",
        )
        incident = list_incidents()[0]

        listing = self.client.get("/admin/soc/incidents")
        self.assertIn(incident.incident_id, listing.text)
        detail_path = f"/admin/soc/incidents/{incident.incident_id}"
        detail = self.client.get(detail_path)
        self.assertEqual(200, detail.status_code)
        self.assertIn("2 correlated events", detail.text)
        self.assertIn("INPUT_FIREWALL", detail.text)
        self.assertIn("CONTEXT_FIREWALL", detail.text)
        self.assertIn("safe-source-reference", detail.text)
        self.assertIn("safe-chunk-reference", detail.text)

        acknowledged = self.client.post(
            f"{detail_path}/acknowledge",
            follow_redirects=False,
        )
        self.assertEqual(303, acknowledged.status_code)
        updated = self.client.get(detail_path)
        self.assertIn("ACKNOWLEDGED", updated.text)
        self.assertIn("OPEN → ACKNOWLEDGED", updated.text)
        self.assertIn("Actor: admin1", updated.text)

        resolved = self.client.post(f"{detail_path}/resolve", follow_redirects=False)
        self.assertEqual(303, resolved.status_code)
        self.assertIn("RESOLVED", self.client.get(detail_path).text)

    def test_non_admin_cannot_mutate_incident(self) -> None:
        self._record(
            request_id="read-only-denied",
            classification="malicious",
            severity="high",
            risk_score=0.98,
            action="block",
        )
        incident_id = list_incidents()[0].incident_id
        self._login("security-read-only", "Employee@123")
        response = self.client.post(
            f"/admin/soc/incidents/{incident_id}/acknowledge",
            follow_redirects=False,
        )
        self.assertEqual(403, response.status_code)

    def test_request_trace_is_ordered_and_marks_missing_stages(self) -> None:
        request_id = "trace-with-gap"
        self._record(request_id=request_id, stage="input", event_type="INPUT_FIREWALL")
        self._record(request_id=request_id, stage="output", event_type="OUTPUT_FIREWALL")

        response = self.client.get(
            "/admin/soc/trace",
            params={"request_id": request_id},
        )

        self.assertEqual(200, response.status_code)
        self.assertLess(response.text.index("INPUT_FIREWALL"), response.text.index("OUTPUT_FIREWALL"))
        self.assertIn("No event recorded; this stage may not have executed.", response.text)
        self.assertIn("1 event recorded", response.text)

    def test_quarantine_view_is_metadata_only_and_links_incident(self) -> None:
        request_id = "quarantine-metadata-only"
        raw_payload = "RAW-QUARANTINED-PROMPT-MUST-NEVER-RENDER"
        self._record(
            request_id=request_id,
            stage="context",
            event_type="CONTEXT_FIREWALL",
            classification="malicious",
            severity="high",
            risk_score=0.99,
            action="quarantine",
            source_id="quarantine-source-id",
            chunk_id="quarantine-chunk-id",
        )
        incident_id = list_incidents()[0].incident_id

        response = self.client.get("/admin/soc/quarantine")

        self.assertEqual(200, response.status_code)
        self.assertIn(request_id, response.text)
        self.assertIn("quarantine-source-id", response.text)
        self.assertIn("quarantine-chunk-id", response.text)
        self.assertIn(incident_id, response.text)
        self.assertNotIn(raw_payload, response.text)
        self.assertNotIn("prompt", response.text.lower())
        self.assertNotIn("document text", response.text.lower())


if __name__ == "__main__":
    unittest.main()
