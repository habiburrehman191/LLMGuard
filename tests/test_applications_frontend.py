from __future__ import annotations

from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.application_registry import UNIVERSITY_APPLICATION_ID, bootstrap_default_application, get_application
from app.auth import seed_development_users
from app.config import reset_settings_cache
from app.database import Base, get_db
from app.db import init_db
from app.integration_health import record_heartbeat
from app.protection_control import record_guard_stage_failure, record_guard_stage_success, set_protection_enabled


class ListElements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class ApplicationsFrontendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("LLMGUARD_DB_PATH")
        os.environ["LLMGUARD_DB_PATH"] = str(Path(self.temp.name) / "registry.db")
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
        def isolated_auth():
            with self.sessions() as db:
                yield db
        app.dependency_overrides[get_db] = isolated_auth
        self.client = TestClient(app)
        self.login("admin1", "Admin@123")

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

    def login(self, username, password):
        self.client.cookies.clear()
        self.assertEqual(200, self.client.post("/auth/login", json={"username": username, "password": password}).status_code)

    def page(self):
        response = self.client.get("/admin/applications")
        self.assertEqual(200, response.status_code)
        return response.text

    def heartbeat(self, old=False):
        return record_heartbeat(application_id=UNIVERSITY_APPLICATION_ID, environment="development",
                                application_version="synthetic-app-version", integration_version="synthetic-integration-version",
                                channels=("public", "student", "employee"),
                                received_at=datetime.now(timezone.utc) - timedelta(days=1) if old else None)

    def test_one_actual_application_and_one_primary_detail_link(self):
        html = self.page()
        elements = ListElements(html).elements
        cards = [attrs for _, attrs in elements if "data-application-card" in attrs]
        self.assertEqual([UNIVERSITY_APPLICATION_ID], [attrs["data-application-card"] for attrs in cards])
        links = [attrs for tag, attrs in elements if tag == "a" and "application-card-link" in attrs.get("class", "")]
        self.assertEqual(1, len(links))
        self.assertEqual("/admin/applications/university-of-haripur", links[0]["href"])
        self.assertIn("1 registered application", html)
        self.assertIn("University of Haripur AI System", html)
        self.assertIn("Development", html)
        self.assertIn("Protected applications connected to LLMGuard.", html)
        self.assertEqual(["public", "student", "employee"], [attrs["data-channel"] for _, attrs in elements if "data-channel" in attrs])
        self.assertEqual(1, html.count('class="console-header"'))
        self.assertNotIn('data-application-tabs', html)
        self.assertNotIn('data-protection-control', html)
        for unsupported in ("Register Application", "Configure Pipeline", "Rotate Key", "Revoke Key",
                            "gpt-4o-mini", "Pinecone", "ChromaDB", "Live WebSocket",
                            "84,920", "LLM-SOC-V3", "SSO", "MFA", "Promote to Production"):
            self.assertNotIn(unsupported, html)
        self.assertNotIn("tailwind", html.lower())

    def test_pending_has_no_fabricated_heartbeat_or_guard_verification(self):
        html = self.page()
        self.assertIn('data-runtime-state="INTEGRATION_PENDING"', html)
        self.assertIn("Not received", html)
        self.assertEqual(3, html.count('data-verified="false"'))
        self.assertEqual(3, html.count("NOT REPORTED"))
        self.assertNotIn("<time ", html)

    def test_protected_uses_real_heartbeat_metadata_and_three_available_stages(self):
        health = self.heartbeat()
        for stage in ("input", "context", "output"):
            record_guard_stage_success(UNIVERSITY_APPLICATION_ID, stage)
        html = self.page()
        self.assertIn('data-runtime-state="PROTECTED"', html)
        self.assertEqual(3, html.count('data-verified="true"'))
        self.assertIn(health.last_heartbeat_at, html)
        self.assertIn("synthetic-app-version", html)
        self.assertIn("synthetic-integration-version", html)
        self.assertIn(">Connected</dd>", html)
        self.assertIn('protection-state enabled', html)

    def test_degraded_shows_only_available_guard_checks_and_bypass_is_explicit(self):
        self.heartbeat()
        record_guard_stage_success(UNIVERSITY_APPLICATION_ID, "input")
        html = self.page()
        self.assertIn('data-runtime-state="DEGRADED"', html)
        self.assertEqual(1, html.count('data-verified="true"'))
        self.assertEqual(2, html.count('data-verified="false"'))
        record_guard_stage_failure(UNIVERSITY_APPLICATION_ID, "input", error_code="synthetic-qa-failure")
        self.assertEqual(3, self.page().count('data-verified="false"'))
        set_protection_enabled(UNIVERSITY_APPLICATION_ID, enabled=False, actor="synthetic-test",
                               reason="Synthetic local presentation test")
        html = self.page()
        self.assertIn('data-runtime-state="BYPASSED"', html)
        self.assertIn('protection-state disabled', html)
        self.assertIn(">Disabled</strong>", html)

    def test_disconnected_preserves_stale_heartbeat_and_does_not_invent_readiness(self):
        health = self.heartbeat(old=True)
        html = self.page()
        self.assertIn('data-runtime-state="DISCONNECTED"', html)
        self.assertIn(health.last_heartbeat_at, html)
        self.assertIn(">Disconnected</dd>", html)
        self.assertEqual(3, html.count('data-verified="false"'))

    def test_empty_registry_renders_no_sample_application_or_actions(self):
        with patch("app.portals.admin.list_applications", return_value=[]):
            html = self.page()
        self.assertIn("0 registered applications", html)
        self.assertIn("No applications registered", html)
        self.assertIn("Applications appear here after they are registered with LLMGuard.", html)
        self.assertNotIn("data-application-card", html)
        self.assertNotIn("application-card-link", html)
        self.assertNotIn("University of Haripur AI System", html)

    def test_disabled_channel_is_labelled_without_an_authentication_claim(self):
        from dataclasses import replace
        actual = get_application(UNIVERSITY_APPLICATION_ID)
        channels = tuple(replace(channel, enabled=False) if channel.channel == "employee" else channel for channel in actual.channels)
        with patch("app.portals.admin.list_applications", return_value=[replace(actual, channels=channels)]):
            html = self.page()
        self.assertIn('aria-label="Employee channel disabled"', html)
        self.assertIn("Employee<small>Disabled</small>", html)

    def test_list_still_requires_existing_administrator_role(self):
        self.client.cookies.clear()
        self.assertEqual(401, self.client.get("/admin/applications").status_code)
        self.login("student1", "Student@123")
        self.assertEqual(403, self.client.get("/admin/applications").status_code)


if __name__ == "__main__":
    unittest.main()
