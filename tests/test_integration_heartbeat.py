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

from app.application_credentials import create_credential, revoke_credential
from app.application_registry import (
    UNIVERSITY_APPLICATION_ID,
    bootstrap_default_application,
    get_application,
    register_application,
)
from app.auth import seed_development_users
from app.config import reset_settings_cache
from app.database import Base, get_db
from app.db import init_db
from app.integration_health import (
    CONNECTED,
    DISCONNECTED,
    INTEGRATION_PENDING,
    get_integration_health,
    integration_status_for,
)


class IntegrationHeartbeatTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._temp_dir.name) / "logs" / "llmguard.db"
        self.previous_env = {
            name: os.environ.get(name)
            for name in (
                "LLMGUARD_DB_PATH",
                "LLMGUARD_HEARTBEAT_TIMEOUT_SECONDS",
                "LLMGUARD_HEARTBEAT_MAX_SKEW_SECONDS",
            )
        }
        os.environ["LLMGUARD_DB_PATH"] = str(self.db_path)
        os.environ["LLMGUARD_HEARTBEAT_TIMEOUT_SECONDS"] = "60"
        os.environ["LLMGUARD_HEARTBEAT_MAX_SKEW_SECONDS"] = "120"
        reset_settings_cache()
        init_db()
        bootstrap_default_application()
        self.created_credential = create_credential(UNIVERSITY_APPLICATION_ID)

        self.auth_engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.auth_engine)
        self.auth_session = sessionmaker(bind=self.auth_engine, expire_on_commit=False)
        with self.auth_session() as db:
            seed_development_users(db)

        from app.main import app

        def isolated_auth_db():
            with self.auth_session() as db:
                yield db

        self.app = app
        self.app.dependency_overrides[get_db] = isolated_auth_db
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.app.dependency_overrides.pop(get_db, None)
        self.client.close()
        self.auth_engine.dispose()
        for name, previous in self.previous_env.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous
        reset_settings_cache()
        self._temp_dir.cleanup()

    def _headers(self, *, secret: str | None = None, key_id: str | None = None) -> dict[str, str]:
        return {
            "X-LLMGuard-Key-ID": key_id or self.created_credential.credential.key_id,
            "X-LLMGuard-API-Secret": secret or self.created_credential.secret,
        }

    def _payload(
        self,
        *,
        application_id: str = UNIVERSITY_APPLICATION_ID,
        environment: str = "development",
        timestamp: datetime | None = None,
    ) -> dict[str, object]:
        return {
            "application_id": application_id,
            "environment": environment,
            "application_version": "uoh-demo-1.0",
            "integration_version": "heartbeat-v1",
            "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
            "channels": ["public", "student", "employee"],
        }

    def test_valid_heartbeat_moves_pending_to_connected(self) -> None:
        application = get_application(UNIVERSITY_APPLICATION_ID)
        self.assertIsNotNone(application)
        self.assertEqual(INTEGRATION_PENDING, integration_status_for(application).state)

        response = self.client.post(
            "/api/v1/integrations/heartbeat",
            json=self._payload(),
            headers=self._headers(),
        )

        self.assertEqual(200, response.status_code)
        self.assertTrue(response.json()["accepted"])
        self.assertEqual(CONNECTED, response.json()["integration_state"])
        health = get_integration_health(UNIVERSITY_APPLICATION_ID)
        self.assertIsNotNone(health)
        self.assertEqual("uoh-demo-1.0", health.application_version)
        self.assertEqual("heartbeat-v1", health.integration_version)
        self.assertEqual("development", health.environment)
        self.assertEqual(("public", "student", "employee"), health.channels)
        self.assertEqual(CONNECTED, integration_status_for(application).state)

    def test_wrong_and_revoked_credentials_are_rejected(self) -> None:
        wrong = self.client.post(
            "/api/v1/integrations/heartbeat",
            json=self._payload(),
            headers=self._headers(secret="wrong-secret"),
        )
        self.assertEqual(401, wrong.status_code)
        self.assertIsNone(get_integration_health(UNIVERSITY_APPLICATION_ID))

        revoke_credential(
            UNIVERSITY_APPLICATION_ID,
            self.created_credential.credential.key_id,
        )
        revoked = self.client.post(
            "/api/v1/integrations/heartbeat",
            json=self._payload(),
            headers=self._headers(),
        )
        self.assertEqual(401, revoked.status_code)
        self.assertIsNone(get_integration_health(UNIVERSITY_APPLICATION_ID))

    def test_credential_cannot_report_for_another_application(self) -> None:
        register_application(
            organization_name="Example Organization",
            organization_slug="example-organization",
            application_id="example-application",
            name="Example Application",
            slug="example-application",
            environment="development",
            status="REGISTERED",
            channels=("public", "student", "employee"),
        )

        response = self.client.post(
            "/api/v1/integrations/heartbeat",
            json=self._payload(application_id="example-application"),
            headers=self._headers(),
        )

        self.assertEqual(401, response.status_code)
        self.assertIsNone(get_integration_health("example-application"))

    def test_stale_timestamp_and_wrong_environment_are_rejected(self) -> None:
        stale = self.client.post(
            "/api/v1/integrations/heartbeat",
            json=self._payload(
                timestamp=datetime.now(timezone.utc) - timedelta(seconds=121)
            ),
            headers=self._headers(),
        )
        self.assertEqual(422, stale.status_code)
        self.assertIsNone(get_integration_health(UNIVERSITY_APPLICATION_ID))

        wrong_environment = self.client.post(
            "/api/v1/integrations/heartbeat",
            json=self._payload(environment="production"),
            headers=self._headers(),
        )
        self.assertEqual(422, wrong_environment.status_code)
        self.assertIsNone(get_integration_health(UNIVERSITY_APPLICATION_ID))

    def test_connected_state_becomes_disconnected_after_timeout(self) -> None:
        response = self.client.post(
            "/api/v1/integrations/heartbeat",
            json=self._payload(),
            headers=self._headers(),
        )
        self.assertEqual(200, response.status_code)
        application = get_application(UNIVERSITY_APPLICATION_ID)
        health = get_integration_health(UNIVERSITY_APPLICATION_ID)
        heartbeat_time = datetime.fromisoformat(health.last_heartbeat_at)

        self.assertEqual(
            DISCONNECTED,
            integration_status_for(
                application,
                now=heartbeat_time + timedelta(seconds=61),
                timeout_seconds=60,
            ).state,
        )

    def test_admin_views_render_real_heartbeat_metadata(self) -> None:
        heartbeat = self.client.post(
            "/api/v1/integrations/heartbeat",
            json=self._payload(),
            headers=self._headers(),
        )
        self.assertEqual(200, heartbeat.status_code)
        login = self.client.post(
            "/auth/login",
            json={"username": "admin1", "password": "Admin@123"},
        )
        self.assertEqual(200, login.status_code)

        for path in (
            "/admin/dashboard",
            "/admin/applications",
            f"/admin/applications/{UNIVERSITY_APPLICATION_ID}",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(200, response.status_code)
                self.assertIn("Connected", response.text)
                self.assertIn("uoh-demo-1.0", response.text)
                self.assertIn("heartbeat-v1", response.text)
                self.assertIn("public", response.text)
                self.assertNotIn("Secured", response.text)
                self.assertNotIn("Healthy", response.text)


if __name__ == "__main__":
    unittest.main()
