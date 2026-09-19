from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.application_registry import (
    UNIVERSITY_APPLICATION_ID,
    bootstrap_default_application,
    get_application,
    list_applications,
    list_channels,
    register_application,
)
from app.auth import seed_development_users
from app.config import reset_settings_cache
from app.database import Base, get_db
from app.db import init_db


class ApplicationRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._temp_dir.name) / "logs" / "llmguard.db"
        self.previous_db_path = os.environ.get("LLMGUARD_DB_PATH")
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
        if self.previous_db_path is None:
            os.environ.pop("LLMGUARD_DB_PATH", None)
        else:
            os.environ["LLMGUARD_DB_PATH"] = self.previous_db_path
        reset_settings_cache()
        self._temp_dir.cleanup()

    def test_registry_initialization_and_bootstrap_are_idempotent(self) -> None:
        init_db()
        bootstrap_default_application()
        bootstrap_default_application()

        with closing(sqlite3.connect(self.db_path)) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            organization_count = conn.execute(
                "SELECT COUNT(*) FROM organizations WHERE slug = ?",
                ("university-of-haripur",),
            ).fetchone()[0]
            application_count = conn.execute(
                "SELECT COUNT(*) FROM applications WHERE application_id = ?",
                (UNIVERSITY_APPLICATION_ID,),
            ).fetchone()[0]
            channel_count = conn.execute(
                "SELECT COUNT(*) FROM application_channels WHERE application_id = ?",
                (UNIVERSITY_APPLICATION_ID,),
            ).fetchone()[0]

        self.assertTrue(
            {"organizations", "applications", "application_channels"}.issubset(tables)
        )
        self.assertEqual(1, organization_count)
        self.assertEqual(1, application_count)
        self.assertEqual(3, channel_count)

    def test_university_application_and_channels_are_registered(self) -> None:
        application = get_application(UNIVERSITY_APPLICATION_ID)

        self.assertIsNotNone(application)
        self.assertEqual("University of Haripur AI System", application.name)
        self.assertEqual("University of Haripur", application.organization.name)
        self.assertEqual("development", application.environment)
        self.assertEqual("INTEGRATION_PENDING", application.status)
        self.assertEqual([UNIVERSITY_APPLICATION_ID], [item.application_id for item in list_applications()])
        self.assertEqual(
            ["public", "student", "employee"],
            [channel.channel for channel in list_channels(UNIVERSITY_APPLICATION_ID)],
        )
        self.assertTrue(all(channel.enabled for channel in application.channels))

    def test_register_application_service_is_idempotent(self) -> None:
        for _ in range(2):
            register_application(
                organization_name="Example Organization",
                organization_slug="example-organization",
                application_id="example-development-app",
                name="Example AI Application",
                slug="example-ai-application",
                environment="development",
                status="REGISTERED",
                channels=("public", "public", "internal"),
            )

        with closing(sqlite3.connect(self.db_path)) as conn:
            self.assertEqual(
                1,
                conn.execute(
                    "SELECT COUNT(*) FROM applications WHERE application_id = ?",
                    ("example-development-app",),
                ).fetchone()[0],
            )
            self.assertEqual(
                2,
                conn.execute(
                    "SELECT COUNT(*) FROM application_channels WHERE application_id = ?",
                    ("example-development-app",),
                ).fetchone()[0],
            )

    def test_applications_page_requires_admin_and_renders_registry(self) -> None:
        unauthenticated = self.client.get("/admin/applications")
        self.assertEqual(401, unauthenticated.status_code)

        login = self.client.post(
            "/auth/login",
            json={"username": "admin1", "password": "Admin@123"},
        )
        self.assertEqual(200, login.status_code)

        page = self.client.get("/admin/applications")
        dashboard = self.client.get("/admin/dashboard")
        self.assertEqual(200, page.status_code)
        self.assertEqual(200, dashboard.status_code)
        for expected in (
            "University of Haripur AI System",
            "University of Haripur",
            "Development",
            "Integration Pending",
            UNIVERSITY_APPLICATION_ID,
            "public",
            "student",
            "employee",
        ):
            self.assertIn(expected, page.text)
        self.assertIn("Registration records identity and intended channels only", page.text)
        self.assertIn("University of Haripur AI System", dashboard.text)
        self.assertIn("Integration Pending", dashboard.text)


if __name__ == "__main__":
    unittest.main()
