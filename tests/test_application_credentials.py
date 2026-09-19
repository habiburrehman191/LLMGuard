from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.application_credentials import (
    create_credential,
    list_credentials,
    revoke_credential,
    verify_credential,
)
from app.application_registry import (
    UNIVERSITY_APPLICATION_ID,
    bootstrap_default_application,
    register_application,
)
from app.auth import seed_development_users
from app.config import reset_settings_cache
from app.database import Base, get_db
from app.db import init_db


class ApplicationCredentialTests(unittest.TestCase):
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

    def test_plaintext_is_not_stored_and_valid_secret_verifies(self) -> None:
        init_db()
        init_db()
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        created = create_credential(
            UNIVERSITY_APPLICATION_ID,
            expires_at=expires_at,
        )

        with closing(sqlite3.connect(self.db_path)) as conn:
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(api_credentials)")
            }
            stored_hash = conn.execute(
                "SELECT secret_hash FROM api_credentials WHERE key_id = ?",
                (created.credential.key_id,),
            ).fetchone()[0]

        self.assertEqual(
            {
                "id",
                "application_id",
                "key_id",
                "secret_hash",
                "status",
                "created_at",
                "expires_at",
                "revoked_at",
                "last_used_at",
            },
            columns,
        )
        self.assertNotEqual(created.secret, stored_hash)
        self.assertNotIn(created.secret, stored_hash)
        self.assertNotIn(created.secret.encode("utf-8"), self.db_path.read_bytes())
        self.assertNotIn(created.secret, repr(created))
        self.assertRegex(stored_hash, r"^sha256\$[0-9a-f]{64}$")
        self.assertFalse(
            verify_credential(
                UNIVERSITY_APPLICATION_ID,
                created.credential.key_id,
                "wrong-secret",
            )
        )
        self.assertTrue(
            verify_credential(
                UNIVERSITY_APPLICATION_ID,
                created.credential.key_id,
                created.secret,
            )
        )
        listed = list_credentials(UNIVERSITY_APPLICATION_ID)[0]
        self.assertFalse(hasattr(listed, "secret"))
        self.assertFalse(hasattr(listed, "secret_hash"))
        self.assertIsNotNone(listed.expires_at)
        self.assertIsNotNone(listed.last_used_at)

    def test_revoked_secret_fails_verification(self) -> None:
        created = create_credential(UNIVERSITY_APPLICATION_ID)

        self.assertTrue(
            revoke_credential(
                UNIVERSITY_APPLICATION_ID,
                created.credential.key_id,
            )
        )
        self.assertFalse(
            verify_credential(
                UNIVERSITY_APPLICATION_ID,
                created.credential.key_id,
                created.secret,
            )
        )
        credential = list_credentials(UNIVERSITY_APPLICATION_ID)[0]
        self.assertEqual("REVOKED", credential.status)
        self.assertIsNotNone(credential.revoked_at)

    def test_credential_is_scoped_to_its_application(self) -> None:
        register_application(
            organization_name="Example Organization",
            organization_slug="example-organization",
            application_id="example-application",
            name="Example Application",
            slug="example-application",
            environment="development",
            status="REGISTERED",
            channels=("public",),
        )
        created = create_credential(UNIVERSITY_APPLICATION_ID)

        self.assertFalse(
            verify_credential(
                "example-application",
                created.credential.key_id,
                created.secret,
            )
        )
        self.assertFalse(
            revoke_credential("example-application", created.credential.key_id)
        )
        self.assertEqual([], list_credentials("example-application"))

    def test_rotation_keeps_new_credential_valid_when_old_is_revoked(self) -> None:
        old = create_credential(UNIVERSITY_APPLICATION_ID)
        replacement = create_credential(UNIVERSITY_APPLICATION_ID)

        self.assertNotEqual(old.credential.key_id, replacement.credential.key_id)
        self.assertNotEqual(old.secret, replacement.secret)
        self.assertTrue(
            verify_credential(
                UNIVERSITY_APPLICATION_ID,
                old.credential.key_id,
                old.secret,
            )
        )
        self.assertTrue(
            verify_credential(
                UNIVERSITY_APPLICATION_ID,
                replacement.credential.key_id,
                replacement.secret,
            )
        )
        self.assertTrue(
            revoke_credential(
                UNIVERSITY_APPLICATION_ID,
                old.credential.key_id,
            )
        )
        self.assertFalse(
            verify_credential(
                UNIVERSITY_APPLICATION_ID,
                old.credential.key_id,
                old.secret,
            )
        )
        self.assertTrue(
            verify_credential(
                UNIVERSITY_APPLICATION_ID,
                replacement.credential.key_id,
                replacement.secret,
            )
        )

    def test_admin_management_requires_auth_and_secret_is_shown_once(self) -> None:
        detail_path = f"/admin/applications/{UNIVERSITY_APPLICATION_ID}"
        create_path = f"{detail_path}/credentials"
        existing = create_credential(UNIVERSITY_APPLICATION_ID)
        revoke_path = f"{create_path}/{existing.credential.key_id}/revoke"

        self.assertEqual(401, self.client.get(detail_path).status_code)
        self.assertEqual(401, self.client.post(create_path).status_code)
        self.assertEqual(401, self.client.post(revoke_path).status_code)

        login = self.client.post(
            "/auth/login",
            json={"username": "admin1", "password": "Admin@123"},
        )
        self.assertEqual(200, login.status_code)

        detail = self.client.get(detail_path)
        self.assertEqual(200, detail.status_code)
        self.assertIn(existing.credential.key_id, detail.text)
        self.assertNotIn(existing.secret, detail.text)

        creation = self.client.post(create_path)
        self.assertEqual(201, creation.status_code)
        self.assertEqual("no-store", creation.headers["cache-control"])
        secret_match = re.search(r"llmg_secret_[A-Za-z0-9_-]+", creation.text)
        self.assertIsNotNone(secret_match)
        one_time_secret = secret_match.group(0)
        self.assertIn("will not be shown again", creation.text)

        subsequent_detail = self.client.get(detail_path)
        self.assertEqual(200, subsequent_detail.status_code)
        self.assertNotIn(one_time_secret, subsequent_detail.text)

        revoked = self.client.post(revoke_path, follow_redirects=False)
        self.assertEqual(303, revoked.status_code)
        self.assertEqual(detail_path, revoked.headers["location"])
        self.assertIn("Revoked", self.client.get(detail_path).text)


if __name__ == "__main__":
    unittest.main()
