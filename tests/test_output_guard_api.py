from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient

from app.application_credentials import create_credential, revoke_credential
from app.application_registry import (
    UNIVERSITY_APPLICATION_ID,
    bootstrap_default_application,
    register_application,
)
from app.config import reset_settings_cache
from app.db import get_connection, init_db
from app.output_guard_telemetry import get_output_guard_decision


class OutputGuardApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._temp_dir.name) / "llmguard.db"
        self.previous_db_path = os.environ.get("LLMGUARD_DB_PATH")
        os.environ["LLMGUARD_DB_PATH"] = str(self.db_path)
        reset_settings_cache()
        init_db()
        bootstrap_default_application()
        self.credential = create_credential(UNIVERSITY_APPLICATION_ID)

        from app.main import app

        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        if self.previous_db_path is None:
            os.environ.pop("LLMGUARD_DB_PATH", None)
        else:
            os.environ["LLMGUARD_DB_PATH"] = self.previous_db_path
        reset_settings_cache()
        self._temp_dir.cleanup()

    def _headers(
        self,
        *,
        key_id: str | None = None,
        secret: str | None = None,
    ) -> dict[str, str]:
        return {
            "X-LLMGuard-Key-ID": key_id or self.credential.credential.key_id,
            "X-LLMGuard-API-Secret": secret or self.credential.secret,
        }

    def _payload(
        self,
        *,
        application_id: str = UNIVERSITY_APPLICATION_ID,
        request_id: str = "output-001",
        channel: str = "public",
        content: str = "The admissions office is open during published hours.",
        security_context: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "application_id": application_id,
            "request_id": request_id,
            "channel": channel,
            "stage": "output",
            "content": content,
            "security_context": security_context or {},
        }

    def test_benign_output_is_allowed_and_raw_content_is_not_stored(self) -> None:
        init_db()
        response = self.client.post(
            "/api/v1/guard",
            json=self._payload(),
            headers=self._headers(),
        )

        self.assertEqual(200, response.status_code)
        body = response.json()
        self.assertEqual("output-001", body["request_id"])
        self.assertEqual("output", body["stage"])
        self.assertEqual("allow", body["decision"])
        self.assertEqual("safe", body["classification"])
        self.assertEqual("allow", body["action"])
        self.assertEqual("none", body["severity"])
        self.assertNotIn("sanitized_content", body)

        telemetry = get_output_guard_decision(
            UNIVERSITY_APPLICATION_ID,
            "output-001",
        )
        self.assertIsNotNone(telemetry)
        self.assertEqual("allow", telemetry.decision)
        self.assertEqual("safe", telemetry.classification)

        conn = get_connection()
        try:
            columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(guard_output_events)")
            }
            rows = conn.execute("SELECT * FROM guard_output_events").fetchall()
        finally:
            conn.close()
        self.assertNotIn("content", columns)
        self.assertNotIn("security_context", columns)
        self.assertNotIn("sanitized_content", columns)
        self.assertNotIn("admissions office", repr(rows))

    def test_redaction_returns_only_changed_sanitized_content(self) -> None:
        unsafe = "The password reset instructions are available in the support guide."
        response = self.client.post(
            "/api/v1/guard",
            json=self._payload(
                request_id="output-redact",
                content=unsafe,
            ),
            headers=self._headers(),
        )

        self.assertEqual(200, response.status_code)
        body = response.json()
        self.assertEqual("restrict", body["decision"])
        self.assertEqual("suspicious", body["classification"])
        self.assertEqual("sanitize", body["action"])
        self.assertEqual("medium", body["severity"])
        self.assertEqual("output", body["threat_type"])
        self.assertIn("sanitized_content", body)
        self.assertIn("[REDACTED SENSITIVE VALUE]", body["sanitized_content"])
        self.assertNotEqual(unsafe, body["sanitized_content"])
        self.assertNotIn("password", body["sanitized_content"].lower())

    def test_secret_leakage_is_blocked_without_unsafe_continuation(self) -> None:
        unsafe = "The admin token is SYNTHETIC-DEMO-VALUE."
        response = self.client.post(
            "/api/v1/guard",
            json=self._payload(
                request_id="output-secret-block",
                content=unsafe,
            ),
            headers=self._headers(),
        )

        self.assertEqual(200, response.status_code)
        body = response.json()
        self.assertEqual("restrict", body["decision"])
        self.assertEqual("malicious", body["classification"])
        self.assertIn(body["action"], {"block", "quarantine"})
        self.assertEqual("high", body["severity"])
        self.assertEqual("output", body["threat_type"])
        self.assertNotIn("sanitized_content", body)
        self.assertNotIn(unsafe, response.text)

    def test_canary_leakage_is_quarantined_without_unsafe_continuation(self) -> None:
        canary = "CANARY_ADMIN_TOKEN_DEMO_ONLY"
        response = self.client.post(
            "/api/v1/guard",
            json=self._payload(
                request_id="output-canary-block",
                content=f"Generated output contained {canary}.",
            ),
            headers=self._headers(),
        )

        self.assertEqual(200, response.status_code)
        body = response.json()
        self.assertEqual("restrict", body["decision"])
        self.assertEqual("malicious", body["classification"])
        self.assertIn(body["action"], {"block", "quarantine"})
        self.assertNotIn("sanitized_content", body)

    def test_input_context_and_output_share_request_id_by_stage(self) -> None:
        request_id = "three-stage-request"
        input_response = self.client.post(
            "/api/v1/guard",
            json={
                "application_id": UNIVERSITY_APPLICATION_ID,
                "request_id": request_id,
                "channel": "public",
                "stage": "input",
                "content": "What are the published admissions requirements?",
                "security_context": {"actor_type": "anonymous"},
            },
            headers=self._headers(),
        )
        context_response = self.client.post(
            "/api/v1/guard",
            json={
                "application_id": UNIVERSITY_APPLICATION_ID,
                "request_id": request_id,
                "channel": "public",
                "stage": "context",
                "chunks": [
                    {
                        "source_id": "policy",
                        "chunk_id": "policy-1",
                        "text": "Applications close on the published deadline.",
                    }
                ],
            },
            headers=self._headers(),
        )
        output_response = self.client.post(
            "/api/v1/guard",
            json=self._payload(request_id=request_id),
            headers=self._headers(),
        )

        self.assertEqual(200, input_response.status_code)
        self.assertEqual("input", input_response.json()["stage"])
        self.assertEqual(200, context_response.status_code)
        self.assertEqual("context", context_response.json()["stage"])
        self.assertEqual(200, output_response.status_code)
        self.assertEqual("output", output_response.json()["stage"])

    def test_output_authentication_scope_revocation_and_channel_are_enforced(self) -> None:
        wrong = self.client.post(
            "/api/v1/guard",
            json=self._payload(request_id="output-wrong-secret"),
            headers=self._headers(secret="wrong-secret"),
        )
        self.assertEqual(401, wrong.status_code)

        register_application(
            organization_name="Other Output Organization",
            organization_slug="other-output-organization",
            application_id="other-output-application",
            name="Other Output Application",
            slug="other-output-application",
            environment="development",
            status="REGISTERED",
            channels=("public",),
        )
        scoped = self.client.post(
            "/api/v1/guard",
            json=self._payload(
                application_id="other-output-application",
                request_id="output-wrong-scope",
            ),
            headers=self._headers(),
        )
        self.assertEqual(401, scoped.status_code)

        other_credential = create_credential("other-output-application")
        channel = self.client.post(
            "/api/v1/guard",
            json=self._payload(
                application_id="other-output-application",
                request_id="output-invalid-channel",
                channel="employee",
            ),
            headers={
                "X-LLMGuard-Key-ID": other_credential.credential.key_id,
                "X-LLMGuard-API-Secret": other_credential.secret,
            },
        )
        self.assertEqual(403, channel.status_code)

        revoke_credential(
            UNIVERSITY_APPLICATION_ID,
            self.credential.credential.key_id,
        )
        revoked = self.client.post(
            "/api/v1/guard",
            json=self._payload(request_id="output-revoked"),
            headers=self._headers(),
        )
        self.assertEqual(401, revoked.status_code)

    def test_duplicate_malformed_and_oversized_output_requests_are_rejected(self) -> None:
        first = self.client.post(
            "/api/v1/guard",
            json=self._payload(request_id="output-duplicate"),
            headers=self._headers(),
        )
        duplicate = self.client.post(
            "/api/v1/guard",
            json=self._payload(request_id="output-duplicate"),
            headers=self._headers(),
        )
        self.assertEqual(200, first.status_code)
        self.assertEqual(409, duplicate.status_code)

        cases = (
            self._payload(request_id="blank-output", content="   "),
            self._payload(request_id="large-output", content="x" * 16_001),
            self._payload(
                request_id="many-context-fields",
                security_context={f"field-{index}": index for index in range(33)},
            ),
            self._payload(
                request_id="large-security-context",
                security_context={"opaque": "x" * 8_193},
            ),
        )
        extra = self._payload(request_id="extra-output-field")
        extra["chunks"] = []

        for payload in (*cases, extra):
            with self.subTest(request_id=payload["request_id"]):
                response = self.client.post(
                    "/api/v1/guard",
                    json=payload,
                    headers=self._headers(),
                )
                self.assertEqual(422, response.status_code)


if __name__ == "__main__":
    unittest.main()
