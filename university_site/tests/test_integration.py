from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from sdk.llmguard_client import HeartbeatResult, LLMGuardClient
from university_site.integration import (
    HeartbeatClientConfig,
    heartbeat_config_from_env,
    send_heartbeat,
)


def run(coro):
    return asyncio.run(coro)


class LLMGuardHeartbeatClientTests(unittest.TestCase):
    def test_heartbeat_is_disabled_without_environment_secret(self) -> None:
        with patch.dict(
            os.environ,
            {
                "UOH_LLMGUARD_KEY_ID": "",
                "UOH_LLMGUARD_API_SECRET": "",
            },
        ):
            self.assertIsNone(heartbeat_config_from_env())

    def test_backend_heartbeat_uses_headers_and_excludes_secret_from_body(self) -> None:
        synthetic_secret = "synthetic-heartbeat-secret-not-real"
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(request.headers)
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "accepted": True,
                    "application_id": "university-of-haripur",
                    "integration_state": "CONNECTED",
                    "last_heartbeat_at": "2026-09-20T00:00:00+00:00",
                },
            )

        sdk_client = LLMGuardClient(
            base_url="http://127.0.0.1:8000",
            application_id="university-of-haripur",
            key_id="synthetic-key-id",
            api_secret=synthetic_secret,
            environment="development",
            timeout=5,
        )
        config = HeartbeatClientConfig(
            sdk_client=sdk_client,
            application_version="uoh-test",
        )
        transport = httpx.MockTransport(handler)

        async def exercise() -> HeartbeatResult:
            async with httpx.AsyncClient(
                transport=transport,
            ) as client:
                return await send_heartbeat(config, client=client)

        result = run(exercise())
        self.assertTrue(result.accepted)
        self.assertEqual(
            synthetic_secret,
            captured["headers"]["x-llmguard-api-secret"],
        )
        self.assertEqual("synthetic-key-id", captured["headers"]["x-llmguard-key-id"])
        self.assertNotIn(synthetic_secret, json.dumps(captured["body"]))
        self.assertEqual(
            ["public", "student", "employee"],
            captured["body"]["channels"],
        )
        self.assertNotIn(synthetic_secret, repr(config))

    def test_university_heartbeat_delegates_to_sdk(self) -> None:
        sdk_client = LLMGuardClient(
            base_url="http://127.0.0.1:8000",
            application_id="university-of-haripur",
            key_id="synthetic-key-id",
            api_secret="synthetic-sdk-delegation-secret",
            environment="development",
        )
        config = HeartbeatClientConfig(
            sdk_client=sdk_client,
            application_version="uoh-test",
            integration_version="heartbeat-v1",
        )
        expected = HeartbeatResult(
            ok=True,
            accepted=True,
            application_id="university-of-haripur",
            integration_state="CONNECTED",
            last_heartbeat_at="2026-09-20T12:00:00+00:00",
        )

        with patch.object(
            sdk_client,
            "send_heartbeat",
            new=AsyncMock(return_value=expected),
        ) as sdk_send:
            result = run(send_heartbeat(config))

        self.assertIs(expected, result)
        sdk_send.assert_awaited_once_with(
            application_version="uoh-test",
            integration_version="heartbeat-v1",
            channels=("public", "student", "employee"),
            http_client=None,
        )

    def test_secret_is_absent_from_university_browser_responses_and_assets(self) -> None:
        synthetic_secret = "synthetic-browser-leak-check-secret"
        university_root = Path(__file__).resolve().parents[1]
        browser_files = [
            *university_root.joinpath("templates").rglob("*.html"),
            *university_root.joinpath("static").rglob("*.js"),
        ]
        self.assertTrue(browser_files)
        for path in browser_files:
            with self.subTest(path=path):
                self.assertNotIn(
                    synthetic_secret,
                    path.read_text(encoding="utf-8", errors="replace"),
                )

        async def fetch_homepage() -> httpx.Response:
            from university_site.main import app

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://university.test",
            ) as client:
                return await client.get("/")

        with patch.dict(
            os.environ,
            {
                "UOH_LLMGUARD_KEY_ID": "synthetic-browser-key-id",
                "UOH_LLMGUARD_API_SECRET": synthetic_secret,
            },
        ):
            response = run(fetch_homepage())
        self.assertEqual(200, response.status_code)
        self.assertNotIn(synthetic_secret, response.text)


if __name__ == "__main__":
    unittest.main()
