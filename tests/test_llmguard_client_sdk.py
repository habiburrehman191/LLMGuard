from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import io
import json
import logging
import unittest

import httpx

from sdk.llmguard_client import ClientErrorCode, LLMGuardClient


def run(coro):
    return asyncio.run(coro)


class LLMGuardClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = "synthetic-sdk-secret-not-real"
        self.client = LLMGuardClient(
            base_url="http://llmguard.test/",
            application_id="generic-test-application",
            key_id="synthetic-key-id",
            api_secret=self.secret,
            environment="development",
            timeout=2.5,
        )

    def test_heartbeat_request_body_auth_headers_and_timeout(self) -> None:
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["request"] = request
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "accepted": True,
                    "application_id": "generic-test-application",
                    "integration_state": "CONNECTED",
                    "last_heartbeat_at": "2026-09-20T12:00:00+00:00",
                },
            )

        result = self._send(handler)
        request = captured["request"]
        body = captured["body"]

        self.assertTrue(result.ok)
        self.assertTrue(result.accepted)
        self.assertEqual("/api/v1/integrations/heartbeat", request.url.path)
        self.assertEqual("synthetic-key-id", request.headers["X-LLMGuard-Key-ID"])
        self.assertEqual(self.secret, request.headers["X-LLMGuard-API-Secret"])
        self.assertEqual("generic-test-application", body["application_id"])
        self.assertEqual("development", body["environment"])
        self.assertEqual("app-1.2.3", body["application_version"])
        self.assertEqual("sdk-1", body["integration_version"])
        self.assertEqual(["public", "student"], body["channels"])
        self.assertEqual("2026-09-20T12:00:00+00:00", body["timestamp"])
        self.assertNotIn(self.secret, json.dumps(body))
        self.assertEqual(2.5, request.extensions["timeout"]["read"])
        self.assertNotIn(self.secret, repr(self.client))

    def test_timeout_is_returned_as_safe_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("synthetic secret: " + self.secret, request=request)

        result, logs = self._send_with_logs(handler)
        self.assertFalse(result.ok)
        self.assertEqual(ClientErrorCode.TIMEOUT, result.error.code)
        self._assert_secret_safe(result, logs)

    def test_connection_failure_is_returned_as_safe_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("synthetic secret: " + self.secret, request=request)

        result, logs = self._send_with_logs(handler)
        self.assertFalse(result.ok)
        self.assertEqual(ClientErrorCode.CONNECTION_FAILURE, result.error.code)
        self._assert_secret_safe(result, logs)

    def test_non_success_response_is_returned_without_response_body(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                json={"detail": "server echoed " + self.secret},
            )

        result, logs = self._send_with_logs(handler)
        self.assertFalse(result.ok)
        self.assertEqual(ClientErrorCode.HTTP_ERROR, result.error.code)
        self.assertEqual(401, result.error.status_code)
        self._assert_secret_safe(result, logs)

    def test_invalid_json_is_returned_as_safe_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"not-json")

        result, logs = self._send_with_logs(handler)
        self.assertFalse(result.ok)
        self.assertEqual(ClientErrorCode.INVALID_RESPONSE, result.error.code)
        self._assert_secret_safe(result, logs)

    def _send(self, handler):
        async def exercise():
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler),
            ) as http_client:
                return await self.client.send_heartbeat(
                    application_version="app-1.2.3",
                    integration_version="sdk-1",
                    channels=("public", "student"),
                    timestamp=datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc),
                    http_client=http_client,
                )

        return run(exercise())

    def _send_with_logs(self, handler):
        stream = io.StringIO()
        log_handler = logging.StreamHandler(stream)
        root_logger = logging.getLogger()
        previous_level = root_logger.level
        root_logger.setLevel(logging.DEBUG)
        root_logger.addHandler(log_handler)
        try:
            result = self._send(handler)
        finally:
            root_logger.removeHandler(log_handler)
            root_logger.setLevel(previous_level)
        return result, stream.getvalue()

    def _assert_secret_safe(self, result, logs: str) -> None:
        self.assertIsNotNone(result.error)
        self.assertNotIn(self.secret, str(result.error))
        self.assertNotIn(self.secret, repr(result))
        self.assertNotIn(self.secret, logs)


if __name__ == "__main__":
    unittest.main()
