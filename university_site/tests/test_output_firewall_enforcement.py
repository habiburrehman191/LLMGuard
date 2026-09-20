from __future__ import annotations

import asyncio
import os
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from sdk.llmguard_client import (
    ClientErrorCode,
    ContextInspectionResult,
    InputInspectionResult,
    LLMGuardClient,
    LLMGuardClientError,
    OutputInspectionResult,
)
from university_site.chatbot.input_firewall import (
    GENERIC_BLOCKED_MESSAGE,
    GENERIC_FAILURE_MESSAGE,
)
from university_site.chatbot.types import RetrievalBundle, SourceReference
from university_site.database import SessionLocal
from university_site.models import ChatMessage
from university_site.main import app


def run(coro):
    return asyncio.run(coro)


async def login(
    client: httpx.AsyncClient,
    portal: str,
    username: str,
    password: str,
) -> httpx.Response:
    return await client.post(
        f"/portal/{portal}/login",
        content=f"username={username}&password={password.replace('@', '%40')}",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )


def source_for(channel: str) -> SourceReference:
    if channel == "student":
        return SourceReference(
            source_type="student_policy",
            source_id="student:1:output-policy",
            title="Student Academic Policy",
            route="/portal/student/dashboard",
            classification="student_self",
            portal_scope="student",
            content="Authorized student policy evidence.",
        )
    if channel == "employee":
        return SourceReference(
            source_type="employee_policy",
            source_id="employee:output-policy",
            title="Employee Institutional Policy",
            route="/portal/employee/policies",
            classification="staff_only",
            portal_scope="employee",
            content="Authorized employee policy evidence.",
        )
    return SourceReference(
        source_type="public_policy",
        source_id="public:output-policy",
        title="Published University Policy",
        route="/university/policies",
        classification="public",
        portal_scope="public",
        content="Published public policy evidence.",
    )


def bundle_for(channel: str) -> RetrievalBundle:
    source = source_for(channel)
    return RetrievalBundle(
        retrieval_type="semantic",
        topic="policy",
        context=source.content,
        sources=[source],
        grounded_answer=None,
        answer_status="supported",
    )


class UniversityOutputFirewallEnforcementTests(unittest.TestCase):
    def _configured_client(
        self,
        output_factory,
    ) -> tuple[LLMGuardClient, AsyncMock, AsyncMock, AsyncMock]:
        client = LLMGuardClient(
            base_url="http://llmguard.test",
            application_id="university-of-haripur",
            key_id="synthetic-key-id",
            api_secret="synthetic-secret-not-real",
            environment="development",
        )

        async def inspect_input(**kwargs):
            return InputInspectionResult(
                ok=True,
                request_id=kwargs["request_id"],
                stage="input",
                decision="allow",
                classification="safe",
                threat_type=None,
                severity="none",
                risk_score=0.03,
                action="allow",
                reasons=("Safe input",),
            )

        async def inspect_context(**kwargs):
            return ContextInspectionResult(
                ok=True,
                request_id=kwargs["request_id"],
                stage="context",
                decision="allow",
                classification="safe",
                threat_type=None,
                severity="none",
                risk_score=0.04,
                action="allow",
                reasons=("Safe context",),
            )

        async def inspect_output(**kwargs):
            return output_factory(kwargs)

        input_mock = AsyncMock(side_effect=inspect_input)
        context_mock = AsyncMock(side_effect=inspect_context)
        output_mock = AsyncMock(side_effect=inspect_output)
        client.inspect_input = input_mock
        client.inspect_context = context_mock
        client.inspect_output = output_mock
        return client, input_mock, context_mock, output_mock

    def _patch_configured_pipeline(self, sdk_client, generated):
        def retrieve_for_identity(session, identity, *args, **kwargs):
            return bundle_for(identity.portal_context)

        def generate(channel, question, context, history):
            return generated(channel)

        return (
            patch(
                "university_site.chatbot.input_firewall.llmguard_client_from_env",
                return_value=sdk_client,
            ),
            patch(
                "university_site.chatbot.context_firewall.llmguard_client_from_env",
                return_value=sdk_client,
            ),
            patch(
                "university_site.chatbot.output_firewall.llmguard_client_from_env",
                return_value=sdk_client,
            ),
            patch(
                "university_site.chatbot.service.inspect_prompt_with_llmguard",
                return_value=None,
            ),
            patch(
                "university_site.chatbot.service.retrieve",
                side_effect=retrieve_for_identity,
            ),
            patch(
                "university_site.chatbot.service.generate_answer",
                side_effect=generate,
            ),
        )

    def test_benign_output_is_returned_for_all_channels_with_one_request_id(self) -> None:
        def allowed(kwargs) -> OutputInspectionResult:
            return OutputInspectionResult(
                ok=True,
                request_id=kwargs["request_id"],
                stage="output",
                decision="allow",
                classification="safe",
                threat_type=None,
                severity="none",
                risk_score=0.04,
                action="allow",
                reasons=("Safe output",),
            )

        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            sdk_client, input_mock, context_mock, output_mock = (
                self._configured_client(allowed)
            )
            patches = self._patch_configured_pipeline(
                sdk_client,
                lambda channel: f"Benign generated {channel} answer.",
            )

            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
                follow_redirects=False,
            ) as student_client:
                await login(
                    student_client,
                    "student",
                    "student.demo001",
                    "Student@123",
                )
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="http://test",
                    follow_redirects=False,
                ) as employee_client:
                    await login(
                        employee_client,
                        "employee",
                        "employee.registrar",
                        "Employee@123",
                    )
                    async with httpx.AsyncClient(
                        transport=transport,
                        base_url="http://test",
                    ) as public_client:
                        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                            responses = (
                                await public_client.post(
                                    "/api/university/chat/public",
                                    json={"question": "Explain the public policy."},
                                ),
                                await student_client.post(
                                    "/api/university/chat/student",
                                    json={"question": "Explain my academic policy."},
                                ),
                                await employee_client.post(
                                    "/api/university/chat/employee",
                                    json={"question": "Explain the employee policy."},
                                ),
                            )

            self.assertEqual(3, input_mock.await_count)
            self.assertEqual(3, context_mock.await_count)
            self.assertEqual(3, output_mock.await_count)
            for channel, input_call, context_call, output_call, response in zip(
                ("public", "student", "employee"),
                input_mock.await_args_list,
                context_mock.await_args_list,
                output_mock.await_args_list,
                responses,
            ):
                body = response.json()
                request_id = input_call.kwargs["request_id"]
                self.assertEqual(request_id, context_call.kwargs["request_id"])
                self.assertEqual(request_id, output_call.kwargs["request_id"])
                self.assertEqual(request_id, body["request_id"])
                self.assertEqual(channel, output_call.kwargs["channel"])
                session_ids = (
                    input_call.kwargs["security_context"]["session_id"],
                    context_call.kwargs["security_context"]["session_id"],
                    output_call.kwargs["security_context"]["session_id"],
                )
                self.assertTrue(all(session_ids))
                self.assertEqual(1, len(set(session_ids)))
                self.assertEqual(
                    f"Benign generated {channel} answer.",
                    output_call.kwargs["content"],
                )
                self.assertEqual(output_call.kwargs["content"], body["answer"])
                self.assertEqual("supported", body["status"])
                self.assertTrue(body["model_called"])
                self.assertTrue(body["sources"])

            contexts = [
                call.kwargs["security_context"]
                for call in output_mock.await_args_list
            ]
            self.assertEqual("public_user", contexts[0]["user_role"])
            self.assertEqual("student", contexts[1]["user_role"])
            self.assertEqual("student:1", contexts[1]["actor_ref"])
            self.assertEqual("super_admin", contexts[2]["user_role"])
            self.assertTrue(contexts[2]["actor_ref"].startswith("employee:"))

        run(scenario())

    def test_sanitized_output_replaces_raw_content_and_drops_sources(self) -> None:
        raw = "Password reset instructions expose SYNTHETIC-CREDENTIAL-VALUE."
        sanitized = "[REDACTED SENSITIVE VALUE]."
        internal_reason = "Internal detector reason must not reach the user."

        def sanitize(kwargs) -> OutputInspectionResult:
            return OutputInspectionResult(
                ok=True,
                request_id=kwargs["request_id"],
                stage="output",
                decision="restrict",
                classification="suspicious",
                threat_type="output",
                severity="medium",
                risk_score=0.55,
                action="sanitize",
                reasons=(internal_reason,),
                sanitized_content=sanitized,
            )

        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            sdk_client, _, _, output_mock = self._configured_client(sanitize)
            patches = self._patch_configured_pipeline(
                sdk_client,
                lambda channel: raw,
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="http://test",
                ) as client:
                    response = await client.post(
                        "/api/university/chat/public",
                        json={"question": "Explain the public policy."},
                    )

            body = response.json()
            self.assertEqual(1, output_mock.await_count)
            self.assertEqual(raw, output_mock.await_args.kwargs["content"])
            self.assertEqual(sanitized, body["answer"])
            self.assertNotIn(raw, response.text)
            self.assertNotIn("SYNTHETIC-CREDENTIAL-VALUE", response.text)
            self.assertNotIn(internal_reason, response.text)
            self.assertEqual([], body["sources"])
            self.assertTrue(body["model_called"])
            with SessionLocal() as session:
                stored = session.get(ChatMessage, body["message_id"])
                self.assertEqual(sanitized, stored.content)
                self.assertNotIn("SYNTHETIC-CREDENTIAL-VALUE", stored.content)

        run(scenario())

    def test_blocked_output_returns_generic_response_for_all_channels(self) -> None:
        raw = "The admin token is SYNTHETIC-RAW-SECRET."
        internal_reason = "Matched restricted output rule with risk score 0.99."

        def blocked(kwargs) -> OutputInspectionResult:
            return OutputInspectionResult(
                ok=True,
                request_id=kwargs["request_id"],
                stage="output",
                decision="restrict",
                classification="malicious",
                threat_type="output",
                severity="high",
                risk_score=0.99,
                action="block",
                reasons=(internal_reason,),
            )

        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            sdk_client, _, _, output_mock = self._configured_client(blocked)
            patches = self._patch_configured_pipeline(
                sdk_client,
                lambda channel: raw,
            )
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
                follow_redirects=False,
            ) as student_client:
                await login(
                    student_client,
                    "student",
                    "student.demo001",
                    "Student@123",
                )
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="http://test",
                    follow_redirects=False,
                ) as employee_client:
                    await login(
                        employee_client,
                        "employee",
                        "employee.registrar",
                        "Employee@123",
                    )
                    async with httpx.AsyncClient(
                        transport=transport,
                        base_url="http://test",
                    ) as public_client:
                        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                            responses = (
                                await public_client.post(
                                    "/api/university/chat/public",
                                    json={"question": "Explain the public policy."},
                                ),
                                await student_client.post(
                                    "/api/university/chat/student",
                                    json={"question": "Explain my academic policy."},
                                ),
                                await employee_client.post(
                                    "/api/university/chat/employee",
                                    json={"question": "Explain the employee policy."},
                                ),
                            )

            self.assertEqual(3, output_mock.await_count)
            for response in responses:
                body = response.json()
                self.assertEqual(GENERIC_BLOCKED_MESSAGE, body["answer"])
                self.assertEqual("access_restricted", body["status"])
                self.assertEqual([], body["sources"])
                self.assertTrue(body["model_called"])
                self.assertNotIn(raw, response.text)
                self.assertNotIn("SYNTHETIC-RAW-SECRET", response.text)
                self.assertNotIn(internal_reason, response.text)
                with SessionLocal() as session:
                    stored = session.get(ChatMessage, body["message_id"])
                    self.assertEqual(GENERIC_BLOCKED_MESSAGE, stored.content)

        run(scenario())

    def test_configured_output_inspection_failure_fails_closed(self) -> None:
        raw = "Raw generated content must never be returned after inspection failure."

        def failed(kwargs) -> OutputInspectionResult:
            return OutputInspectionResult(
                ok=False,
                error=LLMGuardClientError(
                    code=ClientErrorCode.CONNECTION_FAILURE,
                    message="Could not connect to LLMGuard.",
                ),
            )

        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            sdk_client, _, _, output_mock = self._configured_client(failed)
            patches = self._patch_configured_pipeline(
                sdk_client,
                lambda channel: raw,
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="http://test",
                ) as client:
                    response = await client.post(
                        "/api/university/chat/public",
                        json={"question": "Explain the public policy."},
                    )

            body = response.json()
            self.assertEqual(1, output_mock.await_count)
            self.assertEqual(GENERIC_FAILURE_MESSAGE, body["answer"])
            self.assertEqual("unavailable", body["status"])
            self.assertEqual([], body["sources"])
            self.assertTrue(body["model_called"])
            self.assertNotIn(raw, response.text)
            with SessionLocal() as session:
                stored = session.get(ChatMessage, body["message_id"])
                self.assertEqual(GENERIC_FAILURE_MESSAGE, stored.content)

        run(scenario())

    def test_absent_credentials_preserve_standalone_output_behavior(self) -> None:
        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            with (
                patch.dict(
                    os.environ,
                    {
                        "UOH_LLMGUARD_KEY_ID": "",
                        "UOH_LLMGUARD_API_SECRET": "",
                    },
                ),
                patch.object(
                    LLMGuardClient,
                    "inspect_output",
                    new=AsyncMock(),
                ) as sdk_output,
                patch(
                    "university_site.chatbot.service.inspect_prompt_with_llmguard",
                    return_value=None,
                ),
                patch(
                    "university_site.chatbot.service.retrieve",
                    return_value=bundle_for("public"),
                ),
                patch(
                    "university_site.chatbot.service._llmguard_context_block",
                    return_value=False,
                ),
                patch(
                    "university_site.chatbot.service.generate_answer",
                    return_value="Standalone generated answer.",
                ),
                patch(
                    "university_site.chatbot.service._safe_output",
                    return_value="Standalone generated answer.",
                ) as local_output,
            ):
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="http://test",
                ) as client:
                    response = await client.post(
                        "/api/university/chat/public",
                        json={"question": "Explain the public policy."},
                    )

            self.assertEqual("Standalone generated answer.", response.json()["answer"])
            sdk_output.assert_not_awaited()
            local_output.assert_called_once()

        run(scenario())


if __name__ == "__main__":
    unittest.main()
