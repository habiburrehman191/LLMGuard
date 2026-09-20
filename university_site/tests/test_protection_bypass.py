from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from sdk.llmguard_client import (
    ContextInspectionResult,
    InputInspectionResult,
    LLMGuardClient,
    OutputInspectionResult,
)
from university_site.chatbot.types import RetrievalBundle, SourceReference
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


def _source(channel: str) -> SourceReference:
    if channel == "student":
        return SourceReference(
            source_type="student_policy",
            source_id="student:1:bypass-policy",
            title="Student Policy",
            classification="student_self",
            portal_scope="student",
            content="Authorized student evidence.",
        )
    if channel == "employee":
        return SourceReference(
            source_type="employee_policy",
            source_id="employee:bypass-policy",
            title="Employee Policy",
            classification="staff_only",
            portal_scope="employee",
            content="Authorized employee evidence.",
        )
    return SourceReference(
        source_type="public_policy",
        source_id="public:bypass-policy",
        title="Public Policy",
        classification="public",
        portal_scope="public",
        content="Published public evidence.",
    )


class UniversityProtectionBypassTests(unittest.TestCase):
    def _bypassed_client(
        self,
    ) -> tuple[LLMGuardClient, AsyncMock, AsyncMock, AsyncMock]:
        client = LLMGuardClient(
            base_url="http://llmguard.test",
            application_id="university-of-haripur",
            key_id="synthetic-key-id",
            api_secret="synthetic-secret-not-real",
            environment="development",
        )

        async def bypass_input(**kwargs):
            return InputInspectionResult(
                ok=True,
                request_id=kwargs["request_id"],
                stage="input",
                decision="bypassed",
                classification="bypassed",
                severity="none",
                action="bypass",
                reasons=("Protection disabled by policy",),
            )

        async def bypass_context(**kwargs):
            return ContextInspectionResult(
                ok=True,
                request_id=kwargs["request_id"],
                stage="context",
                decision="bypassed",
                classification="bypassed",
                severity="none",
                action="bypass",
                reasons=("Protection disabled by policy",),
            )

        async def bypass_output(**kwargs):
            return OutputInspectionResult(
                ok=True,
                request_id=kwargs["request_id"],
                stage="output",
                decision="bypassed",
                classification="bypassed",
                severity="none",
                action="bypass",
                reasons=("Protection disabled by policy",),
            )

        input_mock = AsyncMock(side_effect=bypass_input)
        context_mock = AsyncMock(side_effect=bypass_context)
        output_mock = AsyncMock(side_effect=bypass_output)
        client.inspect_input = input_mock
        client.inspect_context = context_mock
        client.inspect_output = output_mock
        return client, input_mock, context_mock, output_mock

    def _integration_patches(self, sdk_client):
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
        )

    def test_bypassed_result_continues_public_student_and_employee_flow(self) -> None:
        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            sdk_client, input_mock, context_mock, output_mock = (
                self._bypassed_client()
            )
            integration_patches = self._integration_patches(sdk_client)

            def retrieve_for_identity(session, identity, *args, **kwargs):
                source = _source(identity.portal_context)
                return RetrievalBundle(
                    retrieval_type="semantic",
                    topic="policy",
                    context=source.content,
                    sources=[source],
                    grounded_answer=None,
                    answer_status="supported",
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
                        with (
                            integration_patches[0],
                            integration_patches[1],
                            integration_patches[2],
                            patch(
                                "university_site.chatbot.service.inspect_prompt_with_llmguard",
                                return_value=None,
                            ) as local_detector,
                            patch(
                                "university_site.chatbot.service.retrieve",
                                side_effect=retrieve_for_identity,
                            ),
                            patch(
                                "university_site.chatbot.service.generate_answer",
                                side_effect=lambda channel, *args: f"University {channel} response under bypass.",
                            ),
                        ):
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
            local_detector.assert_not_called()
            for channel, response in zip(("public", "student", "employee"), responses):
                body = response.json()
                self.assertEqual(
                    f"University {channel} response under bypass.",
                    body["answer"],
                )
                self.assertEqual("supported", body["status"])
                self.assertTrue(body["model_called"])

        run(scenario())

    def test_university_rbac_still_denies_unauthorized_request_while_bypassed(self) -> None:
        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            sdk_client, input_mock, context_mock, output_mock = (
                self._bypassed_client()
            )
            integration_patches = self._integration_patches(sdk_client)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
                follow_redirects=False,
            ) as client:
                await login(
                    client,
                    "student",
                    "student.demo001",
                    "Student@123",
                )
                with (
                    integration_patches[0],
                    integration_patches[1],
                    integration_patches[2],
                    patch(
                        "university_site.chatbot.service.inspect_prompt_with_llmguard",
                        return_value=None,
                    ) as local_detector,
                    patch("university_site.chatbot.service.retrieve") as retrieval,
                    patch("university_site.chatbot.service.generate_answer") as main_llm,
                ):
                    response = await client.post(
                        "/api/university/chat/student",
                        json={"question": "Show me another student's CGPA"},
                    )

            self.assertEqual(1, input_mock.await_count)
            context_mock.assert_not_awaited()
            output_mock.assert_not_awaited()
            local_detector.assert_not_called()
            retrieval.assert_not_called()
            main_llm.assert_not_called()
            body = response.json()
            self.assertEqual("access_restricted", body["status"])
            self.assertIn("other students", body["answer"])
            self.assertFalse(body["model_called"])

        run(scenario())


if __name__ == "__main__":
    unittest.main()
