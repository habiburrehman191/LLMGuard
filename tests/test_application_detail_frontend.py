"""Application Detail contracts using isolated synthetic application/auth stores."""
import unittest
from xml.etree import ElementTree

from app.application_credentials import create_credential, list_credentials, verify_credential
from app.application_registry import UNIVERSITY_APPLICATION_ID
from app.integration_health import record_heartbeat
from app.protection_control import record_guard_stage_failure, record_guard_stage_success, set_protection_enabled
from tests import test_applications_frontend as fixtures


class ApplicationDetailFrontendTests(unittest.TestCase):
    setUp = fixtures.ApplicationsFrontendTests.setUp
    tearDown = fixtures.ApplicationsFrontendTests.tearDown
    login = fixtures.ApplicationsFrontendTests.login
    heartbeat = fixtures.ApplicationsFrontendTests.heartbeat
    path = f"/admin/applications/{UNIVERSITY_APPLICATION_ID}"

    def page(self):
        response = self.client.get(self.path)
        self.assertEqual(200, response.status_code)
        return response.text

    @staticmethod
    def panel(html, name):
        return html.split(f'<section id="{name}"', 1)[1].split('<section id="', 1)[0]

    def test_tabs_keep_existing_hooks_and_accessible_panel_relationships(self):
        html = self.page()
        elements = fixtures.ListElements(html).elements
        tabs = [attrs for _, attrs in elements if "data-application-tab" in attrs]
        panels = [attrs for _, attrs in elements if "data-application-panel" in attrs]
        names = ["overview", "integration", "protection", "credentials"]
        self.assertEqual(names, [tab["data-application-tab"] for tab in tabs])
        self.assertEqual(names, [panel["data-application-panel"] for panel in panels])
        for tab, panel in zip(tabs, panels):
            self.assertEqual(panel["id"], tab["aria-controls"])
            self.assertEqual(tab["id"], panel["aria-labelledby"])
            self.assertEqual("tabpanel", panel["role"])
        self.assertEqual(1, html.count('class="console-header"'))
        self.assertIn('data-initial-tab="overview"', html)
        self.assertIn('/static/application_detail.css?v=', html)
        self.assertIn('/static/product.js?v=', html)
        symbols = {node.attrib["id"] for node in ElementTree.parse(fixtures.Path("static/llmguard-icons.svg")).iter() if "id" in node.attrib}
        for tag, attrs in elements:
            if tag == "use":
                self.assertIn(attrs["href"].split("#")[1], symbols)

    def test_pending_overview_is_real_and_keeps_sensitive_areas_in_their_tabs(self):
        html = self.page()
        overview = self.panel(html, "overview")
        self.assertIn("University of Haripur AI System", html)
        self.assertIn(UNIVERSITY_APPLICATION_ID, html)
        self.assertIn("Development", overview)
        self.assertIn('data-runtime-state="INTEGRATION_PENDING"', html)
        self.assertEqual(3, overview.count("NOT REPORTED"))
        self.assertNotIn("VERIFIED", overview)
        self.assertIn("University RBAC enforced by protected application", overview)
        for name in ("Public", "Student", "Employee"):
            self.assertIn(f">{name}</span>", overview)
        for unsupported in ("data-protection-control", "Create credential", "data-one-time-secret", "Application version", "ad-metadata"):
            self.assertNotIn(unsupported, overview)
        self.assertIn("No protection changes recorded", self.panel(html, "protection"))
        self.assertIn("No API credentials yet", self.panel(html, "credentials"))

    def test_reported_integration_values_and_registered_channels_remain_distinct(self):
        health = record_heartbeat(application_id=UNIVERSITY_APPLICATION_ID, environment="test",
                                 application_version="synthetic-app-7", integration_version="synthetic-sdk-2",
                                 channels=("public",))
        integration = self.panel(self.page(), "integration")
        for value in (health.last_heartbeat_at, "synthetic-app-7", "synthetic-sdk-2", "Test", "Connected", "Degraded"):
            self.assertIn(value, integration)
        self.assertIn("Registered channels", integration)
        self.assertIn("Reported channels", integration)
        self.assertEqual(2, integration.count(">Public</span>"))
        self.assertEqual(1, integration.count(">Student</span>"))
        self.assertEqual(1, integration.count(">Employee</span>"))
        for node in ("Protected Application", "LLMGuard", "Security Pipeline", "Local Model"):
            self.assertIn(node, integration)
        pending = self.panel(self.page(), "integration")
        self.assertNotIn("latency", pending.lower())

    def test_unavailable_versions_and_heartbeat_are_not_reported(self):
        integration = self.panel(self.page(), "integration")
        self.assertIn('<dt>Last heartbeat</dt><dd>Not reported</dd>', integration)
        for field in ("Application version", "Integration version"):
            self.assertIn(f'<dt>{field}</dt><dd><code>Not reported</code></dd>', integration)
        self.assertNotIn('<time ', integration)

    def test_guard_success_missing_failure_and_bypass_do_not_fabricate_stage_health(self):
        self.heartbeat()
        record_guard_stage_success(UNIVERSITY_APPLICATION_ID, "input")
        overview = self.panel(self.page(), "overview")
        self.assertEqual(1, overview.count('data-verified="true"'))
        self.assertEqual(2, overview.count("NOT REPORTED"))
        record_guard_stage_failure(UNIVERSITY_APPLICATION_ID, "input", "synthetic-failure")
        html = self.page()
        self.assertIn('data-runtime-state="DEGRADED"', html)
        self.assertEqual(3, self.panel(html, "overview").count('data-verified="false"'))
        for stage in ("input", "context", "output"):
            record_guard_stage_success(UNIVERSITY_APPLICATION_ID, stage)
        self.assertIn('data-runtime-state="PROTECTED"', self.page())
        set_protection_enabled(UNIVERSITY_APPLICATION_ID, enabled=False, actor="synthetic-test", reason="Synthetic bypass")
        html = self.page()
        self.assertIn('data-runtime-state="BYPASSED"', html)
        self.assertEqual(3, self.panel(html, "overview").count('data-verified="true"'))

    def test_stale_heartbeat_remains_visible_as_disconnected(self):
        health = self.heartbeat(old=True)
        html = self.page()
        self.assertIn('data-runtime-state="DISCONNECTED"', html)
        self.assertIn(health.last_heartbeat_at, self.panel(html, "integration"))

    def test_protection_reason_form_and_real_audit_preserve_contract(self):
        html = self.page()
        form = next(attrs for _, attrs in fixtures.ListElements(html).elements if "data-protection-control" in attrs)
        reason = next(attrs for tag, attrs in fixtures.ListElements(html).elements if tag == "textarea")
        self.assertEqual(UNIVERSITY_APPLICATION_ID, form["data-application-id"])
        self.assertEqual("false", form["data-next-enabled"])
        self.assertIn("required", reason)
        self.assertEqual("500", reason["maxlength"])
        self.assertEqual(422, self.client.post(self.path + "/protection", json={"protection_enabled": False, "reason": " "}).status_code)
        result = self.client.post(self.path + "/protection", json={"protection_enabled": False, "reason": "Synthetic <audit> reason"})
        self.assertEqual(200, result.status_code)
        protection = self.panel(self.page(), "protection")
        self.assertIn('data-next-enabled="true"', protection)
        self.assertIn("Synthetic &lt;audit&gt; reason", protection)
        self.assertNotIn("Synthetic <audit>", protection)
        self.assertIn("admin1", protection)
        self.assertEqual(200, self.client.post(self.path + "/protection", json={"protection_enabled": True, "reason": "Synthetic restore"}).status_code)

    def test_credential_rows_create_once_revoke_and_last_used_use_real_values(self):
        existing = create_credential(UNIVERSITY_APPLICATION_ID)
        verify_credential(UNIVERSITY_APPLICATION_ID, existing.credential.key_id, existing.secret)
        initial = self.page()
        credential_panel = self.panel(initial, "credentials")
        self.assertIn(existing.credential.key_id, credential_panel)
        self.assertIn(list_credentials(UNIVERSITY_APPLICATION_ID)[0].last_used_at, credential_panel)
        self.assertNotIn(existing.secret, initial)
        creation = self.client.post(self.path + "/credentials")
        self.assertEqual(201, creation.status_code)
        self.assertEqual("no-store", creation.headers["cache-control"])
        self.assertIn('data-initial-tab="credentials"', creation.text)
        self.assertIn("New API Secret", creation.text)
        secret = creation.text.split('<code data-one-time-secret>', 1)[1].split('</code>', 1)[0]
        self.assertTrue(secret.startswith("llmg_secret_"))
        self.assertEqual(1, creation.text.count(secret))
        self.assertNotIn(secret, self.panel(creation.text, "overview"))
        self.assertNotIn(secret, self.page())
        revoke = self.client.post(self.path + f"/credentials/{existing.credential.key_id}/revoke")
        self.assertEqual(200, revoke.status_code)
        self.assertIn("Revoked", revoke.text)
        self.assertNotIn(secret, revoke.text)
        self.assertFalse(verify_credential(UNIVERSITY_APPLICATION_ID, existing.credential.key_id, existing.secret))

    def test_external_text_is_escaped_and_demo_content_is_excluded(self):
        record_heartbeat(application_id=UNIVERSITY_APPLICATION_ID, environment="development",
                         application_version='<script>synthetic-version</script>', integration_version=None, channels=("public",))
        html = self.page()
        self.assertIn("&lt;script&gt;synthetic-version&lt;/script&gt;", html)
        self.assertNotIn("<script>synthetic-version", html)
        for fake in ("gpt-4o-mini", "Pinecone", "ChromaDB", "84,920", "1,428", "LLM-SOC-V3", "SLA", "uptime", "throughput", "Promote to Production", "Register Application", "Rotate Key", "llmg_live_", "tailwind"):
            self.assertNotIn(fake, html)

    def test_existing_access_control_is_preserved(self):
        self.client.cookies.clear()
        self.assertEqual(401, self.client.get(self.path).status_code)
        self.login("student1", "Student@123")
        self.assertEqual(403, self.client.get(self.path).status_code)
        self.assertEqual(403, self.client.post(self.path + "/credentials").status_code)


if __name__ == "__main__":
    unittest.main()
