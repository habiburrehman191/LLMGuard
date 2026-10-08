"""Events-only presentation tests using isolated synthetic stores."""
from html.parser import HTMLParser
from pathlib import Path
import unittest
from unittest.mock import patch
from xml.etree import ElementTree

from app.application_registry import UNIVERSITY_APPLICATION_ID, register_application
from app.security_events import list_security_events
from tests import test_soc_console as fixtures


class Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class SecurityEventsFrontendTests(unittest.TestCase):
    setUp = fixtures.SocConsoleTests.setUp
    tearDown = fixtures.SocConsoleTests.tearDown
    _login = fixtures.SocConsoleTests._login
    _record = fixtures.SocConsoleTests._record
    path = "/admin/soc/events"

    def page(self, **params):
        response = self.client.get(self.path, params=params)
        self.assertEqual(200, response.status_code)
        return response.text

    @staticmethod
    def rows(html):
        return [attrs for _, attrs in Elements(html).elements if "data-security-event" in attrs]

    def test_header_empty_state_and_shared_subnav_keep_real_routes(self):
        html = self.page()
        self.assertIn("Security Operations", html)
        self.assertIn("Inspect security decisions across protected LLM applications.", html)
        self.assertIn("No security events", html)
        self.assertIn("No events match the selected filters.", html)
        self.assertIn("0 events shown", html)
        self.assertEqual(1, html.count('class="console-header"'))
        self.assertEqual([], self.rows(html))
        self.assertIn('/static/security_events.css?v=27', html)
        self.assertIn('/static/security_events.js?v=27', html)
        for route in ("events", "incidents", "trace", "quarantine"):
            self.assertIn(f'href="/admin/soc/{route}"', html)
        self.assertIn('class="active" href="/admin/soc/events"', html)
        self.assertNotIn('href="#"', html)

    def test_form_keeps_all_get_parameter_names_and_original_values(self):
        elements = Elements(self.page()).elements
        form = next(attrs for tag, attrs in elements if tag == "form")
        self.assertEqual("get", form["method"])
        self.assertEqual(self.path, form["action"])
        self.assertEqual({"event_type", "application_id", "stage", "action", "channel", "classification", "severity"},
                         {attrs["name"] for tag, attrs in elements if tag in {"input", "select"}})
        values = {attrs.get("value") for tag, attrs in elements if tag == "option"}
        for value in ("input", "context", "output", "ingestion", "integration", "allow", "block", "session_restrict", "fail_closed", "bypass", "public", "student", "employee", "session_risk", "none", "critical"):
            self.assertIn(value, values)
        toggle = next(attrs for _, attrs in elements if "data-more-filters" in attrs)
        self.assertEqual("se-secondary-filters", toggle["aria-controls"])
        self.assertIn("hidden", toggle)  # No-JS baseline shows all secondary controls.
        css = Path("static/security_events.css").read_text()
        self.assertIn(".se-enhanced-filters .se-advanced-filters", css)
        self.assertIn(".se-enhanced-filters.show-advanced-filters .se-advanced-filters", css)

    def test_event_metadata_trace_and_numeric_risk_are_actual(self):
        event = self._record(request_id="synthetic-trace-visible", channel="student", stage="context",
                             event_type="INDIRECT_PROMPT_INJECTION", classification="malicious", severity="high", risk_score=.973, action="quarantine")
        html = self.page()
        self.assertEqual([event.event_id], [row["data-security-event"] for row in self.rows(html)])
        for value in ("Indirect Prompt Injection", "University of Haripur AI System", "Student", "Context Firewall", "MALICIOUS", "0.97", "Quarantine", event.created_at):
            self.assertIn(value, html)
        self.assertIn('soc-action-quarantine', html)
        self.assertIn(f'/admin/soc/trace?application_id={UNIVERSITY_APPLICATION_ID}&amp;request_id=synthetic-trace-visible', html)
        self.assertNotIn("97%", html)

    def test_none_and_zero_risk_are_not_manufactured_from_classification(self):
        bypass = self._record(request_id="synthetic-bypass", event_type="PROTECTION_BYPASS", classification="bypassed", severity="none", risk_score=None, action="bypass")
        zero = self._record(request_id="synthetic-zero", risk_score=0)
        html = self.page()
        rows = self.rows(html)
        self.assertEqual({bypass.event_id, zero.event_id}, {row["data-security-event"] for row in rows})
        self.assertEqual(1, html.count('class="se-risk-score"'))
        self.assertIn("0.00", html)
        self.assertIn("BYPASSED", html)
        self.assertIn("soc-state-bypassed", html)

    def test_operational_failure_and_session_restriction_remain_distinct(self):
        self._record(request_id="synthetic-failure", stage="integration", channel="integration", event_type="INTEGRATION_VALIDATION_FAILURE", classification="error", risk_score=None, action="reject")
        self._record(request_id="synthetic-restriction", event_type="SESSION_RESTRICTION", classification="session_risk", action="session_restrict")
        html = self.page()
        for label in ("Integration Validation Failure", "soc-state-failure", "Session Restriction", "Session Restrict", "SESSION RISK"):
            self.assertIn(label, html)

    def test_application_stage_action_and_combined_filters_use_real_storage(self):
        safe = self._record(request_id="synthetic-safe")
        blocked = self._record(request_id="synthetic-block", stage="output", channel="employee", action="block", event_type="SENSITIVE_OUTPUT", classification="malicious", severity="high")
        register_application(organization_name="Synthetic QA", organization_slug="synthetic-qa",
                             application_id="synthetic-empty", name="Synthetic Empty", slug="synthetic-empty", environment="test", status="registered", channels=("public",))
        cases = [({"application_id": UNIVERSITY_APPLICATION_ID}, {safe.event_id, blocked.event_id}),
                 ({"application_id": "synthetic-empty"}, set()), ({"stage": "output"}, {blocked.event_id}),
                 ({"action": "allow"}, {safe.event_id}),
                 ({"application_id": UNIVERSITY_APPLICATION_ID, "channel": "employee", "stage": "output", "action": "block", "classification": "malicious", "severity": "high", "event_type": "SENSITIVE_OUTPUT"}, {blocked.event_id})]
        for params, expected in cases:
            with self.subTest(params=params):
                html = self.page(**params)
                self.assertEqual(expected, {row["data-security-event"] for row in self.rows(html)})
                selected = {attrs["value"] for tag, attrs in Elements(html).elements if tag == "option" and "selected" in attrs}
                for name, value in params.items():
                    if name != "event_type":
                        self.assertIn(value, selected)

    def test_event_type_search_retains_exact_match_semantics(self):
        event = self._record(request_id="synthetic-search", event_type="CROSS_CHUNK_DETECTION")
        self.assertEqual([event.event_id], [row["data-security-event"] for row in self.rows(self.page(event_type="CROSS_CHUNK_DETECTION"))])
        self.assertEqual([], self.rows(self.page(event_type="CROSS")))

    def test_primary_list_uses_a_metadata_allowlist_and_escapes_external_text(self):
        self._record(request_id="synthetic-request-" + "x" * 170, event_type='SYNTHETIC_<SCRIPT>')
        from app.soc_routes import _event_views
        def with_sensitive_fields(events, names):
            return [{**row, "raw_prompt": "SYNTHETIC_RAW_PROMPT_MARKER", "raw_context": "SYNTHETIC_RAW_CONTEXT_MARKER",
                     "raw_output": "SYNTHETIC_RAW_OUTPUT_MARKER", "secret": "SYNTHETIC_SECRET_MARKER", "session_hash": "SYNTHETIC_SESSION_MARKER"} for row in _event_views(events, names)]
        with patch("app.soc_routes._event_views", side_effect=with_sensitive_fields):
            html = self.page()
        for marker in ("SYNTHETIC_RAW_PROMPT_MARKER", "SYNTHETIC_RAW_CONTEXT_MARKER", "SYNTHETIC_RAW_OUTPUT_MARKER", "SYNTHETIC_SECRET_MARKER", "SYNTHETIC_SESSION_MARKER"):
            self.assertNotIn(marker, html)
        self.assertNotIn("<Script>", html)
        self.assertIn("&lt;Script&gt;", html)

    def test_demo_network_controls_totals_and_pagination_are_absent(self):
        html = self.page()
        for unsupported in ("PCAP", "Source IP", "Destination IP", "Isolate", "Assign SOC", "Packet", "Port scanning", "86,340", "3,420", "198.51.100.44", "INC-2025-089", "Threat Matrix", "material-symbols", "tailwind", "pagination"):
            self.assertNotIn(unsupported, html)
        symbols = {node.attrib["id"] for node in ElementTree.parse("static/llmguard-icons.svg").iter() if "id" in node.attrib}
        for tag, attrs in Elements(html).elements:
            if tag == "use":
                self.assertIn(attrs["href"].split("#")[1], symbols)

    def test_new_assets_are_only_loaded_by_events_and_stored_data_is_unchanged(self):
        self._record(request_id="synthetic-storage-preservation", classification="malicious", action="block", severity="high")
        before = list_security_events()
        self.page()
        self.assertEqual(before, list_security_events())
        for route in ("/admin/soc/incidents", "/admin/soc/trace", "/admin/soc/quarantine", "/admin/security-dashboard",
                      "/admin/dashboard", "/admin/applications", f"/admin/applications/{UNIVERSITY_APPLICATION_ID}", "/admin/evaluation", "/login"):
            with self.subTest(route=route):
                html = self.client.get(route).text
                self.assertNotIn("security_events.css", html)
                self.assertNotIn("security_events.js", html)
                self.assertNotIn("security-events-page", html)

    def test_existing_reader_rbac_is_unchanged(self):
        self.client.cookies.clear()
        self.assertEqual(401, self.client.get(self.path).status_code)
        self._login("student1", "Student@123")
        self.assertEqual(403, self.client.get(self.path).status_code)
        self._login("security-read-only", "Employee@123")
        self.assertEqual(403, self.client.get(self.path).status_code)
        self._login("admin1", "Admin@123")
        self.assertEqual(200, self.client.get(self.path).status_code)


if __name__ == "__main__":
    unittest.main()
