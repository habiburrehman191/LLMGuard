"""Incidents-only presentation checks against isolated synthetic persistence."""
from dataclasses import replace
from pathlib import Path
import re
import unittest
from unittest.mock import patch
from xml.etree import ElementTree

from app.application_registry import UNIVERSITY_APPLICATION_ID, register_application
from app.security_events import get_incident, list_incidents, record_security_event, update_incident_status
from tests import test_soc_console as fixtures
from tests.test_security_events_frontend import Elements


class SecurityIncidentsFrontendTests(unittest.TestCase):
    setUp = fixtures.SocConsoleTests.setUp
    tearDown = fixtures.SocConsoleTests.tearDown
    _login = fixtures.SocConsoleTests._login
    _record = fixtures.SocConsoleTests._record
    path = "/admin/soc/incidents"

    def page(self, **params):
        response = self.client.get(self.path, params=params)
        self.assertEqual(200, response.status_code)
        return response.text

    @staticmethod
    def rows(html):
        return [attrs for _, attrs in Elements(html).elements if "data-incident" in attrs]

    def test_header_empty_state_and_active_subnav(self):
        html = self.page()
        for text in ("Security Incidents", "Investigate correlated security activity requiring review.",
                     "No security incidents", "No incidents match the current filters.", "0 incidents shown"):
            self.assertIn(text, html)
        self.assertEqual([], self.rows(html))
        self.assertEqual(1, html.count('class="console-header"'))
        self.assertIn('class="active" href="/admin/soc/incidents"', html)
        for route in ("events", "incidents", "trace", "quarantine"):
            self.assertIn(f'href="/admin/soc/{route}"', html)

    def test_get_contract_and_jinja_context_are_preserved(self):
        response = self.client.get(self.path)
        for key in ("applications", "incidents", "filters", "user", "page_title", "active_soc_page",
                    "portal_scope", "firewall_active", "asset_version"):
            self.assertIn(key, response.context)
        elements = Elements(response.text).elements
        form = next(attrs for tag, attrs in elements if tag == "form")
        self.assertEqual("get", form["method"])
        self.assertEqual(self.path, form["action"])
        self.assertEqual({"application_id", "incident_status", "severity", "category"},
                         {a["name"] for tag, a in elements if tag in {"input", "select"}})
        values = {a.get("value") for tag, a in elements if tag == "option"}
        self.assertTrue({"OPEN", "ACKNOWLEDGED", "RESOLVED", "low", "medium", "high", "critical"} <= values)

    def test_metadata_counts_timestamps_and_investigate_use_stored_values(self):
        self._record(request_id="synthetic-correlated", classification="malicious", severity="high", action="block")
        self._record(request_id="synthetic-correlated", stage="context", classification="malicious", severity="critical", action="quarantine")
        incident = list_incidents()[0]
        html = self.page()
        self.assertEqual([incident.incident_id], [r["data-incident"] for r in self.rows(html)])
        for value in (incident.summary_code.replace("_", " ").title(), incident.category.replace("_", " ").title(),
                      "University of Haripur AI System", "CRITICAL", "OPEN", "Related events", "<strong>2</strong>", "First seen", "Last seen"):
            self.assertIn(value, html)
        self.assertEqual([incident.first_seen, incident.last_seen],
                         [a["datetime"] for tag, a in Elements(html).elements if tag == "time"])
        links = [a["href"] for tag, a in Elements(html).elements if tag == "a" and a.get("class") == "si-investigate"]
        self.assertEqual([f"{self.path}/{incident.incident_id}"], links)
        self.assertEqual(200, self.client.get(links[0]).status_code)

    def test_statuses_are_actual_and_listing_does_not_mutate(self):
        for index, state in enumerate(("OPEN", "ACKNOWLEDGED", "RESOLVED")):
            self._record(request_id=f"synthetic-state-{index}", classification="malicious", severity="high", action="block")
            incident = list_incidents()[0]
            if state != "OPEN":
                update_incident_status(incident.incident_id, new_status=state, actor="synthetic-qa")
        before = list_incidents()
        details = [get_incident(i.incident_id) for i in before]
        html = self.page()
        self.assertEqual(3, len(self.rows(html)))
        for state in ("OPEN", "ACKNOWLEDGED", "RESOLVED"):
            self.assertIn(f'si-status-{state.lower()}', html)
        self.assertEqual(before, list_incidents())
        self.assertEqual(details, [get_incident(i.incident_id) for i in before])

    def test_individual_combined_and_empty_filters_match_backend(self):
        self._record(request_id="synthetic-high", classification="malicious", severity="high", action="block")
        self._record(request_id="synthetic-critical", classification="malicious", severity="critical", action="block")
        critical = list_incidents(severity="critical")[0]
        update_incident_status(critical.incident_id, new_status="ACKNOWLEDGED", actor="synthetic-qa")
        register_application(organization_name="Synthetic QA", organization_slug="synthetic-incidents",
                             application_id="synthetic-incidents", name="Synthetic QA Application", slug="synthetic-incidents",
                             environment="test", status="registered", channels=("public",))
        record_security_event(application_id="synthetic-incidents", request_id="synthetic-other-app", channel="public", stage="input",
                              event_type="SESSION_RESTRICTION", classification="session_risk", severity="high", action="session_restrict", risk_score=.7)
        cases = [{"application_id": UNIVERSITY_APPLICATION_ID}, {"application_id": "synthetic-incidents"},
                 {"incident_status": "OPEN"}, {"incident_status": "ACKNOWLEDGED"}, {"incident_status": "RESOLVED"},
                 {"severity": "critical"}, {"severity": "low"}, {"category": "SESSION_ACTIVITY"}, {"category": "SESSION"},
                 {"application_id": UNIVERSITY_APPLICATION_ID, "incident_status": "ACKNOWLEDGED", "severity": "critical", "category": "MALICIOUS_ACTIVITY"}]
        for params in cases:
            with self.subTest(params=params):
                expected = list_incidents(**{("status" if k == "incident_status" else k): v for k, v in params.items()})
                html = self.page(**params)
                self.assertEqual([i.incident_id for i in expected], [r["data-incident"] for r in self.rows(html)])
                for tag, attrs in Elements(html).elements:
                    if tag == "input" and attrs.get("name") == "category":
                        self.assertEqual(params.get("category", ""), attrs["value"])
                    if tag == "option" and attrs.get("value") in params.values():
                        self.assertIn("selected", attrs)
                if not expected:
                    self.assertIn("No incidents match the current filters.", html)

    def test_all_supported_severities_render_without_inventing_scores(self):
        self._record(request_id="synthetic-severity", classification="malicious", severity="high", action="block")
        stored = list_incidents()[0]
        # Presentation-only fixtures exercise supplied metadata, not correlation rules.
        for severity in ("critical", "high", "medium", "low"):
            with self.subTest(severity=severity), patch("app.soc_routes.list_incidents", return_value=[replace(stored, severity=severity)]):
                html = self.page()
                self.assertIn(f'si-severity-{severity}', html)
                self.assertIn(f'</svg>{severity.upper()}</span>', html)
                self.assertNotIn("Risk:", html)
        self.assertEqual(stored, list_incidents()[0])

    def test_only_safe_metadata_is_rendered_and_escaped(self):
        self._record(request_id="RAW-SYNTHETIC-PROMPT-NOT-FOR-LIST", classification="malicious", severity="high", action="quarantine",
                     source_id="RAW-SYNTHETIC-CONTEXT-NOT-FOR-LIST", chunk_id="RAW-SYNTHETIC-OUTPUT-NOT-FOR-LIST")
        html = self.page()
        for secret in ("RAW-SYNTHETIC-PROMPT-NOT-FOR-LIST", "RAW-SYNTHETIC-CONTEXT-NOT-FOR-LIST", "RAW-SYNTHETIC-OUTPUT-NOT-FOR-LIST", list_incidents()[0].primary_event_id):
            self.assertNotIn(secret, html)
        escaped = self.page(category='<script>synthetic</script>')
        self.assertNotIn('<script>synthetic</script>', escaped)
        self.assertIn('&lt;script&gt;synthetic&lt;/script&gt;', escaped)

    def test_unsupported_soc_content_is_absent_and_icons_resolve(self):
        html = self.page()
        for unsupported in ("Assign SOC", "Isolate Endpoint", "Block IP", "Terminate Process", "Contain Host", "Network Quarantine",
                            "CONTAINED", "MITIGATED", "ISOLATED", "ESCALATED", "198.51.100.44", "INC-2025-089", "3,420", "PCAP", "tailwind", "material-symbols"):
            self.assertNotIn(unsupported, html)
        symbols = {n.attrib["id"] for n in ElementTree.parse("static/llmguard-icons.svg").iter() if "id" in n.attrib}
        self.assertTrue(all(a["href"].split("#")[1] in symbols for tag, a in Elements(html).elements if tag == "use"))
        css = Path("static/security_incidents.css").read_text()
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        selectors = [s.strip() for s in re.findall(r"([^{}]+)\{", css)]
        self.assertTrue(all(s.startswith((".security-incidents-page", "@media")) for s in selectors))

    def test_assets_only_load_on_list_and_reader_rbac_is_unchanged(self):
        self._record(request_id="synthetic-detail", classification="malicious", severity="high", action="block")
        for route in (f"{self.path}/{list_incidents()[0].incident_id}", "/admin/soc/events", "/admin/soc/trace", "/admin/soc/quarantine",
                      "/admin/dashboard", "/admin/applications", f"/admin/applications/{UNIVERSITY_APPLICATION_ID}", "/admin/evaluation", "/login"):
            html = self.client.get(route).text
            self.assertNotIn("security_incidents.css", html)
            self.assertNotIn("security_incidents.js", html)
        self.client.cookies.clear()
        self.assertEqual(401, self.client.get(self.path).status_code)
        for username, password in (("student1", "Student@123"), ("security-read-only", "Employee@123")):
            self._login(username, password)
            self.assertEqual(403, self.client.get(self.path).status_code)


if __name__ == "__main__":
    unittest.main()
