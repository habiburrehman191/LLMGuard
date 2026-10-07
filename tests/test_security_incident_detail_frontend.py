"""Incident Detail presentation and native lifecycle checks with synthetic stores."""
from dataclasses import replace
from pathlib import Path
import re
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree

from app.application_registry import UNIVERSITY_APPLICATION_ID
from app.security_events import get_incident, list_incidents, record_security_event
from tests import test_soc_console as fixtures
from tests.test_security_events_frontend import Elements


class SecurityIncidentDetailFrontendTests(unittest.TestCase):
    setUp = fixtures.SocConsoleTests.setUp
    tearDown = fixtures.SocConsoleTests.tearDown
    _login = fixtures.SocConsoleTests._login
    _record = fixtures.SocConsoleTests._record

    def correlated(self, request_id="synthetic-detail-request"):
        self._record(request_id=request_id, channel="student", classification="malicious", severity="high", action="block")
        self._record(request_id=request_id, channel="student", stage="context", event_type="CONTEXT_FIREWALL",
                     classification="malicious", severity="critical", action="quarantine", risk_score=None,
                     source_id="synthetic-source-reference", chunk_id="synthetic-chunk-reference")
        return list_incidents()[0]

    def path(self, incident):
        return f"/admin/soc/incidents/{incident.incident_id}"

    def page(self, incident, **params):
        response = self.client.get(self.path(incident), params=params)
        self.assertEqual(200, response.status_code)
        return response

    def test_header_summary_context_and_navigation(self):
        incident = self.correlated()
        response = self.page(incident)
        html = response.text
        for key in ("incident", "events", "status_audit", "updated_status", "user", "page_title", "active_soc_page",
                    "portal_scope", "firewall_active", "asset_version"):
            self.assertIn(key, response.context)
        for value in ("Security Incident", incident.summary_code.replace("_", " ").title(), incident.category,
                      incident.incident_id, incident.primary_event_id, "University of Haripur AI System", "2 correlated events",
                      "First seen", "Last seen", "CRITICAL", "OPEN", "Back to Incidents"):
            self.assertIn(value, html)
        self.assertIn(f'datetime="{incident.first_seen}"', html)
        self.assertIn(f'datetime="{incident.last_seen}"', html)
        self.assertEqual(1, html.count('class="console-header"'))
        self.assertIn('class="active" href="/admin/soc/incidents"', html)
        for route in ("events", "incidents", "trace", "quarantine"):
            self.assertIn(f'href="/admin/soc/{route}"', html)
        self.assertNotIn(f'<h1>{incident.incident_id}</h1>', html)

    def test_open_actions_keep_exact_post_contract(self):
        incident = self.correlated()
        forms = [attrs for tag, attrs in Elements(self.page(incident).text).elements if tag == "form"]
        self.assertEqual([{"method": "post", "action": self.path(incident) + "/acknowledge"},
                          {"method": "post", "action": self.path(incident) + "/resolve"}], forms)

    def test_acknowledge_resolve_redirect_status_controls_and_actual_audit(self):
        incident = self.correlated()
        for action, expected in (("acknowledge", "ACKNOWLEDGED"), ("resolve", "RESOLVED")):
            result = self.client.post(self.path(incident) + "/" + action, follow_redirects=False)
            self.assertEqual(303, result.status_code)
            self.assertEqual(self.path(incident) + "?updated=" + expected, result.headers["location"])
            response = self.client.get(result.headers["location"])
            self.assertIn(f'Incident status updated to {expected}.', response.text)
            self.assertIn(f'sid-status-{expected.lower()}', response.text)
            detail = get_incident(incident.incident_id)
            self.assertEqual(expected, detail.incident.status)
            for entry in detail.status_audit:
                self.assertIn(f'{entry.old_status} → {entry.new_status}', response.text)
                self.assertIn(f'Actor: {entry.actor}', response.text)
                self.assertIn(f'datetime="{entry.created_at}"', response.text)
            forms = [attrs for tag, attrs in Elements(response.text).elements if tag == "form"]
            if expected == "ACKNOWLEDGED":
                self.assertEqual([{"method": "post", "action": self.path(incident) + "/resolve"}], forms)
            else:
                self.assertEqual([], forms)
                self.assertIn("This incident is resolved.", response.text)
        self.assertEqual(2, len(get_incident(incident.incident_id).status_audit))
        self.assertEqual(409, self.client.post(self.path(incident) + "/acknowledge", follow_redirects=False).status_code)

    def test_open_can_resolve_directly_with_existing_audit_semantics(self):
        incident = self.correlated()
        response = self.client.post(self.path(incident) + "/resolve", follow_redirects=False)
        self.assertEqual(303, response.status_code)
        detail = get_incident(incident.incident_id)
        self.assertEqual("RESOLVED", detail.incident.status)
        self.assertEqual([("OPEN", "RESOLVED")], [(e.old_status, e.new_status) for e in detail.status_audit])

    def test_correlated_events_are_real_ordered_metadata_and_trace_queries(self):
        request_id = "synthetic trace & encoded=".ljust(200, "x")
        incident = self.correlated(request_id)
        response = self.page(incident)
        html = response.text
        detail = get_incident(incident.incident_id)
        rows = [a for _, a in Elements(html).elements if "data-correlated-event" in a]
        self.assertEqual([e.event_id for e in detail.events], [r["data-correlated-event"] for r in rows])
        for event in detail.events:
            for value in (event.event_type, event.event_id, event.classification.upper(), event.severity.upper(), event.channel.title()):
                self.assertIn(value, html)
            self.assertIn(f'datetime="{event.created_at}"', html)
        links = [a["href"] for tag, a in Elements(html).elements if tag == "a" and a.get("class") == "sid-trace-link"]
        self.assertEqual(2, len(links))
        for href in links:
            url = urlparse(href)
            self.assertEqual("/admin/soc/trace", url.path)
            self.assertEqual({"application_id": [UNIVERSITY_APPLICATION_ID], "request_id": [request_id]}, parse_qs(url.query))
            self.assertEqual(200, self.client.get(href).status_code)
        self.assertIn("synthetic-source-reference", html)
        self.assertIn("synthetic-chunk-reference", html)
        self.assertEqual(2, html.count('<summary>Event identifiers</summary>'))

    def test_risk_is_only_numeric_supplied_data_including_zero(self):
        incident = self.correlated()
        self._record(request_id="synthetic-detail-request", stage="output", classification="malicious", severity="high", action="block", risk_score=0)
        html = self.page(incident).text
        self.assertIn('<strong>0.05</strong>', html)
        self.assertIn('<strong>0.00</strong>', html)
        self.assertEqual(2, html.count('class="sid-risk"'))
        self.assertNotIn("100%", html)
        self.assertNotIn("97%", html)

    def test_missing_request_id_has_no_trace_action(self):
        record_security_event(application_id=UNIVERSITY_APPLICATION_ID, channel="public", request_id=None, stage="input",
                              event_type="INPUT_FIREWALL", classification="malicious", severity="high", risk_score=None, action="block")
        html = self.page(list_incidents()[0]).text
        self.assertNotIn('class="sid-trace-link"', html)
        self.assertNotIn('<dt>Request ID</dt>', html)
        self.assertNotIn('class="sid-risk"', html)

    def test_empty_history_and_events_have_polished_states(self):
        incident = self.correlated()
        self.assertIn("No lifecycle changes have been recorded.", self.page(incident).text)
        detail = replace(get_incident(incident.incident_id), events=())
        with patch("app.soc_routes.get_incident", return_value=detail):
            self.assertIn("No correlated events are available.", self.page(incident).text)

    def test_status_notice_cannot_claim_a_status_different_from_stored_state(self):
        incident = self.correlated()
        for value in ("CONTAINED", "RESOLVED", "<b>synthetic</b>"):
            html = self.page(incident, updated=value).text
            self.assertNotIn("Incident status updated to", html)
            self.assertEqual("OPEN", get_incident(incident.incident_id).incident.status)

    def test_page_is_read_only_and_unused_raw_fields_are_never_rendered(self):
        incident = self.correlated()
        before = get_incident(incident.incident_id)
        rows = self.page(incident).context["events"]
        sentinels = ["RAW-SYNTHETIC-PROMPT", "RAW-SYNTHETIC-CONTEXT", "RAW-SYNTHETIC-OUTPUT", "SYNTHETIC-SECRET-MATERIAL"]
        rows[0].update(dict(zip(("prompt", "retrieved_context", "model_output", "api_secret"), sentinels)))
        with patch("app.soc_routes._event_views", return_value=rows):
            html = self.page(incident).text
            for sentinel in sentinels:
                self.assertNotIn(sentinel, html)
        self.assertEqual(before, get_incident(incident.incident_id))

    def test_scoped_styles_existing_icons_and_no_unsupported_network_content(self):
        incident = self.correlated()
        html = self.page(incident).text
        for unsupported in ("Assign Analyst", "Assign SOC", "Block IP", "Isolate Endpoint", "Terminate Process", "Contain Host",
                            "Kill Session", "Disable Account", "PCAP", "packet capture", "Source IP", "Destination IP", "INC-2025-089",
                            "46 ms", "4,096", "countdown", "tailwind", "material-symbols"):
            self.assertNotIn(unsupported, html)
        self.assertIn('/static/security_incident_detail.css?v=', html)
        self.assertNotIn('security_incident_detail.js', html)
        symbols = {n.attrib["id"] for n in ElementTree.parse("static/llmguard-icons.svg").iter() if "id" in n.attrib}
        for tag, attrs in Elements(html).elements:
            if tag == "use":
                self.assertIn(attrs["href"].split("#")[1], symbols)
        css = re.sub(r"/\*.*?\*/", "", Path("static/security_incident_detail.css").read_text(), flags=re.S)
        self.assertTrue(all(s.strip().startswith((".security-incident-detail-page", "@media")) for s in re.findall(r"([^{}]+)\{", css)))

    def test_completed_pages_do_not_load_detail_assets(self):
        for route in ("/admin/soc/incidents", "/admin/soc/events", "/admin/soc/trace", "/admin/soc/quarantine", "/admin/dashboard",
                      "/admin/applications", f"/admin/applications/{UNIVERSITY_APPLICATION_ID}", "/admin/evaluation", "/login"):
            html = self.client.get(route).text
            self.assertNotIn('security_incident_detail.css', html)
            self.assertNotIn('security-incident-detail-page', html)

    def test_missing_incident_and_reader_mutation_rbac_are_preserved(self):
        incident = self.correlated()
        self.assertEqual(404, self.client.get('/admin/soc/incidents/synthetic-missing').status_code)
        self.client.cookies.clear()
        self.assertEqual(401, self.client.get(self.path(incident)).status_code)
        for username, password in (("student1", "Student@123"), ("security-read-only", "Employee@123")):
            self._login(username, password)
            self.assertEqual(403, self.client.get(self.path(incident)).status_code)
            for action in ("acknowledge", "resolve"):
                self.assertEqual(403, self.client.post(self.path(incident) + '/' + action, follow_redirects=False).status_code)
        self.assertEqual('OPEN', get_incident(incident.incident_id).incident.status)


if __name__ == '__main__':
    unittest.main()
