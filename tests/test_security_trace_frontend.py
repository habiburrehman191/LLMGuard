"""Request Trace presentation contracts using isolated synthetic records."""
from pathlib import Path
import re
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree

from app.application_registry import UNIVERSITY_APPLICATION_ID, register_application
from app.security_events import get_request_trace, record_security_event
from tests import test_soc_console as fixtures
from tests.test_security_events_frontend import Elements


class SecurityTraceFrontendTests(unittest.TestCase):
    setUp = fixtures.SocConsoleTests.setUp
    tearDown = fixtures.SocConsoleTests.tearDown
    _login = fixtures.SocConsoleTests._login
    _record = fixtures.SocConsoleTests._record
    path = '/admin/soc/trace'

    def page(self, **params):
        response = self.client.get(self.path, params=params)
        self.assertEqual(200, response.status_code)
        return response

    def nodes(self, html, attribute):
        return [attrs[attribute] for _, attrs in Elements(html).elements if attribute in attrs]

    def later(self, request_id='synthetic-later', context_action='allow', output_action='allow'):
        for index, (stage, action, risk) in enumerate([('input', 'allow', 0), ('context', context_action, .45), ('output', output_action, None)]):
            # Distinct stored timestamps avoid platform clock ties; production sorts by time then ID.
            with patch('app.security_events._utc_timestamp', return_value=f'2026-10-07T14:00:0{index}+00:00'):
                self._record(request_id=request_id, stage=stage, event_type=stage.upper() + '_FIREWALL', action=action, risk_score=risk)
        return request_id

    def test_unsearched_header_context_search_contract_and_navigation(self):
        response = self.page()
        for key in ('request_id', 'selected_application_id', 'application_names', 'matching_applications', 'events',
                    'stage_summary', 'other_stages', 'trace_searched', 'user', 'page_title', 'active_soc_page',
                    'portal_scope', 'firewall_active', 'asset_version', 'applications'):
            self.assertIn(key, response.context)
        html = response.text
        self.assertIn('Follow recorded LLMGuard security decisions across the request lifecycle.', html)
        self.assertIn('Trace a request', html)
        self.assertIn('Enter a request ID to inspect its recorded security path.', html)
        self.assertEqual([], self.nodes(html, 'data-recorded-stage'))
        forms = [a for t, a in Elements(html).elements if t == 'form']
        self.assertEqual([{'method': 'get', 'action': self.path}], forms)
        fields = [a for t, a in Elements(html).elements if t in ('input', 'select')]
        self.assertEqual(['request_id', 'application_id'], [a['name'] for a in fields])
        self.assertEqual('200', fields[0]['maxlength'])
        self.assertEqual(1, html.count('class="console-header"'))
        self.assertIn('class="active" href="/admin/soc/trace"', html)
        for route in ('events', 'incidents', 'trace', 'quarantine'):
            self.assertIn(f'href="/admin/soc/{route}"', html)

    def test_searched_empty_and_blank_query_have_no_fabricated_pipeline(self):
        html = self.page(request_id='synthetic-missing', application_id=UNIVERSITY_APPLICATION_ID).text
        self.assertIn('No recorded trace found', html)
        self.assertIn('No security events matched this request and application.', html)
        self.assertEqual([], self.nodes(html, 'data-recorded-stage'))
        self.assertNotIn('data-final-event', html)
        self.assertIn('data-trace-state="unsearched"', self.page(request_id='   ').text)

    def test_early_input_block_ends_without_downstream_execution_nodes(self):
        event = self._record(request_id='synthetic-block', classification='malicious', severity='high', action='block', risk_score=.97)
        response = self.page(request_id='synthetic-block')
        self.assertEqual(['input'], self.nodes(response.text, 'data-recorded-stage'))
        self.assertEqual([event.event_id], self.nodes(response.text, 'data-stage-event'))
        self.assertIn('No later canonical stages are recorded for this request.', response.text)
        self.assertEqual([event.event_id], self.nodes(response.text, 'data-final-event'))
        self.assertNotIn('Request Ingress', response.text)
        self.assertNotIn('Response / Audit', response.text)
        self.assertNotIn('Local LLM', response.text)
        self.assertNotIn('Retrieval', response.text)
        self.assertIn('No event recorded; this stage may not have executed.', response.text)

    def test_session_restriction_stays_in_actual_input_stage(self):
        self._record(request_id='synthetic-session', event_type='SESSION_RESTRICTION', classification='session_risk',
                     action='session_restrict', risk_score=.62, severity='high')
        html = self.page(request_id='synthetic-session').text
        self.assertEqual(['input'], self.nodes(html, 'data-recorded-stage'))
        self.assertIn('Session Restriction', html)
        self.assertIn('SESSION_RESTRICT', html)
        self.assertIn('str-outcome str-tone-amber', html)
        self.assertNotIn('data-recorded-stage="context"', html)

    def test_allowed_later_stages_map_existing_summary_and_actual_decisions(self):
        request_id = self.later()
        response = self.page(request_id=request_id)
        self.assertEqual(['input', 'context', 'output'], self.nodes(response.text, 'data-recorded-stage'))
        self.assertEqual([{'stage': stage, 'recorded': True, 'event_count': 1} for stage in ('input', 'context', 'output')], response.context['stage_summary'])
        for title in ('02 Input Firewall', '06 Context Firewall', '09 Output Firewall'):
            self.assertIn(title, response.text)
        self.assertIn('str-outcome str-tone-green', response.text)
        self.assertNotIn('No later canonical stages', response.text)

    def test_sanitized_context_and_output_block_use_real_decisions(self):
        request_id = self.later(context_action='sanitize', output_action='block')
        response = self.page(request_id=request_id)
        self.assertIn('SANITIZE', response.text)
        self.assertIn('BLOCK', response.text)
        self.assertIn('str-outcome str-tone-red', response.text)
        self.assertEqual([get_request_trace(UNIVERSITY_APPLICATION_ID, request_id)[-1].event_id], self.nodes(response.text, 'data-final-event'))

    def test_bypassed_records_are_amber_without_claiming_success(self):
        self._record(request_id='synthetic-bypass', event_type='PROTECTION_BYPASS', classification='bypassed',
                     action='bypass', severity='none', risk_score=None)
        html = self.page(request_id='synthetic-bypass').text
        self.assertIn('BYPASS', html)
        self.assertIn('BYPASSED', html)
        self.assertIn('str-outcome str-tone-amber', html)
        self.assertNotIn('Highest recorded risk', html)
        self.assertNotIn('class="str-risk"', html)

    def test_risk_only_numeric_and_zero_preserved_without_latency(self):
        request_id = self.later()
        html = self.page(request_id=request_id).text
        self.assertIn('<strong>0.00</strong>', html)
        self.assertIn('<dd class="str-numeric">0.45</dd>', html)
        self.assertEqual(4, html.count('class="str-risk"'))
        self.assertNotIn('Latency', html)
        self.assertNotIn(' ms', html)
        self.assertNotIn('100%', html)

    def test_evidence_chronology_is_distinct_from_architectural_guard_order(self):
        # The persistence contract breaks timestamp ties by event ID, not insertion order.
        for index, (stage, event_type, action) in enumerate([
            ('output', 'OUTPUT_FIREWALL', 'allow'),
            ('input', 'INPUT_FIREWALL', 'allow'),
            ('input', 'SESSION_AUDIT', 'log'),
        ]):
            with patch('app.security_events._utc_timestamp', return_value=f'2026-10-07T14:00:0{index}+00:00'):
                self._record(request_id='synthetic-order', stage=stage, event_type=event_type, action=action)
        events = get_request_trace(UNIVERSITY_APPLICATION_ID, 'synthetic-order')
        response = self.page(request_id='synthetic-order')
        self.assertEqual([e.event_id for e in events], self.nodes(response.text, 'data-trace-event'))
        self.assertEqual(['input', 'output'], self.nodes(response.text, 'data-recorded-stage'))
        self.assertEqual([events[1].event_id, events[2].event_id, events[0].event_id], self.nodes(response.text, 'data-stage-event'))
        self.assertIn('2 events recorded', response.text)
        self.assertEqual([events[-1].event_id], self.nodes(response.text, 'data-final-event'))

    def test_other_stages_and_university_boundary_are_preserved_without_fake_guards(self):
        for stage, event_type in [('university_authorization', 'UNIVERSITY_AUTHORIZATION'), ('integration', 'INTEGRATION_VALIDATION_FAILURE')]:
            self._record(request_id='synthetic-other', stage=stage, event_type=event_type, action='log', risk_score=None)
        response = self.page(request_id='synthetic-other')
        self.assertEqual(['integration', 'university_authorization'], response.context['other_stages'])
        self.assertEqual([], self.nodes(response.text, 'data-recorded-stage'))
        self.assertIn('No canonical guard events recorded.', response.text)
        self.assertIn('Additional Security Evidence', response.text)
        self.assertIn('University Authorization', response.text)
        self.assertNotIn('LLMGuard RBAC', response.text)
        self.assertEqual(self.nodes(response.text, 'data-trace-event'), self.nodes(response.text, 'data-additional-event'))

    def test_application_ambiguity_requires_scope_and_encoded_links_isolate_records(self):
        other = register_application(organization_name='Synthetic QA', organization_slug='synthetic-qa',
                                     application_id='synthetic-trace-app', name='Synthetic Trace App', slug='synthetic-trace-app',
                                     environment='test', status='active', channels=('public',))
        request_id = 'synthetic trace & scope='.ljust(200, 'x')
        first = self._record(request_id=request_id)
        second = record_security_event(application_id=other.application_id, channel='public', request_id=request_id,
                                       stage='integration', event_type='INTEGRATION_AUDIT', classification='safe', severity='low', action='log')
        response = self.page(request_id=request_id)
        self.assertEqual([], response.context['events'])
        self.assertIn('Choose an application', response.text)
        links = [a['href'] for t, a in Elements(response.text).elements if t == 'a' and 'request_id=' in a.get('href', '')]
        self.assertEqual(2, len(links))
        for href in links:
            parts = urlparse(href)
            query = parse_qs(parts.query)
            self.assertEqual(self.path, parts.path)
            self.assertEqual([request_id], query['request_id'])
            scoped = self.client.get(href)
            expected = first if query['application_id'] == [UNIVERSITY_APPLICATION_ID] else second
            self.assertEqual([expected.event_id], self.nodes(scoped.text, 'data-trace-event'))
        self.assertIn('No recorded trace found', self.page(request_id=request_id, application_id='unknown-synthetic-app').text)

    def test_template_is_metadata_only_and_search_does_not_mutate_records(self):
        request_id = self.later()
        before = get_request_trace(UNIVERSITY_APPLICATION_ID, request_id)
        rows = self.page(request_id=request_id).context['events']
        sentinels = ('RAW-SYNTHETIC-PROMPT', 'RAW-SYNTHETIC-CONTEXT', 'RAW-SYNTHETIC-OUTPUT', 'SYNTHETIC-SECRET')
        rows[0].update(dict(zip(('prompt', 'retrieved_context', 'model_output', 'api_secret'), sentinels)))
        with patch('app.soc_routes._event_views', return_value=rows):
            html = self.page(request_id=request_id).text
            for value in sentinels:
                self.assertNotIn(value, html)
        self.assertEqual(before, get_request_trace(UNIVERSITY_APPLICATION_ID, request_id))

    def test_scoped_styles_sprite_and_export_exclusions(self):
        html = self.page(request_id=self.later()).text
        self.assertIn('/static/security_trace.css?v=', html)
        self.assertNotIn('security_trace.js', html)
        for value in ('PCAP', 'Packet Trace', 'Span ID', 'Source IP', 'Destination IP', 'Network Hop', '46 ms',
                      'Isolate Endpoint', 'Assign SOC', 'gpt-4o-mini', 'Pinecone', 'ChromaDB', 'tailwind', 'material-symbols'):
            self.assertNotIn(value, html)
        symbols = {n.attrib['id'] for n in ElementTree.parse('static/llmguard-icons.svg').iter() if 'id' in n.attrib}
        for tag, attrs in Elements(self.page().text + html).elements:
            if tag == 'use':
                self.assertIn(attrs['href'].split('#')[1], symbols)
        css = re.sub(r'/\*.*?\*/', '', Path('static/security_trace.css').read_text(), flags=re.S)
        self.assertTrue(all(s.strip().startswith(('.security-trace-page', '@media')) for s in re.findall(r'([^{}]+)\{', css)))
        self.assertIn(':not(:last-child)::after', css)

    def test_completed_pages_do_not_load_trace_assets(self):
        self._record(request_id='synthetic-incident', action='block', classification='malicious', severity='high')
        from app.security_events import list_incidents
        for route in ('/admin/soc/events', '/admin/soc/incidents', '/admin/soc/incidents/' + list_incidents()[0].incident_id,
                      '/admin/soc/quarantine', '/admin/dashboard', '/admin/applications',
                      '/admin/applications/' + UNIVERSITY_APPLICATION_ID, '/admin/evaluation', '/login'):
            html = self.client.get(route).text
            self.assertNotIn('security_trace.css', html)
            self.assertNotIn('security-trace-page', html)

    def test_authentication_rbac_and_query_limits_unchanged(self):
        self.assertEqual(422, self.client.get(self.path, params={'request_id': 'x' * 201}).status_code)
        self.client.cookies.clear()
        self.assertEqual(401, self.client.get(self.path).status_code)
        for username, password in (('student1', 'Student@123'), ('security-read-only', 'Employee@123')):
            self._login(username, password)
            self.assertEqual(403, self.client.get(self.path).status_code)


if __name__ == '__main__':
    unittest.main()
