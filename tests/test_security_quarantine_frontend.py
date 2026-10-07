"""Metadata-only Quarantine presentation using isolated stored synthetic evidence."""
from pathlib import Path
import unittest
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree

from app.application_registry import UNIVERSITY_APPLICATION_ID, register_application
from app.security_events import list_quarantine_events, record_security_event
from tests import test_soc_console as fixtures
from tests.test_security_events_frontend import Elements


class SecurityQuarantineFrontendTests(unittest.TestCase):
    setUp = fixtures.SocConsoleTests.setUp
    tearDown = fixtures.SocConsoleTests.tearDown
    _login = fixtures.SocConsoleTests._login
    _record = fixtures.SocConsoleTests._record
    path = '/admin/soc/quarantine'

    def page(self, **params):
        response = self.client.get(self.path, params=params)
        self.assertEqual(200, response.status_code)
        return response

    def rows(self, html):
        return [a['data-quarantine-event'] for _, a in Elements(html).elements if 'data-quarantine-event' in a]

    def quarantine(self, **params):
        return self._record(request_id=params.pop('request_id', 'synthetic-quarantine'), action='quarantine',
                            classification='malicious', severity='high', stage='context',
                            event_type='CONTEXT_FIREWALL', **params)

    def test_header_context_native_filter_and_active_subnav(self):
        response = self.page()
        for key in ('applications', 'selected_application_id', 'quarantine_records', 'user', 'page_title',
                    'active_soc_page', 'portal_scope', 'firewall_active', 'asset_version'):
            self.assertIn(key, response.context)
        html = response.text
        self.assertIn('Review security evidence isolated by LLMGuard policy decisions.', html)
        forms = [a for t, a in Elements(html).elements if t == 'form']
        self.assertEqual(1, len(forms))
        self.assertEqual('get', forms[0]['method'])
        self.assertEqual(self.path, forms[0]['action'])
        fields = [a for t, a in Elements(html).elements if t in ('input', 'select')]
        self.assertEqual(['application_id'], [a['name'] for a in fields])
        self.assertIn('All Applications', html)
        self.assertEqual(1, html.count('class="console-header"'))
        self.assertIn('class="active" href="/admin/soc/quarantine"', html)
        for route in ('events', 'incidents', 'trace', 'quarantine'):
            self.assertIn(f'href="/admin/soc/{route}"', html)

    def test_true_empty_uses_requested_copy_and_zero_rendered_count(self):
        html = self.page().text
        self.assertIn('No quarantined records', html)
        self.assertIn('No quarantine evidence matches the selected application.', html)
        self.assertIn('0 records shown', html)
        self.assertEqual([], self.rows(html))

    def test_only_actual_quarantine_records_in_backend_order(self):
        for action in ('allow', 'block', 'sanitize'):
            self._record(request_id='synthetic-' + action, action=action)
        self.quarantine(request_id='synthetic-context', source_id='synthetic-source', chunk_id='synthetic-chunk')
        self.quarantine(request_id='synthetic-second')
        expected = list_quarantine_events(limit=200)
        response = self.page()
        self.assertEqual([r.event.event_id for r in expected], self.rows(response.text))
        self.assertIn('2 records shown', response.text)
        for stored, row in zip(expected, response.context['quarantine_records']):
            self.assertEqual(stored.event.created_at, row['created_at'])
            self.assertIn(f'datetime="{stored.event.created_at}"', response.text)
            self.assertEqual(stored.event.request_id, row['request_id'])

    def test_application_filter_selects_real_application_and_excludes_other_records(self):
        other = register_application(organization_name='Synthetic QA', organization_slug='synthetic-qa',
                                     application_id='synthetic-quarantine-app', name='Synthetic Quarantine App',
                                     slug='synthetic-quarantine-app', environment='test', status='active', channels=('public',))
        own = self.quarantine()
        different = record_security_event(application_id=other.application_id, channel='public', stage='input',
                                          event_type='INPUT_FIREWALL', classification='suspicious', severity='medium',
                                          action='quarantine', request_id='synthetic-other-request')
        response = self.page(application_id=other.application_id)
        self.assertEqual([different.event_id], self.rows(response.text))
        self.assertNotIn(own.event_id, response.text)
        self.assertIn(other.name, response.text)
        self.assertIn('1 record shown', response.text)
        options = [a for t, a in Elements(response.text).elements if t == 'option' and 'selected' in a]
        self.assertEqual([other.application_id], [a['value'] for a in options])
        self.assertEqual(other.application_id, response.context['selected_application_id'])
        self.assertEqual(2, len(self.rows(self.page(application_id='').text)))

    def test_filtered_empty_has_no_demo_records(self):
        self.quarantine()
        html = self.page(application_id='synthetic-no-records').text
        self.assertEqual([], self.rows(html))
        self.assertIn('No quarantined records', html)
        self.assertIn('Clear filter', html)

    def test_context_references_are_safe_identifiers_without_inferred_fields(self):
        event = self.quarantine(source_id='synthetic-rag-source', chunk_id='synthetic-rag-chunk')
        response = self.page()
        self.assertIn(event.source_id, response.text)
        self.assertIn(event.chunk_id, response.text)
        self.assertIn('Source ID', response.text)
        self.assertIn('Chunk ID', response.text)
        # The existing route deliberately supplies eight fields, not the underlying full event.
        self.assertEqual({'event_id', 'application_id', 'application_name', 'request_id', 'source_id',
                          'chunk_id', 'created_at', 'incident_id'}, set(response.context['quarantine_records'][0]))
        self.assertNotIn('CONTEXT_FIREWALL', response.text)
        self.assertNotIn('MALICIOUS', response.text)
        self.assertNotIn('Guard stage', response.text)

    def test_trace_link_round_trips_long_encoded_request_and_application(self):
        request_id = 'synthetic-request-&-=/#'.ljust(200, 'x')
        event = self.quarantine(request_id=request_id, source_id='synthetic-source-'.ljust(300, 's'),
                                chunk_id='synthetic-chunk-'.ljust(300, 'c'))
        html = self.page().text
        links = [a['href'] for t, a in Elements(html).elements if t == 'a' and a['href'].startswith('/admin/soc/trace?')]
        self.assertEqual(1, len(links))
        self.assertEqual('/admin/soc/trace', urlparse(links[0]).path)
        self.assertEqual({'application_id': [UNIVERSITY_APPLICATION_ID], 'request_id': [request_id]}, parse_qs(urlparse(links[0]).query))
        self.assertEqual(200, self.client.get(links[0]).status_code)
        for identifier in (event.source_id, event.chunk_id):
            self.assertIn(identifier, html)
        self.assertIn('synthetic-request-&amp;-=', html)

    def test_existing_incident_link_preserved(self):
        self.quarantine()
        record = list_quarantine_events()[0]
        self.assertIsNotNone(record.incident_id)
        html = self.page().text
        self.assertIn(f'href="/admin/soc/incidents/{record.incident_id}"', html)
        self.assertIn('View Incident', html)
        self.assertEqual(200, self.client.get('/admin/soc/incidents/' + record.incident_id).status_code)

    def test_missing_optional_references_do_not_create_fake_links_or_values(self):
        record_security_event(application_id=UNIVERSITY_APPLICATION_ID, channel='public', stage='context',
                              event_type='CONTEXT_FIREWALL', classification='safe', severity='low', action='quarantine')
        html = self.page().text
        self.assertNotIn('View Trace', html)
        self.assertNotIn('View Incident', html)
        self.assertNotIn('<dt>Source ID</dt>', html)
        self.assertNotIn('<dt>Chunk ID</dt>', html)
        self.assertNotIn('Not reported', html)

    def test_only_explicit_safe_fields_render_even_if_extra_content_is_supplied(self):
        self.quarantine()
        response = self.page()
        row = dict(response.context['quarantine_records'][0])
        for key in ('prompt', 'context', 'chunk_text', 'document_body', 'model_output', 'password', 'api_secret', 'personal_record'):
            row[key] = 'SYNTHETIC-PRIVATE-CONTENT-' + key
        context = dict(response.context, quarantine_records=[row])
        html = response.template.render(context)
        self.assertNotIn('SYNTHETIC-PRIVATE-CONTENT', html)
        for term in ('prompt', 'document text', 'Open Payload', 'Download', 'Release', 'Restore', 'Delete', 'Reprocess',
                     'Endpoint', 'PCAP', 'Malware', 'Antivirus', 'Isolate Endpoint', 'Contain Host'):
            self.assertNotIn(term.lower(), html.lower())
        self.assertIn('Metadata only', html)

    def test_identifiers_are_escaped_and_native_disclosure_requires_no_page_javascript(self):
        self.quarantine(source_id='synthetic-<script>alert(1)</script>', chunk_id='synthetic-&chunk')
        html = self.page().text
        self.assertIn('synthetic-&lt;script&gt;alert(1)&lt;/script&gt;', html)
        self.assertNotIn('<script>alert(1)</script>', html)
        tags = Elements(html).elements
        self.assertEqual(1, len([1 for t, _ in tags if t == 'details']))
        self.assertEqual(1, len([1 for t, _ in tags if t == 'summary']))
        scripts = [a.get('src', '') for t, a in tags if t == 'script']
        self.assertEqual(1, len(scripts))
        self.assertTrue(scripts[0].startswith('http://testserver/static/product.js'))

    def test_scoped_asset_and_existing_icon_symbols_resolve(self):
        html = self.page().text
        self.assertIn('/static/security_quarantine.css?v=', html)
        self.assertEqual(200, self.client.get('/static/security_quarantine.css').status_code)
        root = Path(__file__).resolve().parents[1]
        symbols = {node.attrib['id'] for node in ElementTree.parse(root / 'static/llmguard-icons.svg').iter() if 'id' in node.attrib}
        for tag, attrs in Elements(html).elements:
            if tag == 'use':
                self.assertIn(attrs['href'].split('#')[-1], symbols)
        css = (root / 'static/security_quarantine.css').read_text(encoding='utf-8')
        self.assertIn('overflow-wrap: anywhere', css)
        self.assertIn('prefers-reduced-motion', css)

    def test_authentication_and_soc_rbac_unchanged(self):
        self.client.cookies.clear()
        self.assertEqual(401, self.client.get(self.path).status_code)
        self._login('security-read-only', 'Employee@123')
        self.assertEqual(403, self.client.get(self.path).status_code)


if __name__ == '__main__':
    unittest.main()
