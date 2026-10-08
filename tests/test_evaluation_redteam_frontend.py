"""Truthful unavailable state and preservation of the stored-case/stub contracts."""
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from xml.etree import ElementTree

from sqlalchemy import select

from app.config import reset_settings_cache
from app.models import RedteamCase
from tests import test_soc_console as fixtures
from tests.test_security_events_frontend import Elements

ROOT = Path(__file__).resolve().parents[1]


class EvaluationRedteamFrontendTests(unittest.TestCase):
    setUp = fixtures.SocConsoleTests.setUp
    tearDown = fixtures.SocConsoleTests.tearDown
    _login = fixtures.SocConsoleTests._login
    path = '/admin/redteam'

    def page(self):
        response = self.client.get(self.path)
        self.assertEqual(200,response.status_code)
        return response

    def configured_page(self, enabled, app_env='local'):
        with patch.dict(os.environ,{'REDTEAM_MODE':str(enabled).lower(),'APP_ENV':app_env}):
            reset_settings_cache()
            try: return self.page()
            finally: reset_settings_cache()

    def seed_case(self, **fields):
        values = {'case_id':'SYNTHETIC-CASE-001','name':'Synthetic context injection case',
                  'prompt':'SYNTHETIC-PRIVATE-PAYLOAD-NOT-FOR-DISPLAY','attack_type':'indirect_prompt_injection',
                  'severity':'high','expected_action':'quarantine','expected_label':'malicious',
                  'user_role':'student','portal_scope':'student',
                  'metadata_json':{'raw_output':'SYNTHETIC-PRIVATE-PAYLOAD-NOT-FOR-DISPLAY'}}
        values.update(fields)
        with self.auth_session() as db:
            db.add(RedteamCase(**values)); db.commit()
        return values

    def test_get_retains_context_header_and_evaluation_subnav(self):
        response = self.page()
        self.assertEqual('redteam_dashboard.html',response.template.name)
        for key in ('cases','runner_available','redteam_enabled','user','portal_scope','firewall_active','asset_version'):
            self.assertIn(key,response.context)
        self.assertIn('<h1>Red Team</h1>',response.text)
        self.assertIn('Adversarial evaluation runner is not configured in this environment.',response.text)
        self.assertIn('class="active" href="/admin/redteam"',response.text)
        self.assertIn('href="/admin/evaluation"',response.text)
        self.assertIn('href="/admin/compare"',response.text)
        self.assertNotIn('href="#"',response.text)
        self.assertEqual(1,response.text.count('class="console-header"'))

    def test_disabled_flag_shows_not_configured_and_disabled_action(self):
        response = self.configured_page(False)
        self.assertFalse(response.context['redteam_enabled'])
        self.assertFalse(response.context['runner_available'])
        self.assertIn('data-redteam-enabled="false"',response.text)
        self.assertIn('data-runner-state="not-configured"',response.text)
        self.assertIn('data-runner-status>NOT CONFIGURED',response.text)
        self.assertIn('data-redteam-flag class="">Disabled',response.text)
        button = [a for t,a in Elements(response.text).elements if a.get('id')=='run-redteam-suite'][0]
        self.assertIn('disabled',button)

    def test_enabled_flag_does_not_claim_a_runner_or_enable_execution(self):
        response = self.configured_page(True)
        self.assertTrue(response.context['redteam_enabled'])
        self.assertFalse(response.context['runner_available'])
        self.assertIn('data-redteam-enabled="true"',response.text)
        self.assertIn('data-runner-status>NOT CONFIGURED',response.text)
        self.assertIn('ert-flag-enabled">Enabled',response.text)
        self.assertIn('Execution remains unavailable in either flag state.',response.text)
        button = [a for t,a in Elements(response.text).elements if a.get('id')=='run-redteam-suite'][0]
        self.assertIn('disabled',button)
        for claim in ('Runner connected','Full suite execution is available.','AVAILABLE</span>','Ready'):
            self.assertNotIn(claim,response.text)

    def test_local_redteam_env_sets_flag_without_changing_capability(self):
        response = self.configured_page(False,'local_redteam')
        self.assertTrue(response.context['redteam_enabled'])
        self.assertFalse(response.context['runner_available'])
        self.assertIn('data-runner-status>NOT CONFIGURED',response.text)

    def test_execution_stays_http501_in_all_real_flag_configurations(self):
        expected = {'available':False,'detail':'No reusable red-team runner is installed. No results were fabricated.'}
        for enabled,app_env in [('false','local'),('true','local'),('false','local_redteam')]:
            with patch.dict(os.environ,{'REDTEAM_MODE':enabled,'APP_ENV':app_env}):
                reset_settings_cache()
                try:
                    response = self.client.post(self.path+'/run')
                    self.assertEqual(501,response.status_code)
                    self.assertEqual(expected,response.json())
                finally: reset_settings_cache()

    def test_stub_does_not_call_gateway_model_or_evaluation_and_creates_no_results(self):
        self.seed_case()
        with self.auth_session() as db:
            before = [c.case_id for c in db.scalars(select(RedteamCase)).all()]
        with patch('app.portals.admin.process_ai_request') as gateway, patch('app.ai.gateway.call_qwen') as qwen:
            response = self.client.post(self.path+'/run')
            self.assertEqual(501,response.status_code)
            gateway.assert_not_called(); qwen.assert_not_called()
        with self.auth_session() as db:
            self.assertEqual(before,[c.case_id for c in db.scalars(select(RedteamCase)).all()])
        self.assertEqual([],self.client.get(self.path+'/export').json()['results'])

    def test_empty_state_has_no_fabricated_cases_or_execution_results(self):
        response = self.page()
        self.assertEqual([],response.context['cases'])
        self.assertIn('data-stored-case-count>0',response.text)
        self.assertIn('No red-team cases are stored in the database.',response.text)
        self.assertNotIn('data-case-name',response.text)
        for placeholder in ('Protected results','Critical failures','Pending','Not run','Vulnerable result','Protected result'):
            self.assertNotIn(placeholder,response.text)

    def test_stored_cases_render_real_safe_metadata_and_expected_not_actual_action(self):
        values = self.seed_case()
        response = self.page()
        for key in ('case_id','name','attack_type','severity','expected_action'):
            self.assertIn(values[key],response.text)
        self.assertIn('data-stored-case-count>1',response.text)
        self.assertIn('Expected action',response.text)
        self.assertIn('expected actions are test specifications',response.text)
        self.assertIn('Definitions, not execution results',response.text)
        self.assertNotIn('SYNTHETIC-PRIVATE-PAYLOAD-NOT-FOR-DISPLAY',response.text)

    def test_route_order_and_all_stored_cases_are_preserved(self):
        self.seed_case(case_id='SYNTHETIC-Z',name='Synthetic Z',severity='high')
        self.seed_case(case_id='SYNTHETIC-A',name='Synthetic A',severity='medium')
        response = self.page()
        with self.auth_session() as db:
            expected = db.scalars(select(RedteamCase).order_by(RedteamCase.severity.desc(),RedteamCase.case_id)).all()
        self.assertEqual([c.case_id for c in expected],[c.case_id for c in response.context['cases']])
        self.assertLess(response.text.index(expected[0].case_id),response.text.index(expected[1].case_id))

    def test_export_preserves_real_allowlisted_manifest_and_empty_results(self):
        values = self.seed_case()
        response = self.client.get(self.path+'/export')
        self.assertEqual(200,response.status_code)
        self.assertEqual({'runner_available':False,'results':[],
                          'cases':[{k:values[k] for k in ('case_id','name','attack_type','severity','expected_action')}]},response.json())
        self.assertIn('href="/admin/redteam/export"',self.page().text)
        self.assertNotIn('SYNTHETIC-PRIVATE-PAYLOAD',response.text)

    def test_cases_api_keeps_metadata_contract(self):
        values = self.seed_case()
        response = self.client.get(self.path+'/cases')
        self.assertEqual(200,response.status_code)
        self.assertEqual({'cases':[{k:values[k] for k in ('case_id','name','attack_type','severity','expected_action','user_role')}]},response.json())

    def test_long_and_markup_metadata_is_escaped_without_new_payload_views(self):
        self.seed_case(case_id='SYNTHETIC-'+('X'*170),name='<script>SYNTHETIC-XSS</script>',
                       attack_type='SYNTHETIC-'+('Y'*100),expected_action='<img onerror="synthetic">')
        html = self.page().text
        self.assertIn('SYNTHETIC-'+('X'*170),html)
        self.assertIn('&lt;script&gt;SYNTHETIC-XSS&lt;/script&gt;',html)
        self.assertNotIn('<script>SYNTHETIC-XSS',html)
        self.assertNotIn('<img onerror=',html)
        self.assertNotIn('SYNTHETIC-PRIVATE-PAYLOAD',html)

    def test_only_existing_disabled_run_and_real_links_no_fake_forms(self):
        elements = Elements(self.page().text).elements
        self.assertEqual([],[(t,a) for t,a in elements if t in ('form','input','select','textarea')])
        controls = [a for t,a in elements if a.get('id')=='run-redteam-suite']
        self.assertEqual(1,len(controls)); self.assertIn('disabled',controls[0])
        self.assertEqual(1,len([a for t,a in elements if a.get('id')=='redteam-message']))
        self.assertEqual(1,len([a for t,a in elements if a.get('href')=='/admin/redteam/export']))

    def test_unsupported_exported_controls_categories_and_benchmark_duplicates_absent(self):
        html = self.page().text
        for fake in ('AutoDAN','GCG','PAIR','TAP','Attack intensity','Iterations','Temperature',
                     'Mutation engine','Attack corpus','LIVE RUN','Launch Attack','Start Attack',
                     'Attack Success Rate','94.4%','51 / 54','54 Cases','Regression','Previous Run',
                     'Privileged Escalation','Cross-application role bypass','Poisoned document context',
                     'DLP and canary tests','Historical Accuracy','Compromised System'):
            self.assertNotIn(fake,html)
        self.assertNotIn('data-metric=',html)
        self.assertNotIn('progressbar',html)
        self.assertNotIn('<table',html)
        self.assertIn('Stored case definitions are not evidence of a completed adversarial campaign.',html)

    def test_existing_js_hooks_are_preserved_and_no_new_runner_script(self):
        html = self.page().text
        self.assertIn('/static/product.js',html)
        self.assertIn('/static/redteam_dashboard.js',html)
        js = (ROOT/'static/redteam_dashboard.js').read_text()
        self.assertIn('apiRequest("/admin/redteam/run", {method: "POST"})',js)
        for fake in ('setInterval','requestAnimationFrame','animation:','@keyframes'):
            self.assertNotIn(fake,(ROOT/'static/evaluation_redteam.css').read_text())
        template = (ROOT/'templates/redteam_dashboard.html').read_text()
        self.assertNotIn('<script>',template)

    def test_existing_icons_scoped_styles_and_completed_page_assets(self):
        html = self.page().text
        self.assertIn('/static/evaluation_redteam.css?v=',html)
        self.assertEqual(200,self.client.get('/static/evaluation_redteam.css').status_code)
        symbols = {n.attrib['id'] for n in ElementTree.parse(ROOT/'static/llmguard-icons.svg').iter() if 'id' in n.attrib}
        for tag,attrs in Elements(html).elements:
            if tag=='use': self.assertIn(attrs['href'].split('#')[-1],symbols)
        for route in ('/admin/evaluation','/admin/compare','/admin/soc/events','/admin/soc/incidents','/admin/soc/trace','/admin/soc/quarantine'):
            self.assertNotIn('evaluation_redteam.css',self.client.get(route).text)

    def test_get_post_export_cases_authentication_and_rbac_unchanged(self):
        self.client.cookies.clear()
        for method,path in [('get',self.path),('post',self.path+'/run'),('get',self.path+'/export'),('get',self.path+'/cases')]:
            self.assertEqual(401,getattr(self.client,method)(path).status_code)
        for username,password in [('student1','Student@123'),('employee1','Employee@123'),('security-read-only','Employee@123')]:
            self._login(username,password)
            for method,path in [('get',self.path),('post',self.path+'/run'),('get',self.path+'/export'),('get',self.path+'/cases')]:
                self.assertEqual(403,getattr(self.client,method)(path).status_code)


if __name__=='__main__': unittest.main()
