"""Benchmark presentation and artifact provenance, without running evaluation."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree

from app.benchmark_presentation import FINAL_REPORT, MODE_LABELS, RATE_LABELS, load_benchmark_presentation
from evaluation.artifact_hashing import canonical_text_sha256, canonical_text_sha256_bytes
from evaluation.dataset import DEFAULT_DATASET_PATH, load_evaluation_cases
from evaluation.harness import MODE_ORDER
from evaluation.run import build_parser
from tests import test_soc_console as fixtures
from tests.test_security_events_frontend import Elements


class EvaluationBenchmarkFrontendTests(unittest.TestCase):
    setUp = fixtures.SocConsoleTests.setUp
    tearDown = fixtures.SocConsoleTests.tearDown
    _login = fixtures.SocConsoleTests._login
    path = '/admin/evaluation'

    def page(self):
        response = self.client.get(self.path)
        self.assertEqual(200, response.status_code)
        return response

    def report(self):
        return json.loads(FINAL_REPORT.read_text(encoding='utf-8'))

    def with_report(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'benchmark.json'
            path.write_text(json.dumps(data), encoding='utf-8')
            return load_benchmark_presentation(DEFAULT_DATASET_PATH, report_path=path)

    def test_existing_context_header_and_real_subnav_preserved(self):
        response = self.page()
        for key in ('benchmark_case_count', 'benchmark_report', 'user', 'portal_scope', 'firewall_active', 'asset_version'):
            self.assertIn(key, response.context)
        self.assertEqual(len(load_evaluation_cases()), response.context['benchmark_case_count'])
        self.assertIn('Controlled synthetic evaluation of LLMGuard security behavior.', response.text)
        self.assertIn('class="active" href="/admin/evaluation"', response.text)
        self.assertIn('href="/admin/compare"', response.text)
        self.assertIn('href="/admin/redteam"', response.text)
        self.assertNotIn('href="#"', response.text)
        self.assertEqual(1, response.text.count('class="console-header"'))

    def test_metadata_has_actual_runs_seeds_modes_and_matching_dataset(self):
        b = self.page().context['benchmark_report']
        metadata = self.report()['metadata']
        self.assertTrue(b['available'])
        self.assertEqual(metadata['dataset_case_count'], b['case_count'])
        self.assertEqual(metadata['run_count'], b['run_count'])
        self.assertEqual(metadata['run_seeds'], b['seeds'])
        self.assertEqual(list(MODE_ORDER), [m['id'] for m in b['modes']])
        self.assertEqual(list(MODE_ORDER), list(MODE_LABELS))
        self.assertEqual(canonical_text_sha256(DEFAULT_DATASET_PATH), b['dataset_sha256'])

    def test_all_protected_metrics_use_artifact_values_and_percentage_units(self):
        response = self.page()
        source = self.report()['metrics']['full_protected_pipeline']
        for key in RATE_LABELS:
            value = response.context['benchmark_report']['protected'][key]
            self.assertEqual(source[key], value['value'])
            self.assertEqual(f'{source[key] * 100:.1f}%', value['percent'])
            self.assertIn(f'data-mode="full_protected_pipeline" data-metric="{key}">{value["percent"]}', response.text)
        self.assertNotIn('94.4%', response.text)
        self.assertNotIn('51 / 54', response.text)

    def test_bypassed_comparison_is_supported_by_artifact(self):
        response = self.page()
        source = self.report()['metrics']['bypassed']
        for key in ('accuracy', 'attack_success_rate', 'false_negative_rate', 'clean_pass_rate'):
            self.assertEqual(source[key], response.context['benchmark_report']['bypassed'][key]['value'])
            self.assertIn(f'data-mode="bypassed" data-metric="{key}">{source[key] * 100:.1f}%', response.text)
        self.assertIn('University RBAC remains active in both modes.', response.text)
        self.assertNotIn('Compromised System', response.text)

    def test_sanitized_downstream_explanation_comes_from_actual_result_rows(self):
        response = self.page()
        rows = [r for r in self.report()['results'] if r['mode'] == 'full_protected_pipeline'
                and r['malicious_downstream_execution']]
        safe = response.context['benchmark_report']['sanitized']
        self.assertEqual(len(rows), safe['observations'])
        self.assertEqual(len({r['case_id'] for r in rows}), safe['cases'])
        self.assertTrue(all(r['actual_action'] == 'sanitize' and not r['attack_success'] for r in rows))
        self.assertEqual(0, safe['attack_successes'])
        self.assertIn('Sanitized continuation, not attack success', response.text)
        self.assertIn(f'{safe["observations"]} / {safe["measured"]} measured malicious observations', response.text)

    def test_coverage_is_actual_dataset_metadata_not_owasp_statistics(self):
        response = self.page()
        counts = self.report()['metadata']['category_counts']
        coverage = response.context['benchmark_report']['coverage']
        self.assertEqual(counts, {r['id']: r['count'] for r in coverage})
        self.assertEqual(len(load_evaluation_cases()), sum(r['count'] for r in coverage))
        for row in coverage:
            self.assertIn(f'data-category="{row["id"]}"', response.text)
        self.assertNotIn('OWASP', response.text)

    def test_confusion_matrix_uses_observations_without_fake_robustness_history(self):
        response = self.page()
        source = self.report()['metrics']['full_protected_pipeline']
        self.assertEqual(source['confusion_matrix'], response.context['benchmark_report']['confusion'])
        self.assertIn('Observations, not unique cases', response.text)
        self.assertIn(f'{source["observation_count"]} recorded observations', response.text)
        for key, value in source['confusion_matrix'].items():
            self.assertIn(f'data-confusion="{key}">{value}', response.text)
        for fake in ('Regression', 'Previous Run', 'Last 7 Runs', 'Historical Accuracy', 'Today', 'Temporal Robustness'):
            self.assertNotIn(fake, response.text)

    def test_latency_hashes_and_command_are_verified(self):
        response = self.page()
        b = response.context['benchmark_report']
        source = self.report()
        for key in ('mean_latency_ms', 'median_latency_ms'):
            self.assertEqual(f'{source["metrics"]["full_protected_pipeline"][key]:.3f}', b['latency'][key])
        order = canonical_text_sha256_bytes(
            '\n'.join(c.case_id for c in load_evaluation_cases()).encode()
        )
        self.assertEqual(order, b['case_order_sha256'])
        self.assertIn(b['dataset_sha256'], response.text)
        self.assertIn(order, response.text)
        self.assertTrue(b['command'].startswith('python -m evaluation.run '))
        args = build_parser().parse_args(b['command'].split()[3:])
        self.assertEqual(source['metadata']['run_count'], args.runs)
        self.assertEqual(source['metadata']['seed'], args.seed)
        self.assertEqual(list(MODE_ORDER), args.modes)
        self.assertNotEqual(FINAL_REPORT.parent, args.output_dir.resolve())
        self.assertIn('Benchmark latency', response.text)
        self.assertIn('not production latency', response.text)
        self.assertNotIn('p95', response.text)

    def test_missing_corrupt_and_mismatched_report_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'missing.json'
            self.assertFalse(load_benchmark_presentation(DEFAULT_DATASET_PATH, report_path=path)['available'])
            path.write_text('{invalid', encoding='utf-8')
            self.assertFalse(load_benchmark_presentation(DEFAULT_DATASET_PATH, report_path=path)['available'])
        for key, value in [('dataset_sha256', '0' * 64), ('case_order_sha256', '0' * 64), ('synthetic_data', False), ('run_count', 7)]:
            data = self.report()
            data['metadata'][key] = value
            with self.subTest(key=key):
                self.assertFalse(self.with_report(data)['available'])

    def test_unavailable_route_has_no_placeholder_metrics_or_runner_state(self):
        with patch('app.portals.admin.load_benchmark_presentation', return_value={'available': False, 'reason': 'No verified final report is available.'}):
            html = self.page().text
        self.assertIn('No verified benchmark results', html)
        self.assertNotIn('data-metric=', html)
        self.assertNotIn('data-evaluation-mode=', html)
        self.assertNotIn('eb-ring', html)
        self.assertIn('python -m evaluation.run', html)
        self.assertIn('data-benchmark-fact="cases"', html)

    def test_values_are_not_hardcoded_and_unavailable_metric_fields_are_omitted(self):
        data = self.report()
        data['metrics']['full_protected_pipeline']['accuracy'] = .8
        data['metrics']['full_protected_pipeline']['precision'] = 'invalid'
        data['metrics']['full_protected_pipeline']['median_latency_ms'] = None
        view = self.with_report(data)
        with patch('app.portals.admin.load_benchmark_presentation', return_value=view):
            html = self.page().text
        self.assertIn('data-metric="accuracy">80.0%', html)
        self.assertNotIn('data-metric="precision"', html)
        self.assertNotIn('data-latency="median_latency_ms"', html)

    def test_unknown_sensitive_fields_are_never_rendered_and_page_is_read_only(self):
        data = self.report()
        data['raw_prompt'] = 'SYNTHETIC-PRIVATE-PAYLOAD'
        data['metadata']['api_secret'] = 'SYNTHETIC-PRIVATE-PAYLOAD'
        data['results'][0]['context'] = 'SYNTHETIC-PRIVATE-PAYLOAD'
        view = self.with_report(data)
        with patch('app.portals.admin.load_benchmark_presentation', return_value=view):
            html = self.page().text
        self.assertNotIn('SYNTHETIC-PRIVATE-PAYLOAD', html)
        for fake in ('LIVE RUN', 'Streaming', 'Running Now', 'AUDIT PASS VERIFIED', 'AutoDAN', 'ChromaDB', 'Production Certified'):
            self.assertNotIn(fake, html)
        self.assertIn('do not imply complete protection against all prompt-injection attacks.', html)
        self.assertEqual([], [a for t, a in Elements(html).elements if t == 'form'])
        self.assertEqual(1, len([a for t, a in Elements(html).elements if t == 'script']))
        self.assertNotIn('data-run', html)

    def test_adapter_does_not_write_reports_or_modify_evaluation_inputs(self):
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (FINAL_REPORT, DEFAULT_DATASET_PATH)}
        self.page()
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before})

    def test_scoped_asset_existing_icons_and_completed_page_assets(self):
        html = self.page().text
        self.assertIn('/static/evaluation_benchmark.css?v=', html)
        self.assertEqual(200, self.client.get('/static/evaluation_benchmark.css').status_code)
        root = Path(__file__).resolve().parents[1]
        symbols = {n.attrib['id'] for n in ElementTree.parse(root / 'static/llmguard-icons.svg').iter() if 'id' in n.attrib}
        for tag, attrs in Elements(html).elements:
            if tag == 'use':
                self.assertIn(attrs['href'].split('#')[-1], symbols)
        for route in ('/admin/compare', '/admin/redteam', '/admin/soc/quarantine', '/admin/soc/trace', '/admin/soc/events', '/admin/soc/incidents'):
            self.assertNotIn('evaluation_benchmark.css', self.client.get(route).text)

    def test_authentication_and_existing_portal_rbac_preserved(self):
        self.client.cookies.clear()
        self.assertEqual(401, self.client.get(self.path).status_code)
        self._login('student1', 'Student@123')
        self.assertEqual(403, self.client.get(self.path).status_code)
        self._login('security-read-only', 'Employee@123')
        self.assertEqual(403, self.client.get(self.path).status_code)


if __name__ == '__main__':
    unittest.main()
