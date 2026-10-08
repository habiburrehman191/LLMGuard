"""Read-only, metadata-only view of the existing final evaluation artifact.

This adapter never runs evaluation, recalculates benchmark metrics, or writes
reports. Paths are repository-controlled and are not supplied by HTTP requests.
"""
from collections import Counter
import json
import math
from pathlib import Path

from evaluation.artifact_hashing import canonical_text_sha256_bytes

ROOT = Path(__file__).resolve().parents[1]
FINAL_REPORT = ROOT / 'reports/evaluation/final/benchmark.json'
MODE_LABELS = {
    'rules_only': 'Rules Only', 'semantic_only': 'Semantic Only', 'ml_only': 'ML Only',
    'hybrid': 'Hybrid', 'full_protected_pipeline': 'Protected', 'bypassed': 'Bypassed',
}
RATE_LABELS = {
    'accuracy': 'Accuracy', 'precision': 'Precision', 'recall': 'Recall', 'f1': 'F1',
    'attack_success_rate': 'Attack Success Rate', 'false_positive_rate': 'False Positive Rate',
    'false_negative_rate': 'False Negative Rate', 'clean_pass_rate': 'Clean Pass Rate',
}
CATEGORY_LABELS = {
    'clean': 'Clean', 'direct_prompt_injection': 'Direct Prompt Injection',
    'indirect_prompt_injection': 'Indirect Prompt Injection', 'paraphrased_attack': 'Paraphrased Attack',
    'obfuscated_encoded_attack': 'Obfuscated / Encoded Attack',
    'privilege_cross_user_attempt': 'Privilege / Cross-user Attempt',
    'data_exfiltration_system_prompt_leakage': 'Data Exfiltration / System Prompt Leakage',
    'retrieval_poisoning': 'Retrieval Poisoning', 'cross_chunk_attack': 'Cross-chunk Attack',
}


def _number(value, *, maximum=None):
    return (type(value) in (int, float) and math.isfinite(value) and value >= 0
            and (maximum is None or value <= maximum))


def _rate(value):
    return {'value': value, 'percent': f'{value * 100:.1f}%'}


def load_benchmark_presentation(dataset_path: Path, *, report_path: Path = FINAL_REPORT) -> dict:
    unavailable = {'available': False, 'reason': 'No verified final report is available.'}
    try:
        raw_dataset = dataset_path.read_bytes()
        dataset = [json.loads(line) for line in raw_dataset.decode('utf-8').splitlines() if line.strip()]
        if not dataset:
            return unavailable
        report = json.loads(report_path.read_text(encoding='utf-8'))
        metadata = report['metadata']
        if report['schema_version'] != 'phase14b-v1' or metadata['synthetic_data'] is not True:
            return unavailable
        order_hash = canonical_text_sha256_bytes('\n'.join(sorted(row['case_id'] for row in dataset)).encode('utf-8'))
        if (metadata['dataset_sha256'] != canonical_text_sha256_bytes(raw_dataset)
                or metadata['dataset_case_count'] != len(dataset)
                or metadata['case_order_sha256'] != order_hash):
            return {'available': False, 'reason': 'The stored final report does not match the current dataset.'}
        run_count = metadata['run_count']
        seeds = metadata['run_seeds']
        runs = report['repeated_runs']['runs']
        if (type(run_count) is not int or not 1 <= run_count <= 100
                or len(seeds) != run_count or any(type(seed) is not int for seed in seeds)
                or seeds != list(range(metadata['seed'], metadata['seed'] + run_count))
                or len(runs) != run_count
                or any(run['seed'] != seeds[i] or run['run_index'] != i + 1 for i, run in enumerate(runs))):
            return unavailable
        modes = []
        metrics = {}
        for mode, label in MODE_LABELS.items():
            source = report['metrics'].get(mode)
            if (not isinstance(source, dict) or source.get('case_count') != len(dataset)
                    or source.get('observation_count') != len(dataset) * run_count
                    or any(mode not in run['metrics'] for run in runs)):
                continue
            modes.append({'id': mode, 'label': label})
            metrics[mode] = {key: _rate(source[key]) for key in RATE_LABELS if _number(source.get(key), maximum=1)}
        protected = metrics.get('full_protected_pipeline', {})
        if not protected:
            return unavailable
        source = report['metrics']['full_protected_pipeline']
        latency = {key: f'{source[key]:.3f}' for key in ('mean_latency_ms', 'median_latency_ms') if _number(source.get(key))}
        confusion = source.get('confusion_matrix', {})
        confusion_keys = ('true_positive', 'true_negative', 'false_positive', 'false_negative')
        if (any(type(confusion.get(key)) is not int or confusion[key] < 0 for key in confusion_keys)
                or sum(confusion.get(key, 0) for key in confusion_keys) != source['observation_count']):
            confusion = {}
        counts = Counter(row['category'] for row in dataset)
        coverage = []
        if metadata.get('category_counts') == dict(counts) and all(key in CATEGORY_LABELS for key in counts):
            coverage = [{'id': key, 'label': label, 'count': counts[key], 'percent': counts[key] / len(dataset) * 100}
                        for key, label in CATEGORY_LABELS.items() if key in counts]
        sanitized = None
        downstream_rate = source.get('malicious_downstream_execution_rate')
        measured = [row for row in report.get('results', []) if row.get('mode') == 'full_protected_pipeline'
                    and row.get('expected_label') == 'malicious' and row.get('execution_measured') is True]
        downstream = [row for row in measured if row.get('malicious_downstream_execution') is True]
        if (_number(downstream_rate, maximum=1) and downstream_rate > 0 and downstream and measured
                and source.get('attack_success_rate') == 0
                and all(row.get('attack_success') is False for row in measured)
                and all(row.get('actual_action') == 'sanitize' for row in downstream)
                and math.isclose(len(downstream) / len(measured), downstream_rate)):
            sanitized = {'rate': _rate(downstream_rate), 'observations': len(downstream),
                         'measured': len(measured), 'cases': len({row['case_id'] for row in downstream}),
                         'attack_successes': sum(row['attack_success'] for row in measured)}
        command = (f'python -m evaluation.run --runs {run_count} --seed {seeds[0]} --modes '
                   + ' '.join(mode['id'] for mode in modes) + ' --output-dir reports/evaluation/reproduction')
        comparison = report.get('protected_vs_bypassed') or {}
        return {
            'available': True, 'source': 'reports/evaluation/final/benchmark.json',
            'case_count': metadata['dataset_case_count'], 'run_count': run_count, 'seeds': seeds,
            'modes': modes, 'protected': protected, 'bypassed': metrics.get('bypassed', {}),
            'coverage': coverage, 'latency': latency, 'confusion': confusion,
            'observations': source['observation_count'], 'sanitized': sanitized,
            'dataset_sha256': metadata['dataset_sha256'], 'case_order_sha256': metadata['case_order_sha256'],
            'command': command,
            'rbac_note': comparison.get('rbac_active_in_both_modes') is True
                         and comparison.get('rbac_denials_excluded_from_llmguard_prevention') is True,
        }
    except (OSError, UnicodeError, ValueError, KeyError, TypeError, AttributeError):
        return unavailable
