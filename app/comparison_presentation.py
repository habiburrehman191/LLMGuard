"""Comparison-only projection of verified final evidence; never runs evaluation."""
import json
import math
from pathlib import Path

from app.benchmark_presentation import FINAL_REPORT, load_benchmark_presentation

DETECTOR_LABELS = {'rules_only': 'Rules', 'semantic_only': 'Semantic', 'ml_only': 'ML', 'hybrid': 'Hybrid'}
SYSTEM_LABELS = {'full_protected_pipeline': 'Protected Pipeline', 'bypassed': 'Bypassed'}
DETECTOR_METRICS = {
    'accuracy': 'Accuracy', 'precision': 'Precision', 'recall': 'Recall', 'f1': 'F1',
    'false_positive_rate': 'FPR', 'false_negative_rate': 'FNR', 'attack_success_rate': 'ASR',
}
SYSTEM_METRICS = {
    'accuracy': 'Accuracy', 'attack_success_rate': 'ASR', 'false_negative_rate': 'FNR',
    'clean_pass_rate': 'Clean Pass Rate', 'malicious_downstream_execution_rate': 'Malicious downstream rate',
}
EXECUTION_METRICS = {'attack_success_rate', 'malicious_downstream_execution_rate'}


def _valid_number(value, maximum=None):
    return (type(value) in (int, float) and math.isfinite(value) and value >= 0
            and (maximum is None or value <= maximum))


def load_comparison_presentation(dataset_path: Path, *, report_path: Path = FINAL_REPORT) -> dict:
    """Keep Benchmark's provenance checks and its completed presentation unchanged.

    Only allowlisted aggregate fields leave this adapter. Execution-rate zero
    sentinels become N/A when execution was not measured, matching reporting.py.
    Missing/invalid individual metrics remain N/A, never an invented zero.
    """
    unavailable = {'available': False, 'reason': 'No verified final comparison report is available.'}
    try:
        raw = report_path.read_bytes()
        verified = load_benchmark_presentation(dataset_path, report_path=report_path)
        if not verified['available']:
            return {'available': False, 'reason': verified['reason']}
        if raw != report_path.read_bytes():
            return unavailable
        report = json.loads(raw)
        valid_modes = {m['id'] for m in verified['modes']}

        def project(mode, label, keys):
            source = report['metrics'][mode]
            measured = source.get('execution_measured_malicious_count')
            execution_available = type(measured) is int and measured > 0
            rates = {}
            for key in keys:
                value = source.get(key)
                rates[key] = ({'value': value, 'percent': f'{value * 100:.2f}%'}
                              if _valid_number(value, 1) and
                              (key not in EXECUTION_METRICS or execution_available) else None)
            latency = {key: f'{source[key]:.3f}' for key in ('mean_latency_ms', 'median_latency_ms')
                       if _valid_number(source.get(key))}
            return {'id': mode, 'label': label, 'rates': rates, 'latency': latency}

        detectors = [project(mode, label, DETECTOR_METRICS) for mode, label in DETECTOR_LABELS.items()
                     if mode in valid_modes]
        systems = [project(mode, label, SYSTEM_METRICS) for mode, label in SYSTEM_LABELS.items()
                   if mode in valid_modes]
        if not detectors:
            return unavailable
        return {'available': True, 'source': verified['source'],
                'case_count': verified['case_count'], 'run_count': verified['run_count'],
                'seeds': verified['seeds'], 'detectors': detectors, 'systems': systems,
                'detector_metrics': DETECTOR_METRICS, 'system_metrics': SYSTEM_METRICS,
                'latencies': [m for m in detectors + systems if m['latency']],
                'sanitized': verified['sanitized'], 'rbac_note': verified['rbac_note']}
    except (OSError, UnicodeError, ValueError, KeyError, TypeError, AttributeError):
        return unavailable
