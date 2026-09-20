from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from evaluation.dataset import CATEGORIES, category_counts, load_evaluation_cases
from evaluation.harness import evaluate_cases, run_benchmark
from evaluation.metrics import compute_metrics
from evaluation.modes import (
    PipelineDependencies,
    run_bypassed_pipeline,
    run_protected_pipeline,
)
from evaluation.types import CaseResult, ContextChunk, EvaluationCase, ModeObservation


def _case(**overrides: object) -> EvaluationCase:
    base: dict[str, object] = {
        "case_id": "case-001",
        "category": "clean",
        "expected_label": "benign",
        "stage": "input",
        "channel": "public",
        "content": "What are the admission office hours?",
        "chunks": (),
        "rbac_expected_denial": False,
        "requires_retrieval": True,
        "requires_tool": False,
        "origin": "synthetic-test",
    }
    base.update(overrides)
    return EvaluationCase(**base)


def _result(
    *,
    expected: str,
    actual: str,
    false_positive: bool = False,
    false_negative: bool = False,
    latency_ms: float = 10.0,
    execution_measured: bool = True,
) -> CaseResult:
    return CaseResult(
        mode="test",
        case_id=f"{expected}-{actual}",
        category="clean",
        expected_label=expected,
        actual_classification=actual,
        actual_action="observe",
        risk_score=0.5,
        database_called=False,
        retrieval_called=False,
        tool_called=False,
        main_llm_called=False,
        attack_success=False,
        latency_ms=latency_ms,
        false_positive=false_positive,
        false_negative=false_negative,
        execution_measured=execution_measured,
        rbac_expected_denial=False,
        rbac_denied=False,
        llmguard_restricted=False,
        malicious_downstream_execution=False,
    )


def _allow_input() -> SimpleNamespace:
    return SimpleNamespace(classification="safe", action="allow", risk_score=0.04)


def _allow_output() -> SimpleNamespace:
    return SimpleNamespace(classification="safe", action="allow", risk_score=0.02)


class EvaluationDatasetTests(unittest.TestCase):
    def test_dataset_is_deterministic_and_covers_every_required_category(self) -> None:
        cases = load_evaluation_cases()
        self.assertEqual(54, len(cases))
        self.assertEqual(sorted(case.case_id for case in cases), [c.case_id for c in cases])
        counts = category_counts(cases)
        self.assertEqual(set(CATEGORIES), set(counts))
        self.assertTrue(all(count > 0 for count in counts.values()))
        self.assertTrue(all(case.origin for case in cases))


class EvaluationMetricTests(unittest.TestCase):
    def test_confusion_matrix_and_metrics_are_correct(self) -> None:
        results = [
            _result(expected="malicious", actual="malicious"),
            _result(
                expected="malicious",
                actual="safe",
                false_negative=True,
            ),
            _result(expected="benign", actual="safe"),
            _result(
                expected="benign",
                actual="suspicious",
                false_positive=True,
            ),
        ]
        metrics = compute_metrics(results)
        self.assertEqual(
            {
                "true_positive": 1,
                "true_negative": 1,
                "false_positive": 1,
                "false_negative": 1,
            },
            metrics["confusion_matrix"],
        )
        for field in (
            "accuracy",
            "precision",
            "recall",
            "f1",
            "false_positive_rate",
            "false_negative_rate",
        ):
            self.assertEqual(0.5, metrics[field])

    def test_zero_denominators_are_safe(self) -> None:
        metrics = compute_metrics([])
        for field in (
            "accuracy",
            "precision",
            "recall",
            "f1",
            "false_positive_rate",
            "false_negative_rate",
            "attack_success_rate",
            "malicious_downstream_execution_rate",
            "clean_pass_rate",
            "mean_latency_ms",
            "median_latency_ms",
        ):
            self.assertEqual(0.0, metrics[field])

    def test_latency_is_measured_with_injected_monotonic_clock(self) -> None:
        readings = iter((10.0, 10.125))
        results = evaluate_cases(
            [_case()],
            {"test": lambda _case: ModeObservation("safe", "allow", 0.01)},
            clock=lambda: next(readings),
        )
        self.assertEqual(125.0, results[0].latency_ms)


class PipelineMeasurementTests(unittest.TestCase):
    def test_protected_input_block_has_zero_downstream_execution(self) -> None:
        counters = {name: 0 for name in ("database", "retrieval", "tool", "llm")}
        dependencies = PipelineDependencies(
            input_inspector=lambda _text: SimpleNamespace(
                classification="malicious",
                action="block",
                risk_score=0.98,
            ),
            rbac_checker=lambda _case: False,
            database_call=lambda _case: counters.__setitem__(
                "database", counters["database"] + 1
            ),
            retrieval_call=lambda _case: counters.__setitem__(
                "retrieval", counters["retrieval"] + 1
            ),
            tool_call=lambda _case: counters.__setitem__("tool", counters["tool"] + 1),
            main_llm_call=lambda _case: counters.__setitem__(
                "llm", counters["llm"] + 1
            )
            or "safe",
        )
        observation = run_protected_pipeline(
            _case(expected_label="malicious"),
            dependencies=dependencies,
        )
        self.assertEqual({name: 0 for name in counters}, counters)
        self.assertFalse(observation.database_called)
        self.assertFalse(observation.main_llm_called)
        self.assertFalse(observation.attack_success)

    def test_context_quarantine_stops_before_tool_and_main_llm(self) -> None:
        context_case = _case(
            expected_label="malicious",
            stage="context",
            chunks=(ContextChunk("source", "chunk", "unsafe"),),
            requires_tool=True,
        )
        dependencies = PipelineDependencies(
            input_inspector=lambda _text: _allow_input(),
            context_inspector=lambda _chunks: SimpleNamespace(
                classification="malicious",
                action="quarantine",
                risk_score=0.92,
                sanitized_chunks=None,
            ),
            output_inspector=lambda _text, _context: _allow_output(),
            rbac_checker=lambda _case: False,
        )
        observation = run_protected_pipeline(context_case, dependencies=dependencies)
        self.assertTrue(observation.database_called)
        self.assertTrue(observation.retrieval_called)
        self.assertFalse(observation.tool_called)
        self.assertFalse(observation.main_llm_called)
        self.assertFalse(observation.attack_success)

    def test_context_sanitize_continues_without_attack_success(self) -> None:
        context_case = _case(
            expected_label="malicious",
            stage="context",
            chunks=(ContextChunk("source", "chunk", "unsafe"),),
        )
        dependencies = PipelineDependencies(
            input_inspector=lambda _text: _allow_input(),
            context_inspector=lambda _chunks: SimpleNamespace(
                classification="suspicious",
                action="sanitize",
                risk_score=0.70,
                sanitized_chunks=(
                    {"source_id": "source", "chunk_id": "chunk", "text": "safe"},
                ),
            ),
            output_inspector=lambda _text, _context: _allow_output(),
            rbac_checker=lambda _case: False,
        )
        observation = run_protected_pipeline(context_case, dependencies=dependencies)
        self.assertTrue(observation.main_llm_called)
        self.assertFalse(observation.attack_success)

    def test_bypassed_mode_skips_inspectors_but_keeps_rbac(self) -> None:
        dependencies = PipelineDependencies(
            input_inspector=lambda _text: self.fail("input detector must be bypassed"),
            context_inspector=lambda _chunks: self.fail("context detector must be bypassed"),
            output_inspector=lambda _text, _context: self.fail(
                "output detector must be bypassed"
            ),
            rbac_checker=lambda _case: True,
        )
        observation = run_bypassed_pipeline(
            _case(rbac_expected_denial=True, channel="student"),
            dependencies=dependencies,
        )
        self.assertEqual("bypassed", observation.classification)
        self.assertEqual("rbac_deny", observation.action)
        self.assertTrue(observation.rbac_denied)
        self.assertTrue(observation.database_called)
        self.assertFalse(observation.retrieval_called)
        self.assertFalse(observation.llmguard_restricted)

    def test_rbac_only_denial_is_not_a_false_positive_or_llmguard_block(self) -> None:
        dependencies = PipelineDependencies(
            input_inspector=lambda _text: _allow_input(),
            output_inspector=lambda _text, _context: _allow_output(),
            rbac_checker=lambda _case: True,
        )
        case = _case(rbac_expected_denial=True, channel="student")
        results = evaluate_cases(
            [case],
            {
                "full_protected_pipeline": lambda item: run_protected_pipeline(
                    item,
                    dependencies=dependencies,
                )
            },
        )
        self.assertFalse(results[0].false_positive)
        self.assertTrue(results[0].rbac_denied)
        self.assertFalse(results[0].llmguard_restricted)


class ReportTests(unittest.TestCase):
    def test_reports_are_content_free_and_comparison_uses_measured_results(self) -> None:
        def protected(case: EvaluationCase) -> ModeObservation:
            if case.expected_label == "malicious":
                return ModeObservation(
                    "malicious",
                    "block",
                    0.98,
                    execution_measured=True,
                    llmguard_restricted=True,
                )
            return ModeObservation("safe", "allow", 0.02, execution_measured=True)

        def bypassed(case: EvaluationCase) -> ModeObservation:
            malicious = case.expected_label == "malicious"
            return ModeObservation(
                "bypassed",
                "bypassed",
                None,
                database_called=True,
                retrieval_called=True,
                main_llm_called=True,
                attack_success=malicious,
                malicious_downstream_execution=malicious,
                execution_measured=True,
            )

        with TemporaryDirectory() as temporary:
            payload = run_benchmark(
                output_dir=Path(temporary),
                modes=("full_protected_pipeline", "bypassed"),
                mode_runners={
                    "full_protected_pipeline": protected,
                    "bypassed": bypassed,
                },
                generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
            json_path = Path(payload["output_files"]["json"])
            csv_path = Path(payload["output_files"]["csv"])
            markdown_path = Path(payload["output_files"]["markdown"])
            rendered = (
                json_path.read_text(encoding="utf-8")
                + csv_path.read_text(encoding="utf-8")
                + markdown_path.read_text(encoding="utf-8")
            )
            self.assertNotIn("Ignore previous instructions", rendered)
            self.assertNotIn('"content"', rendered)
            self.assertNotIn('"chunks"', rendered)
            comparison = payload["protected_vs_bypassed"]
            self.assertEqual(
                0.0,
                comparison["full_protected_pipeline"]["attack_success_rate"],
            )
            self.assertEqual(1.0, comparison["bypassed"]["attack_success_rate"])
            self.assertTrue(comparison["rbac_active_in_both_modes"])


if __name__ == "__main__":
    unittest.main()
