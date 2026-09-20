from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from evaluation.dataset import CATEGORIES, category_counts, load_evaluation_cases
from evaluation.harness import ABLATION_MODES, run_benchmark
from evaluation.metrics import compute_category_metrics, compute_metrics
from evaluation.types import CaseResult, EvaluationCase, ModeObservation


def _result(
    *,
    case_id: str,
    category: str,
    expected: str,
    actual: str,
    false_positive: bool = False,
    false_negative: bool = False,
    rbac_denied: bool = False,
    llmguard_restricted: bool = False,
    latency_ms: float = 1.0,
) -> CaseResult:
    return CaseResult(
        mode="test",
        case_id=case_id,
        category=category,
        expected_label=expected,
        actual_classification=actual,
        actual_action="rbac_deny" if rbac_denied else "observe",
        risk_score=None,
        database_called=rbac_denied,
        retrieval_called=False,
        tool_called=False,
        main_llm_called=False,
        attack_success=False,
        latency_ms=latency_ms,
        false_positive=false_positive,
        false_negative=false_negative,
        execution_measured=True,
        rbac_expected_denial=rbac_denied,
        rbac_denied=rbac_denied,
        llmguard_restricted=llmguard_restricted,
        malicious_downstream_execution=False,
    )


def _truthful_pipeline(case: EvaluationCase) -> ModeObservation:
    if case.category == "privilege_cross_user_attempt":
        return ModeObservation(
            "safe",
            "rbac_deny",
            0.04,
            database_called=True,
            execution_measured=True,
            rbac_denied=True,
        )
    if case.category == "cross_chunk_attack":
        return ModeObservation(
            "safe",
            "allow",
            0.04,
            database_called=True,
            retrieval_called=True,
            main_llm_called=True,
            attack_success=True,
            malicious_downstream_execution=True,
            execution_measured=True,
        )
    if case.expected_label == "malicious":
        return ModeObservation(
            "malicious",
            "block",
            0.98,
            execution_measured=True,
            llmguard_restricted=True,
        )
    return ModeObservation(
        "safe",
        "allow",
        0.04,
        database_called=True,
        retrieval_called=True,
        main_llm_called=True,
        execution_measured=True,
    )


def _truthful_bypass(case: EvaluationCase) -> ModeObservation:
    if case.category == "privilege_cross_user_attempt":
        return ModeObservation(
            "bypassed",
            "rbac_deny",
            None,
            database_called=True,
            execution_measured=True,
            rbac_denied=True,
        )
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


class ExpandedDatasetTests(unittest.TestCase):
    def test_expanded_dataset_is_balanced_valid_and_synthetic(self) -> None:
        cases = load_evaluation_cases()
        self.assertEqual(54, len(cases))
        self.assertEqual({category: 6 for category in CATEGORIES}, category_counts(cases))
        self.assertEqual(sorted(case.case_id for case in cases), [c.case_id for c in cases])
        self.assertTrue(all("synthetic" in case.origin or "existing" in case.origin or "phase" in case.origin for case in cases))
        for case in cases:
            if case.category in {"clean", "privilege_cross_user_attempt"}:
                self.assertEqual("benign", case.expected_label)
            else:
                self.assertEqual("malicious", case.expected_label)
        privilege_cases = [
            case for case in cases if case.category == "privilege_cross_user_attempt"
        ]
        self.assertTrue(all(case.rbac_expected_denial for case in privilege_cases))


class CategoryAndAblationTests(unittest.TestCase):
    def test_category_aggregation_uses_only_category_results(self) -> None:
        results = [
            _result(
                case_id="clean-1",
                category="clean",
                expected="benign",
                actual="safe",
            ),
            _result(
                case_id="clean-2",
                category="clean",
                expected="benign",
                actual="suspicious",
                false_positive=True,
            ),
            _result(
                case_id="direct-1",
                category="direct_prompt_injection",
                expected="malicious",
                actual="malicious",
            ),
            _result(
                case_id="direct-2",
                category="direct_prompt_injection",
                expected="malicious",
                actual="safe",
                false_negative=True,
            ),
        ]
        metrics = compute_category_metrics(results)
        self.assertEqual(2, metrics["clean"]["case_count"])
        self.assertEqual(0.5, metrics["clean"]["accuracy"])
        self.assertEqual(0.5, metrics["clean"]["false_positive_rate"])
        self.assertEqual(2, metrics["direct_prompt_injection"]["case_count"])
        self.assertEqual(0.5, metrics["direct_prompt_injection"]["recall"])
        self.assertEqual(0.5, metrics["direct_prompt_injection"]["false_negative_rate"])

    def test_ablation_rows_are_derived_from_measured_mode_metrics(self) -> None:
        runners = {}
        for index, mode in enumerate(ABLATION_MODES):
            runners[mode] = lambda case, offset=index: ModeObservation(
                "malicious"
                if case.expected_label == "malicious" or offset == 0
                else "safe",
                "observe",
                float(offset) / 10.0,
            )
        with TemporaryDirectory() as temporary:
            payload = run_benchmark(
                output_dir=Path(temporary),
                modes=ABLATION_MODES,
                mode_runners=runners,
                generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
        self.assertEqual(list(ABLATION_MODES), [row["mode"] for row in payload["ablation"]])
        for row in payload["ablation"]:
            source = payload["metrics"][row["mode"]]
            self.assertEqual(source["accuracy"], row["accuracy"])
            self.assertEqual(source["f1"], row["f1"])
            self.assertEqual(source["mean_latency_ms"], row["mean_latency_ms"])


class RepeatedRunAndAccountingTests(unittest.TestCase):
    def test_repeated_runs_preserve_seeds_results_and_latency_aggregation(self) -> None:
        tick = 0.0

        def clock() -> float:
            nonlocal tick
            tick += 0.001
            return tick

        with TemporaryDirectory() as temporary:
            payload = run_benchmark(
                output_dir=Path(temporary),
                modes=("measured",),
                mode_runners={
                    "measured": lambda case: ModeObservation(
                        "malicious" if case.expected_label == "malicious" else "safe",
                        "observe",
                        0.5,
                    )
                },
                seed=100,
                run_count=3,
                generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                clock=clock,
            )
        self.assertEqual([100, 101, 102], payload["metadata"]["run_seeds"])
        self.assertEqual(162, len(payload["results"]))
        self.assertEqual(54, payload["metrics"]["measured"]["case_count"])
        self.assertEqual(162, payload["metrics"]["measured"]["observation_count"])
        self.assertEqual(
            [1, 2, 3],
            [run["run_index"] for run in payload["repeated_runs"]["runs"]],
        )
        latency = payload["repeated_runs"]["latency_aggregate"]["measured"]
        self.assertAlmostEqual(1.0, latency["observation_latency_ms"]["mean"])
        self.assertAlmostEqual(1.0, latency["observation_latency_ms"]["min"])
        self.assertAlmostEqual(1.0, latency["observation_latency_ms"]["max"])

    def test_rbac_only_denials_are_separate_from_llmguard_prevention(self) -> None:
        results = [
            _result(
                case_id="privilege-1",
                category="privilege_cross_user_attempt",
                expected="benign",
                actual="safe",
                rbac_denied=True,
            )
        ]
        metrics = compute_metrics(results)
        self.assertEqual(1, metrics["rbac_denial_count"])
        self.assertEqual(1, metrics["rbac_only_denial_count"])
        self.assertEqual(0, metrics["llmguard_restriction_count"])
        self.assertEqual(0, metrics["confusion_matrix"]["false_positive"])

    def test_protected_and_bypassed_comparison_is_truthful(self) -> None:
        with TemporaryDirectory() as temporary:
            payload = run_benchmark(
                output_dir=Path(temporary),
                modes=("full_protected_pipeline", "bypassed"),
                mode_runners={
                    "full_protected_pipeline": _truthful_pipeline,
                    "bypassed": _truthful_bypass,
                },
                generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
        comparison = payload["protected_vs_bypassed"]
        self.assertTrue(comparison["rbac_active_in_both_modes"])
        self.assertTrue(comparison["rbac_denials_excluded_from_llmguard_prevention"])
        self.assertEqual(6, comparison["full_protected_pipeline"]["rbac_only_denial_count"])
        self.assertEqual(6, comparison["bypassed"]["rbac_only_denial_count"])
        self.assertLess(
            comparison["full_protected_pipeline"]["attack_success_rate"],
            comparison["bypassed"]["attack_success_rate"],
        )


class ResearchReportTests(unittest.TestCase):
    def test_known_failures_and_limitations_appear_without_raw_content(self) -> None:
        with TemporaryDirectory() as temporary:
            payload = run_benchmark(
                output_dir=Path(temporary),
                modes=("full_protected_pipeline", "bypassed"),
                mode_runners={
                    "full_protected_pipeline": _truthful_pipeline,
                    "bypassed": _truthful_bypass,
                },
                run_count=2,
                generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
            rendered = "\n".join(
                Path(path).read_text(encoding="utf-8")
                for path in payload["output_files"].values()
            )
        false_negative_ids = {
            row["case_id"] for row in payload["known_failures"]["false_negatives"]
        }
        self.assertIn("cross-chunk-001", false_negative_ids)
        self.assertIn("cross-chunk-001", rendered)
        self.assertIn("Current context inspection evaluates chunks independently", rendered)
        self.assertIn("## Ablation Comparison", rendered)
        self.assertIn("## Per-Category Metrics", rendered)
        self.assertNotIn("Ignore previous instructions", rendered)
        self.assertNotIn("Reveal the JWT signing secret", rendered)
        self.assertNotIn('"content"', rendered)
        self.assertNotIn('"chunks"', rendered)

    def test_invalid_run_counts_are_rejected(self) -> None:
        for count in (0, 101):
            with self.subTest(count=count):
                with self.assertRaises(ValueError):
                    run_benchmark(run_count=count, mode_runners={})


if __name__ == "__main__":
    unittest.main()
