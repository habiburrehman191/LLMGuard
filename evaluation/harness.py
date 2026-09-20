from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import platform
from pathlib import Path
import random
from statistics import mean, median
from time import perf_counter
from typing import Callable, Iterable, Mapping

from app.config import get_settings
from evaluation.dataset import (
    DEFAULT_DATASET_PATH,
    category_counts,
    load_evaluation_cases,
)
from evaluation.metrics import compute_category_metrics, compute_metrics
from evaluation.modes import ModeRunner, build_mode_runners
from evaluation.reporting import write_reports
from evaluation.types import CaseResult, EvaluationCase


DEFAULT_OUTPUT_DIR = Path("reports") / "evaluation" / "phase14b"
MODE_ORDER = (
    "rules_only",
    "semantic_only",
    "ml_only",
    "hybrid",
    "full_protected_pipeline",
    "bypassed",
)
POSITIVE_CLASSIFICATIONS = {"suspicious", "malicious"}
DETECTOR_ONLY_MODES = {"rules_only", "semantic_only", "ml_only", "hybrid"}
ABLATION_MODES = (
    "rules_only",
    "semantic_only",
    "ml_only",
    "hybrid",
    "full_protected_pipeline",
)


def evaluate_cases(
    cases: Iterable[EvaluationCase],
    runners: Mapping[str, ModeRunner],
    *,
    selected_modes: Iterable[str] | None = None,
    clock: Callable[[], float] = perf_counter,
    run_index: int = 1,
    run_seed: int = 42,
) -> list[CaseResult]:
    ordered_cases = sorted(cases, key=lambda case: case.case_id)
    modes = tuple(selected_modes) if selected_modes is not None else tuple(runners)
    unknown = [mode for mode in modes if mode not in runners]
    if unknown:
        raise ValueError(f"Unknown evaluation mode(s): {', '.join(unknown)}")

    results: list[CaseResult] = []
    for mode in modes:
        runner = runners[mode]
        if ordered_cases and mode in DETECTOR_ONLY_MODES:
            # Exclude one-time local model/artifact loading from per-case inference
            # latency, matching the established evaluator's warm-up convention.
            runner(ordered_cases[0])
        for case in ordered_cases:
            started = clock()
            observation = runner(case)
            latency_ms = max(0.0, (clock() - started) * 1000.0)
            predicted_malicious = (
                observation.classification.lower() in POSITIVE_CLASSIFICATIONS
            )
            false_positive = case.expected_label == "benign" and predicted_malicious
            false_negative = case.expected_label == "malicious" and not predicted_malicious
            results.append(
                CaseResult(
                    mode=mode,
                    case_id=case.case_id,
                    category=case.category,
                    expected_label=case.expected_label,
                    actual_classification=observation.classification,
                    actual_action=observation.action,
                    risk_score=observation.risk_score,
                    database_called=observation.database_called,
                    retrieval_called=observation.retrieval_called,
                    tool_called=observation.tool_called,
                    main_llm_called=observation.main_llm_called,
                    attack_success=observation.attack_success,
                    latency_ms=round(latency_ms, 6),
                    false_positive=false_positive,
                    false_negative=false_negative,
                    execution_measured=observation.execution_measured,
                    rbac_expected_denial=case.rbac_expected_denial,
                    rbac_denied=observation.rbac_denied,
                    llmguard_restricted=observation.llmguard_restricted,
                    malicious_downstream_execution=(
                        observation.malicious_downstream_execution
                    ),
                    run_index=run_index,
                    run_seed=run_seed,
                )
            )
    return results


def run_benchmark(
    *,
    dataset_path: Path = DEFAULT_DATASET_PATH,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    modes: Iterable[str] | None = None,
    seed: int = 42,
    run_count: int = 1,
    mode_runners: Mapping[str, ModeRunner] | None = None,
    generated_at: datetime | None = None,
    clock: Callable[[], float] = perf_counter,
) -> dict[str, object]:
    if run_count < 1 or run_count > 100:
        raise ValueError("run_count must be between 1 and 100")
    cases = load_evaluation_cases(dataset_path)
    runners = dict(mode_runners or build_mode_runners())
    selected_modes = tuple(modes) if modes is not None else tuple(
        mode for mode in MODE_ORDER if mode in runners
    )
    results: list[CaseResult] = []
    per_run: list[dict[str, object]] = []
    case_order_sha256 = hashlib.sha256(
        "\n".join(case.case_id for case in cases).encode("utf-8")
    ).hexdigest()
    for offset in range(run_count):
        run_index = offset + 1
        run_seed = seed + offset
        _set_deterministic_seed(run_seed)
        run_results = evaluate_cases(
            cases,
            runners,
            selected_modes=selected_modes,
            clock=clock,
            run_index=run_index,
            run_seed=run_seed,
        )
        results.extend(run_results)
        run_metrics = _metrics_by_mode(run_results, selected_modes)
        per_run.append(
            {
                "run_index": run_index,
                "seed": run_seed,
                "case_order_sha256": case_order_sha256,
                "observation_count": len(run_results),
                "metrics": run_metrics,
                "per_category_metrics": _category_metrics_by_mode(
                    run_results,
                    selected_modes,
                ),
            }
        )
    metrics = _metrics_by_mode(results, selected_modes)
    per_category_metrics = _category_metrics_by_mode(results, selected_modes)
    timestamp = generated_at or datetime.now(timezone.utc)
    payload: dict[str, object] = {
        "schema_version": "phase14b-v1",
        "metadata": _metadata(
            dataset_path=dataset_path,
            cases=cases,
            seed=seed,
            run_count=run_count,
            run_seeds=[seed + offset for offset in range(run_count)],
            case_order_sha256=case_order_sha256,
            generated_at=timestamp,
        ),
        "methodology": {
            "data": "synthetic test cases only; no production or personal records",
            "positive_labels": sorted(POSITIVE_CLASSIFICATIONS),
            "detector_only_execution": (
                "not measured; all downstream counters remain false"
            ),
            "latency": (
                "detector-only modes receive one untimed warm-up call; protected "
                "and bypassed latency measures deterministic request-boundary replay"
            ),
            "full_pipeline_execution": (
                "real firewall and University RBAC decisions with deterministic "
                "instrumented DB/retrieval/tool/LLM call boundaries"
            ),
            "attack_success": (
                "malicious instructions reached a tool or main-LLM boundary "
                "without a sanitizing security decision; no real exploit is executed"
            ),
            "malicious_downstream_execution": (
                "input attacks count any post-input DB/tool/LLM execution; context "
                "attacks count only tool/main-LLM execution after context inspection"
            ),
            "rbac": (
                "University RBAC remains active in protected and bypassed modes; "
                "RBAC denials are not counted as LLMGuard restrictions"
            ),
        },
        "metrics": metrics,
        "per_category_metrics": per_category_metrics,
        "ablation": _ablation(metrics),
        "protected_vs_bypassed": _comparison(metrics),
        "repeated_runs": {
            "runs": per_run,
            "latency_aggregate": _repeated_latency_summary(
                results,
                selected_modes,
                per_run,
            ),
        },
        "known_failures": _known_failures(results),
        "known_limitations": _known_limitations(),
        "results": [asdict(result) for result in results],
        "output_files": {
            "json": str(output_dir / "benchmark.json"),
            "csv": str(output_dir / "cases.csv"),
            "markdown": str(output_dir / "summary.md"),
        },
    }
    write_reports(output_dir, payload)
    return payload


def _set_deterministic_seed(seed: int) -> None:
    random.seed(seed)
    try:
        import numpy as np

        np.random.seed(seed)
    except ImportError:
        pass


def _metrics_by_mode(
    results: list[CaseResult],
    modes: Iterable[str],
) -> dict[str, dict[str, object]]:
    return {
        mode: compute_metrics([result for result in results if result.mode == mode])
        for mode in modes
    }


def _category_metrics_by_mode(
    results: list[CaseResult],
    modes: Iterable[str],
) -> dict[str, dict[str, dict[str, object]]]:
    return {
        mode: compute_category_metrics(
            [result for result in results if result.mode == mode]
        )
        for mode in modes
    }


def _ablation(
    metrics: Mapping[str, dict[str, object]],
) -> list[dict[str, object]]:
    fields = (
        "case_count",
        "observation_count",
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
        "execution_measured_malicious_count",
    )
    return [
        {"mode": mode, **{field: metrics[mode][field] for field in fields}}
        for mode in ABLATION_MODES
        if mode in metrics
    ]


def _repeated_latency_summary(
    results: list[CaseResult],
    modes: Iterable[str],
    per_run: list[dict[str, object]],
) -> dict[str, dict[str, dict[str, float]]]:
    summary: dict[str, dict[str, dict[str, float]]] = {}
    for mode in modes:
        observations = [
            result.latency_ms for result in results if result.mode == mode
        ]
        run_means = [
            float(run["metrics"][mode]["mean_latency_ms"])
            for run in per_run
        ]
        summary[mode] = {
            "observation_latency_ms": _numeric_summary(observations),
            "run_mean_latency_ms": _numeric_summary(run_means),
        }
    return summary


def _numeric_summary(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "median": 0.0, "min": 0.0, "max": 0.0}
    return {
        "mean": float(mean(values)),
        "median": float(median(values)),
        "min": float(min(values)),
        "max": float(max(values)),
    }


def _known_failures(results: list[CaseResult]) -> dict[str, list[dict[str, object]]]:
    return {
        "false_positives": _failure_rows(results, failure_type="false_positive"),
        "false_negatives": _failure_rows(results, failure_type="false_negative"),
    }


def _failure_rows(
    results: list[CaseResult],
    *,
    failure_type: str,
) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str, str, str, str], dict[str, object]] = {}
    for result in results:
        failed = (
            result.false_positive
            if failure_type == "false_positive"
            else result.false_negative
        )
        if not failed:
            continue
        key = (
            result.mode,
            result.case_id,
            result.category,
            result.actual_classification,
            result.actual_action,
        )
        row = grouped.setdefault(
            key,
            {
                "mode": result.mode,
                "case_id": result.case_id,
                "category": result.category,
                "actual_classification": result.actual_classification,
                "actual_action": result.actual_action,
                "occurrences": 0,
                "run_indices": [],
            },
        )
        row["occurrences"] = int(row["occurrences"]) + 1
        row["run_indices"].append(result.run_index)
    return [grouped[key] for key in sorted(grouped)]


def _known_limitations() -> list[str]:
    return [
        "The benchmark uses synthetic cases and does not represent production traffic.",
        "Downstream execution is measured with deterministic instrumented boundaries, not live University database mutations or live Qwen generation.",
        "Detector-only modes do not measure downstream execution or attack success.",
        "Current context inspection evaluates chunks independently and can miss instructions split across chunk boundaries.",
        "Latency is local-machine timing and is not a production throughput or scalability claim.",
        "Privilege and cross-user cases are benign for LLMGuard detector scoring and are evaluated separately as University RBAC denials.",
    ]


def _metadata(
    *,
    dataset_path: Path,
    cases: list[EvaluationCase],
    seed: int,
    run_count: int,
    run_seeds: list[int],
    case_order_sha256: str,
    generated_at: datetime,
) -> dict[str, object]:
    settings = get_settings()
    thresholds = {
        "semantic_threshold": settings.semantic_threshold,
        "ml_classifier_min_confidence": settings.ml_classifier_min_confidence,
        "suspicious_risk_threshold": settings.suspicious_risk_threshold,
        "malicious_risk_threshold": settings.malicious_risk_threshold,
        "quarantine_risk_threshold": settings.quarantine_risk_threshold,
        "block_risk_threshold": settings.block_risk_threshold,
    }
    threshold_bytes = json.dumps(thresholds, sort_keys=True).encode("utf-8")
    return {
        "generated_at": generated_at.astimezone(timezone.utc).isoformat(),
        "seed": seed,
        "run_count": run_count,
        "run_seeds": run_seeds,
        "case_order_sha256": case_order_sha256,
        "python_version": platform.python_version(),
        "platform": platform.system(),
        "dataset_name": dataset_path.name,
        "dataset_sha256": _sha256(dataset_path),
        "dataset_case_count": len(cases),
        "category_counts": category_counts(cases),
        "synthetic_data": True,
        "configuration": thresholds,
        "configuration_sha256": hashlib.sha256(threshold_bytes).hexdigest(),
        "classifier_artifact_sha256": (
            _sha256(settings.ml_model_path)
            if settings.ml_model_path.is_file()
            else None
        ),
        "detector_source_sha256": _detector_source_hashes(settings.base_dir),
    }


def _comparison(metrics: Mapping[str, dict[str, object]]) -> dict[str, object] | None:
    protected = metrics.get("full_protected_pipeline")
    bypassed = metrics.get("bypassed")
    if protected is None or bypassed is None:
        return None
    fields = (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "attack_success_rate",
        "malicious_downstream_execution_rate",
        "clean_pass_rate",
        "mean_latency_ms",
        "median_latency_ms",
        "rbac_denial_count",
        "rbac_only_denial_count",
        "rbac_only_denial_case_count",
        "llmguard_restriction_count",
        "llmguard_restriction_case_count",
    )
    return {
        "full_protected_pipeline": {field: protected[field] for field in fields},
        "bypassed": {field: bypassed[field] for field in fields},
        "protected_minus_bypassed": {
            field: float(protected[field]) - float(bypassed[field])
            for field in fields
        },
        "rbac_active_in_both_modes": True,
        "rbac_denials_excluded_from_llmguard_prevention": True,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _detector_source_hashes(base_dir: Path) -> dict[str, str]:
    relative_paths = {
        "rules": Path("app/firewall.py"),
        "semantic": Path("app/semantic_firewall.py"),
        "ml": Path("app/ml_firewall.py"),
        "hybrid": Path("app/hybrid_firewall.py"),
        "input_guard": Path("app/input_guard.py"),
        "context_guard": Path("app/context_guard.py"),
        "output_guard": Path("app/output_guard.py"),
    }
    return {
        name: _sha256(base_dir / relative_path)
        for name, relative_path in relative_paths.items()
    }
