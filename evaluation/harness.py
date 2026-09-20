from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import platform
from pathlib import Path
import random
from time import perf_counter
from typing import Callable, Iterable, Mapping

from app.config import get_settings
from evaluation.dataset import (
    DEFAULT_DATASET_PATH,
    category_counts,
    load_evaluation_cases,
)
from evaluation.metrics import compute_metrics
from evaluation.modes import ModeRunner, build_mode_runners
from evaluation.reporting import write_reports
from evaluation.types import CaseResult, EvaluationCase


DEFAULT_OUTPUT_DIR = Path("reports") / "evaluation" / "phase14a"
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


def evaluate_cases(
    cases: Iterable[EvaluationCase],
    runners: Mapping[str, ModeRunner],
    *,
    selected_modes: Iterable[str] | None = None,
    clock: Callable[[], float] = perf_counter,
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
                )
            )
    return results


def run_benchmark(
    *,
    dataset_path: Path = DEFAULT_DATASET_PATH,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    modes: Iterable[str] | None = None,
    seed: int = 42,
    mode_runners: Mapping[str, ModeRunner] | None = None,
    generated_at: datetime | None = None,
    clock: Callable[[], float] = perf_counter,
) -> dict[str, object]:
    random.seed(seed)
    cases = load_evaluation_cases(dataset_path)
    runners = dict(mode_runners or build_mode_runners())
    selected_modes = tuple(modes) if modes is not None else tuple(
        mode for mode in MODE_ORDER if mode in runners
    )
    results = evaluate_cases(
        cases,
        runners,
        selected_modes=selected_modes,
        clock=clock,
    )
    metrics = {
        mode: compute_metrics([result for result in results if result.mode == mode])
        for mode in selected_modes
    }
    timestamp = generated_at or datetime.now(timezone.utc)
    payload: dict[str, object] = {
        "schema_version": "phase14a-v1",
        "metadata": _metadata(
            dataset_path=dataset_path,
            cases=cases,
            seed=seed,
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
        "protected_vs_bypassed": _comparison(metrics),
        "results": [asdict(result) for result in results],
        "output_files": {
            "json": str(output_dir / "benchmark.json"),
            "csv": str(output_dir / "cases.csv"),
        },
    }
    write_reports(output_dir, payload)
    return payload


def _metadata(
    *,
    dataset_path: Path,
    cases: list[EvaluationCase],
    seed: int,
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
        "attack_success_rate",
        "malicious_downstream_execution_rate",
        "clean_pass_rate",
        "mean_latency_ms",
        "median_latency_ms",
    )
    return {
        "full_protected_pipeline": {field: protected[field] for field in fields},
        "bypassed": {field: bypassed[field] for field in fields},
        "protected_minus_bypassed": {
            field: float(protected[field]) - float(bypassed[field])
            for field in fields
        },
        "rbac_active_in_both_modes": True,
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
