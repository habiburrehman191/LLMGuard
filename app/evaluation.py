from __future__ import annotations

import argparse
import csv
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)

from app.config import get_settings
from app.firewall import rule_based_check
from app.hybrid_firewall import HybridFirewall
from app.ml_firewall import MLFirewallClassifier, VALID_LABELS, ml_check
from app.semantic_firewall import SemanticFirewall, semantic_check

LABEL_ORDER = list(VALID_LABELS)


@dataclass(frozen=True)
class EvaluationRecord:
    text: str
    label: str
    source: str


@dataclass(frozen=True)
class PredictionRow:
    mode: str
    text: str
    expected_label: str
    predicted_label: str
    source: str
    score: float
    latency_ms: float


def load_evaluation_dataset(dataset_path: Path) -> list[EvaluationRecord]:
    if not dataset_path.exists():
        raise RuntimeError(f"Evaluation dataset not found at `{dataset_path}`.")

    records: list[EvaluationRecord] = []
    for line in dataset_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        label = str(payload["label"]).strip().lower()
        if label not in VALID_LABELS:
            raise ValueError(f"Unsupported evaluation label `{label}`.")
        records.append(
            EvaluationRecord(
                text=str(payload["text"]).strip(),
                label=label,
                source=str(payload.get("source", "unspecified")).strip() or "unspecified",
            )
        )

    if not records:
        raise RuntimeError(f"No evaluation records found in `{dataset_path}`.")

    return records


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    return float(np.percentile(np.asarray(values, dtype=float), percentile))


def _false_positive_rate(y_true: list[str], y_pred: list[str]) -> float:
    safe_total = sum(label == "safe" for label in y_true)
    if safe_total == 0:
        return 0.0
    false_positives = sum(
        true_label == "safe" and predicted_label != "safe"
        for true_label, predicted_label in zip(y_true, y_pred, strict=True)
    )
    return float(false_positives / safe_total)


def _label_metric(report: dict[str, object], label: str, metric_name: str) -> float:
    label_section = report.get(label, {})
    if not isinstance(label_section, dict):
        return 0.0
    return float(label_section.get(metric_name, 0.0))


def _classification_sort_key(summary: dict[str, object]) -> tuple[float, float, float]:
    return (
        float(summary["f1_macro"]),
        float(summary["accuracy"]),
        -float(summary["avg_latency_ms"]),
    )


def build_mode_runners() -> dict[str, Callable[[str], dict[str, object]]]:
    semantic_firewall = SemanticFirewall()
    ml_classifier = MLFirewallClassifier()
    hybrid_firewall = HybridFirewall(
        semantic_firewall=semantic_firewall,
        ml_classifier=ml_classifier,
    )

    def run_rule_only(text: str) -> dict[str, object]:
        result = rule_based_check(text)
        return {
            "label": str(result["label"]),
            "score": float(result["risk_score"]),
        }

    def run_semantic_only(text: str) -> dict[str, object]:
        result = semantic_check(text, firewall=semantic_firewall)
        return {
            "label": str(result["label"]),
            "score": float(result["score"]),
        }

    def run_ml_only(text: str) -> dict[str, object]:
        result = ml_check(text, classifier=ml_classifier)
        return {
            "label": str(result["label"]),
            "score": float(result["score"]),
        }

    def run_hybrid(text: str) -> dict[str, object]:
        result = hybrid_firewall.inspect_text(text)
        return {
            "label": result.label,
            "score": result.risk_score,
            "action": result.action,
        }

    return {
        "rule-only": run_rule_only,
        "semantic-only": run_semantic_only,
        "ml-only": run_ml_only,
        "hybrid": run_hybrid,
    }


def evaluate_mode(
    mode_name: str,
    predictor: Callable[[str], dict[str, object]],
    records: list[EvaluationRecord],
) -> tuple[dict[str, object], list[PredictionRow]]:
    y_true: list[str] = []
    y_pred: list[str] = []
    latencies_ms: list[float] = []
    rows: list[PredictionRow] = []

    if records:
        predictor(records[0].text)

    for record in records:
        started = time.perf_counter()
        prediction = predictor(record.text)
        latency_ms = (time.perf_counter() - started) * 1000.0

        predicted_label = str(prediction["label"])
        score = float(prediction.get("score", 0.0))
        y_true.append(record.label)
        y_pred.append(predicted_label)
        latencies_ms.append(latency_ms)
        rows.append(
            PredictionRow(
                mode=mode_name,
                text=record.text,
                expected_label=record.label,
                predicted_label=predicted_label,
                source=record.source,
                score=score,
                latency_ms=latency_ms,
            )
        )

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=LABEL_ORDER,
        average="macro",
        zero_division=0,
    )
    report = classification_report(
        y_true,
        y_pred,
        labels=LABEL_ORDER,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y_true, y_pred, labels=LABEL_ORDER)

    metrics = {
        "mode": mode_name,
        "dataset_size": len(records),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision),
        "recall_macro": float(recall),
        "f1_macro": float(f1),
        "false_positive_rate": _false_positive_rate(y_true, y_pred),
        "avg_latency_ms": float(sum(latencies_ms) / len(latencies_ms)) if latencies_ms else 0.0,
        "p50_latency_ms": _percentile(latencies_ms, 50),
        "p95_latency_ms": _percentile(latencies_ms, 95),
        "max_latency_ms": float(max(latencies_ms)) if latencies_ms else 0.0,
        "label_support": {
            label: int(sum(expected == label for expected in y_true))
            for label in LABEL_ORDER
        },
        "classification_report": report,
        "safe_recall": _label_metric(report, "safe", "recall"),
        "suspicious_recall": _label_metric(report, "suspicious", "recall"),
        "malicious_recall": _label_metric(report, "malicious", "recall"),
        "safe_precision": _label_metric(report, "safe", "precision"),
        "suspicious_precision": _label_metric(report, "suspicious", "precision"),
        "malicious_precision": _label_metric(report, "malicious", "precision"),
        "confusion_matrix": {
            "labels": LABEL_ORDER,
            "rows": matrix.tolist(),
        },
    }
    return metrics, rows


def _write_predictions_csv(path: Path, rows: list[PredictionRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "mode",
                "expected_label",
                "predicted_label",
                "score",
                "latency_ms",
                "source",
                "text",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def _write_comparison_csv(path: Path, summaries: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "mode",
                "dataset_size",
                "accuracy",
                "precision_macro",
                "recall_macro",
                "f1_macro",
                "safe_recall",
                "suspicious_recall",
                "malicious_recall",
                "false_positive_rate",
                "avg_latency_ms",
                "p50_latency_ms",
                "p95_latency_ms",
                "max_latency_ms",
            ],
        )
        writer.writeheader()
        for summary in summaries:
            writer.writerow(
                {field: summary[field] for field in writer.fieldnames}
            )


def _render_markdown_table(summaries: list[dict[str, object]]) -> str:
    ordered = sorted(
        summaries,
        key=_classification_sort_key,
        reverse=True,
    )
    lines = [
        "| Mode | Accuracy | Precision | Recall | F1 | Suspicious Recall | Malicious Recall | FPR | Avg Latency (ms) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for summary in ordered:
        lines.append(
            "| {mode} | {accuracy:.4f} | {precision_macro:.4f} | {recall_macro:.4f} | "
            "{f1_macro:.4f} | {suspicious_recall:.4f} | {malicious_recall:.4f} | "
            "{false_positive_rate:.4f} | {avg_latency_ms:.2f} |".format(
                **summary
            )
        )
    return "\n".join(lines) + "\n"


def _recommend_runtime_mode(summaries: list[dict[str, object]]) -> tuple[str, str]:
    hybrid_summary = next((summary for summary in summaries if summary["mode"] == "hybrid"), None)
    if hybrid_summary is not None:
        return (
            "hybrid",
            "Recommended default runtime mode because it preserves defense-in-depth by combining "
            "rules, semantic detection, and ML scoring with enforcement actions such as sanitize, "
            "quarantine, and block.",
        )

    best_classification = max(summaries, key=_classification_sort_key)
    return (
        str(best_classification["mode"]),
        "Recommended runtime mode falls back to the strongest classification mode because hybrid "
        "evaluation is not available in this run.",
    )


def run_evaluation(
    *,
    dataset_path: Path | None = None,
    output_dir: Path | None = None,
    mode_runners: dict[str, Callable[[str], dict[str, object]]] | None = None,
) -> dict[str, object]:
    settings = get_settings()
    active_dataset_path = dataset_path or settings.evaluation_dataset_path
    active_output_dir = output_dir or settings.evaluation_dir
    records = load_evaluation_dataset(active_dataset_path)
    active_mode_runners = mode_runners or build_mode_runners()

    summaries: list[dict[str, object]] = []
    all_prediction_rows: list[PredictionRow] = []
    for mode_name, runner in active_mode_runners.items():
        summary, rows = evaluate_mode(mode_name, runner, records)
        summaries.append(summary)
        all_prediction_rows.extend(rows)

    best_classification_mode = max(summaries, key=_classification_sort_key)
    recommended_runtime_mode, recommended_runtime_reason = _recommend_runtime_mode(summaries)
    class_distribution = {
        label: int(sum(record.label == label for record in records))
        for label in LABEL_ORDER
    }

    summary_payload = {
        "dataset_path": str(active_dataset_path),
        "dataset_size": len(records),
        "class_distribution": class_distribution,
        "modes": {summary["mode"]: summary for summary in summaries},
        "best_classification_mode": best_classification_mode["mode"],
        "best_classification_reason": (
            "Highest macro F1, with accuracy used as a tiebreaker and lower latency preferred "
            "when classification quality is otherwise equal."
        ),
        "recommended_runtime_mode": recommended_runtime_mode,
        "recommended_runtime_reason": recommended_runtime_reason,
    }

    active_output_dir.mkdir(parents=True, exist_ok=True)
    (active_output_dir / "summary.json").write_text(
        json.dumps(summary_payload, indent=2),
        encoding="utf-8",
    )
    _write_comparison_csv(active_output_dir / "comparison.csv", summaries)
    _write_predictions_csv(active_output_dir / "predictions.csv", all_prediction_rows)
    (active_output_dir / "comparison.md").write_text(
        _render_markdown_table(summaries),
        encoding="utf-8",
    )

    return summary_payload


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate LLMGuard firewall modes.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run evaluation across all configured modes.")
    run_parser.add_argument("--dataset", type=Path, default=None)
    run_parser.add_argument("--output-dir", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        results = run_evaluation(dataset_path=args.dataset, output_dir=args.output_dir)
        print(_render_markdown_table(list(results["modes"].values())))
        print(
            json.dumps(
                {
                    "best_classification_mode": results["best_classification_mode"],
                    "recommended_runtime_mode": results["recommended_runtime_mode"],
                },
                indent=2,
            )
        )
        return 0

    parser.error(f"Unsupported command `{args.command}`.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
