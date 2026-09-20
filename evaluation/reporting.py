from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


CASE_FIELDS = (
    "run_index",
    "run_seed",
    "mode",
    "case_id",
    "category",
    "expected_label",
    "actual_classification",
    "actual_action",
    "risk_score",
    "database_called",
    "retrieval_called",
    "tool_called",
    "main_llm_called",
    "attack_success",
    "latency_ms",
    "false_positive",
    "false_negative",
    "execution_measured",
    "rbac_expected_denial",
    "rbac_denied",
    "llmguard_restricted",
    "malicious_downstream_execution",
)


def write_reports(
    output_dir: Path,
    payload: dict[str, Any],
) -> tuple[Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "benchmark.json"
    csv_path = output_dir / "cases.csv"
    markdown_path = output_dir / "summary.md"

    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CASE_FIELDS)
        writer.writeheader()
        for result in payload["results"]:
            writer.writerow({field: result[field] for field in CASE_FIELDS})
    markdown_path.write_text(_render_markdown(payload), encoding="utf-8")
    return json_path, csv_path, markdown_path


def _render_markdown(payload: dict[str, Any]) -> str:
    metadata = payload["metadata"]
    lines = [
        "# LLMGuard Phase 14B Evaluation Summary",
        "",
        "> Synthetic evaluation only. These measurements are not production claims.",
        "",
        "## Dataset",
        "",
        f"- Cases: {metadata['dataset_case_count']}",
        f"- Repeated runs: {metadata['run_count']}",
        f"- Seeds: {', '.join(str(seed) for seed in metadata['run_seeds'])}",
        f"- Dataset SHA-256: `{metadata['dataset_sha256']}`",
        f"- Deterministic case-order SHA-256: `{metadata['case_order_sha256']}`",
        "",
        "| Category | Cases |",
        "| --- | ---: |",
    ]
    lines.extend(
        f"| {category} | {count} |"
        for category, count in metadata["category_counts"].items()
    )
    lines.extend(["", "## Overall Metrics", "", _metric_header()])
    for mode, metrics in payload["metrics"].items():
        lines.append(_metric_row(mode, metrics))

    lines.extend(["", "## Per-Category Metrics", "", _category_header()])
    for mode, categories in payload["per_category_metrics"].items():
        for category, metrics in categories.items():
            lines.append(_category_row(mode, category, metrics))

    lines.extend(["", "## Ablation Comparison", "", _metric_header()])
    for metrics in payload["ablation"]:
        lines.append(_metric_row(str(metrics["mode"]), metrics))

    lines.extend(["", "## Protected vs BYPASSED", ""])
    comparison = payload.get("protected_vs_bypassed")
    if comparison is None:
        lines.append("Comparison unavailable because both modes were not selected.")
    else:
        lines.extend(
            [
                "University RBAC remained active in both modes. RBAC-only denials are excluded from LLMGuard prevention counts.",
                "",
                "| Mode | Attack success | Malicious downstream execution | Clean pass | RBAC-only cases | LLMGuard-restricted cases | Mean latency (ms) |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for mode in ("full_protected_pipeline", "bypassed"):
            values = comparison[mode]
            lines.append(
                f"| {mode} | {_decimal(values['attack_success_rate'])} | "
                f"{_decimal(values['malicious_downstream_execution_rate'])} | "
                f"{_decimal(values['clean_pass_rate'])} | "
                f"{values['rbac_only_denial_case_count']} | "
                f"{values['llmguard_restriction_case_count']} | "
                f"{_latency(values['mean_latency_ms'])} |"
            )

    lines.extend(["", "## RBAC-Only Denials", ""])
    lines.extend(
        [
            "| Mode | Denials |",
            "| --- | ---: |",
            *[
                f"| {mode} | {metrics['rbac_only_denial_case_count']} |"
                for mode, metrics in payload["metrics"].items()
            ],
        ]
    )

    lines.extend(["", "## Known False Positives", ""])
    lines.extend(_failure_lines(payload["known_failures"]["false_positives"]))
    lines.extend(["", "## Known False Negatives", ""])
    lines.extend(_failure_lines(payload["known_failures"]["false_negatives"]))

    lines.extend(["", "## Repeated-Run Latency", ""])
    lines.extend(
        [
            "| Mode | Mean | Median | Min | Max |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for mode, summary in payload["repeated_runs"]["latency_aggregate"].items():
        values = summary["observation_latency_ms"]
        lines.append(
            f"| {mode} | {_latency(values['mean'])} | "
            f"{_latency(values['median'])} | {_latency(values['min'])} | "
            f"{_latency(values['max'])} |"
        )

    lines.extend(["", "## Known Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in payload["known_limitations"])

    lines.extend(
        [
            "",
            "## Reproducibility Metadata",
            "",
            f"- Schema: `{payload['schema_version']}`",
            f"- Generated: `{metadata['generated_at']}`",
            f"- Python: `{metadata['python_version']}`",
            f"- Platform: `{metadata['platform']}`",
            f"- Configuration SHA-256: `{metadata['configuration_sha256']}`",
            f"- Classifier artifact SHA-256: `{metadata['classifier_artifact_sha256']}`",
            "",
            "### Configuration",
            "",
        ]
    )
    lines.extend(
        f"- `{name}`: `{value}`"
        for name, value in metadata["configuration"].items()
    )
    lines.extend(["", "### Detector Source Hashes", ""])
    lines.extend(
        f"- `{name}`: `{value}`"
        for name, value in metadata["detector_source_sha256"].items()
    )
    return "\n".join(lines) + "\n"


def _metric_header() -> str:
    return (
        "| Mode | Cases | Observations | Accuracy | Precision | Recall | F1 | FPR | FNR | "
        "Attack success | Malicious downstream | Clean pass | Mean latency (ms) | "
        "Median latency (ms) |\n"
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | "
        "---: | ---: | ---: | ---: |"
    )


def _metric_row(mode: str, metrics: dict[str, Any]) -> str:
    return (
        f"| {mode} | {metrics['case_count']} | {metrics['observation_count']} | "
        f"{_decimal(metrics['accuracy'])} | "
        f"{_decimal(metrics['precision'])} | {_decimal(metrics['recall'])} | "
        f"{_decimal(metrics['f1'])} | {_decimal(metrics['false_positive_rate'])} | "
        f"{_decimal(metrics['false_negative_rate'])} | "
        f"{_execution_decimal(metrics, 'attack_success_rate')} | "
        f"{_execution_decimal(metrics, 'malicious_downstream_execution_rate')} | "
        f"{_decimal(metrics['clean_pass_rate'])} | "
        f"{_latency(metrics['mean_latency_ms'])} | "
        f"{_latency(metrics['median_latency_ms'])} |"
    )


def _category_header() -> str:
    return (
        "| Mode | Category | Cases | Observations | Accuracy | Precision | Recall | F1 | FPR | "
        "FNR | Attack success | Malicious downstream | Clean pass | Mean latency "
        "(ms) | Median latency (ms) |\n"
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | "
        "---: | ---: | ---: | ---: |"
    )


def _category_row(mode: str, category: str, metrics: dict[str, Any]) -> str:
    return (
        f"| {mode} | {category} | {metrics['case_count']} | "
        f"{metrics['observation_count']} | "
        f"{_decimal(metrics['accuracy'])} | {_decimal(metrics['precision'])} | "
        f"{_decimal(metrics['recall'])} | {_decimal(metrics['f1'])} | "
        f"{_decimal(metrics['false_positive_rate'])} | "
        f"{_decimal(metrics['false_negative_rate'])} | "
        f"{_execution_decimal(metrics, 'attack_success_rate')} | "
        f"{_execution_decimal(metrics, 'malicious_downstream_execution_rate')} | "
        f"{_decimal(metrics['clean_pass_rate'])} | "
        f"{_latency(metrics['mean_latency_ms'])} | "
        f"{_latency(metrics['median_latency_ms'])} |"
    )


def _failure_lines(rows: list[dict[str, Any]]) -> list[str]:
    if not rows:
        return ["No failures observed in the selected modes and runs."]
    lines = [
        "| Mode | Case | Category | Observed classification | Action | Occurrences | Runs |",
        "| --- | --- | --- | --- | --- | ---: | --- |",
    ]
    lines.extend(
        f"| {row['mode']} | {row['case_id']} | {row['category']} | "
        f"{row['actual_classification']} | {row['actual_action']} | "
        f"{row['occurrences']} | {', '.join(str(item) for item in row['run_indices'])} |"
        for row in rows
    )
    return lines


def _decimal(value: object) -> str:
    return f"{float(value):.4f}"


def _latency(value: object) -> str:
    return f"{float(value):.3f}"


def _execution_decimal(metrics: dict[str, Any], field: str) -> str:
    if int(metrics["execution_measured_malicious_count"]) == 0:
        return "N/A"
    return _decimal(metrics[field])
