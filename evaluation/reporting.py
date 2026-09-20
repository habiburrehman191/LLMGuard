from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


CASE_FIELDS = (
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
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "benchmark.json"
    csv_path = output_dir / "cases.csv"

    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CASE_FIELDS)
        writer.writeheader()
        for result in payload["results"]:
            writer.writerow({field: result[field] for field in CASE_FIELDS})
    return json_path, csv_path
