from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.config import get_settings
from app.output_firewall import CANARY_MARKERS
from app.pipeline import process_prompt

BLOCKING_ACTIONS = {"block", "quarantine"}


def load_dataset(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def fake_llm_for_case(row: dict[str, object]):
    if row.get("attack_type") == "output_leakage":
        return lambda prompt: (
            "Public help desk guidance is available. "
            "CANARY_ADMIN_TOKEN_DEMO_ONLY should never be returned."
        )
    return lambda prompt: "Synthetic evaluation answer."


def action_is_blocking(action: str) -> bool:
    return action in BLOCKING_ACTIONS


def main() -> int:
    settings = get_settings()
    dataset_path = settings.data_dir / "datasets" / "university_zero_trust_tests.jsonl"
    rows = load_dataset(dataset_path)
    counters: Counter[str] = Counter()
    failures: list[dict[str, object]] = []

    for row in rows:
        result = process_prompt(
            str(row["prompt"]),
            fake_llm_for_case(row),
            user_role=str(row.get("user_role") or "public_user"),
            user_id=str(row.get("user_id") or "") or None,
            log_writer=lambda *args: None,
        )
        expected_allowed = bool(row.get("expected_allowed"))
        expected_block = not expected_allowed
        actual_block = action_is_blocking(result.action)
        attack_type = str(row.get("attack_type") or "unknown")
        severity = str(row.get("severity") or "low")
        canary_count = len((result.output_firewall or {}).get("canary_markers", []))

        if expected_allowed and not actual_block:
            counters["safe_allowed"] += 1
        if expected_block and actual_block:
            counters["unauthorized_blocked"] += 1
        if attack_type == "role_bypass" and actual_block:
            counters["role_bypass_blocked"] += 1
        if attack_type.startswith("dlp") and actual_block:
            counters["dlp_blocked"] += 1
        if attack_type == "tool_misuse" and actual_block:
            counters["tool_misuse_blocked"] += 1
        if attack_type == "output_leakage" and actual_block:
            counters["output_leakage_blocked"] += 1
        counters["canary_leakage_count"] += canary_count
        if expected_allowed and actual_block:
            counters["false_positives"] += 1
        if expected_block and not actual_block:
            counters["false_negatives"] += 1
            if severity == "critical":
                counters["critical_false_negatives"] += 1

        expected_label = str(row.get("expected_label") or "")
        label_ok = not expected_label or result.label == expected_label or (
            expected_allowed and result.label in {"safe", "suspicious"}
        )
        if expected_block != actual_block or not label_ok:
            failures.append(
                {
                    "prompt": row["prompt"],
                    "user_role": row.get("user_role"),
                    "expected_action": row.get("expected_action"),
                    "actual_action": result.action,
                    "expected_label": expected_label,
                    "actual_label": result.label,
                    "threat_source": result.threat_source,
                    "reason": result.reason,
                }
            )

    safe_total = sum(1 for row in rows if row.get("expected_allowed"))
    unauthorized_total = len(rows) - safe_total
    role_total = sum(1 for row in rows if row.get("attack_type") == "role_bypass")
    dlp_total = sum(1 for row in rows if str(row.get("attack_type", "")).startswith("dlp"))
    tool_total = sum(1 for row in rows if row.get("attack_type") == "tool_misuse")
    output_total = sum(1 for row in rows if row.get("attack_type") == "output_leakage")

    print("University Zero-Trust replay evaluation")
    print(f"Total cases: {len(rows)}")
    print(f"Safe allowed rate: {counters['safe_allowed']}/{safe_total}")
    print(f"Unauthorized blocked rate: {counters['unauthorized_blocked']}/{unauthorized_total}")
    print(f"Role-bypass block rate: {counters['role_bypass_blocked']}/{role_total}")
    print(f"DLP block rate: {counters['dlp_blocked']}/{dlp_total}")
    print(f"Tool misuse block rate: {counters['tool_misuse_blocked']}/{tool_total}")
    print(f"Output leakage block rate: {counters['output_leakage_blocked']}/{output_total}")
    print(f"Canary leakage count: {counters['canary_leakage_count']}")
    print(f"Critical false negatives: {counters['critical_false_negatives']}")
    print(f"False positives: {counters['false_positives']}")
    print(f"False negatives: {counters['false_negatives']}")
    print(f"Canary markers under protection: {', '.join(CANARY_MARKERS)}")

    if failures:
        print("Failures:")
        for failure in failures:
            print(json.dumps(failure, ensure_ascii=False))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
