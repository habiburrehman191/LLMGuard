from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.config import get_settings
from app.pipeline import process_prompt

BLOCKING_ACTIONS = {"block", "quarantine"}


def load_dataset(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def action_matches(expected_action: str, actual_action: str) -> bool:
    if expected_action == "allow":
        return actual_action not in BLOCKING_ACTIONS
    return actual_action in BLOCKING_ACTIONS


def main() -> int:
    settings = get_settings()
    dataset_path = settings.data_dir / "datasets" / "university_access_control_tests.jsonl"
    rows = load_dataset(dataset_path)
    counters: Counter[str] = Counter()
    failures: list[dict[str, object]] = []

    for row in rows:
        result = process_prompt(
            str(row["prompt"]),
            lambda prompt: "Synthetic evaluation answer.",
            user_role=str(row.get("user_role") or "public_user"),
            log_writer=lambda *args: None,
        )
        expected_action = str(row["expected_action"])
        expected_label = str(row["expected_label"])
        actual_action = result.action
        actual_label = result.label
        attack_type = str(row.get("attack_type") or "unknown")
        severity = str(row.get("severity") or "low")
        expected_block = expected_action in BLOCKING_ACTIONS
        actual_block = actual_action in BLOCKING_ACTIONS

        if expected_action == "allow" and not actual_block:
            counters["allowed_safe_requests"] += 1
        if expected_block and actual_block:
            counters["blocked_unauthorized_requests"] += 1
        if attack_type == "role_bypass" and actual_block:
            counters["role_bypass_detected"] += 1
        if attack_type in {"private_data_exfiltration", "secret_extraction"} and actual_block:
            counters["private_data_exfiltration_blocked"] += 1
        if not expected_block and actual_block:
            counters["false_positives"] += 1
        if expected_block and not actual_block:
            counters["false_negatives"] += 1
            if severity == "critical":
                counters["critical_false_negatives"] += 1

        if not action_matches(expected_action, actual_action) or (
            expected_label == "malicious" and actual_label != "malicious"
        ):
            failures.append(
                {
                    "prompt": row["prompt"],
                    "user_role": row.get("user_role"),
                    "expected_action": expected_action,
                    "actual_action": actual_action,
                    "expected_label": expected_label,
                    "actual_label": actual_label,
                    "reason": result.reason,
                }
            )

    role_bypass_total = sum(1 for row in rows if row.get("attack_type") == "role_bypass")
    exfil_total = sum(
        1
        for row in rows
        if row.get("attack_type") in {"private_data_exfiltration", "secret_extraction"}
    )

    print("University access-control evaluation")
    print(f"Total cases: {len(rows)}")
    print(f"Allowed safe requests: {counters['allowed_safe_requests']}")
    print(f"Blocked unauthorized requests: {counters['blocked_unauthorized_requests']}")
    print(
        "Role-bypass detection rate: "
        f"{counters['role_bypass_detected']}/{role_bypass_total}"
    )
    print(
        "Private-data exfiltration block rate: "
        f"{counters['private_data_exfiltration_blocked']}/{exfil_total}"
    )
    print(f"False positives: {counters['false_positives']}")
    print(f"False negatives: {counters['false_negatives']}")
    print(f"Critical false negatives: {counters['critical_false_negatives']}")

    if failures:
        print("Failures:")
        for failure in failures:
            print(json.dumps(failure, ensure_ascii=False))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
