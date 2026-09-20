from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from evaluation.types import ContextChunk, EvaluationCase


CATEGORIES = (
    "clean",
    "direct_prompt_injection",
    "indirect_prompt_injection",
    "paraphrased_attack",
    "obfuscated_encoded_attack",
    "privilege_cross_user_attempt",
    "data_exfiltration_system_prompt_leakage",
    "retrieval_poisoning",
    "cross_chunk_attack",
)
EXPECTED_LABELS = {"benign", "malicious"}
STAGES = {"input", "context"}
CHANNELS = {"public", "student", "employee"}
MINIMUM_CASES_PER_CATEGORY = 6
EXPECTED_CATEGORY_LABEL = {
    "clean": "benign",
    "privilege_cross_user_attempt": "benign",
}
DEFAULT_DATASET_PATH = Path(__file__).resolve().parent / "datasets" / "security_cases.jsonl"


def load_evaluation_cases(path: Path = DEFAULT_DATASET_PATH) -> list[EvaluationCase]:
    if not path.is_file():
        raise RuntimeError(f"Evaluation dataset was not found: {path.name}")

    cases: list[EvaluationCase] = []
    seen_ids: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on evaluation dataset line {line_number}") from exc
        case = _case_from_payload(payload, line_number=line_number)
        if case.case_id in seen_ids:
            raise ValueError(f"Duplicate evaluation case_id: {case.case_id}")
        seen_ids.add(case.case_id)
        cases.append(case)

    if not cases:
        raise RuntimeError("Evaluation dataset contains no cases")
    missing_categories = set(CATEGORIES) - {case.category for case in cases}
    if missing_categories:
        raise ValueError(
            "Evaluation dataset is missing required categories: "
            + ", ".join(sorted(missing_categories))
        )
    counts = category_counts(cases)
    undersized = {
        category: count
        for category, count in counts.items()
        if count < MINIMUM_CASES_PER_CATEGORY
    }
    if undersized:
        details = ", ".join(
            f"{category}={count}" for category, count in undersized.items()
        )
        raise ValueError(
            "Expanded evaluation dataset requires at least "
            f"{MINIMUM_CASES_PER_CATEGORY} cases per category: {details}"
        )
    return sorted(cases, key=lambda case: case.case_id)


def category_counts(cases: list[EvaluationCase]) -> dict[str, int]:
    counts = Counter(case.category for case in cases)
    return {category: counts.get(category, 0) for category in CATEGORIES}


def _case_from_payload(payload: object, *, line_number: int) -> EvaluationCase:
    if not isinstance(payload, dict):
        raise ValueError(f"Evaluation dataset line {line_number} must be an object")

    case_id = _required_text(payload, "case_id", line_number=line_number, maximum=100)
    category = _required_text(payload, "category", line_number=line_number, maximum=100)
    expected_label = _required_text(
        payload,
        "expected_label",
        line_number=line_number,
        maximum=20,
    ).lower()
    stage = _required_text(payload, "stage", line_number=line_number, maximum=20).lower()
    channel = _required_text(payload, "channel", line_number=line_number, maximum=20).lower()
    content = _required_text(payload, "content", line_number=line_number, maximum=16_000)
    origin = _required_text(payload, "origin", line_number=line_number, maximum=200)

    if category not in CATEGORIES:
        raise ValueError(f"Unsupported category on line {line_number}: {category}")
    if expected_label not in EXPECTED_LABELS:
        raise ValueError(
            f"Unsupported expected_label on line {line_number}: {expected_label}"
        )
    if stage not in STAGES:
        raise ValueError(f"Unsupported stage on line {line_number}: {stage}")
    if channel not in CHANNELS:
        raise ValueError(f"Unsupported channel on line {line_number}: {channel}")
    category_label = EXPECTED_CATEGORY_LABEL.get(category, "malicious")
    if expected_label != category_label:
        raise ValueError(
            f"Category {category} requires expected_label={category_label} "
            f"on line {line_number}"
        )

    raw_chunks = payload.get("chunks", [])
    if not isinstance(raw_chunks, list):
        raise ValueError(f"chunks must be a list on line {line_number}")
    chunks = tuple(
        _chunk_from_payload(item, case_id=case_id, index=index)
        for index, item in enumerate(raw_chunks)
    )
    if stage == "context" and not chunks:
        raise ValueError(f"Context case {case_id} must contain chunks")
    if stage == "input" and chunks:
        raise ValueError(f"Input case {case_id} must not contain chunks")

    return EvaluationCase(
        case_id=case_id,
        category=category,
        expected_label=expected_label,
        stage=stage,
        channel=channel,
        content=content,
        chunks=chunks,
        rbac_expected_denial=_required_bool(
            payload,
            "rbac_expected_denial",
            line_number=line_number,
        ),
        requires_retrieval=_required_bool(
            payload,
            "requires_retrieval",
            line_number=line_number,
        ),
        requires_tool=_required_bool(
            payload,
            "requires_tool",
            line_number=line_number,
        ),
        origin=origin,
    )


def _chunk_from_payload(payload: object, *, case_id: str, index: int) -> ContextChunk:
    if not isinstance(payload, dict):
        raise ValueError(f"Chunk {index} in {case_id} must be an object")
    return ContextChunk(
        source_id=_required_text(payload, "source_id", line_number=index, maximum=200),
        chunk_id=_required_text(payload, "chunk_id", line_number=index, maximum=200),
        text=_required_text(payload, "text", line_number=index, maximum=16_000),
    )


def _required_text(
    payload: dict[str, object],
    field: str,
    *,
    line_number: int,
    maximum: int,
) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text on dataset line {line_number}")
    normalized = value.strip()
    if not normalized or len(normalized.encode("utf-8")) > maximum:
        raise ValueError(
            f"{field} must contain 1 to {maximum} UTF-8 bytes on dataset line {line_number}"
        )
    return normalized


def _required_bool(
    payload: dict[str, object],
    field: str,
    *,
    line_number: int,
) -> bool:
    value = payload.get(field)
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be boolean on dataset line {line_number}")
    return value
