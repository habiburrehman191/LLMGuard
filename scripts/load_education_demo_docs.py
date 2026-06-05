from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.config import get_settings
from app.retriever import rebuild_index, reset_retriever

SAFE_FILES = {
    "admission_policy.txt",
    "attendance_policy.txt",
    "exam_rechecking_policy.txt",
    "scholarship_policy.txt",
    "fee_refund_policy.txt",
    "hostel_policy.txt",
    "student_support_policy.txt",
    "synthetic_student_records.txt",
    "synthetic_internal_admin_notes.txt",
}
POISONED_FILES = {"malicious_exam_policy_injection.txt"}


def copy_demo_docs() -> int:
    settings = get_settings()
    source_dir = settings.data_dir / "sector_templates" / "education"
    if not source_dir.exists():
        raise RuntimeError(f"Education demo template directory not found: {source_dir}")

    clean_target = settings.docs_dir / "clean" / "education_demo"
    poisoned_target = settings.docs_dir / "poisoned" / "education_demo"
    clean_target.mkdir(parents=True, exist_ok=True)
    poisoned_target.mkdir(parents=True, exist_ok=True)

    copied = 0
    for filename in sorted(SAFE_FILES):
        source = source_dir / filename
        if not source.exists():
            raise RuntimeError(f"Required education demo document is missing: {source}")
        shutil.copy2(source, clean_target / filename)
        copied += 1

    for filename in sorted(POISONED_FILES):
        source = source_dir / filename
        if not source.exists():
            raise RuntimeError(f"Required education demo document is missing: {source}")
        shutil.copy2(source, poisoned_target / filename)
        copied += 1

    return copied


def main() -> int:
    copied = copy_demo_docs()
    reset_retriever()
    result = rebuild_index()
    print(f"Loaded education demo documents: {copied}")
    print(f"Total documents: {result['documents']}")
    print(f"Total chunks: {result['chunks']}")
    print(f"Index path: {result['index_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
