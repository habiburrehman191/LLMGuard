from __future__ import annotations

from collections import Counter
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.access_control import classification_for_repository_path
from app.config import get_settings
from app.retriever import rebuild_index, reset_retriever

REPOSITORY_CATEGORIES = (
    "public",
    "student_portal",
    "staff",
    "exam_cell",
    "finance",
    "contracts",
    "admin",
    "restricted",
)

REQUIRED_FILES = {
    "public": {
        "admissions_policy.txt",
        "portal_help_public.txt",
        "programs_public.txt",
        "scholarships_public.txt",
        "hostel_transport_public.txt",
    },
    "student_portal": {"synthetic_student_self_records.txt"},
    "staff": {"synthetic_staff_directory.txt", "synthetic_teacher_office_hours.txt"},
    "exam_cell": {"synthetic_exam_records_confidential.txt", "synthetic_exam_rechecking_internal.txt"},
    "finance": {"synthetic_fee_status_internal.txt", "synthetic_budget_summary_confidential.txt"},
    "contracts": {"synthetic_vendor_contracts_confidential.txt"},
    "admin": {"synthetic_admin_notes.txt", "synthetic_portal_rules_internal.txt"},
    "restricted": {"synthetic_admin_token_placeholder.txt"},
}


def default_file_content(category: str, filename: str) -> str:
    title = filename.replace("_", " ").replace(".txt", "").title()
    if category == "public":
        return (
            f"{title}\n\n"
            "Public synthetic university gateway document. This file is safe for public RAG answers "
            "and contains only admissions, portal, program, scholarship, hostel, transport, or help desk guidance.\n"
        )
    return (
        "SYNTHETIC DEMO DATA — NOT REAL UNIVERSITY DATA\n\n"
        f"{title}\n\n"
        "Synthetic internal document for the controlled Zero-Trust LLMGuard demo. "
        "Do not treat this as real university private data.\n"
    )


def ensure_repository_folders(repository_dir: Path) -> None:
    for category in REPOSITORY_CATEGORIES:
        (repository_dir / category).mkdir(parents=True, exist_ok=True)


def ensure_repository_files(repository_dir: Path) -> None:
    for category, filenames in REQUIRED_FILES.items():
        for filename in filenames:
            path = repository_dir / category / filename
            if not path.exists():
                path.write_text(default_file_content(category, filename), encoding="utf-8")


def copy_repository_docs() -> int:
    settings = get_settings()
    repository_dir = settings.data_dir / "university_repository"
    ensure_repository_folders(repository_dir)
    ensure_repository_files(repository_dir)

    target_root = settings.docs_dir / "clean" / "university_repository"
    copied = 0
    for category, filenames in REQUIRED_FILES.items():
        source_dir = repository_dir / category
        target_dir = target_root / category
        target_dir.mkdir(parents=True, exist_ok=True)
        for filename in sorted(filenames):
            source = source_dir / filename
            if not source.exists():
                raise RuntimeError(f"Required university repository document is missing: {source}")
            shutil.copy2(source, target_dir / filename)
            copied += 1
    return copied


def count_documents_by_classification(docs_root: Path) -> Counter[str]:
    counts: Counter[str] = Counter()
    for path in sorted((docs_root / "clean" / "university_repository").rglob("*.txt")):
        source_path = path.relative_to(get_settings().base_dir).as_posix()
        counts[classification_for_repository_path(source_path, path.name)] += 1
    return counts


def count_chunks_by_classification(metadata_path: Path) -> Counter[str]:
    chunks = json.loads(metadata_path.read_text(encoding="utf-8"))
    return Counter(str(chunk.get("classification", "public")) for chunk in chunks)


def main() -> int:
    settings = get_settings()
    copied = copy_repository_docs()
    reset_retriever()
    result = rebuild_index()
    document_counts = count_documents_by_classification(settings.docs_dir)
    chunk_counts = count_chunks_by_classification(settings.retrieval_index_dir / "chunks.json")

    print(f"Loaded university repository documents: {copied}")
    print(f"Total documents: {result['documents']}")
    print(f"Total chunks: {result['chunks']}")
    print("Documents by classification:")
    for classification, count in sorted(document_counts.items()):
        print(f"  {classification}: {count}")
    print("Chunks by classification:")
    for classification, count in sorted(chunk_counts.items()):
        print(f"  {classification}: {count}")
    print(f"Index path: {result['index_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
