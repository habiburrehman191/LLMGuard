from __future__ import annotations

from collections import Counter
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import select

from app.database import SessionLocal, init_database
from app.models import DocumentChunk
from app.rag.retriever import chunk_row_to_metadata
from app.rag.vector_store import build_index


def main() -> int:
    init_database()
    with SessionLocal() as db:
        rows = db.scalars(select(DocumentChunk).order_by(DocumentChunk.id)).all()
        chunks = [chunk_row_to_metadata(row) for row in rows]

    result = build_index(chunks)
    by_scope = Counter(str(chunk.get("portal_scope") or "none") for chunk in chunks)
    by_classification = Counter(str(chunk.get("classification") or "unknown") for chunk in chunks)

    print(f"Rebuilt university RAG index with {result['total_chunks']} chunks.")
    print("Chunks by portal_scope:")
    for scope, count in sorted(by_scope.items()):
        print(f"  {scope}: {count}")
    print("Chunks by classification:")
    for classification, count in sorted(by_classification.items()):
        print(f"  {classification}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
