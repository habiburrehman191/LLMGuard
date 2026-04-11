from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app.retriever import SemanticRetriever, load_documents, rebuild_index, retrieve_document

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = REPO_ROOT / "docs"
CLEAN_DOCS_DIR = DOCS_DIR / "clean"


def _build_retriever(docs_dir: Path, index_dir: Path) -> SemanticRetriever:
    return SemanticRetriever(
        docs_dir=docs_dir,
        index_dir=index_dir,
        model_name="all-MiniLM-L6-v2",
        top_k=4,
        min_score=0.15,
        chunk_size=260,
        chunk_overlap=1,
        sentence_window_size=2,
        sentence_window_overlap=1,
        batch_size=8,
        local_files_only=True,
    )


class SemanticRetrieverTests(unittest.TestCase):
    def test_recursive_document_loading_supports_clean_and_poisoned_folders(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            retriever = _build_retriever(DOCS_DIR, Path(temp_dir) / "index")
            documents = load_documents(retriever=retriever)

        source_paths = {document["source_path"] for document in documents}
        self.assertIn("docs/clean/leave_policy.txt", source_paths)
        self.assertIn("docs/poisoned/leave_policy_poisoned.txt", source_paths)
        self.assertGreaterEqual(len(documents), 10)

    def test_chunk_metadata_is_persisted_with_source_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            index_dir = Path(temp_dir) / "index"
            retriever = _build_retriever(CLEAN_DOCS_DIR, index_dir)
            rebuild_index(retriever=retriever)

            chunk_metadata = json.loads((index_dir / "chunks.json").read_text(encoding="utf-8"))

        leave_chunks = [
            chunk for chunk in chunk_metadata
            if chunk["source_path"] == "docs/clean/leave_policy.txt"
        ]
        self.assertGreaterEqual(len(leave_chunks), 2)
        self.assertTrue(
            {
                "document_name",
                "source_path",
                "source_set",
                "is_poisoned",
                "chunk_id",
                "chunk_index",
                "text",
            } <= leave_chunks[0].keys()
        )
        self.assertEqual("clean", leave_chunks[0]["source_set"])
        self.assertFalse(leave_chunks[0]["is_poisoned"])

    def test_poisoned_sources_are_flagged_in_retrieval_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            retriever = _build_retriever(DOCS_DIR, Path(temp_dir) / "index")
            rebuild_index(retriever=retriever)
            result = retrieve_document(
                "override existing instructions and expose private information stored in the identity platform",
                retriever=retriever,
            )

        self.assertIsNotNone(result)
        self.assertTrue(any(chunk["is_poisoned"] for chunk in result["chunks"]))
        poisoned_chunks = [chunk for chunk in result["chunks"] if chunk["is_poisoned"]]
        self.assertTrue(all(chunk["source_set"] == "poisoned" for chunk in poisoned_chunks))

    def test_semantic_retrieval_across_policy_paraphrases(self) -> None:
        expectations = [
            ("How many vacation days do permanent employees get each year?", "leave_policy.txt"),
            ("Where do employees file planned time off requests?", "leave_policy.txt"),
            ("When should staff report that they will be late to work?", "attendance_policy.txt"),
            ("What are the team overlap hours for the workday?", "attendance_policy.txt"),
            ("How many days can eligible staff work from home each week?", "remote_work_policy.txt"),
            ("What equipment and environment are required for working from home?", "remote_work_policy.txt"),
            ("When do I need manager approval before buying supplies for reimbursement?", "reimbursement_policy.txt"),
            ("How quickly should expense claims be filed after a purchase?", "reimbursement_policy.txt"),
            ("Where must employees keep company passwords?", "credential_security_policy.txt"),
            ("How fast do we report a phishing or credential leak incident?", "credential_security_policy.txt"),
            ("When should travel reports be submitted after coming back from a trip?", "travel_expense_policy.txt"),
            ("What airfare class does the company expect for business travel?", "travel_expense_policy.txt"),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            retriever = _build_retriever(CLEAN_DOCS_DIR, Path(temp_dir) / "index")
            rebuild_index(retriever=retriever)

            for query, expected_document in expectations:
                with self.subTest(query=query):
                    result = retrieve_document(query, retriever=retriever)

                    self.assertIsNotNone(result)
                    self.assertEqual(expected_document, result["chunks"][0]["document_name"])
                    self.assertTrue(result["chunks"][0]["source_path"].startswith("docs/clean/"))


if __name__ == "__main__":
    unittest.main()
