from __future__ import annotations

import unittest
from unittest.mock import patch

from app.models import DataClassification, PortalScope, UserRole
from app.rag.retriever import retrieve


def _user(user_id: int, role: UserRole):
    return type("UserObj", (), {"id": user_id, "role": role})()


def _candidate(
    chunk_id: str,
    *,
    portal_scope: PortalScope,
    classification: DataClassification,
    owner_user_id: int | None,
) -> dict[str, object]:
    return {
        "chunk_id": chunk_id,
        "document_id": f"doc-{chunk_id}",
        "chunk_text": f"SYNTHETIC DEMO DATA chunk {chunk_id}",
        "portal_scope": portal_scope.value,
        "classification": classification.value,
        "owner_user_id": owner_user_id,
        "allowed_roles": ["student", "employee", "super_admin"],
        "source_filename": f"{chunk_id}.txt",
        "chunk_index": 0,
        "score": 0.99,
        "is_synthetic": True,
    }


class RagMetadataIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidates = [
            _candidate(
                "student-own",
                portal_scope=PortalScope.student,
                classification=DataClassification.student_private,
                owner_user_id=1,
            ),
            _candidate(
                "student-other",
                portal_scope=PortalScope.student,
                classification=DataClassification.student_private,
                owner_user_id=99,
            ),
            _candidate(
                "employee-private",
                portal_scope=PortalScope.employee,
                classification=DataClassification.employee_private,
                owner_user_id=2,
            ),
            _candidate(
                "admin-internal",
                portal_scope=PortalScope.admin,
                classification=DataClassification.admin_internal,
                owner_user_id=3,
            ),
            _candidate(
                "restricted-secret",
                portal_scope=PortalScope.admin,
                classification=DataClassification.restricted_secret,
                owner_user_id=None,
            ),
        ]

    def _retrieve_ids(self, user, *, vulnerable_mode: bool = False) -> list[str]:
        with patch("app.rag.retriever.vector_store.search", return_value=self.candidates):
            return [
                result.chunk_id
                for result in retrieve(
                    "summarize portal records",
                    user,
                    top_k=10,
                    vulnerable_mode=vulnerable_mode,
                )
            ]

    def test_student_cannot_retrieve_employee_or_admin_chunks_in_protected_mode(self) -> None:
        ids = self._retrieve_ids(_user(1, UserRole.student))

        self.assertEqual(["student-own"], ids)

    def test_employee_cannot_retrieve_student_or_admin_chunks_in_protected_mode(self) -> None:
        ids = self._retrieve_ids(_user(2, UserRole.employee))

        self.assertEqual(["employee-private"], ids)

    def test_super_admin_can_retrieve_all_except_restricted_secret(self) -> None:
        ids = self._retrieve_ids(_user(3, UserRole.super_admin))

        self.assertIn("student-own", ids)
        self.assertIn("student-other", ids)
        self.assertIn("employee-private", ids)
        self.assertIn("admin-internal", ids)
        self.assertNotIn("restricted-secret", ids)

    def test_vulnerable_mode_can_retrieve_cross_scope_synthetic_chunks(self) -> None:
        ids = self._retrieve_ids(_user(1, UserRole.student), vulnerable_mode=True)

        self.assertIn("employee-private", ids)
        self.assertIn("admin-internal", ids)
        self.assertNotIn("restricted-secret", ids)


if __name__ == "__main__":
    unittest.main()
