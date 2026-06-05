from __future__ import annotations

import unittest

from app.auth import hash_password, seed_development_users, verify_password
from app.models import DataClassification, Document, PortalScope, UserRole
from app.rbac import can_access_classification, can_access_document, can_access_portal


class TestbedFoundationTests(unittest.TestCase):
    def test_password_hashing_round_trip(self) -> None:
        password_hash = hash_password("Student@123", salt="fixed-demo-salt")

        self.assertTrue(verify_password("Student@123", password_hash))
        self.assertFalse(verify_password("wrong-password", password_hash))

    def test_rbac_portal_boundaries(self) -> None:
        student = type("UserObj", (), {"role": UserRole.student})()
        employee = type("UserObj", (), {"role": UserRole.employee})()
        admin = type("UserObj", (), {"role": UserRole.super_admin})()

        self.assertTrue(can_access_portal(student, PortalScope.student))
        self.assertFalse(can_access_portal(student, PortalScope.employee))
        self.assertTrue(can_access_portal(employee, PortalScope.employee))
        self.assertFalse(can_access_portal(employee, PortalScope.admin))
        self.assertTrue(can_access_portal(admin, PortalScope.student))
        self.assertTrue(can_access_portal(admin, PortalScope.employee))
        self.assertTrue(can_access_portal(admin, PortalScope.admin))

    def test_rbac_classification_rules(self) -> None:
        student = type("UserObj", (), {"role": UserRole.student})()
        employee = type("UserObj", (), {"role": UserRole.employee})()
        admin = type("UserObj", (), {"role": UserRole.super_admin})()

        self.assertTrue(can_access_classification(student, DataClassification.student_private))
        self.assertFalse(can_access_classification(student, DataClassification.employee_private))
        self.assertTrue(can_access_classification(employee, DataClassification.employee_private))
        self.assertFalse(can_access_classification(employee, DataClassification.student_private))
        self.assertTrue(can_access_classification(admin, DataClassification.admin_internal))
        self.assertFalse(can_access_classification(admin, DataClassification.restricted_secret))

    def test_document_access_blocks_restricted_secret(self) -> None:
        admin = type("UserObj", (), {"role": UserRole.super_admin})()
        document = type(
            "DocumentObj",
            (),
            {
                "classification": DataClassification.restricted_secret,
                "portal_scope": PortalScope.admin,
            },
        )()

        self.assertFalse(can_access_document(admin, document))


if __name__ == "__main__":
    unittest.main()
