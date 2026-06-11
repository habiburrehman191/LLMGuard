from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from app.auth import seed_development_users
from app.database import SessionLocal, init_database
from scripts.seed_testbed import seed_portal_records


class PortalRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        init_database()
        with SessionLocal() as db:
            seed_development_users(db)
            seed_portal_records(db)

        from app.main import app

        cls.client = TestClient(app)

    def _token(self, username: str, password: str) -> str:
        response = self.client.post(
            "/auth/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(200, response.status_code)
        return response.json()["access_token"]

    def test_student_can_access_student_portal_only(self) -> None:
        token = self._token("student1", "Student@123")
        headers = {"Authorization": f"Bearer {token}"}

        self.assertEqual(200, self.client.get("/student/dashboard", headers=headers).status_code)
        self.assertEqual(403, self.client.get("/employee/dashboard", headers=headers).status_code)
        self.assertEqual(403, self.client.get("/admin/dashboard", headers=headers).status_code)

    def test_employee_can_access_employee_portal_only(self) -> None:
        token = self._token("employee1", "Employee@123")
        headers = {"Authorization": f"Bearer {token}"}

        self.assertEqual(200, self.client.get("/employee/dashboard", headers=headers).status_code)
        self.assertEqual(403, self.client.get("/student/dashboard", headers=headers).status_code)
        self.assertEqual(403, self.client.get("/admin/dashboard", headers=headers).status_code)

    def test_super_admin_can_view_all_non_secret_records(self) -> None:
        token = self._token("admin1", "Admin@123")
        headers = {"Authorization": f"Bearer {token}"}

        dashboard = self.client.get("/admin/dashboard", headers=headers)
        self.assertEqual(200, dashboard.status_code)
        records = self.client.get("/admin/all-records", headers=headers)
        self.assertEqual(200, records.status_code)
        payload = records.json()
        classifications = {record["classification"] for record in payload["records"]}
        self.assertIn("student_private", classifications)
        self.assertIn("employee_private", classifications)
        self.assertIn("admin_internal", classifications)
        self.assertNotIn("restricted_secret", classifications)

    def test_portal_ai_and_upload_require_authentication(self) -> None:
        self.client.cookies.clear()
        self.assertEqual(401, self.client.post("/student/ai/ask", json={"prompt": "Hi"}).status_code)
        self.assertEqual(
            401,
            self.client.post(
                "/student/documents/upload",
                json={"title": "x", "filename": "x.txt", "content": "SYNTHETIC DEMO DATA — NOT REAL UNIVERSITY DATA"},
            ).status_code,
        )


if __name__ == "__main__":
    unittest.main()
