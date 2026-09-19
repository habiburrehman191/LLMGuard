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

    def test_student_routes_are_not_exposed_by_llmguard(self) -> None:
        token = self._token("student1", "Student@123")
        headers = {"Authorization": f"Bearer {token}"}

        for method, path in (
            ("GET", "/student/dashboard"),
            ("GET", "/student/records"),
            ("POST", "/student/ai/ask"),
            ("POST", "/student/documents/upload"),
        ):
            with self.subTest(path=path):
                response = self.client.request(method, path, headers=headers, json={})
                self.assertEqual(404, response.status_code)

    def test_employee_routes_are_not_exposed_by_llmguard(self) -> None:
        token = self._token("employee1", "Employee@123")
        headers = {"Authorization": f"Bearer {token}"}

        for method, path in (
            ("GET", "/employee/dashboard"),
            ("GET", "/employee/records"),
            ("POST", "/employee/ai/ask"),
            ("POST", "/employee/documents/upload"),
        ):
            with self.subTest(path=path):
                response = self.client.request(method, path, headers=headers, json={})
                self.assertEqual(404, response.status_code)

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

    def test_removed_portal_routes_are_unavailable_without_authentication(self) -> None:
        self.client.cookies.clear()
        for path in (
            "/student/ai/ask",
            "/student/documents/upload",
            "/employee/ai/ask",
            "/employee/documents/upload",
        ):
            with self.subTest(path=path):
                self.assertEqual(404, self.client.post(path, json={}).status_code)


if __name__ == "__main__":
    unittest.main()
