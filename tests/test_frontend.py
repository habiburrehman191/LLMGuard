from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.auth import seed_development_users
from app.config import reset_settings_cache
from app.database import SessionLocal, init_database
from app.db import init_db, insert_log


class FrontendRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp_dir.cleanup)
        self.db_path = Path(self._temp_dir.name) / "logs" / "llmguard.db"
        self.previous_db_path = os.environ.get("LLMGUARD_DB_PATH")
        os.environ["LLMGUARD_DB_PATH"] = str(self.db_path)
        reset_settings_cache()
        init_db()

        insert_log(
            "What is the reimbursement deadline?",
            "reimbursement_policy.txt",
            ["docs/clean/reimbursement_policy.txt"],
            [
                {
                    "document_name": "reimbursement_policy.txt",
                    "source_path": "docs/clean/reimbursement_policy.txt",
                    "chunk_id": "reimbursement_policy.txt::0",
                    "chunk_index": 0,
                    "text": "Expense claims should be submitted within 30 calendar days.",
                    "score": 0.88,
                    "rule_score": 0.05,
                    "semantic_score": 0.06,
                    "ml_score": 0.04,
                    "risk_score": 0.05,
                    "rule_label": "safe",
                    "semantic_label": "safe",
                    "ml_label": "safe",
                    "label": "safe",
                    "action": "allow",
                    "reasons": ["All hybrid firewall layers classified the content as safe"],
                }
            ],
            "allow",
            "safe",
            False,
            "All hybrid firewall layers classified the content as safe",
            0.05,
            0.06,
            0.04,
            "safe",
            "safe",
            "safe",
            0.05,
            "Submit within 30 calendar days.",
        )

        from app.main import app

        self.client = TestClient(app)
        init_database()
        with SessionLocal() as db:
            seed_development_users(db)
        login = self.client.post(
            "/auth/login",
            json={"username": "admin1", "password": "Admin@123"},
        )
        self.assertEqual(200, login.status_code)
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        if self.previous_db_path is None:
            os.environ.pop("LLMGUARD_DB_PATH", None)
        else:
            os.environ["LLMGUARD_DB_PATH"] = self.previous_db_path
        reset_settings_cache()

    def test_user_console_page_renders(self) -> None:
        response = self.client.get("/app", follow_redirects=False)
        self.assertEqual(307, response.status_code)
        self.assertEqual("/login", response.headers["location"])
        response = self.client.get("/app")
        self.assertEqual(200, response.status_code)
        self.assertIn("Enter the LLMGuard security testbed", response.text)
        self.assertIn("/static/product.css?v=15", response.text)

    def test_dashboard_page_renders_live_log_data(self) -> None:
        response = self.client.get("/admin/security-dashboard")
        self.assertEqual(200, response.status_code)
        self.assertIn("AI Firewall Security Dashboard", response.text)
        self.assertIn("Monitor enforcement outcomes", response.text)
        self.assertIn("What is the reimbursement deadline?", response.text)
        self.assertIn("docs/clean/reimbursement_policy.txt", response.text)
        self.assertIn("/static/security_dashboard.js?v=15", response.text)
        self.assertIn("Telemetry live", response.text)

    def test_dashboard_data_endpoint_returns_metrics(self) -> None:
        response = self.client.get("/admin/dashboard/data")
        self.assertEqual(200, response.status_code)
        self.assertEqual("no-store, no-cache, must-revalidate, max-age=0", response.headers["cache-control"])
        payload = response.json()
        self.assertEqual(1, payload["total_queries"])
        self.assertEqual(1, payload["label_counts"]["safe"])
        self.assertEqual(1, payload["action_counts"]["allow"])
        self.assertEqual("reimbursement_policy.txt", payload["recent_logs"][0]["retrieved_document"])


if __name__ == "__main__":
    unittest.main()
