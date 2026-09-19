from __future__ import annotations

import asyncio
from pathlib import Path
import re
import unittest

import httpx
from sqlalchemy import func, select

from university_site.database import SessionLocal
from university_site.main import app
from university_site.models import AuditEvent, ControlledRecord, Employee, Policy, Student
from university_site.repository import data_quality_report


PUBLIC_ROUTES = (
    "/", "/university/about", "/university/academics", "/university/contact", "/search",
    "/university/policies", "/university/admissions", "/university/admissions/bs-programs",
    "/university/admissions/ms-programs", "/university/admissions/phd-programs",
    "/university/admissions/eligibility", "/university/admissions/fee",
    "/university/admissions/schedule", "/university/admissions/scholarships",
    "/university/admissions/facilities", "/university/admissions/how-to-apply",
    "/portal", "/portal/student/login", "/portal/employee/login", "/health", "/health/data",
)

STUDENT_ROUTES = (
    "/portal/student/dashboard", "/portal/student/profile", "/portal/student/courses",
    "/portal/student/attendance", "/portal/student/results", "/portal/student/fees",
    "/portal/student/timetable", "/portal/student/notices", "/portal/student/documents",
)

EMPLOYEE_ROUTES = (
    "/portal/employee/dashboard", "/portal/employee/profile", "/portal/employee/attendance",
    "/portal/employee/leave", "/portal/employee/assignments", "/portal/employee/department",
    "/portal/employee/notices", "/portal/employee/policies",
    "/portal/employee/controlled-records", "/portal/employee/directory", "/portal/employee/organogram",
)


def run(coro):
    return asyncio.run(coro)


def login_body(username: str, password: str) -> str:
    return f"username={username}&password={password.replace('@', '%40')}"


async def login(client: httpx.AsyncClient, portal: str, username: str, password: str) -> httpx.Response:
    return await client.post(
        f"/portal/{portal}/login",
        content=login_body(username, password),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )


class UniversityDataTests(unittest.TestCase):
    def test_exact_counts_uniqueness_and_relations(self) -> None:
        with SessionLocal() as db:
            report = data_quality_report(db)
        self.assertEqual(report["student_count"], 200)
        self.assertEqual(report["employee_count"], 30)
        self.assertEqual(report["policy_count"], 70)
        self.assertEqual(report["departments_represented"], 22)
        self.assertEqual(report["programs_represented"], 22)
        for key in (
            "duplicate_student_ids", "duplicate_registration_numbers", "duplicate_student_usernames",
            "duplicate_student_emails", "duplicate_employee_numbers", "duplicate_employee_usernames",
            "duplicate_employee_emails", "duplicate_policy_ids", "duplicate_policy_titles",
            "orphan_student_departments", "orphan_student_programs",
            "foreign_key_errors", "duplicate_enrollments", "invalid_results", "invalid_attendance",
            "missing_policy_owners", "cross_realm_duplicate_usernames", "cross_realm_duplicate_emails",
        ):
            self.assertEqual(report[key], 0, key)
        for key in (
            "students_with_enrollments", "students_with_attendance", "students_with_results",
            "students_with_fees", "students_with_timetable",
        ):
            self.assertEqual(report[key], 200, key)

    def test_student_timeline_and_summary_ranges(self) -> None:
        with SessionLocal() as db:
            students = list(db.scalars(select(Student)))
        self.assertEqual(len(students), 200)
        self.assertTrue(all(1 <= item.current_semester <= 8 for item in students))
        self.assertTrue(all(item.current_semester <= (2026 - item.admission_year) * 2 + 2 for item in students))
        self.assertTrue(all(0 <= item.cgpa <= 4 for item in students))
        self.assertTrue(all(0 <= item.attendance_percentage <= 100 for item in students))

    def test_policy_documents_are_substantive_and_unique(self) -> None:
        with SessionLocal() as db:
            policies = list(db.scalars(select(Policy)))
        self.assertEqual(len(policies), 70)
        bodies = {
            "|".join([item.purpose, item.scope, item.responsibilities, item.rules, item.procedures])
            for item in policies
        }
        self.assertEqual(len(bodies), 70)
        self.assertTrue(all(item.owner and item.classification and item.applies_to and item.approving_authority for item in policies))


class AuthenticationTests(unittest.TestCase):
    def test_separate_login_realms_and_cross_route_denial(self) -> None:
        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=False) as client:
                accepted = await login(client, "student", "student.demo001", "Student@123")
                self.assertEqual(accepted.status_code, 303)
                self.assertEqual(accepted.headers["location"], "/portal/student/dashboard")
                cross_route = await client.get("/portal/employee/dashboard")
                self.assertEqual(cross_route.status_code, 403)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=False) as client:
                rejected = await login(client, "employee", "student.demo001", "Student@123")
                self.assertEqual(rejected.status_code, 401)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=False) as client:
                accepted = await login(client, "employee", "employee.lecturer", "Employee@123")
                self.assertEqual(accepted.status_code, 303)
                self.assertEqual(accepted.headers["location"], "/portal/employee/dashboard")
                cross_route = await client.get("/portal/student/dashboard")
                self.assertEqual(cross_route.status_code, 403)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=False) as client:
                rejected = await login(client, "student", "employee.lecturer", "Employee@123")
                self.assertEqual(rejected.status_code, 401)
        run(scenario())

    def test_login_forms_are_local_and_portal_specific(self) -> None:
        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                student = await client.get("/portal/student/login")
                employee = await client.get("/portal/employee/login")
                self.assertIn('action="/portal/student/login"', student.text)
                self.assertNotIn("employee.registrar", student.text)
                self.assertIn('action="/portal/employee/login"', employee.text)
                self.assertNotIn("student.demo001", employee.text)
                combined = student.text + employee.text
                self.assertNotIn("studentportal.uoh.edu.pk", combined)
                self.assertNotIn("employeeportal.uoh.edu.pk", combined)
        run(scenario())


class PortalRouteTests(unittest.TestCase):
    def test_all_public_routes_render(self) -> None:
        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                for route in PUBLIC_ROUTES:
                    response = await client.get(route)
                    self.assertEqual(response.status_code, 200, route)
                department = await client.get("/university/departments/public-health-and-nutrition")
                self.assertEqual(department.status_code, 200)
                searched = await client.get("/search?q=computer")
                self.assertIn("local results", searched.text)
        run(scenario())

    def test_complete_student_journey_and_record_isolation(self) -> None:
        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            registrations: list[str] = []
            for username in ("student.demo001", "student.demo002"):
                async with httpx.AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=False) as client:
                    response = await login(client, "student", username, "Student@123")
                    self.assertEqual(response.status_code, 303)
                    for route in STUDENT_ROUTES:
                        page = await client.get(route)
                        self.assertEqual(page.status_code, 200, route)
                        self.assertIn("Synthetic student record", page.text)
                    profile = await client.get("/portal/student/profile")
                    match = re.search(r"UOH-DEMO-20\d{2}-\d{4}", profile.text)
                    self.assertIsNotNone(match)
                    registrations.append(match.group(0))
                    courses = await client.get("/portal/student/courses")
                    course_code = re.search(r"/portal/student/courses/(D\d{2}-\d{3})", courses.text).group(1)
                    detail = await client.get(f"/portal/student/courses/{course_code}")
                    self.assertEqual(detail.status_code, 200)
                    documents = await client.get("/portal/student/documents")
                    document_id = int(re.search(r"/portal/student/documents/(\d+)/download", documents.text).group(1))
                    download = await client.get(f"/portal/student/documents/{document_id}/download")
                    self.assertEqual(download.status_code, 200)
                    self.assertIn("not valid for official use", download.text)
                    logout = await client.post("/portal/student/logout")
                    self.assertEqual(logout.status_code, 303)
                    blocked = await client.get("/portal/student/dashboard")
                    self.assertEqual(blocked.status_code, 303)
            self.assertNotEqual(registrations[0], registrations[1])
        run(scenario())

    def test_employee_journeys_role_context_and_actions(self) -> None:
        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            for username in ("employee.lecturer", "employee.hod", "employee.registrar", "employee.hr", "employee.finance", "employee.security", "employee.guard"):
                async with httpx.AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=False) as client:
                    response = await login(client, "employee", username, "Employee@123")
                    self.assertEqual(response.status_code, 303, username)
                    for route in EMPLOYEE_ROUTES:
                        page = await client.get(route)
                        self.assertEqual(page.status_code, 200, (username, route))
                        self.assertIn("Synthetic employee environment", page.text)
                    assignments = await client.get("/portal/employee/assignments")
                    assignment_id = int(re.search(r"/portal/employee/assignments/(\d+)", assignments.text).group(1))
                    detail = await client.get(f"/portal/employee/assignments/{assignment_id}")
                    self.assertEqual(detail.status_code, 200)
                    leave = await client.post("/portal/employee/leave", content="leave_type=Casual+Leave&start_date=2026-10-01&end_date=2026-10-02&remarks=QA+demo+request", headers={"content-type": "application/x-www-form-urlencoded"})
                    self.assertEqual(leave.status_code, 303)
                    if username == "employee.guard":
                        students = await client.get("/portal/employee/students")
                        self.assertEqual(students.status_code, 403)
                        controlled = await client.get("/portal/employee/controlled-records")
                        self.assertIn("guard post roster", controlled.text.lower())
                        self.assertNotIn("budget variance", controlled.text.lower())
                    if username in {"employee.hod", "employee.registrar"}:
                        students = await client.get("/portal/employee/students")
                        self.assertEqual(students.status_code, 200)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=False) as client:
                await login(client, "employee", "employee.lecturer", "Employee@123")
                student_list = await client.get("/portal/employee/students")
                self.assertEqual(student_list.status_code, 200)
                self.assertIn("Authorized Student Records", student_list.text)
        run(scenario())

    def test_policy_acknowledgment_and_controlled_audit(self) -> None:
        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=False) as client:
                await login(client, "employee", "employee.registrar", "Employee@123")
                policies = await client.get("/portal/employee/policies?page_size=50")
                policy_id = re.search(r"/portal/employee/policies/(UOH-DEMO-POL-\d{3})", policies.text).group(1)
                detail = await client.get(f"/portal/employee/policies/{policy_id}")
                self.assertEqual(detail.status_code, 200)
                acknowledged = await client.post(f"/portal/employee/policies/{policy_id}/acknowledge")
                self.assertEqual(acknowledged.status_code, 303)
                with SessionLocal() as db:
                    record = db.scalar(select(ControlledRecord).where(ControlledRecord.classification.in_(["CONFIDENTIAL", "RESTRICTED"]), ControlledRecord.allowed_roles.like("%registrar%")))
                    before = int(db.scalar(select(func.count(AuditEvent.id))) or 0)
                opened = await client.get(f"/portal/employee/controlled-records/{record.id}")
                self.assertEqual(opened.status_code, 200)
                with SessionLocal() as db:
                    after = int(db.scalar(select(func.count(AuditEvent.id))) or 0)
                self.assertEqual(after, before + 1)
        run(scenario())


class StaticQualityTests(unittest.TestCase):
    def test_templates_have_no_unfinished_or_dead_markup(self) -> None:
        root = Path(__file__).resolve().parents[1] / "templates"
        content = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*.html"))
        for token in ("TODO", "FIXME", "Lorem ipsum", "Coming Soon", 'href="#"'):
            self.assertNotIn(token, content)

    def test_public_navigation_links_resolve_locally(self) -> None:
        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=True) as client:
                discovered: set[str] = set()
                for seed in ("/", "/portal", "/university/academics", "/university/admissions"):
                    response = await client.get(seed)
                    discovered.update(re.findall(r'href="(/[^"?]*)', response.text))
                for route in sorted(discovered):
                    if route.startswith("/static/") or route.startswith("/portal/employee/") and route != "/portal/employee/login" or route.startswith("/portal/student/") and route != "/portal/student/login":
                        continue
                    response = await client.get(route)
                    self.assertNotEqual(response.status_code, 404, route)
                    self.assertNotEqual(response.status_code, 500, route)
        run(scenario())


if __name__ == "__main__":
    unittest.main()
