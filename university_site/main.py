from __future__ import annotations

import asyncio
from datetime import date, datetime
from pathlib import Path
from urllib.parse import parse_qs, quote_plus

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
from sqlalchemy.orm import joinedload

from .auth import SESSION_COOKIE, SESSION_TTL_SECONDS, create_session, read_session
from .chatbot.indexing import ensure_knowledge_index
from .chatbot.router import router as chatbot_router
from .chatbot.service import analytics as chatbot_analytics
from .data import (
    BS_PROGRAMS,
    CONCESSION_PROGRAMS,
    ELIGIBILITY_ROWS,
    FACILITIES,
    FACULTIES,
    FEE_ROWS,
    HOME_NEWS,
    MS_PROGRAMS,
    PHD_PROGRAMS,
    PUBLIC_INFORMATION_PAGES,
    RECENT_NEWS,
    SCHEDULE_ROWS,
    SCHOLARSHIPS,
)
from .database import SessionLocal
from .integration import heartbeat_config_from_env, heartbeat_loop
from .models import Course, Department, Employee, Enrollment, Faculty, FeeRecord, LeaveRequest, Notice, Policy, Program, Student
from .repository import (
    ACADEMIC_EMPLOYEE_ROLES,
    accessible_policies,
    accessible_policy,
    acknowledge_policy,
    attendance_records,
    authenticate_employee,
    authenticate_student,
    controlled_record_access,
    controlled_records,
    current_enrollments,
    data_quality_report,
    directory_for_employee,
    employee_assignments,
    employee_attendance,
    employee_colleagues,
    employee_leave,
    employee_notices,
    fee_records,
    get_employee,
    get_student,
    policy_acknowledgement,
    policy_revisions,
    public_policies,
    result_records,
    student_document,
    student_documents,
    student_notices,
    students_for_employee,
    timetable_records,
)
from .seed import ensure_seeded


BASE_DIR = Path(__file__).resolve().parent
ensure_seeded()
with SessionLocal() as _chat_index_session:
    ensure_knowledge_index(_chat_index_session)

app = FastAPI(
    title="University of Haripur Local Academic Information Demo",
    description="Standalone public-site and synthetic role-based academic information environment.",
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="university_static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
app.include_router(chatbot_router)


@app.on_event("startup")
async def start_llmguard_heartbeat() -> None:
    config = heartbeat_config_from_env()
    if config is not None:
        app.state.llmguard_heartbeat_task = asyncio.create_task(heartbeat_loop(config))


@app.on_event("shutdown")
async def stop_llmguard_heartbeat() -> None:
    task = getattr(app.state, "llmguard_heartbeat_task", None)
    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    finally:
        del app.state.llmguard_heartbeat_task


def render(request: Request, template: str, status_code: int = 200, **context: object) -> HTMLResponse:
    session_payload = read_session(request.cookies.get(SESSION_COOKIE))
    chatbot_context = "public"
    if request.url.path.startswith("/portal/student/") and session_payload and session_payload.get("portal") == "student" and session_payload.get("role") == "student":
        chatbot_context = "student"
    elif request.url.path.startswith("/portal/employee/") and session_payload and session_payload.get("portal") == "employee" and session_payload.get("role") == "employee":
        chatbot_context = "employee"
    defaults = {
        "request": request,
        "session": session_payload,
        "faculties": FACULTIES,
        "page_title": "The University of Haripur",
        "admissions_shell": False,
        "chatbot_context": chatbot_context,
    }
    defaults.update(context)
    return templates.TemplateResponse(request=request, name=template, context=defaults, status_code=status_code)


async def form_values(request: Request) -> dict[str, str]:
    raw = (await request.body()).decode("utf-8", errors="replace")
    return {key: values[0] for key, values in parse_qs(raw, keep_blank_values=True).items()}


def portal_session(request: Request, portal: str) -> tuple[str, dict[str, object] | None]:
    payload = read_session(request.cookies.get(SESSION_COOKIE))
    if not payload:
        return "login", None
    expected_role = "student" if portal == "student" else "employee"
    if payload.get("portal") != portal or payload.get("role") != expected_role:
        return "denied", payload
    return "ok", payload


def portal_redirect(portal: str) -> RedirectResponse:
    return RedirectResponse(url=f"/portal/{portal}/login", status_code=303)


def access_denied(request: Request, portal: str, message: str = "Your account is not authorized for this resource.") -> HTMLResponse:
    return render(
        request,
        "portal/access_denied.html",
        status_code=403,
        page_title="Access Denied",
        portal_role=portal,
        message=message,
    )


def set_session_cookie(response: Response, user) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        create_session(user),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )


def employee_menu(employee: Employee) -> list[tuple[str, str]]:
    menu = [
        ("Dashboard", "/portal/employee/dashboard"),
        ("Employee Profile", "/portal/employee/profile"),
        ("Attendance", "/portal/employee/attendance"),
        ("Leave", "/portal/employee/leave"),
        ("Assignments", "/portal/employee/assignments"),
        ("Department", "/portal/employee/department"),
        ("Employee Notices", "/portal/employee/notices"),
        ("Policies", "/portal/employee/policies"),
        ("Controlled Records", "/portal/employee/controlled-records"),
        ("Employee Directory", "/portal/employee/directory"),
        ("Organogram", "/portal/employee/organogram"),
        ("AI Assistant Analytics", "/portal/employee/assistant-feedback"),
    ]
    if employee.role_key in {"vice_chancellor", "registrar", "administration", "dean", "hod"} | ACADEMIC_EMPLOYEE_ROLES:
        menu.insert(8, ("Authorized Students", "/portal/employee/students"))
    return menu


def student_context(request: Request) -> tuple[Response | None, dict[str, object] | None, Student | None]:
    state, payload = portal_session(request, "student")
    if state == "login":
        return portal_redirect("student"), None, None
    if state == "denied":
        return access_denied(request, "student"), None, None
    with SessionLocal() as db:
        student = get_student(db, int(payload["user_id"]), str(payload["username"]))
    if not student:
        response = portal_redirect("student")
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response, None, None
    return None, payload, student


def employee_context(request: Request) -> tuple[Response | None, dict[str, object] | None, Employee | None]:
    state, payload = portal_session(request, "employee")
    if state == "login":
        return portal_redirect("employee"), None, None
    if state == "denied":
        return access_denied(request, "employee"), None, None
    with SessionLocal() as db:
        employee = get_employee(db, int(payload["user_id"]), str(payload["username"]))
    if not employee:
        response = portal_redirect("employee")
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response, None, None
    return None, payload, employee


@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request) -> HTMLResponse:
    return render(request, "home.html", home_news=HOME_NEWS, recent_news=RECENT_NEWS)


@app.get("/university")
async def university_root() -> RedirectResponse:
    return RedirectResponse(url="/", status_code=307)


@app.get("/university/about", response_class=HTMLResponse)
async def about(request: Request) -> HTMLResponse:
    return render(request, "public_page.html", page_title="About UOH", heading="About The University of Haripur", paragraphs=[
        "The University of Haripur is represented here through a public-information recreation and wholly synthetic academic demonstration environment.",
        "Its academic structure spans biological and biomedical sciences, information technology and numerical sciences, physical and applied sciences, and social and administrative sciences.",
    ])


@app.get("/university/academics", response_class=HTMLResponse)
async def academics(request: Request) -> HTMLResponse:
    with SessionLocal() as db:
        departments = list(db.scalars(select(Department).options(joinedload(Department.faculty)).order_by(Department.faculty_id, Department.name)))
    return render(request, "public_page.html", page_title="Academics", heading="Academic Departments", departments=departments, paragraphs=["Explore the faculties, departments, and programs represented in this local academic information environment."])


@app.get("/university/departments/{department_slug}", response_class=HTMLResponse)
async def department_page(request: Request, department_slug: str) -> Response:
    with SessionLocal() as db:
        department = db.scalar(select(Department).options(joinedload(Department.faculty), joinedload(Department.programs)).where(Department.slug == department_slug))
        if not department and "-and-" in department_slug:
            department = db.scalar(select(Department).options(joinedload(Department.faculty), joinedload(Department.programs)).where(Department.slug == department_slug.replace("-and-", "-")))
        if not department:
            return render(request, "public_page.html", status_code=404, page_title="Department Not Found", heading="Department Not Found", paragraphs=["The requested local department record does not exist."])
        employees = list(db.scalars(select(Employee).where(Employee.department_id == department.id).order_by(Employee.designation, Employee.full_name)))
    return render(request, "public/department.html", page_title=department.name, department=department, employees=employees)


@app.get("/university/faculties/{faculty_slug}", response_class=HTMLResponse)
async def faculty_page(request: Request, faculty_slug: str) -> Response:
    with SessionLocal() as db:
        faculty = db.scalar(select(Faculty).options(joinedload(Faculty.departments)).where(Faculty.slug == faculty_slug))
        if not faculty:
            return render(request, "public_page.html", status_code=404, page_title="Faculty Not Found", heading="Faculty Not Found", paragraphs=["The requested local faculty record does not exist."])
    return render(request, "public_page.html", page_title=faculty.name, heading=faculty.name, paragraphs=["Select a department to view its local academic information."], departments=faculty.departments)


@app.get("/university/contact", response_class=HTMLResponse)
async def contact(request: Request) -> HTMLResponse:
    return render(request, "public_page.html", page_title="Contact Us", heading="Contact Us", paragraphs=[
        "Registrar Office — Phone: +92-995-920602 — Email: registrar@uoh.edu.pk",
        "Examination Section — Phone: +92-995-920638",
        "Local demo accounts use only the reserved demo.uoh.local domain and never submit information to production authentication services.",
    ])


@app.get("/university/information/{page_slug}", response_class=HTMLResponse)
async def public_information_page(request: Request, page_slug: str) -> Response:
    page = PUBLIC_INFORMATION_PAGES.get(page_slug)
    if not page:
        return render(request, "public_page.html", status_code=404, page_title="Page Not Found", heading="Page Not Found", paragraphs=["The requested local public-information page does not exist."])
    heading, paragraphs, items = page
    return render(request, "public_page.html", page_title=heading, heading=heading, paragraphs=paragraphs, information_items=items)


@app.get("/search", response_class=HTMLResponse)
async def public_search(request: Request, q: str = "") -> HTMLResponse:
    query = q.strip()
    results: list[dict[str, str]] = []
    if query:
        term = f"%{query}%"
        with SessionLocal() as db:
            for department in db.scalars(select(Department).where(or_(Department.name.ilike(term), Department.description.ilike(term))).limit(20)):
                results.append({"type": "Department", "title": department.name, "summary": department.description, "url": f"/university/departments/{department.slug}"})
            for program in db.scalars(select(Program).options(joinedload(Program.department)).where(Program.name.ilike(term)).limit(20)):
                results.append({"type": "Program", "title": program.name, "summary": program.department.name, "url": f"/university/departments/{program.department.slug}"})
            for notice in db.scalars(select(Notice).where(Notice.scope == "PUBLIC", or_(Notice.title.ilike(term), Notice.body.ilike(term))).limit(20)):
                results.append({"type": "Public notice", "title": notice.title, "summary": notice.body, "url": "/"})
            for policy in public_policies(db, query):
                results.append({"type": "Public policy", "title": policy.title, "summary": policy.purpose, "url": f"/university/policies/{policy.policy_id}"})
        lowered = query.lower()
        for slug, (heading, paragraphs, items) in PUBLIC_INFORMATION_PAGES.items():
            searchable = " ".join([heading, *paragraphs, *items]).lower()
            if lowered in searchable:
                results.append({"type": "University page", "title": heading, "summary": paragraphs[0], "url": f"/university/information/{slug}"})
    return render(request, "public/search.html", page_title="Search", query=query, results=results)


@app.get("/university/policies", response_class=HTMLResponse)
async def public_policy_list(request: Request, q: str = "") -> HTMLResponse:
    with SessionLocal() as db:
        policies = public_policies(db, q)
    return render(request, "public/policies.html", page_title="Public Policies", policies=policies, query=q)


@app.get("/university/policies/{policy_id}", response_class=HTMLResponse)
async def public_policy_detail(request: Request, policy_id: str) -> Response:
    with SessionLocal() as db:
        policy = db.get(Policy, policy_id)
        if not policy or policy.classification != "PUBLIC":
            return render(request, "public_page.html", status_code=404, page_title="Policy Not Found", heading="Policy Not Found", paragraphs=["No public policy is available at this address."])
        revisions = policy_revisions(db, policy.policy_id)
    return render(request, "public/policy_detail.html", page_title=policy.title, policy=policy, revisions=revisions)


@app.get("/admissions", response_class=HTMLResponse)
@app.get("/university/admissions", response_class=HTMLResponse)
async def admissions_home(request: Request) -> HTMLResponse:
    return render(request, "admissions/index.html", page_title="Admissions Fall 2026", admissions_shell=True)


@app.get("/university/admissions/programs")
async def programs_redirect() -> RedirectResponse:
    return RedirectResponse(url="/university/admissions/bs-programs", status_code=307)


@app.get("/university/admissions/bs-programs", response_class=HTMLResponse)
async def bs_programs(request: Request) -> HTMLResponse:
    return render(request, "admissions/programs.html", page_title="BS Programs", admissions_shell=True, heading="List of BS Programs Offered (Open Merit)", program_groups=BS_PROGRAMS, concession_programs=CONCESSION_PROGRAMS)


@app.get("/university/admissions/ms-programs", response_class=HTMLResponse)
async def ms_programs(request: Request) -> HTMLResponse:
    return render(request, "admissions/programs.html", page_title="MS/M.Phil Programs", admissions_shell=True, heading="List of MS/M.Phil/M.Sc (Hons) Programs Offered", program_groups=MS_PROGRAMS, scholarship_note=True, concession_programs=set())


@app.get("/university/admissions/phd-programs", response_class=HTMLResponse)
async def phd_programs(request: Request) -> HTMLResponse:
    return render(request, "admissions/programs.html", page_title="Ph.D Programs", admissions_shell=True, heading="List of Ph.D Programs Offered", program_groups=PHD_PROGRAMS, scholarship_note=True, concession_programs=set())


@app.get("/university/admissions/eligibility", response_class=HTMLResponse)
async def eligibility(request: Request) -> HTMLResponse:
    return render(request, "admissions/table_page.html", page_title="Eligibility Criteria", admissions_shell=True, heading="Eligibility Criteria for All Programs", subheading="Eligibility Criteria (BS Programs)", columns=["Department", "Program", "Eligibility Criteria"], rows=ELIGIBILITY_ROWS)


@app.get("/university/admissions/fee", response_class=HTMLResponse)
async def fee_structure(request: Request) -> HTMLResponse:
    return render(request, "admissions/table_page.html", page_title="Fee Structure", admissions_shell=True, heading="Fee Schedule for All Programs", subheading="Fee Schedule of BS/MS/M.Phil/Ph.D Programs for Fall 2026", columns=["Faculty", "Program", "1st Semester", "Subsequent Semesters"], rows=FEE_ROWS, table_note="All amounts are shown in Pakistani Rupees and reproduce the publicly visible schedule for local demonstration.")


@app.get("/university/admissions/schedule", response_class=HTMLResponse)
async def admission_schedule(request: Request) -> HTMLResponse:
    return render(request, "admissions/table_page.html", page_title="Admission Schedule", admissions_shell=True, heading="Admission Schedule (Admissions Fall 2026)", subheading="Admission Schedule for MS/M.Phil/MBA/M.Sc (Hons)/Ph.D Programs", columns=["Activity", "Date"], rows=SCHEDULE_ROWS)


@app.get("/university/admissions/scholarships", response_class=HTMLResponse)
async def scholarships(request: Request) -> HTMLResponse:
    return render(request, "admissions/list_page.html", page_title="Scholarships", admissions_shell=True, heading="Scholarships / Financial Assistance", items=SCHOLARSHIPS)


@app.get("/university/admissions/facilities", response_class=HTMLResponse)
async def facilities(request: Request) -> HTMLResponse:
    return render(request, "admissions/list_page.html", page_title="Facilities", admissions_shell=True, heading="Salient Features of The University of Haripur", items=FACILITIES)


@app.get("/university/admissions/how-to-apply", response_class=HTMLResponse)
async def how_to_apply(request: Request) -> HTMLResponse:
    return render(request, "admissions/how_to_apply.html", page_title="How to Apply", admissions_shell=True)


@app.get("/portal", response_class=HTMLResponse)
async def portal_landing(request: Request) -> HTMLResponse:
    return render(request, "portal/index.html", page_title="Student and Employee Portals")


@app.get("/portal/login")
async def old_portal_login(role: str = "student") -> RedirectResponse:
    target = "employee" if role == "employee" else "student"
    return RedirectResponse(url=f"/portal/{target}/login", status_code=307)


@app.get("/portal/student/login", response_class=HTMLResponse)
async def student_login(request: Request) -> HTMLResponse:
    return render(request, "portal/login.html", page_title="Student Portal Login", portal_type="student", portal_name="Student Portal", demo_accounts=[("student.demo001", "Student@123"), ("student.demo002", "Student@123"), ("student.demo003", "Student@123")])


@app.post("/portal/student/login")
async def student_login_submit(request: Request) -> Response:
    form = await form_values(request)
    with SessionLocal() as db:
        user = authenticate_student(db, form.get("username", ""), form.get("password", ""))
    if not user:
        return render(request, "portal/login.html", status_code=401, page_title="Student Portal Login", portal_type="student", portal_name="Student Portal", error="Invalid student demo username or password. Employee credentials are not accepted here.", demo_accounts=[("student.demo001", "Student@123"), ("student.demo002", "Student@123"), ("student.demo003", "Student@123")])
    response = RedirectResponse(url="/portal/student/dashboard", status_code=303)
    set_session_cookie(response, user)
    return response


@app.get("/portal/employee/login", response_class=HTMLResponse)
async def employee_login(request: Request) -> HTMLResponse:
    return render(request, "portal/login.html", page_title="Employee Portal Login", portal_type="employee", portal_name="Employee Portal", demo_accounts=[("employee.registrar", "Employee@123"), ("employee.lecturer", "Employee@123"), ("employee.hr", "Employee@123"), ("employee.finance", "Employee@123"), ("employee.security", "Employee@123"), ("employee.guard", "Employee@123")])


@app.post("/portal/employee/login")
async def employee_login_submit(request: Request) -> Response:
    form = await form_values(request)
    with SessionLocal() as db:
        user = authenticate_employee(db, form.get("username", ""), form.get("password", ""))
    if not user:
        return render(request, "portal/login.html", status_code=401, page_title="Employee Portal Login", portal_type="employee", portal_name="Employee Portal", error="Invalid employee demo username or password. Student credentials are not accepted here.", demo_accounts=[("employee.registrar", "Employee@123"), ("employee.lecturer", "Employee@123"), ("employee.hr", "Employee@123"), ("employee.finance", "Employee@123"), ("employee.security", "Employee@123"), ("employee.guard", "Employee@123")])
    response = RedirectResponse(url="/portal/employee/dashboard", status_code=303)
    set_session_cookie(response, user)
    return response


@app.post("/portal/student/logout")
async def student_logout() -> RedirectResponse:
    response = RedirectResponse(url="/portal/student/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.post("/portal/employee/logout")
async def employee_logout() -> RedirectResponse:
    response = RedirectResponse(url="/portal/employee/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.post("/portal/logout")
async def generic_logout(request: Request) -> RedirectResponse:
    payload = read_session(request.cookies.get(SESSION_COOKIE)) or {}
    portal = "employee" if payload.get("portal") == "employee" else "student"
    response = RedirectResponse(url=f"/portal/{portal}/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


def render_student_portal(request: Request, student: Student, section: str, **context: object) -> HTMLResponse:
    return render(request, "portal/student_portal.html", page_title=section.replace("_", " ").title(), portal_role="student", student=student, section=section, **context)


@app.get("/portal/student/dashboard", response_class=HTMLResponse)
async def student_dashboard(request: Request) -> Response:
    blocked, _, student = student_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        student = get_student(db, student.id)
        courses = current_enrollments(db, student)
        attendance = attendance_records(db, student)
        fees = fee_records(db, student)
        notices = student_notices(db, student)[:4]
        results = result_records(db, student).get(student.current_semester, [])[:4]
        timetable = timetable_records(db, student)[:3]
    return render_student_portal(request, student, "dashboard", courses=courses, attendance=attendance, fees=fees, notices=notices, results=results, timetable=timetable)


@app.get("/portal/student/profile", response_class=HTMLResponse)
async def student_profile(request: Request) -> Response:
    blocked, _, student = student_context(request)
    return blocked or render_student_portal(request, student, "profile")


@app.get("/portal/student/courses", response_class=HTMLResponse)
async def student_courses(request: Request, q: str = "") -> Response:
    blocked, _, student = student_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        student = get_student(db, student.id)
        courses = current_enrollments(db, student)
        if q:
            term = q.lower()
            courses = [item for item in courses if term in item.course.course_code.lower() or term in item.course.course_title.lower()]
    return render_student_portal(request, student, "courses", courses=courses, query=q)


@app.get("/portal/student/courses/{course_code}", response_class=HTMLResponse)
async def student_course_detail(request: Request, course_code: str) -> Response:
    blocked, _, student = student_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        enrollment = db.scalar(select(Enrollment).join(Course).options(joinedload(Enrollment.course).joinedload(Course.teacher), joinedload(Enrollment.course).joinedload(Course.department)).where(Enrollment.student_id == student.id, Course.course_code == course_code))
        if not enrollment:
            return access_denied(request, "student", "This course is not part of your academic record.")
    return render_student_portal(request, student, "course_detail", enrollment=enrollment)


@app.get("/portal/student/attendance", response_class=HTMLResponse)
async def student_attendance_page(request: Request) -> Response:
    blocked, _, student = student_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        rows = attendance_records(db, student)
    return render_student_portal(request, student, "attendance", attendance=rows)


@app.get("/portal/student/results", response_class=HTMLResponse)
async def student_results(request: Request, q: str = "") -> Response:
    blocked, _, student = student_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        grouped = result_records(db, student, q)
    summaries = {}
    for semester_number, rows in grouped.items():
        credits = sum(row.enrollment.course.credit_hours for row in rows)
        gpa = sum(row.grade_points * row.enrollment.course.credit_hours for row in rows) / credits if credits else 0
        summaries[semester_number] = {"gpa": round(gpa, 2), "attempted": credits, "earned": credits}
    return render_student_portal(request, student, "results", results=grouped, summaries=summaries, query=q)


@app.get("/portal/student/fees", response_class=HTMLResponse)
async def student_fees(request: Request) -> Response:
    blocked, _, student = student_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        fees = fee_records(db, student)
    return render_student_portal(request, student, "fees", fees=fees)


@app.get("/portal/student/fees/{fee_id}/receipt")
async def student_fee_receipt(request: Request, fee_id: int) -> Response:
    blocked, _, student = student_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        fee = db.scalar(select(FeeRecord).where(FeeRecord.id == fee_id, FeeRecord.student_id == student.id))
        if not fee:
            return access_denied(request, "student", "This fee record is not part of your account.")
    text = f"UNIVERSITY ACADEMIC DEMO RECEIPT\nSynthetic record only\nStudent: {student.full_name}\nRegistration: {student.registration_number}\nSemester: {fee.semester_number}\nPaid: PKR {fee.paid_amount:,}\nOutstanding: PKR {fee.outstanding_amount:,}\nStatus: {fee.payment_status}\n"
    return PlainTextResponse(text, headers={"Content-Disposition": f'attachment; filename="demo-fee-receipt-{fee.id}.txt"'})


@app.get("/portal/student/timetable", response_class=HTMLResponse)
async def student_timetable(request: Request) -> Response:
    blocked, _, student = student_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        timetable = timetable_records(db, student)
    return render_student_portal(request, student, "timetable", timetable=timetable)


@app.get("/portal/student/notices", response_class=HTMLResponse)
async def student_notice_page(request: Request, q: str = "") -> Response:
    blocked, _, student = student_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        notices = student_notices(db, student, q)
    return render_student_portal(request, student, "notices", notices=notices, query=q)


@app.get("/portal/student/documents", response_class=HTMLResponse)
async def student_document_page(request: Request, q: str = "") -> Response:
    blocked, _, student = student_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        documents = student_documents(db, student, q)
    return render_student_portal(request, student, "documents", documents=documents, query=q)


@app.get("/portal/student/documents/{document_id}/download")
async def student_document_download(request: Request, document_id: int) -> Response:
    blocked, _, student = student_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        document = student_document(db, student, document_id)
        if not document:
            return access_denied(request, "student", "This document is not assigned to your student record.")
    content = f"THE UNIVERSITY ACADEMIC DEMONSTRATION\n{document.title}\n\nSynthetic document — not valid for official use.\nStudent: {student.full_name}\nRegistration: {student.registration_number}\nProgram: {student.program.name}\nReference: {document.reference_number}\nIssued: {document.issued_at.isoformat()}\n"
    return PlainTextResponse(content, headers={"Content-Disposition": f'attachment; filename="{document.reference_number}.txt"'})


def render_employee_portal(request: Request, employee: Employee, section: str, **context: object) -> HTMLResponse:
    return render(request, "portal/employee_portal.html", page_title=section.replace("_", " ").title(), portal_role="employee", employee=employee, employee_menu=employee_menu(employee), section=section, **context)


@app.get("/portal/employee/dashboard", response_class=HTMLResponse)
async def employee_dashboard(request: Request) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        employee = get_employee(db, employee.id)
        assignments = employee_assignments(db, employee)
        attendance = employee_attendance(db, employee)[:5]
        leave = employee_leave(db, employee)
        notices = employee_notices(db, employee)[:4]
        policies, policy_page = accessible_policies(db, employee, page_size=10)
        pending_policies = sum(1 for policy in policies if not policy_acknowledgement(db, employee, policy))
    return render_employee_portal(request, employee, "dashboard", assignments=assignments, attendance=attendance, leave=leave, notices=notices, pending_policies=pending_policies, policy_total=policy_page["total"])


@app.get("/portal/employee/profile", response_class=HTMLResponse)
async def employee_profile(request: Request) -> Response:
    blocked, _, employee = employee_context(request)
    return blocked or render_employee_portal(request, employee, "profile")


@app.get("/portal/employee/attendance", response_class=HTMLResponse)
async def employee_attendance_page(request: Request) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        rows = employee_attendance(db, employee)
    return render_employee_portal(request, employee, "attendance", attendance=rows)


@app.get("/portal/employee/leave", response_class=HTMLResponse)
async def employee_leave_page(request: Request, status: str = "") -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        rows = employee_leave(db, employee)
        if status:
            rows = [row for row in rows if row.status == status]
    return render_employee_portal(request, employee, "leave", leave=rows, selected_status=status)


@app.post("/portal/employee/leave")
async def employee_leave_submit(request: Request) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    form = await form_values(request)
    try:
        start = date.fromisoformat(form.get("start_date", ""))
        end = date.fromisoformat(form.get("end_date", ""))
        if end < start:
            raise ValueError
        days = (end - start).days + 1
        if days > employee.leave_balance:
            raise ValueError
    except ValueError:
        return RedirectResponse(url="/portal/employee/leave?error=invalid", status_code=303)
    with SessionLocal() as db:
        db.add(LeaveRequest(employee_id=employee.id, leave_type=form.get("leave_type", "Casual Leave"), opening_balance=employee.leave_balance, used_days=days, remaining_days=max(0, employee.leave_balance - days), request_date=date.today(), start_date=start, end_date=end, status="Pending", approving_authority=employee.reporting_authority, remarks=form.get("remarks", "Synthetic leave request")[:220]))
        db.commit()
    return RedirectResponse(url="/portal/employee/leave?submitted=1", status_code=303)


@app.get("/portal/employee/assignments", response_class=HTMLResponse)
async def employee_assignment_page(request: Request) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        assignments = employee_assignments(db, employee)
    return render_employee_portal(request, employee, "assignments", assignments=assignments, is_faculty=employee.role_key in ACADEMIC_EMPLOYEE_ROLES | {"dean", "hod", "professor", "associate_professor", "assistant_professor", "lecturer"})


@app.get("/portal/employee/assignments/{assignment_id}", response_class=HTMLResponse)
async def employee_assignment_detail(request: Request, assignment_id: int) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        assignment = next((item for item in employee_assignments(db, employee) if item.id == assignment_id), None)
        if not assignment:
            return access_denied(request, "employee", "This assignment is not associated with your employee record.")
    return render_employee_portal(request, employee, "assignment_detail", assignment=assignment)


@app.get("/portal/employee/department", response_class=HTMLResponse)
async def employee_department_page(request: Request) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        employee = get_employee(db, employee.id)
        colleagues = employee_colleagues(db, employee)
        notices = employee_notices(db, employee)[:5]
        head = db.scalar(select(Employee).where(Employee.role_key == "hod")) if employee.department_id else db.scalar(select(Employee).where(Employee.role_key == "registrar"))
    return render_employee_portal(request, employee, "department", colleagues=colleagues, notices=notices, department_head=head)


@app.get("/portal/employee/notices", response_class=HTMLResponse)
async def employee_notice_page(request: Request, q: str = "") -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        notices = employee_notices(db, employee, q)
    return render_employee_portal(request, employee, "notices", notices=notices, query=q)


@app.get("/portal/employee/policies", response_class=HTMLResponse)
async def employee_policy_page(request: Request, q: str = "", category: str = "", classification: str = "", owner: str = "", applies_to: str = "", page: int = 1, page_size: int = 10) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        policies, pagination = accessible_policies(db, employee, q, category, classification, owner, applies_to, page, page_size)
        categories = list(db.scalars(select(Policy.category).distinct().order_by(Policy.category)))
        owners = list(db.scalars(select(Policy.owner).distinct().order_by(Policy.owner)))
        acknowledgements = {policy.policy_id: bool(policy_acknowledgement(db, employee, policy)) for policy in policies}
    return render_employee_portal(request, employee, "policies", policies=policies, pagination=pagination, categories=categories, owners=owners, acknowledgements=acknowledgements, filters={"q": q, "category": category, "classification": classification, "owner": owner, "applies_to": applies_to})


@app.get("/portal/employee/policies/{policy_id}", response_class=HTMLResponse)
async def employee_policy_detail(request: Request, policy_id: str) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        policy = accessible_policy(db, employee, policy_id)
        if not policy:
            return access_denied(request, "employee")
        revisions = policy_revisions(db, policy.policy_id)
        acknowledgement = policy_acknowledgement(db, employee, policy)
    return render_employee_portal(request, employee, "policy_detail", policy=policy, revisions=revisions, acknowledgement=acknowledgement)


@app.post("/portal/employee/policies/{policy_id}/acknowledge")
async def employee_policy_acknowledge(request: Request, policy_id: str) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        policy = accessible_policy(db, employee, policy_id)
        if not policy:
            return access_denied(request, "employee")
        acknowledge_policy(db, employee, policy)
    return RedirectResponse(url=f"/portal/employee/policies/{policy_id}?acknowledged=1", status_code=303)


@app.get("/portal/employee/controlled-records", response_class=HTMLResponse)
async def employee_controlled_page(request: Request, q: str = "", category: str = "", classification: str = "", page: int = 1, page_size: int = 10) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        records, pagination = controlled_records(db, employee, q, category, classification, page, page_size)
        categories = list(db.scalars(select(func.distinct(Department.name)).order_by(Department.name)))
        record_categories = sorted({record.category for record in controlled_records(db, employee, page_size=50)[0]})
    return render_employee_portal(request, employee, "controlled_records", records=records, pagination=pagination, categories=record_categories, filters={"q": q, "category": category, "classification": classification})


@app.get("/portal/employee/controlled-records/{record_id}", response_class=HTMLResponse)
async def employee_controlled_detail(request: Request, record_id: int) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        record, allowed = controlled_record_access(db, employee, record_id)
        if not allowed or not record:
            return access_denied(request, "employee")
    return render_employee_portal(request, employee, "controlled_detail", record=record)


@app.get("/portal/employee/directory", response_class=HTMLResponse)
async def employee_directory_page(request: Request, q: str = "", department: str = "", designation: str = "", category: str = "", office: str = "", status: str = "") -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        employees = directory_for_employee(db, employee, q)
        if department: employees = [item for item in employees if item.organizational_unit == department]
        if designation: employees = [item for item in employees if item.designation == designation]
        if category: employees = [item for item in employees if item.employment_category == category]
        if office: employees = [item for item in employees if item.office == office]
        if status: employees = [item for item in employees if item.employment_status == status]
        all_employees = list(db.scalars(select(Employee)))
    options = {"departments": sorted({item.organizational_unit for item in all_employees}), "designations": sorted({item.designation for item in all_employees}), "categories": sorted({item.employment_category for item in all_employees}), "offices": sorted({item.office for item in all_employees})}
    return render_employee_portal(request, employee, "directory", employees=employees, options=options, filters={"q": q, "department": department, "designation": designation, "category": category, "office": office, "status": status})


@app.get("/portal/employee/students", response_class=HTMLResponse)
async def employee_students_page(request: Request, faculty: str = "", department: str = "", program: str = "", semester: int | None = None, batch: str = "", status: str = "", page: int = 1, page_size: int = 20) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        result = students_for_employee(db, employee, faculty, department, program, semester, batch, status, page, page_size)
        if result is None:
            return access_denied(request, "employee")
        students, pagination = result
        faculties = list(db.scalars(select(Faculty).order_by(Faculty.name)))
        departments = list(db.scalars(select(Department).order_by(Department.name)))
        programs = list(db.scalars(select(Program).order_by(Program.name)))
    return render_employee_portal(request, employee, "students", students=students, pagination=pagination, faculty_options=faculties, department_options=departments, program_options=programs, filters={"faculty": faculty, "department": department, "program": program, "semester": semester or "", "batch": batch, "status": status})


@app.get("/portal/employee/students/{student_id}", response_class=HTMLResponse)
async def employee_student_detail(request: Request, student_id: int) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        candidate = get_student(db, student_id)
        if not candidate:
            return access_denied(request, "employee")
        permitted = employee.role_key in {"vice_chancellor", "registrar", "administration"}
        if employee.role_key in {"dean", "hod"} and employee.department_id == candidate.department_id:
            permitted = True
        if employee.role_key in ACADEMIC_EMPLOYEE_ROLES:
            permitted = bool(db.scalar(select(Enrollment.id).join(Course).where(Enrollment.student_id == candidate.id, Course.teacher_id == employee.id).limit(1)))
        if not permitted:
            return access_denied(request, "employee")
        enrollments = current_enrollments(db, candidate)
        attendance = attendance_records(db, candidate)
    return render_employee_portal(request, employee, "student_detail", selected_student=candidate, enrollments=enrollments, attendance=attendance)


@app.get("/portal/employee/organogram", response_class=HTMLResponse)
async def employee_organogram(request: Request) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        employees = list(db.scalars(select(Employee).order_by(Employee.id)))
    children: dict[int | None, list[Employee]] = {}
    for item in employees:
        children.setdefault(item.supervisor_id, []).append(item)
    return render_employee_portal(request, employee, "organogram", hierarchy=children, root=employees[0])


@app.get("/portal/employee/assistant-feedback", response_class=HTMLResponse)
async def employee_assistant_feedback(request: Request) -> Response:
    blocked, _, employee = employee_context(request)
    if blocked:
        return blocked
    with SessionLocal() as db:
        report = chatbot_analytics(db)
    return render(
        request,
        "portal/assistant_analytics.html",
        page_title="AI Assistant Analytics",
        portal_role="employee",
        employee=employee,
        employee_menu=employee_menu(employee),
        analytics=report,
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "uoh-local-academic-demo", "data": "synthetic-only"}


@app.get("/health/data")
async def health_data() -> dict[str, object]:
    with SessionLocal() as db:
        return data_quality_report(db)
