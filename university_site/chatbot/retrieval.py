from __future__ import annotations

from datetime import datetime, timedelta
import re

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from ..data import (
    BS_PROGRAMS,
    ELIGIBILITY_ROWS,
    FACILITIES,
    FEE_ROWS,
    MS_PROGRAMS,
    PHD_PROGRAMS,
    SCHEDULE_ROWS,
    SCHOLARSHIPS,
)
from ..models import (
    ControlledRecord,
    Course,
    Department,
    Employee,
    EmployeeAttendance,
    EmployeePayroll,
    FeeRecord,
    LeaveRequest,
    Notice,
    Policy,
    PolicyAcknowledgement,
    Result,
    Student,
)
from ..repository import (
    attendance_records,
    current_enrollments,
    fee_records,
    result_records,
    student_documents,
    student_notices,
    timetable_records,
)
from .types import ChatIdentity, RetrievalBundle, SourceReference
from .vector_store import semantic_search


def _source(
    source_type: str,
    source_id: str,
    title: str,
    route: str | None,
    content: str,
    *,
    classification: str = "public",
    portal_scope: str = "public",
    role_scope: str = "",
) -> SourceReference:
    return SourceReference(
        source_type, source_id, title, route, classification, portal_scope, content, role_scope
    )


def _bundle(
    topic: str,
    answer: str,
    sources: list[SourceReference],
    retrieval_type: str = "structured",
    answer_status: str = "supported",
) -> RetrievalBundle:
    return RetrievalBundle(
        retrieval_type=retrieval_type,
        topic=topic,
        context="\n".join(source.content for source in sources),
        sources=sources,
        grounded_answer=answer,
        answer_status=answer_status,
    )


def _not_found(answer: str = "I couldn't find that information in the university records available to me.", topic: str = "general") -> RetrievalBundle:
    return _bundle(topic, answer, [], answer_status="insufficient_data")


def _restricted(answer: str, topic: str = "security") -> RetrievalBundle:
    return _bundle(topic, answer, [], retrieval_type="blocked", answer_status="access_restricted")


def _tokens(value: str) -> set[str]:
    stop = {"what", "which", "show", "tell", "about", "your", "have", "from", "that", "this", "course", "grade", "marks", "result", "record"}
    return {token for token in re.findall(r"[a-z0-9]+", value.lower()) if len(token) > 2 and token not in stop}


def _best_rows(question: str, rows: list[tuple[str, ...]], limit: int = 4) -> list[tuple[str, ...]]:
    query_tokens = _tokens(question)
    scored = [(len(query_tokens & _tokens(" ".join(row))), row) for row in rows]
    matched = [row for score, row in sorted(scored, key=lambda item: item[0], reverse=True) if score > 0]
    return matched[:limit] or rows[:limit]


def _program_bundle(question: str) -> RetrievalBundle:
    lowered = question.lower()
    if "phd" in lowered or "ph.d" in lowered or "doctoral" in lowered:
        level, groups, route = "PhD", PHD_PROGRAMS, "/university/admissions/phd-programs"
    elif re.search(r"\bms\b", lowered) or any(term in lowered for term in ("mphil", "m.phil", "graduate program", "master")):
        level, groups, route = "MS/MPhil", MS_PROGRAMS, "/university/admissions/ms-programs"
    else:
        level, groups, route = "BS", BS_PROGRAMS, "/university/admissions/bs-programs"
    lines = [f"{faculty}: {', '.join(programs)}" for faculty, programs in groups.items()]
    content = "\n".join(lines)
    source = _source("program", f"admissions:{level.lower()}", f"{level} Programs", route, content)
    return _bundle("programs", f"The Fall 2026 admissions records list these {level} programs:\n\n" + "\n".join(f"• {line}" for line in lines), [source])


def _admission_schedule() -> RetrievalBundle:
    answer = "The canonical Fall 2026 admission schedule is:\n\n" + "\n".join(
        f"• {activity}: {day}" for activity, day in SCHEDULE_ROWS
    )
    return _bundle(
        "admissions",
        answer,
        [_source("admissions", "admissions:schedule", "Fall 2026 Admission Schedule", "/university/admissions/schedule", answer)],
    )


def _public_structured(question: str, current_page: str = "/") -> RetrievalBundle | None:
    lowered = question.lower()
    if any(term in lowered for term in ("explain this page", "help on this page", "what can i ask here")):
        if current_page.endswith("/eligibility"):
            lowered += " eligibility requirements"
        elif current_page.endswith("/fee"):
            lowered += " fee structure"
        elif current_page.endswith("/schedule"):
            lowered += " admission schedule"
        elif current_page.endswith("/bs-programs"):
            lowered += " bs programs"
    if "eligib" in lowered or "requirement" in lowered and any(term in lowered for term in ("admission", "program", "software", "computer")):
        rows = list(ELIGIBILITY_ROWS)
        if "software engineering" in lowered:
            rows = [row for row in rows if row[0] == "Information Technology"]
        else:
            rows = _best_rows(question, rows)
        answer = "Admission eligibility in the Fall 2026 records:\n\n" + "\n".join(
            f"• {program} ({department}): {criteria}" for department, program, criteria in rows
        )
        return _bundle("admissions", answer, [_source("admissions", "admissions:eligibility", "Admission Eligibility Criteria", "/university/admissions/eligibility", answer)])
    if any(term in lowered for term in ("deadline", "admission schedule", "last date", "entry test", "merit list", "admission process", "application process", "explain the admission")):
        return _admission_schedule()
    if "scholarship" in lowered or "financial assistance" in lowered:
        answer = "The public admissions records list these scholarships and fee-support options:\n\n" + "\n".join(f"• {item}" for item in SCHOLARSHIPS)
        return _bundle("scholarships", answer, [_source("admissions", "admissions:scholarships", "Scholarships and Financial Assistance", "/university/admissions/scholarships", answer)])
    if any(term in lowered for term in ("how can i apply", "how to apply", "apply for admission")):
        schedule = " ".join(f"{activity}: {day}." for activity, day in SCHEDULE_ROWS)
        answer = (
            "Review the program and eligibility criteria, prepare the required academic documents, complete the online application, "
            "and submit it by 1st September 2026. The remaining verified sequence is: entry test on 6th September, result on 8th September, "
            "interviews on 9th–10th September, merit list on 11th September, fee submission by 16th September, registration on 21st–25th September, and classes from 28th September 2026."
        )
        return _bundle("admissions", answer, [_source("admissions", "admissions:schedule", "Fall 2026 Admission Schedule", "/university/admissions/schedule", schedule)])
    if "fee structure" in lowered or "program fee" in lowered or "admission fee" in lowered:
        rows = _best_rows(question, list(FEE_ROWS), limit=5)
        answer = "Published program fees (PKR):\n\n" + "\n".join(
            f"• {program}: first semester {first}; subsequent semesters {later}" for _faculty, program, first, later in rows
        )
        return _bundle("fees", answer, [_source("admissions", "admissions:fee", "Public Fee Structure", "/university/admissions/fee", answer)])
    if "facilit" in lowered or any(term in lowered for term in ("hostel", "transport", "library")) and "policy" not in lowered:
        answer = "Public university facilities include:\n\n" + "\n".join(f"• {item}" for item in FACILITIES)
        return _bundle("facilities", answer, [_source("public_page", "public:facilities", "University Facilities", "/university/admissions/facilities", answer)])
    if "program" in lowered or "degree" in lowered or "courses offered" in lowered:
        return _program_bundle(question)
    return None


def _all_student_results(session: Session, student: Student) -> list[Result]:
    return [item for semester in result_records(session, student).values() for item in semester]


def _course_from_history(session: Session, student: Student, history: list[str]) -> Course | None:
    courses = {item.course.id: item.course for item in current_enrollments(session, student)}
    for result in _all_student_results(session, student):
        courses[result.enrollment.course.id] = result.enrollment.course
    for message in reversed(history):
        if not message.lower().startswith("assistant:"):
            continue
        lowered = message.lower()
        for course in courses.values():
            if course.course_title.lower() in lowered or course.course_code.lower() in lowered:
                return course
    return None


def _requested_course(session: Session, student: Student, question: str, history: list[str]) -> tuple[Course | None, str | None, bool]:
    lowered = question.lower()
    pronoun = any(term in lowered for term in ("that course", "that subject", "which one", "the course we discussed"))
    if pronoun:
        return _course_from_history(session, student, history), None, True
    match = re.search(r"(?:grade|marks?|result)\s+(?:did\s+i\s+get\s+)?(?:for|in|of)\s+(.+?)[?.!]*$", question, flags=re.IGNORECASE)
    requested_name = match.group(1).strip(" .?!") if match else None
    if not requested_name:
        return None, None, False
    records = _all_student_results(session, student)
    normalized = _tokens(requested_name)
    for result in records:
        course = result.enrollment.course
        if requested_name.lower() in {course.course_title.lower(), course.course_code.lower()}:
            return course, requested_name, False
        title_tokens = _tokens(f"{course.course_code} {course.course_title}")
        if normalized and normalized.issubset(title_tokens):
            return course, requested_name, False
    return None, requested_name, False


def _course_grade_bundle(session: Session, student: Student, course: Course) -> RetrievalBundle:
    result = session.scalar(
        select(Result)
        .join(Result.enrollment)
        .where(Result.enrollment.has(student_id=student.id, course_id=course.id))
    )
    if result is None:
        return _not_found(f"I couldn't find {course.course_title} in your academic record.", "results")
    answer = (
        f"{course.course_title} ({course.course_code})\n"
        f"Marks: {result.marks:.0f}\nGrade: {result.grade}\nGrade points: {result.grade_points:.2f}\n"
        f"Semester: {result.enrollment.semester_number}\nResult status: {result.examination_status}"
    )
    return _bundle("results", answer, [_source("result", f"student:{student.id}:result:{result.id}", f"Course Result — {course.course_title}", "/portal/student/results", answer, classification="student_self", portal_scope="student")])


def _student_structured(session: Session, identity: ChatIdentity, question: str, history: list[str], current_page: str) -> RetrievalBundle | None:
    student = identity.student
    if student is None:
        return None
    lowered = question.lower()
    if any(term in lowered for term in ("explain this page", "help on this page", "what can i ask here")):
        if current_page.startswith("/portal/student/results"):
            lowered += " latest results"
        elif current_page.startswith("/portal/student/attendance"):
            lowered += " attendance"
        elif current_page.startswith("/portal/student/fees"):
            lowered += " fee status"
        elif current_page.startswith("/portal/student/timetable"):
            lowered += " timetable"

    fee_intent = any(term in lowered for term in ("fee", "outstanding amount", "outstanding fees", "paid my", "payment status", "voucher"))
    if fee_intent:
        records = fee_records(session, student)
        current = next((item for item in records if item.semester_number == student.current_semester), records[0] if records else None)
        if current is None:
            return _not_found("I couldn't find a fee record for your account.", "fees")
        total = current.tuition + current.admission_fee + current.lab_fee + current.library_fee + current.transport_fee + current.hostel_fee
        answer = (
            f"Your semester {current.semester_number} fee record is {current.payment_status}.\n"
            f"Total assessed fee: PKR {total:,}\nScholarship/waiver: PKR {current.scholarship_waiver:,}\n"
            f"Paid amount: PKR {current.paid_amount:,}\nOutstanding amount: PKR {current.outstanding_amount:,}\n"
            f"Due date: {current.due_date:%d %B %Y}\nPayment status: {current.payment_status}"
        )
        return _bundle("fees", answer, [_source("fee", f"student:{student.id}:fee:{current.id}", f"Student Fee Record — Semester {current.semester_number}", "/portal/student/fees", answer, classification="student_self", portal_scope="student")])

    result_intent = any(term in lowered for term in ("grade", "marks", "result"))
    if result_intent:
        requested_course, requested_name, pronoun = _requested_course(session, student, question, history)
        if requested_course:
            return _course_grade_bundle(session, student, requested_course)
        if requested_name:
            return _not_found(f"I couldn't find {requested_name} in your academic record.", "results")
        if pronoun:
            return _not_found("Which course do you mean?", "results")

    if "attendance policy" in lowered or "attendance requirement" in lowered or "explain the attendance" in lowered:
        policy = session.scalar(select(Policy).where(Policy.title == "Attendance and Examination"))
        if policy:
            answer = f"{policy.title} ({policy.policy_id}, version {policy.version})\n\nResponsibilities: {policy.responsibilities}\n\nRules: {policy.rules}\n\nCorrection and appeal: {policy.procedures}"
            return _bundle("policy", answer, [_source("policy", f"policy:student:{policy.policy_id}", f"{policy.title} — {policy.policy_id}", f"/university/policies/{policy.policy_id}" if policy.classification == "PUBLIC" else None, answer, classification="student_self", portal_scope="student")])
    if "policy" in lowered or "what happens" in lowered or "rules" in lowered or "regulation" in lowered:
        return None
    if "cgpa" in lowered or "gpa" in lowered and "grade" not in lowered:
        answer = f"Your current CGPA is {student.cgpa:.2f}. Your academic status is {student.academic_status}."
        return _bundle("results", answer, [_source("student_record", f"student:{student.id}:academic-summary", "Student Academic Record", "/portal/student/results", answer, classification="student_self", portal_scope="student")])
    if "scholarship" in lowered and any(term in lowered for term in ("my", "status", "awarded")):
        answer = f"Your scholarship status is: {student.scholarship_status}."
        return _bundle("profile", answer, [_source("student_record", f"student:{student.id}:scholarship", "Student Scholarship Status", "/portal/student/profile", answer, classification="student_self", portal_scope="student")])
    if any(term in lowered for term in ("library status", "hostel status", "transport status")):
        answer = f"Your service statuses are: library — {student.library_status}; hostel — {student.hostel_status}; transport — {student.transport_status}."
        return _bundle("profile", answer, [_source("student_record", f"student:{student.id}:services", "Student Service Status", "/portal/student/profile", answer, classification="student_self", portal_scope="student")])
    if any(term in lowered for term in ("my profile", "registration", "my department", "my program", "my semester", "advisor")):
        answer = (
            f"Your student record shows {student.full_name}, registration {student.registration_number}, "
            f"{student.program.name} in the Department of {student.department.name}, semester {student.current_semester}, "
            f"section {student.section}. Your academic advisor is {student.advisor}."
        )
        return _bundle("profile", answer, [_source("student_record", f"student:{student.id}:profile", "Student Profile", "/portal/student/profile", answer, classification="student_self", portal_scope="student")])
    if "lowest attendance" in lowered:
        records = attendance_records(session, student)
        if not records:
            return _not_found("I couldn't find current attendance records for your account.", "attendance")
        record = min(records, key=lambda item: item.percentage)
        course = record.enrollment.course
        answer = f"Your lowest current attendance is {record.percentage:.1f}% in {course.course_title} ({course.course_code}); its status is {record.status}."
        return _bundle("attendance", answer, [_source("attendance", f"student:{student.id}:attendance:{record.id}", f"Course Attendance Record — {course.course_title}", "/portal/student/attendance", answer, classification="student_self", portal_scope="student")])
    if "attendance" in lowered:
        records = attendance_records(session, student)
        query_tokens = _tokens(question)
        matched = [item for item in records if query_tokens and query_tokens.issubset(_tokens(f"{item.enrollment.course.course_code} {item.enrollment.course.course_title}"))]
        selected = matched or records
        if not selected:
            return _not_found("I couldn't find current attendance records for your account.", "attendance")
        answer = "Your current course attendance is:\n\n" + "\n".join(
            f"• {item.enrollment.course.course_title} ({item.enrollment.course.course_code}): {item.percentage:.1f}% — {item.status}"
            for item in selected
        )
        return _bundle("attendance", answer, [_source("attendance", f"student:{student.id}:attendance", "Course Attendance Record", "/portal/student/attendance", answer, classification="student_self", portal_scope="student")])
    if "lowest grade" in lowered:
        records = _all_student_results(session, student)
        if not records:
            return _not_found(topic="results")
        return _course_grade_bundle(session, student, min(records, key=lambda item: (item.grade_points, item.marks)).enrollment.course)
    if any(term in lowered for term in ("result", "grade", "marks", "latest subject")):
        records = _all_student_results(session, student)
        if not records:
            return _not_found("I couldn't find academic results for your account.", "results")
        answer = "Your academic results are:\n\n" + "\n".join(
            f"• Semester {item.enrollment.semester_number} — {item.enrollment.course.course_title}: {item.marks:.0f} marks, grade {item.grade} ({item.grade_points:.2f}), {item.examination_status}"
            for item in records[:8]
        )
        return _bundle("results", answer, [_source("result", f"student:{student.id}:results", "Student Academic Results", "/portal/student/results", answer, classification="student_self", portal_scope="student")])
    if any(term in lowered for term in ("timetable", "class", "classes", "schedule")):
        records = timetable_records(session, student)
        target_day = next((day for day in ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday") if day.lower() in lowered), None)
        if "tomorrow" in lowered:
            target_day = (datetime.now() + timedelta(days=1)).strftime("%A")
        selected = [item for item in records if not target_day or item.day == target_day]
        if not selected:
            return _not_found(f"No classes are listed for {target_day or 'that time'} in your current timetable.", "timetable")
        answer = f"Your {'classes for ' + target_day if target_day else 'current timetable'}:\n\n" + "\n".join(
            f"• {item.day}, {item.start_time}–{item.end_time}: {item.enrollment.course.course_title} in {item.room}"
            for item in selected
        )
        return _bundle("timetable", answer, [_source("timetable", f"student:{student.id}:timetable", "Student Timetable", "/portal/student/timetable", answer, classification="student_self", portal_scope="student")])
    if any(term in lowered for term in ("course", "enrolled", "taking", "subjects")):
        records = current_enrollments(session, student)
        answer = f"You are enrolled in {len(records)} courses this semester:\n\n" + "\n".join(
            f"• {item.course.course_code} — {item.course.course_title} ({item.course.credit_hours} credit hours)" for item in records
        )
        return _bundle("courses", answer, [_source("enrollment", f"student:{student.id}:courses", f"Current Enrollment — Semester {student.current_semester}", "/portal/student/courses", answer, classification="student_self", portal_scope="student")])
    if "notice" in lowered or "announcement" in lowered:
        records = student_notices(session, student)
        if not records:
            return _not_found(topic="notices")
        answer = "Your current student notices are:\n\n" + "\n".join(f"• {item.title}: {item.body}" for item in records[:8])
        return _bundle("notices", answer, [_source("notice", f"student:{student.id}:notices", "Student Notices", "/portal/student/notices", answer, classification="student_self", portal_scope="student")])
    if "document" in lowered or "certificate" in lowered or "admit card" in lowered:
        records = student_documents(session, student)
        if not records:
            return _not_found(topic="documents")
        answer = "Documents available to your account:\n\n" + "\n".join(f"• {item.title} — {item.reference_number}" for item in records)
        return _bundle("documents", answer, [_source("student_document", f"student:{student.id}:documents", "Student Documents", "/portal/student/documents", answer, classification="student_self", portal_scope="student")])
    return _public_structured(question, current_page)


def _history_student_id(history: list[str]) -> str | None:
    for text in reversed(history):
        match = re.search(r"UOH-DEMO-STU-\d{4}", text, flags=re.IGNORECASE)
        if match:
            return match.group(0).upper()
    return None


def _employee_student_query(session: Session, question: str, history: list[str]) -> RetrievalBundle | None:
    lowered = question.lower()
    student_id_match = re.search(r"UOH-DEMO-STU-\d{4}", question, flags=re.IGNORECASE)
    student_id = student_id_match.group(0).upper() if student_id_match else None
    if not student_id and any(term in lowered for term in ("this student", "their attendance", "their result", "this record")):
        student_id = _history_student_id(history)
    student = session.scalar(select(Student).options(joinedload(Student.department), joinedload(Student.program)).where(Student.student_id == student_id)) if student_id else None
    if student_id and not student:
        return _not_found(f"I couldn't find {student_id} in the synthetic student registry.", "student_search")
    if student:
        if "attendance" in lowered:
            records = attendance_records(session, student)
            answer = f"Attendance for {student.student_id}:\n\n" + "\n".join(f"• {item.enrollment.course.course_title}: {item.percentage:.1f}%" for item in records)
            return _bundle("student_search", answer, [_source("attendance", f"employee:student:{student.id}:attendance", f"Course Attendance Record — {student.student_id}", None, answer, classification="admin_only", portal_scope="employee")])
        if "fee" in lowered or "payment" in lowered or "outstanding" in lowered:
            records = fee_records(session, student)
            current = next((item for item in records if item.semester_number == student.current_semester), records[0] if records else None)
            if current is None:
                return _not_found(topic="student_search")
            answer = f"Fee record for {student.student_id}, semester {current.semester_number}: {current.payment_status}; paid PKR {current.paid_amount:,}; outstanding PKR {current.outstanding_amount:,}; due {current.due_date:%d %B %Y}."
            return _bundle("student_search", answer, [_source("fee", f"employee:student:{student.id}:fee:{current.id}", f"Student Fee Record — {student.student_id}", None, answer, classification="admin_only", portal_scope="employee")])
        if any(term in lowered for term in ("result", "grade", "cgpa")):
            if "cgpa" in lowered:
                answer = f"{student.student_id} has a current CGPA of {student.cgpa:.2f} and academic status {student.academic_status}."
            else:
                results = _all_student_results(session, student)[:10]
                answer = f"Recent results for {student.student_id}:\n\n" + "\n".join(f"• {item.enrollment.course.course_title}: {item.grade} ({item.marks:.0f}), {item.examination_status}" for item in results)
            return _bundle("student_search", answer, [_source("result", f"employee:student:{student.id}:results", f"Student Academic Record — {student.student_id}", None, answer, classification="admin_only", portal_scope="employee")])
        if any(term in lowered for term in ("course", "enrolled", "taking")):
            records = current_enrollments(session, student)
            answer = f"Current courses for {student.student_id}:\n\n" + "\n".join(f"• {item.course.course_code} — {item.course.course_title}" for item in records)
            return _bundle("student_search", answer, [_source("enrollment", f"employee:student:{student.id}:courses", f"Current Courses — {student.student_id}", None, answer, classification="admin_only", portal_scope="employee")])
        answer = (
            f"{student.student_id} — {student.full_name}; registration {student.registration_number}; {student.program.name}, "
            f"Department of {student.department.name}; semester {student.current_semester}; CGPA {student.cgpa:.2f}; "
            f"attendance {student.attendance_percentage:.1f}%; fee status {student.fee_status}."
        )
        return _bundle("student_search", answer, [_source("student_record", f"employee:student:{student.id}", f"Student Record — {student.student_id}", None, answer, classification="admin_only", portal_scope="employee")])

    if any(term in lowered for term in ("students in", "show students", "list students", "students enrolled", "student count", "student registry")):
        statement = select(Student).options(joinedload(Student.department), joinedload(Student.program))
        semester_match = re.search(r"semester\s+(\d+)", lowered)
        if semester_match:
            statement = statement.where(Student.current_semester == int(semester_match.group(1)))
        if "software engineering" in lowered or "computer science" in lowered:
            statement = statement.join(Department).where(Department.name == "Information Technology")
        else:
            departments = list(session.scalars(select(Department)))
            matched = next((item for item in departments if item.name.lower() in lowered), None)
            if matched:
                statement = statement.where(Student.department_id == matched.id)
        records = list(session.scalars(statement.order_by(Student.student_id)))
        shown = records[:10]
        answer = f"The synthetic registry contains {len(records)} matching students. Showing up to 10:\n\n" + "\n".join(
            f"• {item.student_id} — {item.full_name}, {item.program.name}, semester {item.current_semester}" for item in shown
        )
        return _bundle("student_search", answer, [_source("student_registry", "employee:student-registry-query", "Synthetic Student Registry", None, answer, classification="admin_only", portal_scope="employee")])
    return None


def _role_allowed(allowed_roles: str, role: str) -> bool:
    return role in {item.strip() for item in allowed_roles.split(",") if item.strip()}


def _employee_policy_bundle(session: Session, identity: ChatIdentity, question: str) -> RetrievalBundle | None:
    lowered = question.lower()
    role = identity.employee.role_key if identity.employee else ""
    responsibility_queries = {
        "vice chancellor": "Vice Chancellor",
        "registrar": "Registrar",
        "treasurer": "Finance",
        "controller of examinations": "Examinations",
        "dean": "Dean",
        "head of department": "Head of Department",
        "professor": "Faculty",
        "associate professor": "Faculty",
        "assistant professor": "Faculty",
        "lecturer": "Faculty",
        "security guard": "Security Guard",
        "security supervisor": "Security Department",
        "security officer": "Security Department",
        "human resources": "Human Resources",
        "hr officer": "Human Resources",
        "finance officer": "Finance",
        "accounts officer": "Finance",
        "accountant": "Finance",
        "examination officer": "Examinations",
        "it staff": "Information Technology",
        "system administrator": "Information Technology",
        "librarian": "Library",
        "library assistant": "Library",
        "laboratory staff": "Laboratory",
        "student affairs": "Student Affairs",
        "hostel staff": "Hostel",
        "transport staff": "Transport",
        "office assistant": "Support Staff",
        "driver": "Support Staff",
        "maintenance": "Support Staff",
    }
    target_category = next((category for phrase, category in responsibility_queries.items() if phrase in lowered), None)
    attendance = "attendance policy" in lowered or "explain the attendance" in lowered
    policy_intent = "polic" in lowered or "responsibilit" in lowered or attendance
    if not policy_intent:
        return None
    statement = select(Policy).order_by(Policy.policy_id)
    classification = next((item for item in ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED") if item.lower() in lowered), None)
    if classification:
        statement = statement.where(Policy.classification == classification)
    if attendance:
        statement = statement.where(Policy.title == "Attendance and Examination")
    elif target_category:
        statement = statement.where(Policy.category == target_category)
    else:
        meaningful = _tokens(question) - {"university", "policies", "policy", "restricted", "internal", "confidential", "public", "search"}
        if meaningful:
            clauses = [Policy.title.ilike(f"%{term}%") for term in meaningful]
            statement = statement.where(or_(*clauses))
    policies = [item for item in session.scalars(statement) if _role_allowed(item.allowed_roles, role)]
    if not policies:
        return _not_found("I couldn't find an authorized matching policy in the university records available to you.", "policy")
    if attendance:
        policy = policies[0]
        answer = f"{policy.title} ({policy.policy_id}, version {policy.version})\n\nResponsibilities: {policy.responsibilities}\n\nRules: {policy.rules}\n\nProcedure and appeal: {policy.procedures}"
        selected = [policy]
    elif target_category and "responsibilit" in lowered:
        selected = policies[:4]
        answer = f"Responsibilities — {target_category}:\n\n" + policies[0].responsibilities
    else:
        selected = policies[:8]
        answer = "Authorized matching university policies:\n\n" + "\n".join(
            f"• {item.title} ({item.policy_id}, {item.classification}, version {item.version}) — {item.purpose}" for item in selected
        )
    sources = [
        _source("policy", f"policy:employee:{item.policy_id}", f"{item.title} — {item.policy_id}", f"/portal/employee/policies/{item.policy_id}", " ".join((item.purpose, item.responsibilities, item.rules, item.procedures)), classification="admin_only", portal_scope="employee", role_scope=item.allowed_roles)
        for item in selected
    ]
    return _bundle("policy", answer, sources)


def _controlled_bundle(session: Session, identity: ChatIdentity, question: str) -> RetrievalBundle | None:
    lowered = question.lower()
    category = None
    if "hr" in lowered or "human resources" in lowered:
        category = "HR"
    elif "finance" in lowered or "budget" in lowered or "procurement" in lowered:
        category = "Finance"
    elif "exam" in lowered:
        category = "Examination"
    elif "security" in lowered or "incident" in lowered:
        category = "Security"
    controlled_intent = category is not None or any(term in lowered for term in ("controlled record", "institutional record"))
    if not controlled_intent:
        return None
    records = list(session.scalars(select(ControlledRecord).order_by(ControlledRecord.created_at.desc())))
    if category == "Finance":
        records = [item for item in records if item.category in {"Finance", "Procurement"}]
    elif category:
        records = [item for item in records if item.category == category]
    role = identity.employee.role_key if identity.employee else ""
    records = [item for item in records if _role_allowed(item.allowed_roles, role)][:8]
    if not records:
        return _not_found("I couldn't find an authorized matching institutional record.", "controlled_records")
    answer = "Authorized synthetic institutional records:\n\n" + "\n".join(
        f"• {item.record_code} — {item.title} [{item.classification}]: {item.summary}" for item in records
    )
    sources = [_source("controlled_record", f"controlled:{item.record_code}", item.title, None, item.summary, classification="admin_only", portal_scope="employee", role_scope=item.allowed_roles) for item in records]
    return _bundle("controlled_records", answer, sources)


def _employee_structured(session: Session, identity: ChatIdentity, question: str, history: list[str], current_page: str) -> RetrievalBundle | None:
    lowered = question.lower()
    employee = identity.employee
    role = employee.role_key if employee else ""
    if "how many students" in lowered and "department" not in lowered and "each" not in lowered:
        total = int(session.scalar(select(func.count(Student.id))) or 0)
        answer = f"The live synthetic university registry contains {total} students."
        return _bundle("statistics", answer, [_source("statistics", "stats:students", "Synthetic Student Registry Count", None, answer, classification="admin_only", portal_scope="employee")])
    if "how many employees" in lowered and "department" not in lowered and "each" not in lowered and "finance" not in lowered:
        total = int(session.scalar(select(func.count(Employee.id))) or 0)
        answer = f"The live synthetic employee directory contains {total} employees."
        return _bundle("statistics", answer, [_source("statistics", "stats:employees", "Synthetic Employee Directory Count", "/portal/employee/directory", answer, classification="staff_only", portal_scope="employee")])
    if "department" in lowered and any(term in lowered for term in ("student count", "students belong", "most students", "each department", "students are in")):
        rows = session.execute(select(Department.name, func.count(Student.id)).outerjoin(Student).group_by(Department.id).order_by(func.count(Student.id).desc(), Department.name)).all()
        answer = "Student counts by department:\n\n" + "\n".join(f"• {name}: {count}" for name, count in rows)
        return _bundle("statistics", answer, [_source("statistics", "stats:students-by-department", "Student Counts by Department", None, answer, classification="admin_only", portal_scope="employee")])
    if "employees" in lowered and ("each department" in lowered or "finance" in lowered or "by department" in lowered):
        rows = session.execute(select(Employee.organizational_unit, func.count(Employee.id)).group_by(Employee.organizational_unit).order_by(Employee.organizational_unit)).all()
        if "finance" in lowered:
            rows = [row for row in rows if any(term in row[0].lower() for term in ("finance", "treasurer", "account"))]
        answer = "Employee counts by organizational unit:\n\n" + "\n".join(f"• {unit}: {count}" for unit, count in rows)
        return _bundle("statistics", answer, [_source("statistics", "stats:employees-by-unit", "Employee Counts by Unit", "/portal/employee/directory", answer, classification="staff_only", portal_scope="employee")])
    if "policies" in lowered and "classified" in lowered:
        classification = next((item for item in ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED") if item.lower() in lowered), None)
        if classification:
            total = int(session.scalar(select(func.count(Policy.policy_id)).where(Policy.classification == classification)) or 0)
            answer = f"There are {total} synthetic university policies classified {classification}."
            return _bundle("statistics", answer, [_source("policy", f"stats:policies:{classification.lower()}", f"{classification} Policy Count", None, answer, classification="admin_only", portal_scope="employee")])

    policy_bundle = _employee_policy_bundle(session, identity, question)
    if policy_bundle:
        return policy_bundle
    student_bundle = _employee_student_query(session, question, history)
    if student_bundle:
        return student_bundle

    if any(term in lowered for term in ("payroll", "compensation", "salary")):
        if role not in {"vice_chancellor", "registrar", "finance", "hr"}:
            return _restricted("Your Employee Portal role is not authorized to view payroll records.", "payroll")
        statement = select(EmployeePayroll).options(joinedload(EmployeePayroll.employee)).order_by(EmployeePayroll.employee_id)
        if "my " in lowered and employee:
            statement = statement.where(EmployeePayroll.employee_id == employee.id)
        rows = list(session.scalars(statement.limit(10)))
        if not rows:
            return _not_found(topic="payroll")
        answer = "Authorized synthetic payroll records for August 2026:\n\n" + "\n".join(
            f"• {item.employee.employee_number} — {item.employee.full_name}: basic PKR {item.basic_pay:,}; allowances PKR {item.allowances:,}; deductions PKR {item.deductions:,}; net PKR {item.net_pay:,}; {item.payment_status}" for item in rows
        )
        return _bundle("payroll", answer, [_source("employee_payroll", "employee:payroll:2026-08", "Employee Payroll Records — August 2026", None, answer, classification="admin_only", portal_scope="employee", role_scope="vice_chancellor,registrar,finance,hr")])

    if "leave" in lowered:
        if "my " not in lowered and role not in {"vice_chancellor", "registrar", "hr", "administration"}:
            return _restricted("Your Employee Portal role is not authorized to view other employees' leave records.", "leave")
        statement = select(LeaveRequest).options(joinedload(LeaveRequest.employee)).order_by(LeaveRequest.request_date.desc(), LeaveRequest.employee_id)
        if "my " in lowered and employee:
            statement = statement.where(LeaveRequest.employee_id == employee.id)
        else:
            requested_employee = re.search(r"UOH-DEMO-EMP-(\d{3})", question, flags=re.IGNORECASE)
            if requested_employee:
                target = session.scalar(select(Employee.id).where(Employee.employee_number == requested_employee.group(0).upper()))
                statement = statement.where(LeaveRequest.employee_id == target) if target else statement.where(LeaveRequest.id == -1)
        rows = list(session.scalars(statement.limit(10)))
        if not rows:
            return _not_found(topic="leave")
        answer = "Authorized employee leave records:\n\n" + "\n".join(
            f"• {item.employee.employee_number} — {item.leave_type}, {item.start_date:%d %b %Y} to {item.end_date:%d %b %Y}; {item.status}; remaining balance {item.remaining_days} days" for item in rows
        )
        return _bundle("leave", answer, [_source("employee_leave", "employee:leave:summary", "Employee Leave Records", "/portal/employee/leave", answer, classification="staff_only", portal_scope="employee", role_scope="vice_chancellor,registrar,hr,administration")])

    if employee and any(term in lowered for term in ("my profile", "my employee record", "my employment")):
        answer = f"{employee.employee_number} — {employee.full_name}; {employee.designation}, {employee.organizational_unit}; {employee.employment_category}, {employee.grade_or_scale}; joined {employee.joining_date:%d %B %Y}; status {employee.employment_status}; reporting authority {employee.reporting_authority}."
        return _bundle("employee_profile", answer, [_source("employee_record", f"employee:{employee.id}:profile", "Employee Profile", "/portal/employee/profile", answer, classification="staff_only", portal_scope="employee")])

    employee_number = re.search(r"UOH-DEMO-EMP-\d{3}", question, flags=re.IGNORECASE)
    directory_intent = employee_number or any(term in lowered for term in ("find employee", "employee record", "employee directory", "head of", "who is the"))
    if directory_intent:
        statement = select(Employee).options(joinedload(Employee.department))
        if employee_number:
            statement = statement.where(Employee.employee_number == employee_number.group(0).upper())
        elif "head" in lowered:
            statement = statement.where(Employee.role_key == "hod")
        records = list(session.scalars(statement.order_by(Employee.employee_number).limit(10)))
        if not records:
            return _not_found(topic="employee_search")
        if employee_number and "attendance" in lowered:
            target = records[0]
            attendance = list(session.scalars(select(EmployeeAttendance).where(EmployeeAttendance.employee_id == target.id).order_by(EmployeeAttendance.attendance_date.desc()).limit(10)))
            answer = f"Recent attendance for {target.employee_number}:\n\n" + "\n".join(f"• {item.attendance_date:%d %b %Y}: {item.status}, {item.check_in}–{item.check_out}, {item.working_hours:.1f} hours" for item in attendance)
            return _bundle("employee_search", answer, [_source("employee_attendance", f"employee:{target.id}:attendance", f"Employee Attendance — {target.employee_number}", None, answer, classification="staff_only", portal_scope="employee")])
        answer = "Matching employee records:\n\n" + "\n".join(f"• {item.employee_number} — {item.full_name}, {item.designation}, {item.organizational_unit}" for item in records)
        return _bundle("employee_search", answer, [_source("employee_directory", "employee:directory-query", "Synthetic Employee Directory", "/portal/employee/directory", answer, classification="staff_only", portal_scope="employee")])

    if "notice" in lowered or "announcement" in lowered:
        rows = list(session.scalars(select(Notice).where(Notice.scope.in_(["ALL_EMPLOYEES", "ADMINISTRATION", "SECURITY", "FINANCE", "HR", "EXAMINATION", "FACULTY", "DEPARTMENT_EMPLOYEES"])).order_by(Notice.published_at.desc()).limit(10)))
        if not rows:
            return _not_found(topic="notices")
        answer = "Current employee notices:\n\n" + "\n".join(f"• {item.title}: {item.body}" for item in rows)
        return _bundle("notices", answer, [_source("notice", "employee:notices", "Internal Employee Notices", "/portal/employee/notices", answer, classification="staff_only", portal_scope="employee")])

    if "acknowledg" in lowered and employee:
        total = int(session.scalar(select(func.count(PolicyAcknowledgement.id)).where(PolicyAcknowledgement.employee_id == employee.id)) or 0)
        answer = f"Your employee record contains {total} policy acknowledgement(s)."
        return _bundle("policy", answer, [_source("policy_acknowledgement", f"employee:{employee.id}:policy-acknowledgements", "Policy Acknowledgement Record", "/portal/employee/policies", answer, classification="staff_only", portal_scope="employee")])

    controlled = _controlled_bundle(session, identity, question)
    if controlled:
        return controlled
    return _public_structured(question, current_page)


def retrieve(
    session: Session,
    identity: ChatIdentity,
    question: str,
    history: list[str],
    current_page: str = "/",
) -> RetrievalBundle:
    if identity.portal_context == "student":
        structured = _student_structured(session, identity, question, history, current_page)
    elif identity.portal_context == "employee":
        structured = _employee_structured(session, identity, question, history, current_page)
    else:
        structured = _public_structured(question, current_page)
    if structured:
        return structured

    role_key = identity.employee.role_key if identity.employee else None
    sources = semantic_search(session, question, identity.portal_context, top_k=4, role_key=role_key)
    if not sources:
        return _not_found()
    return RetrievalBundle(
        retrieval_type="semantic",
        topic=sources[0].source_type,
        context="\n\n".join(f"SOURCE: {item.title}\n{item.content}" for item in sources),
        sources=sources,
        answer_status="supported",
    )
