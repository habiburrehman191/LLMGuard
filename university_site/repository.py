from __future__ import annotations

from datetime import date, datetime
from math import ceil
from typing import Any

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.orm import Session, joinedload

from .auth import AuthenticatedUser, verify_password
from .models import (
    AuditEvent,
    ControlledRecord,
    Course,
    Department,
    Employee,
    EmployeeAssignment,
    EmployeeAttendance,
    Enrollment,
    Faculty,
    FeeRecord,
    LeaveRequest,
    Notice,
    Policy,
    PolicyAcknowledgement,
    PolicyRevision,
    Program,
    Result,
    Student,
    StudentAttendance,
    StudentDocument,
    TimetableEntry,
)


def authenticate_student(session: Session, username: str, password: str) -> AuthenticatedUser | None:
    normalized = username.strip().lower()
    student = session.scalar(select(Student).where(Student.username == normalized))
    if not student or not verify_password(normalized, password, student.password_hash):
        return None
    return AuthenticatedUser(student.id, student.username, "student", "student", student.full_name)


def authenticate_employee(session: Session, username: str, password: str) -> AuthenticatedUser | None:
    normalized = username.strip().lower()
    employee = session.scalar(select(Employee).where(Employee.username == normalized))
    if not employee or not verify_password(normalized, password, employee.password_hash):
        return None
    return AuthenticatedUser(employee.id, employee.username, "employee", "employee", employee.full_name)


def get_student(session: Session, user_id: int, username: str | None = None) -> Student | None:
    query = select(Student).options(joinedload(Student.department).joinedload(Department.faculty), joinedload(Student.program)).where(Student.id == user_id)
    if username:
        query = query.where(Student.username == username)
    return session.scalar(query)


def get_employee(session: Session, user_id: int, username: str | None = None) -> Employee | None:
    query = select(Employee).options(joinedload(Employee.department)).where(Employee.id == user_id)
    if username:
        query = query.where(Employee.username == username)
    return session.scalar(query)


def current_enrollments(session: Session, student: Student) -> list[Enrollment]:
    return list(session.scalars(
        select(Enrollment)
        .options(joinedload(Enrollment.course).joinedload(Course.teacher), joinedload(Enrollment.course).joinedload(Course.department))
        .where(Enrollment.student_id == student.id, Enrollment.semester_number == student.current_semester)
        .order_by(Course.course_code)
        .join(Course)
    ).unique())


def attendance_records(session: Session, student: Student) -> list[StudentAttendance]:
    return list(session.scalars(
        select(StudentAttendance)
        .join(Enrollment)
        .options(joinedload(StudentAttendance.enrollment).joinedload(Enrollment.course))
        .where(Enrollment.student_id == student.id, Enrollment.semester_number == student.current_semester)
        .order_by(Enrollment.course_id)
    ).unique())


def result_records(session: Session, student: Student, query_text: str = "") -> dict[int, list[Result]]:
    statement = (
        select(Result)
        .join(Enrollment)
        .join(Course)
        .options(joinedload(Result.enrollment).joinedload(Enrollment.course))
        .where(Enrollment.student_id == student.id)
        .order_by(Enrollment.semester_number.desc(), Course.course_code)
    )
    if query_text:
        term = f"%{query_text.strip()}%"
        statement = statement.where(or_(Course.course_code.ilike(term), Course.course_title.ilike(term), Result.grade.ilike(term)))
    grouped: dict[int, list[Result]] = {}
    for result in session.scalars(statement).unique():
        grouped.setdefault(result.enrollment.semester_number, []).append(result)
    return grouped


def fee_records(session: Session, student: Student) -> list[FeeRecord]:
    return list(session.scalars(select(FeeRecord).where(FeeRecord.student_id == student.id).order_by(FeeRecord.semester_number.desc())))


def timetable_records(session: Session, student: Student) -> list[TimetableEntry]:
    return list(session.scalars(
        select(TimetableEntry)
        .join(Enrollment)
        .options(joinedload(TimetableEntry.enrollment).joinedload(Enrollment.course).joinedload(Course.teacher))
        .where(Enrollment.student_id == student.id, Enrollment.semester_number == student.current_semester)
        .order_by(TimetableEntry.id)
    ).unique())


def student_notices(session: Session, student: Student, query_text: str = "") -> list[Notice]:
    scopes = ["ALL_STUDENTS"]
    conditions = [Notice.scope.in_(scopes)]
    conditions.append(and_(Notice.scope == "DEPARTMENT_STUDENTS", Notice.department_id == student.department_id))
    conditions.append(and_(Notice.scope == "PROGRAM_STUDENTS", Notice.program_id == student.program_id))
    statement = select(Notice).where(or_(*conditions)).order_by(Notice.published_at.desc())
    if query_text:
        term = f"%{query_text.strip()}%"
        statement = statement.where(or_(Notice.title.ilike(term), Notice.body.ilike(term)))
    return list(session.scalars(statement))


def student_documents(session: Session, student: Student, query_text: str = "") -> list[StudentDocument]:
    statement = select(StudentDocument).where(StudentDocument.student_id == student.id)
    if query_text:
        term = f"%{query_text.strip()}%"
        statement = statement.where(or_(StudentDocument.title.ilike(term), StudentDocument.document_type.ilike(term)))
    return list(session.scalars(statement.order_by(StudentDocument.issued_at.desc())))


def student_document(session: Session, student: Student, document_id: int) -> StudentDocument | None:
    return session.scalar(select(StudentDocument).where(StudentDocument.id == document_id, StudentDocument.student_id == student.id))


def employee_attendance(session: Session, employee: Employee) -> list[EmployeeAttendance]:
    return list(session.scalars(select(EmployeeAttendance).where(EmployeeAttendance.employee_id == employee.id).order_by(EmployeeAttendance.attendance_date.desc())))


def employee_leave(session: Session, employee: Employee) -> list[LeaveRequest]:
    return list(session.scalars(select(LeaveRequest).where(LeaveRequest.employee_id == employee.id).order_by(LeaveRequest.request_date.desc())))


def employee_assignments(session: Session, employee: Employee) -> list[EmployeeAssignment]:
    return list(session.scalars(
        select(EmployeeAssignment)
        .options(joinedload(EmployeeAssignment.course).joinedload(Course.department))
        .where(EmployeeAssignment.employee_id == employee.id)
        .order_by(EmployeeAssignment.status, EmployeeAssignment.title)
    ).unique())


def employee_colleagues(session: Session, employee: Employee) -> list[Employee]:
    if employee.department_id:
        return list(session.scalars(select(Employee).where(Employee.department_id == employee.department_id, Employee.id != employee.id).order_by(Employee.designation, Employee.full_name)))
    return list(session.scalars(select(Employee).where(Employee.organizational_unit == employee.organizational_unit, Employee.id != employee.id).order_by(Employee.designation, Employee.full_name)))


def employee_notices(session: Session, employee: Employee, query_text: str = "") -> list[Notice]:
    role_scope = {
        "finance": "FINANCE", "hr": "HR", "security_officer": "SECURITY",
        "security_supervisor": "SECURITY", "security_guard": "SECURITY", "examination": "EXAMINATION",
    }.get(employee.role_key)
    scopes = ["ALL_EMPLOYEES"]
    if employee.role_key in {"professor", "associate_professor", "assistant_professor", "lecturer", "dean", "hod"}:
        scopes.append("FACULTY")
    if employee.role_key in {"registrar", "administration", "vice_chancellor"}:
        scopes.append("ADMINISTRATION")
    if role_scope:
        scopes.append(role_scope)
    conditions = [Notice.scope.in_(scopes)]
    if employee.department_id:
        conditions.append(and_(Notice.scope == "DEPARTMENT_EMPLOYEES", Notice.department_id == employee.department_id))
    statement = select(Notice).where(or_(*conditions)).order_by(Notice.published_at.desc())
    if query_text:
        term = f"%{query_text.strip()}%"
        statement = statement.where(or_(Notice.title.ilike(term), Notice.body.ilike(term)))
    return list(session.scalars(statement))


def _allowed(csv_roles: str, role_key: str) -> bool:
    return role_key in {item.strip() for item in csv_roles.split(",") if item.strip()}


def accessible_policies(
    session: Session,
    employee: Employee,
    query_text: str = "",
    category: str = "",
    classification: str = "",
    owner: str = "",
    applies_to: str = "",
    page: int = 1,
    page_size: int = 10,
) -> tuple[list[Policy], dict[str, int]]:
    statement = select(Policy).order_by(Policy.category, Policy.title)
    if query_text:
        term = f"%{query_text.strip()}%"
        statement = statement.where(or_(Policy.title.ilike(term), Policy.purpose.ilike(term), Policy.rules.ilike(term)))
    if category:
        statement = statement.where(Policy.category == category)
    if classification:
        statement = statement.where(Policy.classification == classification)
    if owner:
        statement = statement.where(Policy.owner == owner)
    if applies_to:
        statement = statement.where(Policy.applies_to.ilike(f"%{applies_to}%"))
    allowed = [policy for policy in session.scalars(statement) if _allowed(policy.allowed_roles, employee.role_key)]
    total = len(allowed)
    page = max(1, page)
    page_size = page_size if page_size in {10, 20, 25, 50} else 10
    pages = max(1, ceil(total / page_size))
    page = min(page, pages)
    start = (page - 1) * page_size
    return allowed[start:start + page_size], {"page": page, "page_size": page_size, "pages": pages, "total": total}


def accessible_policy(session: Session, employee: Employee, policy_id: str) -> Policy | None:
    policy = session.get(Policy, policy_id)
    return policy if policy and _allowed(policy.allowed_roles, employee.role_key) else None


def policy_revisions(session: Session, policy_id: str) -> list[PolicyRevision]:
    return list(session.scalars(select(PolicyRevision).where(PolicyRevision.policy_id == policy_id).order_by(PolicyRevision.id.desc())))


def policy_acknowledgement(session: Session, employee: Employee, policy: Policy) -> PolicyAcknowledgement | None:
    return session.scalar(select(PolicyAcknowledgement).where(
        PolicyAcknowledgement.employee_id == employee.id,
        PolicyAcknowledgement.policy_id == policy.policy_id,
        PolicyAcknowledgement.version == policy.version,
    ))


def acknowledge_policy(session: Session, employee: Employee, policy: Policy) -> PolicyAcknowledgement:
    existing = policy_acknowledgement(session, employee, policy)
    if existing:
        return existing
    acknowledgement = PolicyAcknowledgement(
        policy_id=policy.policy_id,
        employee_id=employee.id,
        version=policy.version,
        acknowledged_at=datetime.now(),
    )
    session.add(acknowledgement)
    session.commit()
    return acknowledgement


def controlled_records(
    session: Session,
    employee: Employee,
    query_text: str = "",
    category: str = "",
    classification: str = "",
    page: int = 1,
    page_size: int = 10,
) -> tuple[list[ControlledRecord], dict[str, int]]:
    statement = select(ControlledRecord).order_by(ControlledRecord.created_at.desc())
    if query_text:
        term = f"%{query_text.strip()}%"
        statement = statement.where(or_(ControlledRecord.title.ilike(term), ControlledRecord.summary.ilike(term), ControlledRecord.record_code.ilike(term)))
    if category:
        statement = statement.where(ControlledRecord.category == category)
    if classification:
        statement = statement.where(ControlledRecord.classification == classification)
    allowed = [record for record in session.scalars(statement) if _allowed(record.allowed_roles, employee.role_key)]
    page_size = page_size if page_size in {10, 20, 25, 50} else 10
    total = len(allowed)
    pages = max(1, ceil(total / page_size))
    page = min(max(1, page), pages)
    start = (page - 1) * page_size
    return allowed[start:start + page_size], {"page": page, "page_size": page_size, "pages": pages, "total": total}


def controlled_record_access(session: Session, employee: Employee, record_id: int) -> tuple[ControlledRecord | None, bool]:
    record = session.get(ControlledRecord, record_id)
    allowed = bool(record and _allowed(record.allowed_roles, employee.role_key))
    if record and record.classification in {"CONFIDENTIAL", "RESTRICTED"}:
        session.add(AuditEvent(
            employee_id=employee.id,
            employee_number=employee.employee_number,
            record_code=record.record_code,
            classification=record.classification,
            action="OPEN_CONTROLLED_RECORD",
            access_result="ALLOWED" if allowed else "DENIED",
            created_at=datetime.now(),
        ))
        session.commit()
    return (record if allowed else None), allowed


def public_policies(session: Session, query_text: str = "") -> list[Policy]:
    statement = select(Policy).where(Policy.classification == "PUBLIC").order_by(Policy.category, Policy.title)
    if query_text:
        term = f"%{query_text.strip()}%"
        statement = statement.where(or_(Policy.title.ilike(term), Policy.purpose.ilike(term)))
    return list(session.scalars(statement))


def directory_for_employee(session: Session, employee: Employee, query_text: str = "") -> list[Employee]:
    statement = select(Employee).order_by(Employee.organizational_unit, Employee.designation, Employee.full_name)
    if query_text:
        term = f"%{query_text.strip()}%"
        statement = statement.where(or_(Employee.full_name.ilike(term), Employee.designation.ilike(term), Employee.organizational_unit.ilike(term)))
    return list(session.scalars(statement))


def students_for_employee(
    session: Session,
    employee: Employee,
    faculty: str = "",
    department: str = "",
    program: str = "",
    semester: int | None = None,
    batch: str = "",
    status: str = "",
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Student], dict[str, int]] | None:
    if employee.role_key in {"vice_chancellor", "registrar", "administration"}:
        statement = select(Student).options(joinedload(Student.department).joinedload(Department.faculty), joinedload(Student.program))
    elif employee.role_key in {"dean", "hod"} and employee.department_id:
        statement = select(Student).options(joinedload(Student.department).joinedload(Department.faculty), joinedload(Student.program)).where(Student.department_id == employee.department_id)
    elif employee.role_key in ACADEMIC_EMPLOYEE_ROLES:
        statement = (
            select(Student).distinct().options(joinedload(Student.department).joinedload(Department.faculty), joinedload(Student.program))
            .join(Enrollment).join(Course).where(Course.teacher_id == employee.id)
        )
    else:
        return None
    if faculty:
        statement = statement.join(Department, Student.department_id == Department.id).join(Faculty).where(Faculty.name == faculty)
    if department:
        statement = statement.where(Student.department_id == int(department))
    if program:
        statement = statement.where(Student.program_id == int(program))
    if semester:
        statement = statement.where(Student.current_semester == semester)
    if batch:
        statement = statement.where(Student.batch == batch)
    if status:
        statement = statement.where(Student.enrollment_status == status)
    all_students = list(session.scalars(statement.order_by(Student.registration_number)).unique())
    page_size = page_size if page_size in {10, 20, 25, 50} else 20
    total = len(all_students)
    pages = max(1, ceil(total / page_size))
    page = min(max(1, page), pages)
    start = (page - 1) * page_size
    return all_students[start:start + page_size], {"page": page, "page_size": page_size, "pages": pages, "total": total}


ACADEMIC_EMPLOYEE_ROLES = {"professor", "associate_professor", "assistant_professor", "lecturer", "research_officer"}


def data_quality_report(session: Session) -> dict[str, Any]:
    def count(model, column) -> int:
        return int(session.scalar(select(func.count(column))) or 0)

    def duplicates(model, column) -> int:
        groups = session.execute(select(column).group_by(column).having(func.count(column) > 1)).all()
        return len(groups)

    student_count = count(Student, Student.id)
    employee_count = count(Employee, Employee.id)
    policy_count = count(Policy, Policy.policy_id)
    departments_represented = count(Department, Department.id)
    programs_represented = count(Program, Program.id)
    students_with_enrollments = int(session.scalar(select(func.count(func.distinct(Enrollment.student_id)))) or 0)
    students_with_attendance = int(session.scalar(select(func.count(func.distinct(Enrollment.student_id))).join(StudentAttendance)) or 0)
    students_with_results = int(session.scalar(select(func.count(func.distinct(Enrollment.student_id))).join(Result)) or 0)
    students_with_fees = int(session.scalar(select(func.count(func.distinct(FeeRecord.student_id)))) or 0)
    students_with_timetable = int(session.scalar(select(func.count(func.distinct(Enrollment.student_id))).join(TimetableEntry)) or 0)
    orphan_students = int(session.scalar(select(func.count(Student.id)).outerjoin(Department).where(Department.id.is_(None))) or 0)
    orphan_programs = int(session.scalar(select(func.count(Student.id)).outerjoin(Program).where(Program.id.is_(None))) or 0)
    foreign_key_errors = len(session.execute(text("PRAGMA foreign_key_check")).all())
    duplicate_enrollments = len(session.execute(
        select(Enrollment.student_id, Enrollment.course_id)
        .group_by(Enrollment.student_id, Enrollment.course_id)
        .having(func.count(Enrollment.id) > 1)
    ).all())
    invalid_results = int(session.scalar(select(func.count(Result.id)).where(or_(Result.marks < 0, Result.marks > 100, Result.grade_points < 0, Result.grade_points > 4))) or 0)
    invalid_attendance = int(session.scalar(select(func.count(StudentAttendance.id)).where(or_(
        StudentAttendance.present + StudentAttendance.absent + StudentAttendance.late + StudentAttendance.excused != StudentAttendance.total_classes,
        StudentAttendance.percentage < 0,
        StudentAttendance.percentage > 100,
    ))) or 0)
    missing_policy_owners = int(session.scalar(select(func.count(Policy.policy_id)).where(or_(Policy.owner == "", Policy.approving_authority == ""))) or 0)
    student_usernames = set(session.scalars(select(Student.username)))
    employee_usernames = set(session.scalars(select(Employee.username)))
    student_emails = set(session.scalars(select(Student.institutional_email)))
    employee_emails = set(session.scalars(select(Employee.institutional_email)))
    return {
        "student_count": student_count,
        "employee_count": employee_count,
        "policy_count": policy_count,
        "departments_represented": departments_represented,
        "programs_represented": programs_represented,
        "duplicate_student_ids": duplicates(Student, Student.student_id),
        "duplicate_registration_numbers": duplicates(Student, Student.registration_number),
        "duplicate_student_usernames": duplicates(Student, Student.username),
        "duplicate_student_emails": duplicates(Student, Student.institutional_email),
        "duplicate_employee_numbers": duplicates(Employee, Employee.employee_number),
        "duplicate_employee_usernames": duplicates(Employee, Employee.username),
        "duplicate_employee_emails": duplicates(Employee, Employee.institutional_email),
        "duplicate_policy_ids": duplicates(Policy, Policy.policy_id),
        "duplicate_policy_titles": duplicates(Policy, Policy.title),
        "students_with_enrollments": students_with_enrollments,
        "students_with_attendance": students_with_attendance,
        "students_with_results": students_with_results,
        "students_with_fees": students_with_fees,
        "students_with_timetable": students_with_timetable,
        "orphan_student_departments": orphan_students,
        "orphan_student_programs": orphan_programs,
        "foreign_key_errors": foreign_key_errors,
        "duplicate_enrollments": duplicate_enrollments,
        "invalid_results": invalid_results,
        "invalid_attendance": invalid_attendance,
        "missing_policy_owners": missing_policy_owners,
        "cross_realm_duplicate_usernames": len(student_usernames & employee_usernames),
        "cross_realm_duplicate_emails": len(student_emails & employee_emails),
    }
