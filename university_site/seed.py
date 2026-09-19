from __future__ import annotations

from datetime import date, datetime, timedelta
from itertools import cycle
from random import Random
import re

from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .auth import hash_password
from .data import FACULTIES
from .database import engine
from .models import (
    AuditEvent,
    Base,
    ControlledRecord,
    Course,
    Department,
    Employee,
    EmployeeAssignment,
    EmployeeAttendance,
    EmployeePayroll,
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
    SeedMetadata,
    Student,
    StudentAttendance,
    StudentDocument,
    TimetableEntry,
)


SEED_VERSION = "2026.08.chatbot-fix-v3"
STUDENT_COUNT = 200
EMPLOYEE_COUNT = 30
POLICY_COUNT = 70
NOW = datetime(2026, 8, 17, 9, 0, 0)


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


PROGRAM_BY_DEPARTMENT = {
    "Biology": "BS Zoology",
    "Medical Lab Technology": "BS Medical Laboratory Technology",
    "Microbiology": "BS Microbiology",
    "Public Health & Nutrition": "BS Human Nutrition and Dietetics",
    "Information Technology": "BS Computer Science",
    "Mathematics and Statistics": "BS Mathematics",
    "Physics": "BS Physics",
    "Chemistry": "BS Chemistry",
    "Earth Sciences": "BS Geology",
    "Environmental Sciences": "BS Environmental Sciences",
    "Food Science and Technology": "BS Food Science and Technology",
    "Forestry & Wildlife Management": "BS Forestry and Wildlife Management",
    "Agricultural Sciences": "BSc (Hons) Agriculture",
    "Economics": "BS Economics",
    "Education": "BEd (Hons)",
    "History & Politics": "BS International Relations",
    "Islamic & Religious Studies": "BS Islamic and Religious Studies",
    "Law": "LLB",
    "Linguistics": "BS English Language and Literature",
    "Psychology": "BS Psychology",
    "Sports Science & Physical Education": "BS Sports Science and Physical Education",
    "Management Sciences": "Bachelor of Business Administration",
}


EMPLOYEE_SPECS = [
    ("employee.vc", "Aariz", "Qadir", "Vice Chancellor", "vice_chancellor", "Vice Chancellor Secretariat", "Senior Administration", "BPS-22"),
    ("employee.registrar", "Saira", "Naeem", "Registrar", "registrar", "Registrar Office", "Senior Administration", "BPS-21"),
    ("employee.treasurer", "Faris", "Mehmood", "Treasurer", "finance", "Treasurer Office", "Finance", "BPS-20"),
    ("employee.controller", "Maha", "Khan", "Controller of Examinations", "examination", "Examinations Section", "Examination", "BPS-20"),
    ("employee.dean", "Rameez", "Akhtar", "Dean", "dean", "Faculty Dean Office", "Academic Administration", "BPS-21"),
    ("employee.hod", "Amina", "Siddiq", "Head of Department", "hod", "Academic Block A", "Academic Administration", "BPS-20"),
    ("employee.professor", "Hamza", "Rauf", "Professor", "professor", "Academic Block B", "Faculty", "BPS-21"),
    ("employee.associate", "Noor", "Fatima", "Associate Professor", "associate_professor", "Academic Block C", "Faculty", "BPS-20"),
    ("employee.assistant", "Zayan", "Malik", "Assistant Professor", "assistant_professor", "Academic Block D", "Faculty", "BPS-19"),
    ("employee.lecturer", "Hiba", "Tariq", "Lecturer", "lecturer", "Academic Block E", "Faculty", "BPS-18"),
    ("employee.lab", "Sameer", "Iqbal", "Lab Engineer", "lab_engineer", "Central Computing Lab", "Technical", "BPS-17"),
    ("employee.research", "Emaan", "Yousaf", "Research Officer", "research_officer", "ORIC", "Research", "BPS-17"),
    ("employee.deputyregistrar", "Daniyal", "Ahmed", "Deputy Registrar", "registrar", "Registrar Office", "Administration", "BPS-19"),
    ("employee.assistantregistrar", "Anaya", "Saleem", "Assistant Registrar", "administration", "Academic Administration", "Administration", "BPS-18"),
    ("employee.adminofficer", "Rayyan", "Shah", "Administrative Officer", "administration", "General Administration", "Administration", "BPS-17"),
    ("employee.officeassistant", "Maira", "Aziz", "Office Assistant", "support", "General Administration", "Support", "BPS-14"),
    ("employee.finance", "Ibrahim", "Nawaz", "Finance Officer", "finance", "Finance Directorate", "Finance", "BPS-18"),
    ("employee.accounts", "Laiba", "Rashid", "Accounts Officer", "finance", "Accounts Section", "Finance", "BPS-17"),
    ("employee.accountant", "Saad", "Farooq", "Accountant", "finance", "Accounts Section", "Finance", "BPS-16"),
    ("employee.examofficer", "Alina", "Zafar", "Examination Officer", "examination", "Examinations Section", "Examination", "BPS-17"),
    ("employee.sysadmin", "Taha", "Kareem", "System Administrator", "it", "Directorate of IT", "IT", "BPS-18"),
    ("employee.network", "Meher", "Ali", "Network Administrator", "it", "Network Operations", "IT", "BPS-17"),
    ("employee.itsupport", "Adeel", "Hassan", "IT Support Officer", "it", "IT Help Desk", "IT", "BPS-16"),
    ("employee.librarian", "Rida", "Aslam", "Chief Librarian", "library", "Central Library", "Library", "BPS-19"),
    ("employee.libraryassistant", "Shayan", "Mir", "Library Assistant", "library", "Central Library", "Library", "BPS-14"),
    ("employee.studentaffairs", "Minahil", "Saeed", "Student Affairs Officer", "student_affairs", "Student Affairs", "Student Services", "BPS-17"),
    ("employee.hr", "Usman", "Javed", "HR Officer", "hr", "Human Resources", "HR", "BPS-18"),
    ("employee.security", "Izza", "Bashir", "Chief Security Officer", "security_officer", "Security Office", "Security", "BPS-18"),
    ("employee.supervisor", "Bilal", "Waheed", "Security Supervisor", "security_supervisor", "Main Gate Control", "Security", "BPS-14"),
    ("employee.guard", "Aqsa", "Latif", "Security Guard", "security_guard", "Gate No. 2", "Security", "BPS-07"),
]


POLICY_TOPICS = {
    "Governance": ["University Governance Framework", "Authority Delegation", "Ethics and Conflict of Interest", "Official Record Retention"],
    "Vice Chancellor": ["Executive Approval Workflow", "Emergency Authority", "Strategic Compliance Reporting"],
    "Registrar": ["Official Correspondence", "Document Authentication", "Statutory Meeting Records"],
    "Finance": ["Budget and Expenditure Control", "Procurement Approval", "Financial Record Confidentiality"],
    "Examinations": ["Examination Security", "Result Preparation and Approval", "Transcript Issuance", "Unfair Means Case Handling"],
    "Dean": ["Faculty Academic Planning", "Program Oversight", "Faculty Workload Review"],
    "Head of Department": ["Course Allocation", "Departmental Meetings", "Student Issue Escalation"],
    "Faculty": ["Teaching Responsibility", "Assessment and Grading", "Office Hours and Student Communication"],
    "Research": ["Research Ethics", "Intellectual Property and Publication", "Research Data Stewardship"],
    "Information Technology": ["Account and Password Management", "Acceptable Network Use", "Incident Response", "Privileged Access Review"],
    "Human Resources": ["Recruitment and Appointment", "Attendance and Leave", "Workplace Conduct"],
    "Student Affairs": ["Student Societies and Events", "Scholarship Administration", "Student Grievance Handling"],
    "Student Academic": ["Admission and Registration", "Attendance and Examination", "GPA and Academic Probation"],
    "Library": ["Membership and Borrowing", "Digital Resource Use", "Restricted Material Handling"],
    "Laboratory": ["Laboratory Access", "Equipment and Software Use", "Laboratory Incident Reporting"],
    "Hostel": ["Hostel Allocation", "Visitor and Timing Rules", "Hostel Conduct and Inspection"],
    "Transport": ["Route Allocation", "Passenger and Driver Conduct", "Vehicle Safety and Incidents"],
    "Procurement": ["Purchasing Workflow", "Vendor Assessment", "Inventory and Asset Receipt"],
    "Health and Safety": ["Emergency Evacuation", "Fire and First Aid", "Accident Reporting"],
    "Security Department": ["Campus Access Control", "Visitor and Gate Management", "Security Incident Response", "CCTV Evidence Handling"],
    "Security Guard": ["Guard Post Orders", "Shift Handover", "Identity and Vehicle Verification"],
    "Support Staff": ["Support Staff Conduct", "University Asset Handling", "Attendance and Reporting Chain"],
}


ALL_EMPLOYEE_ROLES = {spec[4] for spec in EMPLOYEE_SPECS}
SENIOR_ROLES = {"vice_chancellor", "registrar"}
ACADEMIC_ROLES = {"dean", "hod", "professor", "associate_professor", "assistant_professor", "lecturer", "lab_engineer", "research_officer"}


def policy_roles(category: str) -> set[str]:
    category_roles = {
        "Finance": {"finance"},
        "Procurement": {"finance", "administration"},
        "Examinations": {"examination", "dean", "hod", "professor", "associate_professor", "assistant_professor", "lecturer"},
        "Human Resources": {"hr", "administration"},
        "Information Technology": {"it"},
        "Library": {"library"},
        "Laboratory": {"lab_engineer", "professor", "associate_professor", "assistant_professor", "lecturer"},
        "Security Department": {"security_officer", "security_supervisor", "security_guard"},
        "Security Guard": {"security_officer", "security_supervisor", "security_guard"},
        "Research": ACADEMIC_ROLES,
        "Faculty": ACADEMIC_ROLES,
        "Head of Department": {"hod", "dean"} | ACADEMIC_ROLES,
        "Dean": {"dean", "hod"} | ACADEMIC_ROLES,
        "Registrar": {"registrar", "administration"},
        "Vice Chancellor": {"vice_chancellor"},
        "Support Staff": {"support", "administration", "library", "it", "lab_engineer"},
    }
    return set(category_roles.get(category, ALL_EMPLOYEE_ROLES)) | SENIOR_ROLES


def _seed_faculties(session: Session) -> tuple[list[Faculty], list[Department], list[Program]]:
    faculties: list[Faculty] = []
    departments: list[Department] = []
    programs: list[Program] = []
    for faculty_data in FACULTIES:
        faculty = Faculty(name=faculty_data["name"], slug=slugify(faculty_data["name"]))
        session.add(faculty)
        session.flush()
        faculties.append(faculty)
        for department_name in faculty_data["departments"]:
            department = Department(
                faculty_id=faculty.id,
                name=department_name,
                slug=slugify(department_name),
                description=f"The Department of {department_name} provides synthetic academic-program information, teaching support, and student services in this controlled local demonstration.",
                office=f"{department_name} Academic Office",
                contact_email=f"{slugify(department_name)}@demo.uoh.local",
            )
            session.add(department)
            session.flush()
            departments.append(department)
            program_name = PROGRAM_BY_DEPARTMENT[department_name]
            program = Program(
                department_id=department.id,
                name=program_name,
                degree_level="Undergraduate",
                duration_years=5 if program_name in {"LLB"} else 4,
                status="Active",
            )
            session.add(program)
            session.flush()
            programs.append(program)
    return faculties, departments, programs


def _seed_employees(session: Session, departments: list[Department]) -> list[Employee]:
    password_hash = hash_password("employee-realm", "Employee@123")
    employees: list[Employee] = []
    for index, spec in enumerate(EMPLOYEE_SPECS, start=1):
        username, first, last, designation, role, office, category, scale = spec
        department = departments[(index - 1) % len(departments)] if role in ACADEMIC_ROLES else None
        employee = Employee(
            id=index,
            employee_number=f"UOH-DEMO-EMP-{index:03d}",
            username=username,
            password_hash=password_hash,
            first_name=first,
            last_name=last,
            full_name=f"{first} {last}",
            gender="Female" if index % 2 == 0 else "Male",
            institutional_email=f"employee{index:03d}@demo.uoh.local",
            demo_phone=f"+92-DEMO-EMP-{index:03d}",
            department_id=department.id if department else None,
            organizational_unit=department.name if department else office,
            office=office,
            designation=designation,
            role_key=role,
            employment_category=category,
            grade_or_scale=scale,
            joining_date=date(2009 + index % 14, 1 + index % 11, 1 + index % 25),
            employment_status="Active",
            supervisor_id=None,
            reporting_authority="Vice Chancellor" if index in {2, 3, 4, 5} else "Relevant Directorate Head",
            office_location=office,
            work_schedule="Monday–Friday, 08:30–16:30",
            attendance_status="Present",
            leave_balance=14 + index % 9,
            policy_access_level="Institutional" if role in SENIOR_ROLES else "Role Based",
            document_clearance="RESTRICTED" if role in SENIOR_ROLES else "INTERNAL",
            synthetic_emergency_contact=f"DEMO-EMERGENCY-{index:03d}",
            created_at=NOW,
            updated_at=NOW,
        )
        session.add(employee)
        employees.append(employee)
    session.flush()
    for employee in employees:
        if employee.id == 1:
            employee.reporting_authority = "University statutory bodies"
        elif employee.id in {2, 3, 4, 5}:
            employee.supervisor_id = 1
        elif employee.role_key in {"security_supervisor", "security_guard"}:
            employee.supervisor_id = 28 if employee.id != 28 else 2
            employee.reporting_authority = "Chief Security Officer"
        elif employee.role_key in ACADEMIC_ROLES:
            employee.supervisor_id = 6 if employee.id != 6 else 5
            employee.reporting_authority = "Dean / Head of Department"
        else:
            employee.supervisor_id = 2
            employee.reporting_authority = "Registrar"
    return employees


def _seed_courses(session: Session, departments: list[Department], employees: list[Employee]) -> dict[tuple[int, int], list[Course]]:
    teachers = [employee for employee in employees if employee.role_key in ACADEMIC_ROLES]
    course_map: dict[tuple[int, int], list[Course]] = {}
    themes = ["Foundations", "Methods", "Analysis", "Applied Practice", "Professional Seminar"]
    for department in departments:
        for semester_number in range(1, 9):
            courses: list[Course] = []
            for position, theme in enumerate(themes, start=1):
                course = Course(
                    department_id=department.id,
                    teacher_id=teachers[(department.id + semester_number + position) % len(teachers)].id,
                    course_code=f"D{department.id:02d}-{semester_number}{position:02d}",
                    course_title=f"{department.name} {theme} {semester_number}",
                    credit_hours=1 if position == 5 else 3,
                    semester_number=semester_number,
                )
                session.add(course)
                courses.append(course)
            course_map[(department.id, semester_number)] = courses
    session.flush()
    return course_map


def grade_for_marks(marks: float) -> tuple[str, float]:
    if marks >= 85:
        return "A", 4.0
    if marks >= 80:
        return "A-", 3.67
    if marks >= 75:
        return "B+", 3.33
    if marks >= 70:
        return "B", 3.0
    if marks >= 65:
        return "B-", 2.67
    if marks >= 60:
        return "C+", 2.33
    return "C", 2.0


def _seed_students(
    session: Session,
    departments: list[Department],
    programs: list[Program],
    employees: list[Employee],
    course_map: dict[tuple[int, int], list[Course]],
) -> list[Student]:
    password_hash = hash_password("student-realm", "Student@123")
    first_names = ["Ayla", "Rayan", "Mishal", "Zain", "Eshal", "Ayan", "Nawal", "Rafay", "Inaya", "Shahveer"]
    last_names = ["Rahman", "Khan", "Siddiqi", "Qureshi", "Abbasi", "Malik", "Farooq", "Tariq", "Hameed", "Naseer"]
    provinces = [("Khyber Pakhtunkhwa", "Haripur"), ("Punjab", "Attock"), ("Khyber Pakhtunkhwa", "Abbottabad"), ("Islamabad Capital Territory", "Islamabad")]
    advisors = [employee.full_name for employee in employees if employee.role_key in ACADEMIC_ROLES]
    program_by_department = {program.department_id: program for program in programs}
    students: list[Student] = []
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    times = [("08:30", "09:50"), ("10:00", "11:20"), ("11:30", "12:50"), ("13:30", "14:50"), ("15:00", "16:20")]
    for index in range(1, STUDENT_COUNT + 1):
        department = departments[(index - 1) % len(departments)]
        program = program_by_department[department.id]
        admission_year = 2026 - ((index - 1) % 4)
        current_semester = min(8, (2026 - admission_year) * 2 + (1 if index % 2 else 2))
        province, district = provinces[(index - 1) % len(provinces)]
        cgpa = 0.0
        attendance_percentage = 0.0
        scholarship = "Merit Scholarship" if index % 11 == 0 else ("Need-Based Fee Support" if index % 13 == 0 else "Not awarded")
        has_outstanding = index % 7 == 0
        student = Student(
            student_id=f"UOH-DEMO-STU-{index:04d}",
            registration_number=f"UOH-DEMO-{admission_year}-{index:04d}",
            username=f"student.demo{index:03d}",
            password_hash=password_hash,
            first_name=first_names[(index - 1) % len(first_names)],
            last_name=last_names[((index - 1) // len(first_names)) % len(last_names)],
            full_name=f"{first_names[(index - 1) % len(first_names)]} {last_names[((index - 1) // len(first_names)) % len(last_names)]}",
            gender="Female" if index % 2 == 0 else "Male",
            date_of_birth=date(1999 + admission_year % 5, 1 + index % 11, 1 + index % 25),
            demo_identifier=f"DEMO-ID-STU-{index:04d}",
            institutional_email=f"student{index:04d}@demo.uoh.local",
            demo_phone=f"+92-DEMO-STU-{index:04d}",
            emergency_contact=f"DEMO-EMERGENCY-STU-{index:04d}",
            permanent_address=f"Synthetic Residence {index}, Demo District {district}",
            current_address=f"Demo Student Residence Block {(index % 8) + 1}, Haripur",
            province=province,
            district=district,
            department_id=department.id,
            program_id=program.id,
            degree_level="Undergraduate",
            batch=f"Fall {admission_year}",
            admission_year=admission_year,
            current_semester=current_semester,
            section=chr(65 + index % 3),
            shift="Morning" if index % 4 else "Afternoon",
            academic_status="Good Standing" if cgpa >= 2.7 else "Academic Monitoring",
            enrollment_status="Active",
            advisor=advisors[index % len(advisors)],
            credit_hours_completed=max(0, (current_semester - 1) * 13),
            current_credit_hours=13,
            cgpa=cgpa,
            attendance_percentage=attendance_percentage,
            scholarship_status=scholarship,
            fee_status="Outstanding" if has_outstanding else "Paid",
            library_status="Clear" if index % 9 else "Book return due",
            hostel_status="Resident" if index % 5 == 0 else "Not enrolled",
            transport_status="Route HPR-{0:02d}".format((index % 7) + 1) if index % 3 == 0 else "Not enrolled",
            created_at=NOW - timedelta(days=(2026 - admission_year) * 365),
            updated_at=NOW,
        )
        session.add(student)
        session.flush()
        students.append(student)
        weighted_points = 0.0
        weighted_credits = 0
        current_attendance: list[float] = []
        for semester_number in range(1, current_semester + 1):
            semester_enrollments: list[Enrollment] = []
            grade_points: list[float] = []
            for position, course in enumerate(course_map[(department.id, semester_number)]):
                enrollment = Enrollment(
                    student_id=student.id,
                    course_id=course.id,
                    semester_number=semester_number,
                    enrollment_status="Enrolled" if semester_number == current_semester else "Completed",
                )
                session.add(enrollment)
                session.flush()
                semester_enrollments.append(enrollment)
                marks = float(62 + ((index * 3 + semester_number * 5 + position * 7) % 32))
                grade, points = grade_for_marks(marks)
                grade_points.append(points)
                weighted_points += points * course.credit_hours
                weighted_credits += course.credit_hours
                session.add(Result(
                    enrollment_id=enrollment.id,
                    marks=marks,
                    grade=grade,
                    grade_points=points,
                    examination_status="Provisional" if semester_number == current_semester else "Final",
                ))
                if semester_number == current_semester:
                    total = 28 + ((index + position) % 9)
                    absent = (index + position * 2) % 5
                    late = (index + position) % 3
                    excused = 1 if (index + position) % 8 == 0 else 0
                    present = total - absent - late - excused
                    percentage = round(((present + late) / total) * 100, 1)
                    current_attendance.append(percentage)
                    session.add(StudentAttendance(
                        enrollment_id=enrollment.id,
                        total_classes=total,
                        present=present,
                        absent=absent,
                        late=late,
                        excused=excused,
                        percentage=percentage,
                        status="Satisfactory" if percentage >= 75 else "Attention Required",
                        last_updated=date(2026, 8, 15),
                    ))
                    session.add(TimetableEntry(
                        enrollment_id=enrollment.id,
                        day=days[position],
                        start_time=times[position][0],
                        end_time=times[position][1],
                        room=f"{department.id:02d}-{101 + position}",
                    ))
            tuition = 42000 + department.id * 650
            other = 3500 + (2200 if department.id <= 13 else 800)
            waiver = 12000 if scholarship != "Not awarded" else 0
            total_due = tuition + other - waiver
            outstanding = 8500 if has_outstanding and semester_number == current_semester else 0
            session.add(FeeRecord(
                student_id=student.id,
                semester_number=semester_number,
                category="Regular Semester Fee",
                tuition=tuition,
                admission_fee=6000 if semester_number == 1 else 0,
                lab_fee=2200 if department.id <= 13 else 800,
                library_fee=1300,
                transport_fee=6500 if student.transport_status != "Not enrolled" else 0,
                hostel_fee=18000 if student.hostel_status == "Resident" else 0,
                scholarship_waiver=waiver,
                paid_amount=max(0, total_due - outstanding),
                outstanding_amount=outstanding,
                due_date=date(2026, 9, 15) if semester_number == current_semester else date(2025, 9, 15),
                payment_status="Outstanding" if outstanding else "Paid",
            ))
        student.cgpa = round(weighted_points / weighted_credits, 2)
        student.attendance_percentage = round(sum(current_attendance) / len(current_attendance), 1)
        student.academic_status = "Good Standing" if student.cgpa >= 2.7 else "Academic Monitoring"
        for doc_index, (document_type, title) in enumerate([
            ("Enrollment", "Enrollment Certificate"),
            ("Finance", "Semester Fee Voucher"),
            ("Academic", "Transcript Preview"),
            ("Registration", "Semester Registration Form"),
            ("Examination", "Examination Admit Card"),
        ], start=1):
            session.add(StudentDocument(
                student_id=student.id,
                document_type=document_type,
                title=title,
                reference_number=f"DOC-STU-{index:04d}-{doc_index:02d}",
                issued_at=date(2026, 8, 1 + doc_index),
            ))
    return students


def _seed_employee_activity(session: Session, employees: list[Employee], courses: list[Course]) -> None:
    courses_by_teacher: dict[int, list[Course]] = {}
    for course in courses:
        courses_by_teacher.setdefault(course.teacher_id, []).append(course)
    for employee in employees:
        for offset in range(14):
            day = date(2026, 8, 17) - timedelta(days=offset)
            if day.weekday() >= 5:
                continue
            late = (employee.id + offset) % 9 == 0
            session.add(EmployeeAttendance(
                employee_id=employee.id,
                attendance_date=day,
                check_in="09:02" if late else "08:24",
                check_out="16:32",
                working_hours=7.5 if late else 8.0,
                status="Present",
                late_status="Late" if late else "On Time",
                remarks="Synthetic attendance entry for local demonstration",
            ))
        session.add(LeaveRequest(
            employee_id=employee.id,
            leave_type="Casual Leave",
            opening_balance=employee.leave_balance + 2,
            used_days=2,
            remaining_days=employee.leave_balance,
            request_date=date(2026, 7, 10),
            start_date=date(2026, 7, 20),
            end_date=date(2026, 7, 21),
            status="Approved" if employee.id % 4 else "Pending",
            approving_authority=employee.reporting_authority,
            remarks="Synthetic personal leave request",
        ))
        scale_number = int(re.search(r"\d+", employee.grade_or_scale).group(0))
        basic_pay = 32000 + scale_number * 6400 + employee.id * 275
        allowances = round(basic_pay * 0.32)
        deductions = round(basic_pay * (0.055 + (employee.id % 3) * 0.005))
        session.add(EmployeePayroll(
            employee_id=employee.id,
            pay_period="August 2026",
            basic_pay=basic_pay,
            allowances=allowances,
            deductions=deductions,
            net_pay=basic_pay + allowances - deductions,
            payment_status="Processed",
            disbursement_date=date(2026, 8, 31),
        ))
        teaching = courses_by_teacher.get(employee.id, [])
        if employee.role_key in ACADEMIC_ROLES and teaching:
            for course in teaching[:2]:
                session.add(EmployeeAssignment(
                    employee_id=employee.id,
                    assignment_type="Teaching",
                    title=f"Teach {course.course_code} — {course.course_title}",
                    detail=f"Deliver lectures, maintain attendance, assess coursework, and submit results for {course.course_title}.",
                    schedule="Monday and Wednesday, 10:00–11:20",
                    location=f"Academic Block {course.department_id}",
                    status="Active",
                    course_id=course.id,
                ))
        else:
            role_task = {
                "finance": "Review synthetic budget and fee reconciliation records",
                "hr": "Maintain synthetic employee lifecycle and leave records",
                "security_officer": "Coordinate campus access-control and incident readiness",
                "security_supervisor": "Supervise gate roster and patrol handover",
                "security_guard": "Perform assigned gate post and visitor verification",
                "it": "Maintain local demo systems and service-desk assignments",
                "library": "Manage lending desk and digital-resource support",
                "examination": "Coordinate examination schedule and duty assignments",
            }.get(employee.role_key, "Complete assigned institutional administrative duties")
            session.add(EmployeeAssignment(
                employee_id=employee.id,
                assignment_type="Operational Duty",
                title=role_task,
                detail=f"Role-specific controlled demo assignment for the {employee.designation}; no production records are involved.",
                schedule=employee.work_schedule,
                location=employee.office_location,
                status="Active",
                course_id=None,
            ))


def _seed_notices(session: Session, departments: list[Department], programs: list[Program]) -> None:
    notice_specs = [
        ("PUBLIC", "Admissions information desk schedule", "The synthetic admissions help desk is available during local demonstration hours."),
        ("PUBLIC", "Academic calendar published", "The demo Fall 2026 academic calendar is available on the public university site."),
        ("ALL_STUDENTS", "Semester registration window", "Students should review current courses before the synthetic registration deadline."),
        ("ALL_STUDENTS", "Examination form submission", "Local demo examination forms are available in Student Portal documents."),
        ("DEPARTMENT_STUDENTS", "Department advising week", "Academic advisors will hold scheduled advising sessions for department students."),
        ("PROGRAM_STUDENTS", "Program curriculum review", "Students may review the updated synthetic course sequence in the portal."),
        ("ALL_EMPLOYEES", "Office timing update", "Employee office timing remains 08:30–16:30 for the current demo term."),
        ("DEPARTMENT_EMPLOYEES", "Department board meeting", "Department employees should review the synthetic meeting agenda."),
        ("FACULTY", "Assessment moderation schedule", "Faculty members must complete local demo assessment moderation by the listed date."),
        ("ADMINISTRATION", "Statutory records review", "Authorized administrators should complete the quarterly synthetic records review."),
        ("SECURITY", "Gate roster and emergency drill", "Security personnel should confirm post assignments and emergency drill procedures."),
        ("FINANCE", "Synthetic budget reconciliation", "Finance staff should complete demo ledger reconciliation before month end."),
        ("HR", "Leave balance verification", "Employees may review synthetic leave balances through the Employee Portal."),
        ("EXAMINATION", "Examination duty confirmation", "Authorized examination staff should confirm assigned demo duties."),
    ]
    for index, (scope, title, body) in enumerate(notice_specs, start=1):
        session.add(Notice(
            scope=scope,
            title=title,
            body=body,
            department_id=departments[index % len(departments)].id if "DEPARTMENT" in scope else None,
            program_id=programs[index % len(programs)].id if scope == "PROGRAM_STUDENTS" else None,
            published_at=NOW - timedelta(days=index),
            expires_at=NOW + timedelta(days=60),
            classification="PUBLIC" if scope == "PUBLIC" else "INTERNAL",
        ))


POLICY_DOMAIN_CONTENT = {
    "Governance": (
        "Statutory bodies set institutional direction; the Vice Chancellor executes their decisions; the Registrar keeps the official record; and officers exercise only formally delegated authority.",
        "Decisions must cite the competent authority, declare conflicts of interest, record dissent where required, and enter approved minutes in the statutory register.",
        "The responsible office prepares an agenda and decision note, obtains the prescribed approval, circulates the signed decision, tracks implementation, and reports completion to the originating body.",
    ),
    "Vice Chancellor": (
        "The Vice Chancellor provides overall executive leadership, advances university strategy, implements statutory decisions, oversees academic and administrative affairs, exercises delegated financial authority, represents the university, directs emergency action, delegates duties, and reports to statutory bodies.",
        "Executive decisions must remain within the Act, statutes, approved budget, and recorded delegations; urgent decisions require prompt documentation and submission to the competent statutory body.",
        "Obtain an executive brief from the responsible officer, review legal, academic, financial, and compliance impacts, record the decision and delegation, notify affected offices, and monitor implementation.",
    ),
    "Registrar": (
        "The Registrar authenticates official correspondence, maintains statutory and academic records, issues meeting notices, records resolutions, safeguards the university seal, and monitors action on approved decisions.",
        "Only authorized registers and templates may create an official university record; corrections require an audit trail and the responsible officer's approval.",
        "Verify the originating office and authority, assign a record number, obtain signatures, dispatch through the official channel, archive the final version, and track any action due.",
    ),
    "Finance": (
        "The Treasurer and finance officers prepare budgets, verify availability, control expenditure, maintain ledgers, reconcile fees and banks, produce accounts, and support audit.",
        "No payment may exceed an approved budget line or delegated limit; maker-checker review, supporting evidence, tax deductions, and monthly reconciliation are mandatory.",
        "Confirm budget and procurement authority, validate invoice and receipt evidence, post the transaction, obtain approval, release payment, reconcile the account, and retain the voucher pack.",
    ),
    "Examinations": (
        "The Controller of Examinations secures examination material, schedules assessments, appoints duties, receives awards, validates tabulation, publishes approved results, and controls transcripts.",
        "Question papers and award lists remain sealed to authorized staff; result changes require documented verification and approval, and unfair-means cases follow due process.",
        "Approve the schedule, issue coded material, record custody transfers, collect and validate awards, run tabulation checks, obtain result approval, publish, and archive the signed record.",
    ),
    "Dean": (
        "The Dean leads faculty academic planning, coordinates program quality, chairs faculty forums, reviews workload and resources, and escalates proposals to the relevant statutory body.",
        "Faculty decisions must follow approved curricula, quality standards, workload limits, and documented board recommendations.",
        "Collect departmental submissions, review evidence and resource impact, convene the faculty forum, record recommendations, assign actions, and monitor completion.",
    ),
    "Head of Department": (
        "The Head of Department allocates courses, prepares teaching plans, chairs departmental meetings, monitors delivery and attendance, supports staff, and resolves or escalates student issues.",
        "Allocations must reflect expertise and workload; academic changes require committee approval; student cases must be handled consistently and confidentially.",
        "Review enrollment and staffing, propose allocations, confirm timetable constraints, record the departmental decision, notify teachers and students, and review progress during the semester.",
    ),
    "Faculty": (
        "Professors, Associate Professors, Assistant Professors, and Lecturers prepare courses, teach scheduled classes, maintain attendance, assess fairly, provide feedback and office hours, and submit results on time.",
        "Learning outcomes, assessment rubrics, moderation, attendance registers, and grade deadlines must be followed; conflicts and suspected misconduct must be declared.",
        "Publish the course outline, deliver and record teaching, update attendance after each class, assess against the rubric, moderate where required, submit awards, and retain course evidence.",
    ),
    "Research": (
        "Researchers and supervisors protect participants, obtain ethics approval, manage consent and data, preserve authorship integrity, disclose conflicts, and report progress and incidents.",
        "No human or sensitive-data research begins before approval; fabrication, falsification, plagiarism, undisclosed conflicts, and unauthorized data sharing are prohibited.",
        "Submit protocol and data plan, obtain approvals, document consent, control access, maintain a research log, report deviations, and archive or dispose of data under the approved plan.",
    ),
    "Information Technology": (
        "IT staff provision accounts, maintain services and assets, apply least privilege, monitor availability, respond to incidents, patch systems, and support authorized users.",
        "Named accounts, multifactor controls where configured, approved software, logged privileged access, timely patching, secure backup, and incident escalation are required.",
        "Verify the request and approval, implement the minimum access, test and document the change, monitor service health, review access periodically, and revoke it when no longer required.",
    ),
    "Human Resources": (
        "HR officers manage approved recruitment, appointment records, attendance, leave, performance processes, staff welfare, conduct cases, and separation clearance.",
        "Employment actions require an approved position, merit-based documented assessment, conflict declarations, confidentiality, and authorization by the competent authority.",
        "Validate the request, check establishment and authority, complete the required assessment or record review, obtain approval, notify the employee, update the personnel file, and retain evidence.",
    ),
    "Student Affairs": (
        "Student Affairs supports societies, events, scholarships, counseling referrals, accessibility, discipline coordination, and fair grievance handling.",
        "Activities require an approved sponsor, risk assessment, budget where relevant, inclusive access, conduct safeguards, and a named responsible student and staff member.",
        "Receive the application or grievance, acknowledge it, verify eligibility and evidence, consult the responsible office, record the decision, communicate appeal rights, and close follow-up actions.",
    ),
    "Student Academic": (
        "Students register approved courses, attend and participate, monitor their portal record, complete assessments honestly, meet fee and examination requirements, and report record errors promptly.",
        "Academic standing, attendance, assessment, registration, and examination eligibility are determined from approved course and student records, with documented review and appeal routes.",
        "The department verifies enrollment, instructors maintain course evidence, the examination office validates awards, the Registrar records approved outcomes, and students raise corrections through their department.",
    ),
    "Library": (
        "Library staff register members, issue and return material, maintain catalog records, support research access, protect licensed resources, and manage overdue or damaged items.",
        "Borrowing limits and due dates apply by member type; credentials and licensed content may not be shared; restricted material requires recorded authorization.",
        "Verify membership, record each transaction, issue a due-date notice, renew where eligible, recover overdue material, assess damage consistently, and close the member record after clearance.",
    ),
    "Laboratory": (
        "Laboratory staff control access, prepare equipment, brief users, maintain inventories, supervise hazardous work, record faults, and coordinate incident response.",
        "Authorized supervision, personal protective equipment, approved software and materials, equipment logs, clean shutdown, and immediate incident reporting are mandatory.",
        "Confirm booking and training, inspect the workspace, issue equipment, supervise use, record consumption or faults, isolate hazards, report incidents, and complete the closing checklist.",
    ),
    "Hostel": (
        "Hostel staff allocate rooms transparently, maintain resident records, enforce visiting and quiet hours, coordinate welfare and maintenance, and respond to emergencies.",
        "Only allocated residents may occupy rooms; visitors sign in during approved hours; prohibited items, harassment, unsafe cooking, and unrecorded room changes are not permitted.",
        "Verify eligibility, issue an allocation and inventory, brief the resident, record visitors and incidents, inspect with notice except emergencies, address maintenance, and complete checkout clearance.",
    ),
    "Transport": (
        "Transport staff assign routes, inspect vehicles, schedule licensed drivers, maintain passenger lists, monitor punctuality, and coordinate breakdown or accident response.",
        "Vehicles may operate only with valid inspection and driver authorization; capacity, route, speed, seat, and incident-reporting requirements must be observed.",
        "Publish routes, verify vehicle and driver readiness, record departure and passengers, report delays, secure the scene of an incident, notify authorities, and document corrective action.",
    ),
    "Procurement": (
        "Procurement staff plan purchases, check specifications and budgets, obtain competition, evaluate bids fairly, manage approvals, receive assets, and keep vendor records.",
        "Requirements may not be split to avoid limits; evaluators declare conflicts; award criteria are fixed before opening; receipt and payment duties remain segregated.",
        "Approve the requisition, select the permitted method, invite and record bids, evaluate against published criteria, obtain award approval, issue the order, inspect receipt, and archive the file.",
    ),
    "Health and Safety": (
        "All offices identify hazards, maintain evacuation and first-aid arrangements, report accidents, support drills, and implement corrective action under the responsible safety officer.",
        "Emergency exits remain clear; alarms, extinguishers, first-aid supplies, and contact lists are checked; incidents and near misses are reported without delay.",
        "Raise the alarm, protect life, contact emergency services, account for occupants, provide trained assistance, preserve evidence where safe, record the incident, and track corrective actions.",
    ),
    "Security Department": (
        "Security officers plan campus protection, authorize posts, manage access control, coordinate patrols, receive incident reports, preserve evidence, and liaise with emergency services.",
        "Access decisions use approved identity and visitor procedures; force is a last resort and must be proportionate; incidents, keys, CCTV requests, and evidence transfers are logged.",
        "Assess risk, brief posts, verify access, respond and call support, protect people, secure the scene, record witnesses and evidence, notify the duty officer, and complete a review.",
    ),
    "Security Guard": (
        "A Security Guard reports on time in uniform, receives the post briefing, verifies people and vehicles, maintains gate and patrol logs, protects access points, assists visitors, reports hazards, and responds to alarms under supervisor direction.",
        "Guards must remain at the assigned post until relieved, challenge access courteously, never share keys or logs, avoid unnecessary force, preserve incident scenes, and immediately escalate emergencies.",
        "Inspect and sign for the post, check equipment, read outstanding instructions, verify credentials and vehicle passes, log entries and patrols, call the supervisor for exceptions, and hand over all keys and incidents face to face.",
    ),
    "Support Staff": (
        "Office Assistants maintain files and dispatch, Drivers operate assigned vehicles safely, and Maintenance staff inspect, repair, isolate hazards, and report completed work through their supervisors.",
        "Assigned assets and documents must be signed for; vehicles and equipment require pre-use checks; faults, losses, unsafe conditions, and absences are reported promptly.",
        "Receive and clarify the task, check authorization and equipment, perform it safely, update the register or job card, report exceptions, return assets, and obtain supervisor closure.",
    ),
}


def _policy_content(category: str, title: str, owner: str) -> dict[str, str]:
    responsibilities, rules, procedures = POLICY_DOMAIN_CONTENT[category]
    if title == "Attendance and Examination":
        responsibilities = (
            "Course instructors record attendance after every class; departments review shortages and corrections; students monitor their portal record and report errors within five working days; the Dean may recommend an exemption, and the competent academic authority decides it."
        )
        rules = (
            "A student must attend at least 75% of delivered classes in each course to be eligible for its examination. Attendance equals attended classes divided by delivered classes multiplied by 100. Three recorded late arrivals count as one absence. Approved medical or other excused absence remains documented but does not automatically count as attendance. Departments issue a shortage warning before the final teaching week."
        )
        procedures = (
            "The instructor updates the register after class and signs the monthly summary. A student requests correction with evidence within five working days. The department verifies the register, issues a shortage notice, and forwards any medical or exceptional-case appeal through the Head and Dean to the competent academic authority before the examination eligibility list is finalized."
        )
    return {
        "purpose": f"Set clear, accountable university requirements for {title.lower()}.",
        "scope": f"Applies to the university officers, employees, students, records, decisions, and facilities involved in {title.lower()}.",
        "definitions": f"For this policy, the responsible office is {owner}; competent authority means the officer or statutory body holding the recorded delegation for the decision.",
        "responsibilities": responsibilities,
        "rules": rules,
        "procedures": procedures,
        "approval_matrix": f"Routine actions are approved by the designated supervisor; department matters by the Head or Director; institution-wide or exceptional matters by {owner} or the formally delegated competent authority.",
        "exceptions": "An exception requires written reasons, supporting evidence, the competent authority's approval, a defined duration, and a record of any conditions or follow-up review.",
        "violation_handling": f"A suspected breach is documented, immediate risk is contained, the affected person is heard where applicable, and {owner} refers the matter through the appropriate academic, administrative, or disciplinary process.",
        "record_retention": "The responsible office keeps the signed decision, supporting evidence, approvals, corrections, and review outcome for the approved university retention period with access limited by classification.",
    }


def _seed_policies(session: Session) -> list[Policy]:
    policies: list[Policy] = []
    policy_specs = [(category, title) for category, titles in POLICY_TOPICS.items() for title in titles]
    assert len(policy_specs) == POLICY_COUNT
    for index, (category, title) in enumerate(policy_specs, start=1):
        public_category = category in {"Governance", "Student Academic", "Library", "Health and Safety"}
        classification = "PUBLIC" if title == "Attendance and Examination" or public_category and index % 3 == 0 else (
            "RESTRICTED" if category in {"Vice Chancellor", "Examinations", "Security Department"} and index % 2 == 0 else
            "CONFIDENTIAL" if category in {"Finance", "Human Resources", "Registrar"} and index % 2 == 0 else "INTERNAL"
        )
        roles = policy_roles(category)
        owner = {
            "Finance": "Treasurer Office", "Examinations": "Controller of Examinations",
            "Human Resources": "Human Resources Office", "Information Technology": "Directorate of IT",
            "Security Department": "Chief Security Officer", "Security Guard": "Chief Security Officer",
            "Student Academic": "Registrar Office", "Research": "ORIC",
        }.get(category, f"{category} Policy Owner")
        policy_id = f"UOH-DEMO-POL-{index:03d}"
        version = "2.0" if index % 10 == 0 else ("1.1" if index % 4 == 0 else "1.0")
        content = _policy_content(category, title, owner)
        policy = Policy(
            policy_id=policy_id,
            title=title,
            category=category,
            version=version,
            effective_date=date(2026, 1 + index % 6, 1 + index % 20),
            last_review_date=date(2025, 6 + index % 6, 1 + index % 20),
            next_review_date=date(2027, 1 + index % 6, 1 + index % 20),
            owner=owner,
            approving_authority="Vice Chancellor" if category in {"Governance", "Vice Chancellor"} else "Authorized University Officer",
            applies_to=", ".join(sorted(roles)),
            allowed_roles=",".join(sorted(roles)),
            classification=classification,
            purpose=content["purpose"],
            scope=content["scope"],
            definitions=content["definitions"],
            responsibilities=content["responsibilities"],
            rules=content["rules"],
            procedures=content["procedures"],
            approval_matrix=content["approval_matrix"],
            exceptions=content["exceptions"],
            violation_handling=content["violation_handling"],
            record_retention=content["record_retention"],
            related_policies="University Governance Framework; Official Record Retention; Ethics and Conflict of Interest",
        )
        session.add(policy)
        policies.append(policy)
        revisions = [("1.0", "Initial controlled demo issue")]
        if version in {"1.1", "2.0"}:
            revisions.append(("1.1", f"Clarified role responsibilities and evidence requirements for {title.lower()}"))
        if version == "2.0":
            revisions.append(("2.0", f"Expanded classification and approval controls for {title.lower()}"))
        for revision_version, summary in revisions:
            session.add(PolicyRevision(
                policy_id=policy_id,
                version=revision_version,
                effective_date=date(2024 + len(revisions), 1 + index % 6, 1 + index % 20),
                change_summary=summary,
            ))
    return policies


def _seed_controlled_records(session: Session) -> None:
    records = [
        ("HR", "Synthetic employee status review", "CONFIDENTIAL", {"hr", "registrar", "vice_chancellor"}),
        ("Finance", "Synthetic quarterly budget variance", "CONFIDENTIAL", {"finance", "registrar", "vice_chancellor"}),
        ("Examination", "Synthetic examination duty schedule", "CONFIDENTIAL", {"examination", "registrar", "vice_chancellor"}),
        ("Security", "Synthetic campus incident summary", "RESTRICTED", {"security_officer", "registrar", "vice_chancellor"}),
        ("Security", "Synthetic guard post roster", "INTERNAL", {"security_officer", "security_supervisor", "security_guard", "registrar"}),
        ("IT", "Synthetic IT asset inventory", "INTERNAL", {"it", "registrar", "vice_chancellor"}),
        ("Administration", "Synthetic controlled meeting minutes", "RESTRICTED", {"registrar", "vice_chancellor"}),
        ("Procurement", "Synthetic procurement evaluation", "CONFIDENTIAL", {"finance", "registrar", "vice_chancellor"}),
        ("Academic", "Synthetic program review findings", "INTERNAL", ACADEMIC_ROLES | SENIOR_ROLES),
        ("Security", "Synthetic emergency contact directory", "INTERNAL", {"security_officer", "security_supervisor", "security_guard", "registrar", "vice_chancellor"}),
    ]
    for index in range(1, 41):
        category, title, classification, roles = records[(index - 1) % len(records)]
        unique_title = f"{title} — Cycle {(index - 1) // len(records) + 1}"
        session.add(ControlledRecord(
            record_code=f"UOH-DEMO-CTRL-{index:03d}",
            title=unique_title,
            category=category,
            classification=classification,
            owner=f"{category} Authorized Office",
            allowed_roles=",".join(sorted(roles)),
            summary=f"Role-filtered {category.lower()} record created solely for the local academic information-system demonstration.",
            body=f"{unique_title} contains synthetic workflow observations, assigned actions, review status, and a non-operational reference marker. It contains no real university, employee, student, financial, security, or authentication information.",
            synthetic_marker=f"DEMO_RESTRICTED_CANARY_{index:03d}",
            created_at=NOW - timedelta(days=index),
        ))


def reset_and_seed(target_engine: Engine = engine) -> None:
    Base.metadata.drop_all(target_engine)
    Base.metadata.create_all(target_engine)
    with Session(target_engine) as session:
        _, departments, programs = _seed_faculties(session)
        employees = _seed_employees(session, departments)
        course_map = _seed_courses(session, departments, employees)
        _seed_students(session, departments, programs, employees, course_map)
        all_courses = list(session.scalars(select(Course)).all())
        _seed_employee_activity(session, employees, all_courses)
        _seed_notices(session, departments, programs)
        _seed_policies(session)
        _seed_controlled_records(session)
        session.add(SeedMetadata(key="seed_version", value=SEED_VERSION))
        session.commit()


def ensure_seeded(target_engine: Engine = engine) -> None:
    Base.metadata.create_all(target_engine)
    with Session(target_engine) as session:
        version = session.get(SeedMetadata, "seed_version")
        students = session.scalar(select(func.count(Student.id))) or 0
        employees = session.scalar(select(func.count(Employee.id))) or 0
        policies = session.scalar(select(func.count(Policy.policy_id))) or 0
    if not version or version.value != SEED_VERSION or students != STUDENT_COUNT or employees != EMPLOYEE_COUNT or policies != POLICY_COUNT:
        reset_and_seed(target_engine)


if __name__ == "__main__":
    reset_and_seed()
    print(f"Seeded {STUDENT_COUNT} students, {EMPLOYEE_COUNT} employees, and {POLICY_COUNT} policies.")
