from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class SeedMetadata(Base):
    __tablename__ = "seed_metadata"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(String(200), nullable=False)


class Faculty(Base):
    __tablename__ = "faculties"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    departments: Mapped[list[Department]] = relationship(back_populates="faculty")


class Department(Base):
    __tablename__ = "departments"
    id: Mapped[int] = mapped_column(primary_key=True)
    faculty_id: Mapped[int] = mapped_column(ForeignKey("faculties.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(140), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    office: Mapped[str] = mapped_column(String(120), nullable=False)
    contact_email: Mapped[str] = mapped_column(String(160), nullable=False)
    faculty: Mapped[Faculty] = relationship(back_populates="departments")
    programs: Mapped[list[Program]] = relationship(back_populates="department")


class Program(Base):
    __tablename__ = "programs"
    id: Mapped[int] = mapped_column(primary_key=True)
    department_id: Mapped[int] = mapped_column(ForeignKey("departments.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    degree_level: Mapped[str] = mapped_column(String(30), nullable=False)
    duration_years: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="Active", nullable=False)
    department: Mapped[Department] = relationship(back_populates="programs")
    __table_args__ = (UniqueConstraint("department_id", "name"),)


class Employee(Base):
    __tablename__ = "employees"
    id: Mapped[int] = mapped_column(primary_key=True)
    employee_number: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(200), nullable=False)
    first_name: Mapped[str] = mapped_column(String(80), nullable=False)
    last_name: Mapped[str] = mapped_column(String(80), nullable=False)
    full_name: Mapped[str] = mapped_column(String(170), nullable=False)
    gender: Mapped[str] = mapped_column(String(20), nullable=False)
    institutional_email: Mapped[str] = mapped_column(String(170), unique=True, nullable=False)
    demo_phone: Mapped[str] = mapped_column(String(40), nullable=False)
    department_id: Mapped[int | None] = mapped_column(ForeignKey("departments.id"))
    organizational_unit: Mapped[str] = mapped_column(String(140), nullable=False)
    office: Mapped[str] = mapped_column(String(140), nullable=False)
    designation: Mapped[str] = mapped_column(String(100), nullable=False)
    role_key: Mapped[str] = mapped_column(String(50), nullable=False)
    employment_category: Mapped[str] = mapped_column(String(60), nullable=False)
    grade_or_scale: Mapped[str] = mapped_column(String(30), nullable=False)
    joining_date: Mapped[date] = mapped_column(Date, nullable=False)
    employment_status: Mapped[str] = mapped_column(String(30), nullable=False)
    supervisor_id: Mapped[int | None] = mapped_column(ForeignKey("employees.id"))
    reporting_authority: Mapped[str] = mapped_column(String(140), nullable=False)
    office_location: Mapped[str] = mapped_column(String(140), nullable=False)
    work_schedule: Mapped[str] = mapped_column(String(100), nullable=False)
    attendance_status: Mapped[str] = mapped_column(String(40), nullable=False)
    leave_balance: Mapped[int] = mapped_column(Integer, nullable=False)
    policy_access_level: Mapped[str] = mapped_column(String(30), nullable=False)
    document_clearance: Mapped[str] = mapped_column(String(30), nullable=False)
    synthetic_emergency_contact: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    department: Mapped[Department | None] = relationship()


class Student(Base):
    __tablename__ = "students"
    id: Mapped[int] = mapped_column(primary_key=True)
    student_id: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    registration_number: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(200), nullable=False)
    first_name: Mapped[str] = mapped_column(String(80), nullable=False)
    last_name: Mapped[str] = mapped_column(String(80), nullable=False)
    full_name: Mapped[str] = mapped_column(String(170), nullable=False)
    gender: Mapped[str] = mapped_column(String(20), nullable=False)
    date_of_birth: Mapped[date] = mapped_column(Date, nullable=False)
    demo_identifier: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    institutional_email: Mapped[str] = mapped_column(String(170), unique=True, nullable=False)
    demo_phone: Mapped[str] = mapped_column(String(40), nullable=False)
    emergency_contact: Mapped[str] = mapped_column(String(100), nullable=False)
    permanent_address: Mapped[str] = mapped_column(String(220), nullable=False)
    current_address: Mapped[str] = mapped_column(String(220), nullable=False)
    province: Mapped[str] = mapped_column(String(80), nullable=False)
    district: Mapped[str] = mapped_column(String(80), nullable=False)
    department_id: Mapped[int] = mapped_column(ForeignKey("departments.id"), nullable=False)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"), nullable=False)
    degree_level: Mapped[str] = mapped_column(String(30), nullable=False)
    batch: Mapped[str] = mapped_column(String(30), nullable=False)
    admission_year: Mapped[int] = mapped_column(Integer, nullable=False)
    current_semester: Mapped[int] = mapped_column(Integer, nullable=False)
    section: Mapped[str] = mapped_column(String(10), nullable=False)
    shift: Mapped[str] = mapped_column(String(20), nullable=False)
    academic_status: Mapped[str] = mapped_column(String(40), nullable=False)
    enrollment_status: Mapped[str] = mapped_column(String(40), nullable=False)
    advisor: Mapped[str] = mapped_column(String(140), nullable=False)
    credit_hours_completed: Mapped[int] = mapped_column(Integer, nullable=False)
    current_credit_hours: Mapped[int] = mapped_column(Integer, nullable=False)
    cgpa: Mapped[float] = mapped_column(Float, nullable=False)
    attendance_percentage: Mapped[float] = mapped_column(Float, nullable=False)
    scholarship_status: Mapped[str] = mapped_column(String(80), nullable=False)
    fee_status: Mapped[str] = mapped_column(String(40), nullable=False)
    library_status: Mapped[str] = mapped_column(String(40), nullable=False)
    hostel_status: Mapped[str] = mapped_column(String(40), nullable=False)
    transport_status: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    department: Mapped[Department] = relationship()
    program: Mapped[Program] = relationship()


class Course(Base):
    __tablename__ = "courses"
    id: Mapped[int] = mapped_column(primary_key=True)
    department_id: Mapped[int] = mapped_column(ForeignKey("departments.id"), nullable=False)
    teacher_id: Mapped[int] = mapped_column(ForeignKey("employees.id"), nullable=False)
    course_code: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    course_title: Mapped[str] = mapped_column(String(180), nullable=False)
    credit_hours: Mapped[int] = mapped_column(Integer, nullable=False)
    semester_number: Mapped[int] = mapped_column(Integer, nullable=False)
    department: Mapped[Department] = relationship()
    teacher: Mapped[Employee] = relationship()


class Enrollment(Base):
    __tablename__ = "enrollments"
    id: Mapped[int] = mapped_column(primary_key=True)
    student_id: Mapped[int] = mapped_column(ForeignKey("students.id"), nullable=False)
    course_id: Mapped[int] = mapped_column(ForeignKey("courses.id"), nullable=False)
    semester_number: Mapped[int] = mapped_column(Integer, nullable=False)
    enrollment_status: Mapped[str] = mapped_column(String(30), nullable=False)
    student: Mapped[Student] = relationship()
    course: Mapped[Course] = relationship()
    __table_args__ = (UniqueConstraint("student_id", "course_id"),)


class StudentAttendance(Base):
    __tablename__ = "student_attendance"
    id: Mapped[int] = mapped_column(primary_key=True)
    enrollment_id: Mapped[int] = mapped_column(ForeignKey("enrollments.id"), unique=True, nullable=False)
    total_classes: Mapped[int] = mapped_column(Integer, nullable=False)
    present: Mapped[int] = mapped_column(Integer, nullable=False)
    absent: Mapped[int] = mapped_column(Integer, nullable=False)
    late: Mapped[int] = mapped_column(Integer, nullable=False)
    excused: Mapped[int] = mapped_column(Integer, nullable=False)
    percentage: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    last_updated: Mapped[date] = mapped_column(Date, nullable=False)
    enrollment: Mapped[Enrollment] = relationship()


class Result(Base):
    __tablename__ = "results"
    id: Mapped[int] = mapped_column(primary_key=True)
    enrollment_id: Mapped[int] = mapped_column(ForeignKey("enrollments.id"), unique=True, nullable=False)
    marks: Mapped[float] = mapped_column(Float, nullable=False)
    grade: Mapped[str] = mapped_column(String(5), nullable=False)
    grade_points: Mapped[float] = mapped_column(Float, nullable=False)
    examination_status: Mapped[str] = mapped_column(String(30), nullable=False)
    enrollment: Mapped[Enrollment] = relationship()


class FeeRecord(Base):
    __tablename__ = "fee_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    student_id: Mapped[int] = mapped_column(ForeignKey("students.id"), nullable=False)
    semester_number: Mapped[int] = mapped_column(Integer, nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    tuition: Mapped[int] = mapped_column(Integer, nullable=False)
    admission_fee: Mapped[int] = mapped_column(Integer, nullable=False)
    lab_fee: Mapped[int] = mapped_column(Integer, nullable=False)
    library_fee: Mapped[int] = mapped_column(Integer, nullable=False)
    transport_fee: Mapped[int] = mapped_column(Integer, nullable=False)
    hostel_fee: Mapped[int] = mapped_column(Integer, nullable=False)
    scholarship_waiver: Mapped[int] = mapped_column(Integer, nullable=False)
    paid_amount: Mapped[int] = mapped_column(Integer, nullable=False)
    outstanding_amount: Mapped[int] = mapped_column(Integer, nullable=False)
    due_date: Mapped[date] = mapped_column(Date, nullable=False)
    payment_status: Mapped[str] = mapped_column(String(30), nullable=False)
    student: Mapped[Student] = relationship()
    __table_args__ = (UniqueConstraint("student_id", "semester_number"),)


class TimetableEntry(Base):
    __tablename__ = "timetable_entries"
    id: Mapped[int] = mapped_column(primary_key=True)
    enrollment_id: Mapped[int] = mapped_column(ForeignKey("enrollments.id"), unique=True, nullable=False)
    day: Mapped[str] = mapped_column(String(20), nullable=False)
    start_time: Mapped[str] = mapped_column(String(20), nullable=False)
    end_time: Mapped[str] = mapped_column(String(20), nullable=False)
    room: Mapped[str] = mapped_column(String(60), nullable=False)
    enrollment: Mapped[Enrollment] = relationship()


class Notice(Base):
    __tablename__ = "notices"
    id: Mapped[int] = mapped_column(primary_key=True)
    scope: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    department_id: Mapped[int | None] = mapped_column(ForeignKey("departments.id"))
    program_id: Mapped[int | None] = mapped_column(ForeignKey("programs.id"))
    published_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    classification: Mapped[str] = mapped_column(String(30), nullable=False)
    department: Mapped[Department | None] = relationship()
    program: Mapped[Program | None] = relationship()


class StudentDocument(Base):
    __tablename__ = "student_documents"
    id: Mapped[int] = mapped_column(primary_key=True)
    student_id: Mapped[int] = mapped_column(ForeignKey("students.id"), nullable=False)
    document_type: Mapped[str] = mapped_column(String(60), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    reference_number: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    issued_at: Mapped[date] = mapped_column(Date, nullable=False)
    student: Mapped[Student] = relationship()


class EmployeeAttendance(Base):
    __tablename__ = "employee_attendance"
    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id"), nullable=False)
    attendance_date: Mapped[date] = mapped_column(Date, nullable=False)
    check_in: Mapped[str] = mapped_column(String(20), nullable=False)
    check_out: Mapped[str] = mapped_column(String(20), nullable=False)
    working_hours: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    late_status: Mapped[str] = mapped_column(String(30), nullable=False)
    remarks: Mapped[str] = mapped_column(String(160), nullable=False)
    employee: Mapped[Employee] = relationship()
    __table_args__ = (UniqueConstraint("employee_id", "attendance_date"),)


class LeaveRequest(Base):
    __tablename__ = "leave_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id"), nullable=False)
    leave_type: Mapped[str] = mapped_column(String(50), nullable=False)
    opening_balance: Mapped[int] = mapped_column(Integer, nullable=False)
    used_days: Mapped[int] = mapped_column(Integer, nullable=False)
    remaining_days: Mapped[int] = mapped_column(Integer, nullable=False)
    request_date: Mapped[date] = mapped_column(Date, nullable=False)
    start_date: Mapped[date] = mapped_column(Date, nullable=False)
    end_date: Mapped[date] = mapped_column(Date, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    approving_authority: Mapped[str] = mapped_column(String(140), nullable=False)
    remarks: Mapped[str] = mapped_column(String(220), nullable=False)
    employee: Mapped[Employee] = relationship()


class EmployeeAssignment(Base):
    __tablename__ = "employee_assignments"
    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id"), nullable=False)
    assignment_type: Mapped[str] = mapped_column(String(60), nullable=False)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    schedule: Mapped[str] = mapped_column(String(100), nullable=False)
    location: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    course_id: Mapped[int | None] = mapped_column(ForeignKey("courses.id"))
    employee: Mapped[Employee] = relationship()
    course: Mapped[Course | None] = relationship()


class EmployeePayroll(Base):
    __tablename__ = "employee_payroll"
    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id"), nullable=False)
    pay_period: Mapped[str] = mapped_column(String(30), nullable=False)
    basic_pay: Mapped[int] = mapped_column(Integer, nullable=False)
    allowances: Mapped[int] = mapped_column(Integer, nullable=False)
    deductions: Mapped[int] = mapped_column(Integer, nullable=False)
    net_pay: Mapped[int] = mapped_column(Integer, nullable=False)
    payment_status: Mapped[str] = mapped_column(String(30), nullable=False)
    disbursement_date: Mapped[date] = mapped_column(Date, nullable=False)
    employee: Mapped[Employee] = relationship()
    __table_args__ = (UniqueConstraint("employee_id", "pay_period"),)


class Policy(Base):
    __tablename__ = "policies"
    policy_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    title: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    effective_date: Mapped[date] = mapped_column(Date, nullable=False)
    last_review_date: Mapped[date] = mapped_column(Date, nullable=False)
    next_review_date: Mapped[date] = mapped_column(Date, nullable=False)
    owner: Mapped[str] = mapped_column(String(140), nullable=False)
    approving_authority: Mapped[str] = mapped_column(String(140), nullable=False)
    applies_to: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_roles: Mapped[str] = mapped_column(Text, nullable=False)
    classification: Mapped[str] = mapped_column(String(30), nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    definitions: Mapped[str] = mapped_column(Text, nullable=False)
    responsibilities: Mapped[str] = mapped_column(Text, nullable=False)
    rules: Mapped[str] = mapped_column(Text, nullable=False)
    procedures: Mapped[str] = mapped_column(Text, nullable=False)
    approval_matrix: Mapped[str] = mapped_column(Text, nullable=False)
    exceptions: Mapped[str] = mapped_column(Text, nullable=False)
    violation_handling: Mapped[str] = mapped_column(Text, nullable=False)
    record_retention: Mapped[str] = mapped_column(Text, nullable=False)
    related_policies: Mapped[str] = mapped_column(Text, nullable=False)


class PolicyRevision(Base):
    __tablename__ = "policy_revisions"
    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.policy_id"), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    effective_date: Mapped[date] = mapped_column(Date, nullable=False)
    change_summary: Mapped[str] = mapped_column(Text, nullable=False)
    __table_args__ = (UniqueConstraint("policy_id", "version"),)


class PolicyAcknowledgement(Base):
    __tablename__ = "policy_acknowledgements"
    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.policy_id"), nullable=False)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id"), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    acknowledged_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    __table_args__ = (UniqueConstraint("policy_id", "employee_id", "version"),)


class ControlledRecord(Base):
    __tablename__ = "controlled_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    record_code: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    classification: Mapped[str] = mapped_column(String(30), nullable=False)
    owner: Mapped[str] = mapped_column(String(140), nullable=False)
    allowed_roles: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    synthetic_marker: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id"), nullable=False)
    employee_number: Mapped[str] = mapped_column(String(30), nullable=False)
    record_code: Mapped[str] = mapped_column(String(40), nullable=False)
    classification: Mapped[str] = mapped_column(String(30), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    access_result: Mapped[str] = mapped_column(String(30), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class ChatKnowledgeChunk(Base):
    __tablename__ = "chat_knowledge_chunks"
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[str] = mapped_column(String(180), unique=True, nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(220), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    portal_scope: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    classification: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    department_id: Mapped[int | None] = mapped_column(ForeignKey("departments.id"))
    role_scope: Mapped[str] = mapped_column(Text, nullable=False, default="")
    route: Mapped[str | None] = mapped_column(String(300))
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class ChatConversation(Base):
    __tablename__ = "chat_conversations"
    id: Mapped[int] = mapped_column(primary_key=True)
    portal_context: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    owner_ref: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    messages: Mapped[list[ChatMessage]] = relationship(back_populates="conversation", cascade="all, delete-orphan")


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    conversation_id: Mapped[int] = mapped_column(ForeignKey("chat_conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    answer_status: Mapped[str | None] = mapped_column(String(60))
    retrieval_type: Mapped[str | None] = mapped_column(String(40))
    topic: Mapped[str | None] = mapped_column(String(60))
    model_called: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    conversation: Mapped[ChatConversation] = relationship(back_populates="messages")
    sources: Mapped[list[ChatSource]] = relationship(back_populates="message", cascade="all, delete-orphan")
    feedback: Mapped[list[ChatFeedback]] = relationship(back_populates="message", cascade="all, delete-orphan")


class ChatSource(Base):
    __tablename__ = "chat_sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("chat_messages.id", ondelete="CASCADE"), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(60), nullable=False)
    source_id: Mapped[str] = mapped_column(String(180), nullable=False)
    source_title: Mapped[str] = mapped_column(String(220), nullable=False)
    route: Mapped[str | None] = mapped_column(String(300))
    message: Mapped[ChatMessage] = relationship(back_populates="sources")
    __table_args__ = (UniqueConstraint("message_id", "source_id"),)


class ChatFeedback(Base):
    __tablename__ = "chat_feedback"
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("chat_messages.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer)
    owner_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    portal_context: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    rating: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    reason: Mapped[str | None] = mapped_column(String(80))
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    message: Mapped[ChatMessage] = relationship(back_populates="feedback")
    __table_args__ = (UniqueConstraint("message_id", "owner_ref"),)
