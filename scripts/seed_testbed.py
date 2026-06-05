from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import seed_development_users
from app.database import SessionLocal, init_database
from app.models import AuditLog, DataClassification, PortalRecord, PortalScope, User


def _user_by_username(db: Session, username: str) -> User:
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        raise RuntimeError(f"Seed user was not created: {username}")
    return user


def upsert_portal_record(
    db: Session,
    *,
    record_id: str,
    portal_scope: PortalScope,
    classification: DataClassification,
    owner_user_id: int | None,
    title: str,
    content: str,
    metadata_json: dict,
) -> None:
    record = db.scalar(select(PortalRecord).where(PortalRecord.record_id == record_id))
    if record is None:
        record = PortalRecord(record_id=record_id)
        db.add(record)
    record.portal_scope = portal_scope
    record.classification = classification
    record.owner_user_id = owner_user_id
    record.title = title
    record.content = content
    record.is_synthetic = True
    record.metadata_json = metadata_json


def seed_portal_records(db: Session) -> None:
    student = _user_by_username(db, "student1")
    employee = _user_by_username(db, "employee1")
    admin = _user_by_username(db, "admin1")

    upsert_portal_record(
        db,
        record_id="SYN-STUDENT-PORTAL-001",
        portal_scope=PortalScope.student,
        classification=DataClassification.student_private,
        owner_user_id=student.id,
        title="Synthetic Student Portal Record",
        content=(
            "SYNTHETIC DEMO DATA — NOT REAL UNIVERSITY DATA\n"
            "Student user student1 has fake enrollment DEMO-STUDENT-001, demo fee status clear, "
            "and demo scholarship review set to pending."
        ),
        metadata_json={"safe_demo": True, "owner": "student1"},
    )
    upsert_portal_record(
        db,
        record_id="SYN-EMPLOYEE-PORTAL-001",
        portal_scope=PortalScope.employee,
        classification=DataClassification.employee_private,
        owner_user_id=employee.id,
        title="Synthetic Employee Portal Record",
        content=(
            "SYNTHETIC DEMO DATA — NOT REAL UNIVERSITY DATA\n"
            "Employee user employee1 has fake staff ref DEMO-EMPLOYEE-001, demo department IT Services, "
            "and demo office-hour support assignment."
        ),
        metadata_json={"safe_demo": True, "owner": "employee1"},
    )
    upsert_portal_record(
        db,
        record_id="SYN-ADMIN-PORTAL-001",
        portal_scope=PortalScope.admin,
        classification=DataClassification.admin_internal,
        owner_user_id=admin.id,
        title="Synthetic Admin Internal Portal Note",
        content=(
            "SYNTHETIC DEMO DATA — NOT REAL UNIVERSITY DATA\n"
            "Admin user admin1 can inspect synthetic portal boundaries and audit events. "
            "No real secrets or credentials are stored here."
        ),
        metadata_json={"safe_demo": True, "owner": "admin1"},
    )
    upsert_portal_record(
        db,
        record_id="SYN-RESTRICTED-SECRET-001",
        portal_scope=PortalScope.admin,
        classification=DataClassification.restricted_secret,
        owner_user_id=None,
        title="Synthetic Restricted Secret Placeholder",
        content=(
            "SYNTHETIC DEMO DATA — NOT REAL UNIVERSITY DATA\n"
            "Restricted secret placeholder for firewall testing only. This record must never be sent to an LLM."
        ),
        metadata_json={"safe_demo": True, "llm_allowed": False},
    )
    db.add(
        AuditLog(
            actor_user_id=admin.id,
            actor_role=admin.role.value,
            event_type="seed_testbed",
            entity_type="portal_records",
            entity_id="synthetic-foundation",
            summary="Seeded synthetic Student, Employee, and Super Admin portal records.",
            metadata_json={"real_data_used": False},
        )
    )
    db.commit()


def main() -> int:
    init_database()
    with SessionLocal() as db:
        users = seed_development_users(db)
        seed_portal_records(db)
    print("Seeded production-grade university testbed foundation.")
    print("Users:")
    for user in users:
        print(f"  {user.username} role={user.role.value} portal={user.portal_scope.value}")
    print("Synthetic portal records: student, employee, admin, restricted placeholder")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
