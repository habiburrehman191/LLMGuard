from __future__ import annotations

from collections.abc import Generator
import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def _database_url() -> str:
    configured = os.getenv("LLMGUARD_TESTBED_DATABASE_URL")
    if configured:
        return configured
    db_path = get_settings().logs_dir / "university_testbed.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{db_path.as_posix()}"


engine = create_engine(
    _database_url(),
    connect_args={"check_same_thread": False},
    future=True,
)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    class_=Session,
)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_database() -> None:
    import app.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_compat_columns()


def _ensure_sqlite_compat_columns() -> None:
    if engine.dialect.name != "sqlite":
        return

    additions = {
        "documents": {
            "owner_user_id": "INTEGER",
            "source_filename": "VARCHAR(255)",
        },
        "document_chunks": {
            "portal_scope": "VARCHAR(8)",
            "owner_user_id": "INTEGER",
            "source_filename": "VARCHAR(255)",
            "metadata_json": "JSON",
        },
    }
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as connection:
        for table_name, columns in additions.items():
            if table_name not in existing_tables:
                continue
            existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
            for column_name, ddl_type in columns.items():
                if column_name not in existing_columns:
                    connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl_type}"))
