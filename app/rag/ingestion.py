from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
import zipfile

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AuditLog, DataClassification, Document, DocumentChunk, PortalScope, User, UserRole
from app.output_firewall import detect_canary_markers
from app.rag.chunking import chunk_text
from app.rbac import can_access_classification, can_access_portal, explain_denial

SUPPORTED_EXTENSIONS = {".txt", ".pdf", ".docx"}


@dataclass(frozen=True)
class InMemoryUpload:
    filename: str
    content: bytes

    def read(self) -> bytes:
        return self.content


def uploads_dir() -> Path:
    path = get_settings().data_dir / "uploads"
    path.mkdir(parents=True, exist_ok=True)
    return path


def processed_dir() -> Path:
    path = get_settings().data_dir / "processed"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_filename(filename: str) -> str:
    candidate = filename.strip()
    if not candidate or candidate in {".", ".."} or "/" in candidate or "\\" in candidate:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid upload filename.")
    safe = Path(candidate).name
    if safe != candidate:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Path traversal is not allowed.")
    if Path(safe).suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported file type. Use TXT, PDF, or DOCX.")
    return safe


def _read_upload_bytes(file: object) -> bytes:
    if isinstance(file, bytes):
        return file
    if isinstance(file, str):
        return file.encode("utf-8")
    reader = getattr(file, "read", None)
    if callable(reader):
        data = reader()
        if isinstance(data, str):
            return data.encode("utf-8")
        if isinstance(data, bytes):
            return data
    content = getattr(file, "content", None)
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not read uploaded file bytes.")


def _extract_txt(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _extract_docx(raw: bytes) -> str:
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            xml = archive.read("word/document.xml").decode("utf-8", errors="ignore")
    except (KeyError, zipfile.BadZipFile) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid DOCX upload.") from exc
    xml = re.sub(r"</w:p>", "\n", xml)
    xml = re.sub(r"<[^>]+>", " ", xml)
    return re.sub(r"\s+", " ", xml).strip()


def _extract_pdf(raw: bytes) -> str:
    try:
        try:
            from pypdf import PdfReader
        except ImportError:
            from PyPDF2 import PdfReader  # type: ignore[no-redef]
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PDF extraction requires pypdf or PyPDF2 to be installed.",
        ) from exc

    try:
        reader = PdfReader(BytesIO(raw))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except Exception as exc:  # pragma: no cover - PDF parsers raise library-specific errors.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid PDF upload.") from exc


def extract_text(filename: str, raw: bytes) -> str:
    suffix = Path(filename).suffix.lower()
    if suffix == ".txt":
        return _extract_txt(raw)
    if suffix == ".docx":
        return _extract_docx(raw)
    if suffix == ".pdf":
        return _extract_pdf(raw)
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported file type. Use TXT, PDF, or DOCX.")


def allowed_roles_for_classification(classification: DataClassification) -> list[str]:
    if classification == DataClassification.restricted_secret:
        return []
    if classification == DataClassification.public:
        return [role.value for role in UserRole]
    if classification == DataClassification.student_private:
        return [UserRole.student.value, UserRole.super_admin.value]
    if classification == DataClassification.employee_private:
        return [UserRole.employee.value, UserRole.super_admin.value]
    return [UserRole.super_admin.value]


def _relative_to_base(path: Path) -> str:
    try:
        return path.relative_to(get_settings().base_dir).as_posix()
    except ValueError:
        return path.as_posix()


def ingest_uploaded_file(
    file: object,
    uploader: User,
    portal_scope: PortalScope,
    classification: DataClassification,
    *,
    db: Session,
    title: str | None = None,
) -> Document:
    if not can_access_portal(uploader, portal_scope):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=explain_denial(uploader, portal_scope, classification),
        )
    if classification == DataClassification.restricted_secret or not can_access_classification(uploader, classification):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=explain_denial(uploader, portal_scope, classification),
        )

    filename = _safe_filename(str(getattr(file, "filename", "upload.txt")))
    raw = _read_upload_bytes(file)
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")

    checksum = sha256(raw).hexdigest()
    text = extract_text(filename, raw).strip()
    if not text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file contains no extractable text.")
    if classification != DataClassification.public and not text.startswith("SYNTHETIC DEMO DATA"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Internal/private portal uploads must be synthetic demo data.",
        )

    upload_folder = uploads_dir() / portal_scope.value / str(uploader.id)
    upload_folder.mkdir(parents=True, exist_ok=True)
    stored_name = f"{checksum[:16]}-{filename}"
    upload_path = upload_folder / stored_name
    upload_path.write_bytes(raw)

    document_id = f"upload-{portal_scope.value}-{uploader.id}-{checksum[:16]}"
    roles = allowed_roles_for_classification(classification)
    document = db.query(Document).filter(Document.document_id == document_id).one_or_none()
    if document is None:
        document = Document(document_id=document_id)
        db.add(document)
        db.flush()
    else:
        db.query(DocumentChunk).filter(DocumentChunk.document_pk == document.id).delete()

    document.title = title or Path(filename).stem.replace("_", " ").replace("-", " ").title()
    document.category = f"{portal_scope.value}_upload"
    document.classification = classification
    document.portal_scope = portal_scope
    document.owner_user_id = uploader.id
    document.allowed_roles = roles
    document.source_path = _relative_to_base(upload_path)
    document.source_filename = filename
    document.sha256 = checksum
    document.is_synthetic = text.startswith("SYNTHETIC DEMO DATA")
    document.is_quarantined = False
    document.metadata_json = {
        "controlled_upload": True,
        "uploaded_by": uploader.username,
        "portal_scope": portal_scope.value,
        "source_filename": filename,
    }

    base_metadata = {
        "document_id": document.document_id,
        "portal_scope": portal_scope.value,
        "classification": classification.value,
        "owner_user_id": uploader.id,
        "allowed_roles": roles,
        "source_filename": filename,
    }
    chunks = chunk_text(text, base_metadata)
    if not chunks:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file produced no chunks.")

    processed_payload: list[dict[str, object]] = []
    for chunk in chunks:
        chunk_id = f"{document.document_id}-chunk-{chunk.chunk_index}"
        metadata = dict(chunk.metadata)
        metadata["chunk_id"] = chunk_id
        markers = detect_canary_markers(chunk.chunk_text)
        db.add(
            DocumentChunk(
                chunk_id=chunk_id,
                document_pk=document.id,
                document_id=document.document_id,
                title=document.title,
                category=document.category,
                classification=classification,
                portal_scope=portal_scope,
                owner_user_id=uploader.id,
                allowed_roles=roles,
                source_path=document.source_path,
                source_filename=filename,
                is_synthetic=document.is_synthetic,
                chunk_index=chunk.chunk_index,
                chunk_text=chunk.chunk_text,
                canary_markers=markers,
                metadata_json=metadata,
            )
        )
        processed_payload.append({"chunk_text": chunk.chunk_text, **metadata, "canary_markers": markers})

    processed_path = processed_dir() / f"{document.document_id}.json"
    processed_path.write_text(json.dumps(processed_payload, indent=2), encoding="utf-8")

    db.add(
        AuditLog(
            actor_user_id=uploader.id,
            actor_role=uploader.role.value,
            event_type="rag_file_ingested",
            entity_type="document",
            entity_id=document.document_id,
            summary=f"Controlled upload ingested into {len(chunks)} role-scoped chunks.",
            metadata_json={
                "portal_scope": portal_scope.value,
                "classification": classification.value,
                "source_filename": filename,
                "sha256": checksum,
            },
        )
    )
    db.commit()
    db.refresh(document)
    return document
