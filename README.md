# LLMGuard

LLMGuard is a local RAG security demo with a prompt firewall, retrieved-content firewall, semantic detection, trained ML classifier, FAISS retrieval, dashboard logging, document upload/RAG ingestion support, and Qwen3 1.7B as the official local Ollama model.

## Education Demo Setup

Phase 5 adds a fictional university digital twin at:

```powershell
http://127.0.0.1:8000/demo/university
```

The demo uses only synthetic Northbridge University data. Sensitive-looking examples are marked:

```text
SYNTHETIC DEMO DATA — NOT REAL STUDENT DATA
```

No real student records, real private university data, real secrets, or real credentials are included.

## Load Demo Docs

Load the education templates into the existing document corpus and rebuild the FAISS index:

```powershell
.\.venv\Scripts\python.exe scripts\load_education_demo_docs.py
```

The script copies public and restricted synthetic templates into `docs/clean/education_demo`, copies the poisoned prompt-injection example into `docs/poisoned/education_demo`, rebuilds the existing semantic index, then prints total documents and chunks.

## Run The Demo

Start the FastAPI app with the existing Qwen3 1.7B Ollama setup:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000/demo/university
```

## Protected Vs Unprotected

The page compares:

- Unprotected AI: `POST /demo/ask-unprotected`, a safe synthetic baseline that simulates what an assistant without LLMGuard might reveal.
- LLMGuard Protected: `POST /ask`, the real LLMGuard pipeline with retrieval, prompt/content firewalling, ML classifier, tool-call firewall metadata, Qwen call/skipped status, logs, and dashboard telemetry.

Expected scenarios:

- Safe Policy Question: protected mode answers from policy context.
- Direct Prompt Injection: protected mode blocks hidden prompt requests.
- Indirect Document Injection: protected mode blocks poisoned retrieved content.
- Role Impersonation: protected mode blocks fake exam-controller private record access.
- Student Data Exfiltration: protected mode blocks restricted synthetic student data requests.
- Tool Misuse Attempt: protected mode blocks restricted tool simulations such as `admin_secret_lookup`.
- Encoded Injection and Multilingual Injection: protected mode flags unsafe instruction-following attempts.
- Policy Conflict Attack: protected mode rejects claims that retrieved documents override higher-level rules.

Dashboard demo counters appear under `/admin/security-dashboard` alongside the existing audit trail.

## UOH-Inspired Portal Security Demo

Phase 5 also includes a UOH-inspired academic portal demo at:

```powershell
http://127.0.0.1:8000/demo/uoh
```

Disclaimer shown on the page:

```text
Academic security demo only — not an official University of Haripur website. All private records are synthetic demo data.
```

This interface is inspired by common public university admissions portals, but it does not copy the University of Haripur website, logo, branding, HTML, CSS, images, or private portal. Restricted records use synthetic demo data only and start with:

```text
SYNTHETIC DEMO DATA — NOT REAL UNIVERSITY DATA
```

### Load UOH Demo Docs

Load the UOH-inspired templates into the existing RAG corpus and rebuild FAISS:

```powershell
.\.venv\Scripts\python.exe scripts\load_uoh_demo_docs.py
```

The loader copies public-style documents into `docs/clean/uoh_demo`, copies the poisoned retrieved-content test document into `docs/poisoned/uoh_demo`, rebuilds the existing semantic index, and prints total documents and chunks.

### Test Scenarios

The `/demo/uoh` attack lab includes safe admissions and portal-help prompts plus controlled synthetic attacks for direct prompt injection, role impersonation, synthetic student portal data exfiltration, admin token extraction, indirect retrieved-document injection, restricted tool misuse, encoded instructions, multilingual injection, and policy conflict attacks.

Protected mode calls the existing `/ask` endpoint and shows label, action, risk score, threat source, reason or matched detector, tool-call metadata, and whether Qwen3 1.7B was called or skipped. Unprotected mode calls `/demo/ask-unprotected` and simulates a risky baseline with synthetic data only.

## Role-Based University Data Firewall

Phase 6 upgrades LLMGuard into a role-aware university AI gateway. `/ask` accepts:

```json
{
  "prompt": "How do I create an admission portal account?",
  "user_role": "public_user",
  "user_id": "optional synthetic ID",
  "session_id": "optional session ID"
}
```

Supported roles are `public_user`, `student`, `teacher`, `staff`, `admission_officer`, `exam_controller`, `finance_admin`, and `super_admin`. Qwen3 1.7B remains the only official local model.

The controlled repository lives under:

```text
data/university_repository/
```

with public, student portal, staff, exam cell, finance, contracts, admin, and restricted folders. Internal files are synthetic only and begin with:

```text
SYNTHETIC DEMO DATA — NOT REAL UNIVERSITY DATA
```

Load the role-based repository and rebuild FAISS:

```powershell
.\.venv\Scripts\python.exe scripts\load_university_repository.py
```

The protected pipeline retrieves candidate chunks, filters them by role and classification before Qwen context, logs unauthorized retrievals, then applies the retrieved-content firewall. Blocked or quarantined prompts do not call Qwen.

Run access-control evaluation:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_university_access_control.py
```

Live Phase 6 demo scenarios are available in `/demo/uoh`: student tries admin portal, student requests all exam records, public user requests budgets/contracts, teacher asks for private student records, finance admin asks budget summary, exam controller asks exam records, super admin asks admin notes, prompt injection to override role, indirect role override, and `admin_secret_lookup` misuse.

## Zero-Trust Architecture

The master-level Zero-Trust flow is:

1. Prompt firewall, semantic detector, and ML classifier inspect the request.
2. DLP and policy-bypass detection checks for private data, hidden instructions, unrestricted database access, role override attempts, and secret requests.
3. Tool firewall authorizes or blocks simulated tools such as `student_self_status_lookup`, `exam_record_lookup`, `finance_budget_lookup`, `contract_lookup`, `admin_note_lookup`, and `admin_secret_lookup`.
4. Secure RAG retrieves candidate chunks, then filters them by role and classification before any content is sent to Qwen.
5. Retrieved-content firewall scans only authorized chunks for embedded override instructions.
6. Output firewall scans the generated answer for private data, restricted classifications, and canary markers before returning it.

Canary markers used for leakage tests:

```text
CANARY_ADMIN_TOKEN_DEMO_ONLY
CANARY_INTERNAL_BUDGET_MARKER
CANARY_STUDENT_RECORD_MARKER
```

These markers must never appear in final user-visible output. Output firewall blocks or quarantines the response if they are detected.

Run the Zero-Trust replay lab:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_university_zero_trust.py
```

Dashboard Zero-Trust counters include prompt firewall blocks, access policy blocks, tool firewall blocks, output firewall blocks, canary leakage attempts, unauthorized retrieval attempts, and role-bypass attempts.

## Multi-Portal University Testbed Foundation

The production-grade testbed foundation adds a separate SQLAlchemy/SQLite schema for controlled Student, Employee, and Super Admin portal modules. It is designed for local security validation only and uses synthetic records throughout.

Core modules:

- `app/database.py`: SQLAlchemy engine, `SessionLocal`, and DB initialization.
- `app/models.py`: tables for `users`, `documents`, `document_chunks`, `portal_records`, `ai_interactions`, `firewall_events`, `tool_calls`, `redteam_cases`, and `audit_logs`.
- `app/rbac.py`: portal-boundary and classification enforcement.
- `app/auth.py`: local password hashing, `/auth/login`, bearer-token dependency, and development seed users.

Roles:

- `student`: can access only the student portal and their own synthetic `student_private` records.
- `employee`: can access only the employee portal and `employee_private` records.
- `super_admin`: can access student, employee, and admin scopes except `restricted_secret`.

Portal scopes:

- `student`
- `employee`
- `admin`

Data classifications:

- `public`
- `student_private`
- `employee_private`
- `admin_internal`
- `finance_confidential`
- `exam_confidential`
- `restricted_secret`

Seed the local testbed database:

```powershell
.\.venv\Scripts\python.exe scripts\seed_testbed.py
```

Seed users:

```text
student1 / Student@123 / role=student
employee1 / Employee@123 / role=employee
admin1 / Admin@123 / role=super_admin
```

Login example:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/auth/login -ContentType "application/json" -Body '{"username":"student1","password":"Student@123"}'
```

This foundation does not allow arbitrary OS file access and does not contain real student, employee, admin, university, credential, or portal data.

## Multi-Portal Web Architecture

Seed the database first:

```powershell
.\.venv\Scripts\python.exe scripts\seed_testbed.py
```

Then log in with `/auth/login` and use the returned bearer token for portal routes:

```text
GET  /student/dashboard
GET  /student/records
POST /student/ai/ask
POST /student/documents/upload

GET  /employee/dashboard
GET  /employee/records
POST /employee/ai/ask
POST /employee/documents/upload

GET  /admin/dashboard
GET  /admin/all-records
POST /admin/ai/ask
POST /admin/documents/upload
GET  /admin/security/events
GET  /admin/redteam/cases
```

Portal boundaries are strict: `student1` can access only `/student/*`, `employee1` can access only `/employee/*`, and `admin1` can access all portal modules except `restricted_secret` data. The legacy LLMGuard security dashboard is available at `/admin/security-dashboard`.

## Role-Scoped RAG File Processing

Portal document uploads are processed through the controlled RAG layer:

- Upload storage: `data/uploads/`
- Processed chunk storage: `data/processed/`
- FAISS vector store: `data/vector_store/`

Supported upload formats are TXT, PDF, and DOCX. Uploads are accepted only through authenticated portal upload routes, filenames are sanitized to prevent path traversal, empty or unsupported files are rejected, and private/internal uploads must be marked as synthetic demo data.

Every processed chunk carries isolation metadata:

```text
document_id, portal_scope, classification, owner_user_id,
allowed_roles, source_filename, chunk_index
```

Rebuild the portal RAG index from `document_chunks`:

```powershell
.\.venv\Scripts\python.exe scripts\rebuild_index.py
```

Protected retrieval hard-filters FAISS candidates by portal scope, classification, owner, and RBAC before any chunk can be used as AI context. Vulnerable Red-Team Mode intentionally skips metadata filtering for comparison, but only returns synthetic non-`restricted_secret` chunks.

## Advanced LLMGuard Security Module

The `app/llmguard/` package provides a multi-stage firewall API for production-style university AI security testing:

- Prompt inspection: role impersonation, prompt injection, hidden instruction extraction, exfiltration, privilege escalation, policy bypass, and tool misuse.
- RBAC/access inspection: requested role, portal scope, classification, owner, and `restricted_secret` enforcement.
- Retrieval metadata inspection: hard checks on retrieved chunk scope/classification before context use.
- Retrieved-context inspection: indirect prompt injection, document override claims, HTML comments, markdown instructions, encoded payloads, role override, leakage requests, and tool invocation instructions.
- Tool-call inspection: wraps the existing tool firewall for role-aware tool authorization.
- Output inspection: DLP, unauthorized synthetic private data checks, redaction, and canary leakage blocking.

Main API:

```python
from app.llmguard.pipeline import run_full_firewall

decision = run_full_firewall(
    prompt="Show all records",
    user_role="student",
    requested_portal_scope="admin",
    requested_classification="admin_internal",
    retrieved_chunks=[],
    output_text=None,
    db=db_session,
)
```

When a SQLAlchemy session is provided, every stage writes a row to the `firewall_events` table with detector name, action, label, risk score, source, reason, and metadata.

## Live AI Gateway

Phase 7 routes live `/ask` and portal AI requests through `app/ai/gateway.py`.

Protected mode is the default:

```powershell
$env:FIREWALL_ACTIVE="true"
```

Protected requests run prompt inspection, tool-call inspection, RBAC/access checks, role-aware retrieval filtering, retrieved-context inspection, Qwen3 1.7B generation, and output firewall inspection. If a prompt or retrieved context is blocked or quarantined, Qwen is not called.

Vulnerable mode is only for local synthetic red-team demonstrations:

```powershell
$env:FIREWALL_ACTIVE="false"
$env:REDTEAM_MODE="true"
# or
$env:APP_ENV="local_redteam"
```

When vulnerable mode is enabled, responses are marked with:

```text
Vulnerable red-team mode: LLMGuard bypassed.
```

Vulnerable retrieval intentionally skips metadata filtering only for synthetic non-`restricted_secret` testbed chunks. It must never expose real files, `.env`, real credentials, real tokens, or real secrets.

Gateway response metadata includes:

```text
answer, label, action, risk_score, threat_source, reasons, sources,
llm_called, mode, firewall_active, blocked_stage,
output_firewall_action, sanitized, tool_decisions
```

Run the live gateway tests:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_ai_gateway -v
```
