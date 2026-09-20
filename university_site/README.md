# University of Haripur Local Academic Information Demo

This isolated FastAPI/Jinja/SQLAlchemy module recreates the public University
of Haripur website style and provides a complete, synthetic local Student
Portal and Employee Portal. It does not import, mount, or alter LLMGuard.

All student, employee, academic, policy, attendance, financial, security, and
controlled records are deterministic synthetic fixtures. No route contacts a
production UoH authentication or payment service.

## Run

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m university_site
```

Open `http://127.0.0.1:8001`.

### Optional LLMGuard backend integration

The University backend can report connectivity to LLMGuard on port 8000 when
an application credential has been created by an LLMGuard administrator. The
client is disabled unless both credential environment variables are present:

```powershell
$env:UOH_LLMGUARD_KEY_ID = "<key ID>"
$env:UOH_LLMGUARD_API_SECRET = "<one-time API secret>"
```

Optional settings are `UOH_LLMGUARD_BASE_URL` (default
`http://127.0.0.1:8000`), `UOH_LLMGUARD_APPLICATION_ID`,
`UOH_LLMGUARD_ENVIRONMENT`, `UOH_APPLICATION_VERSION`,
`UOH_LLMGUARD_INTEGRATION_VERSION`, and
`UOH_LLMGUARD_HEARTBEAT_INTERVAL_SECONDS`. HTTP timeout is configured with
`UOH_LLMGUARD_TIMEOUT_SECONDS` (default: 5 seconds). The backend uses the
generic `sdk/llmguard_client` package. The API secret stays in the backend
process environment and is never rendered into University HTML or JavaScript.
When both credentials are absent, the University application keeps its
standalone compatibility behavior. When credentials are configured, the
backend sends every Public, Student, and Employee chatbot prompt to the
LLMGuard input firewall before opening a University database session or
running retrieval, structured-data tools, or the main language model. A
restricted prompt receives a generic response without detector details. A
timeout, connection error, rejected request, or other inspection failure also
fails closed; the University processing path is not executed. Supplying only
one of the two credential variables is treated as a configuration failure for
chat requests, not as standalone mode.

The channel is fixed by the backend route. Student and Employee identities
come only from the signed portal session; prompt content and request JSON
cannot select an identity or role. Each chatbot request receives one request
ID which is sent to LLMGuard and retained by the downstream University request
flow. Input inspection remains separate from University authorization: an
input that LLMGuard allows can still be rejected by portal RBAC.

For responses that require the main language model, the University first
applies its own authorization and retrieval rules. Only the resulting
authorized evidence is sent to `inspect_context()` with the same request ID.
An allow decision continues with the approved evidence. A sanitize decision
rebuilds the model context exclusively from the returned sanitized chunks.
Quarantine, block, a restricted response without sanitized continuation, or a
configured integration failure stops before the model runs. Context metadata
contains only source type, classification, and portal scope; LLMGuard does not
decide University record ownership or permissions.

After model generation, the University sends the answer to `inspect_output()`
with the same request ID before returning it. Allowed output continues,
sanitized output replaces the raw answer, and a blocked response or configured
inspection failure returns only a generic safe message. When both credentials
are absent, the previous local input, context, output, and generation behavior
remain in use.

Immediately before Qwen invocation, all three chatbot channels use one trusted
prompt builder. It places the static security policy and backend-owned channel
instructions in the model's system message, while the current query,
conversation history, and already authorized evidence (context-inspected when
protection is enabled) are placed in explicitly delimited data sections in the
user message. Untrusted
values are JSON serialized with delimiter-forming characters escaped, so user
or retrieved text cannot close a data section or become a system instruction.
The builder performs no authorization; University RBAC and LLMGuard context
inspection remain authoritative before this boundary.

The SQLite database is created at
`university_site/demo_data/university_demo.sqlite3` and is ignored by Git.
Application startup seeds it when missing or when the seed version changes.

To perform an explicit clean, deterministic reset:

```powershell
.\.venv\Scripts\python.exe -m university_site.seed
```

The reset creates exactly 200 students, 30 employees, 22 departments, 22
programs, linked course/enrollment/attendance/result/fee/timetable records,
one August 2026 synthetic payroll record per employee, 70 domain-specific
structured policies, controlled institutional records, and audit tables.

## Separate authentication realms

- Student login: `http://127.0.0.1:8001/portal/student/login`
- Employee login: `http://127.0.0.1:8001/portal/employee/login`

Student credentials are rejected by the Employee Portal and employee
credentials are rejected by the Student Portal. Sessions contain an explicit
portal realm, and cross-portal access is rejected by backend checks.

### Student test accounts

| Department sample | Username | Password |
| --- | --- | --- |
| Biology | `student.demo001` | `Student@123` |
| Medical Lab Technology | `student.demo002` | `Student@123` |
| Microbiology | `student.demo003` | `Student@123` |

Accounts continue deterministically through `student.demo200`.

### Employee test accounts

| Context | Username | Password |
| --- | --- | --- |
| Vice Chancellor | `employee.vc` | `Employee@123` |
| Registrar | `employee.registrar` | `Employee@123` |
| Lecturer | `employee.lecturer` | `Employee@123` |
| HR Officer | `employee.hr` | `Employee@123` |
| Finance Officer | `employee.finance` | `Employee@123` |
| Chief Security Officer | `employee.security` | `Employee@123` |
| Security Guard | `employee.guard` | `Employee@123` |

Passwords are PBKDF2-SHA256 hashes in the database. These published values are
local QA fixtures, not university credentials.

## Functional areas

Student Portal: dashboard, profile, courses and course detail, attendance,
semester results, fee records and demo receipts, weekly timetable, scoped
notices, and downloadable synthetic documents.

Employee Portal: role-specific dashboard/profile, attendance, leave submission,
academic or operational assignments, department context, scoped notices,
employee directory, authorized student registry, organogram, searchable policy
repository, policy revisions/acknowledgment, controlled records, and classified
access auditing.

Public site: university/admissions pages, database-backed departments/programs,
public policy repository, functional search, and a public-information AI
assistant.

## University AI Assistant

One reusable assistant UI is rendered across the public website, Student
Portal, and Employee Portal. The backend derives the active context and user
identity from the signed local session; the request body cannot select a user
ID or elevate the portal role.

- Public assistant: public pages, admissions, programs, departments, public
  notices, and public policies only.
- Student assistant: public/student policy information plus the signed-in
  student's own profile, courses, attendance, results, fees, timetable,
  notices, and documents.
- Employee assistant: authenticated access to the complete synthetic academic
  dataset, authorized leave/payroll/HR/finance/examination/security records,
  policy repository, controlled-record summaries, and calculated university
  statistics. Application secrets remain blocked.

Student identity is always derived from the signed Student Portal session.
Conversation text, request JSON, extracted IDs, and earlier messages cannot
change it. Cross-student, bulk-student, and Student-to-Employee requests fail
closed before retrieval and return no sources. New Chat creates a distinct
conversation, so selected-course and other entity references do not carry
forward. The API derives page context from the server-observed request referrer
and authenticated portal namespace rather than trusting a client title.

Exact questions use live SQLAlchemy repositories. Natural-language policy and
page questions use an isolated FAISS index built with the existing local
`all-MiniLM-L6-v2` embedding helper. If embeddings are unavailable, retrieval
falls back to an authorization-filtered TF-IDF vector search. Only authorized
chunks are supplied to `qwen3:1.7b`; blocked or quarantined prompts never call
the model. Conversation history, response sources, response metadata, and
feedback are persisted in the module's SQLite database.

The assistant UI reuses the existing local UoH header logo, the site's
navy/blue visual variables, compact institutional source panels, persistent
feedback controls, and subtle launcher activity indicators. It supports
keyboard focus containment, Escape-to-close, a near-full-screen mobile layout,
and `prefers-reduced-motion`.

Rebuild the idempotent assistant source and vector indexes with:

```powershell
.\.venv\Scripts\python.exe -m university_site.chatbot.indexing
```

The rebuild validates University-owned, already-extracted sources and then
calls the generic SDK's `inspect_document()` at the shared boundary before any
`ChatKnowledgeChunk` or vector-index write. Validation covers plain filenames,
matching text-oriented extensions/MIME types, a 128,000-byte UTF-8 text limit,
blank or malformed control characters, and bounded JSON metadata. The current
University ingestion path does not accept raw files and has no PDF/DOCX
extractor; this phase does not add a parser or OCR.

After whole-document approval or sanitization, the existing shared text
chunker creates stable `<source-id>::chunk:<index>` identities. Every chunk is
then inspected independently. `APPROVE` stores the original chunk; `SANITIZE`
stores and vectorizes only `sanitized_text`; `QUARANTINE` and `REJECT` omit the
chunk. A whole-document quarantine stops before chunking, while a configured
connection, authentication, or response failure stops before database
replacement. Authenticated `BYPASSED` continues the prior unchunked University
indexing flow without being recorded as approval. When both integration
credentials are absent, standalone indexing remains available. Application
ID, channel, and protection state are derived from backend configuration and
source scope, never browser fields.

Generated vector files remain under
`university_site/demo_data/chat_vector_store/` and are ignored by Git. The
employee-only feedback and usage dashboard is available at
`/portal/employee/assistant-feedback` after Employee Portal login.

Chat APIs are scope-specific:

```text
POST /api/university/chat/public
POST /api/university/chat/student
POST /api/university/chat/employee
GET|POST /api/university/chat/{context}/conversations
GET|DELETE /api/university/chat/{context}/conversations/{id}
POST /api/university/chat/messages/{id}/feedback
```

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s university_site\tests -v
```

The suite validates exact counts, uniqueness, relationships, academic ranges,
separate authentication, record isolation, role-aware access, downloads, leave
submission, policy acknowledgment, controlled-record auditing, route rendering,
navigation links, unfinished template markers, role-aware chat retrieval,
database accuracy samples across students, employees, policies, and admissions,
twenty topic-to-source mappings, identity/bulk-query bypass regressions,
fee and course-reference handling, cross-user conversation isolation, feedback
persistence, and model failure handling.
