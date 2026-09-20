# LLMGuard

LLMGuard is a local RAG security demo with a prompt firewall, retrieved-content firewall, semantic detection, trained ML classifier, FAISS retrieval, dashboard logging, document upload/RAG ingestion support, and Qwen3 1.7B as the official local Ollama model.

## Runtime Boundary

LLMGuard runs on `http://127.0.0.1:8000` and exposes only product, security,
evaluation, authentication, and administration routes. The standalone University
application runs on `http://127.0.0.1:8001`.

LLMGuard owns an external-application registry in `logs/llmguard.db`. The
authenticated `/admin/applications` page lists registered application identity,
organization, environment, integration status, and channels. Registration is
not evidence of an active connection or protection state.

An authenticated application detail page at
`/admin/applications/{application_id}` manages per-application API credentials.
Credential secrets are cryptographically generated, stored only as SHA-256
hashes, and displayed once in a non-cacheable creation response. Normal views
show only the key ID and lifecycle metadata.

Registered applications can report backend connectivity to
`POST /api/v1/integrations/heartbeat` using the application ID in the request
body and the key ID and API secret in the `X-LLMGuard-Key-ID` and
`X-LLMGuard-API-Secret` headers. LLMGuard stores only the latest accepted
heartbeat and derives `INTEGRATION_PENDING`, `CONNECTED`, or `DISCONNECTED`
from it. `LLMGUARD_HEARTBEAT_TIMEOUT_SECONDS` controls when an accepted
heartbeat becomes stale (default: 90 seconds), and
`LLMGUARD_HEARTBEAT_MAX_SKEW_SECONDS` controls accepted client timestamp skew
(default: 300 seconds). Connectivity does not imply that request protection is
active by itself.

### Backend Python SDK

The reusable backend-only client lives in `sdk/llmguard_client`. Applications
must load real credentials from their backend secret store or process
environment; never place them in browser code. Minimal heartbeat usage:

```python
from sdk.llmguard_client import LLMGuardClient

client = LLMGuardClient(
    base_url="http://127.0.0.1:8000",
    application_id="<registered-application-id>",
    key_id="<application-key-id>",
    api_secret="<one-time-api-secret>",
    environment="development",
    timeout=5.0,
)

result = await client.send_heartbeat(
    application_version="<application-version>",
    integration_version="<integration-version>",
    channels=("public",),
)
```

`HeartbeatResult` reports success or a safe structured error for timeouts,
connection failures, rejected requests, and invalid responses. It never
contains the API secret or the server response body.

### Guard API

Authenticated applications can inspect bounded input with
`POST /api/v1/guard`. The API validates that the requested `public`, `student`,
or `employee` channel is enabled for the application. Input inspection reuses
the existing rule, semantic, trained ML, hybrid, and risk-scoring
implementation.

```python
result = await client.inspect_input(
    request_id="<application-generated-request-id>",
    channel="public",
    content="<content-to-inspect>",
    security_context={"session_id": "<backend-derived-session-reference>"},
)
```

Phase 7A also accepts bounded retrieved chunks with `stage="context"` through
the same authenticated endpoint. It reuses the existing retrieved-context
firewall for indirect instructions, document overrides, hidden HTML/Markdown
instructions, encoded payloads, role overrides, leakage requests, and tool
invocation instructions.

```python
result = await client.inspect_context(
    request_id="<application-generated-request-id>",
    channel="public",
    chunks=(
        {
            "source_id": "<source-id>",
            "chunk_id": "<chunk-id>",
            "text": "<retrieved-context>",
            "metadata": {"format": "policy"},
        },
    ),
    security_context={"session_id": "<same-backend-session-reference>"},
)
```

Context requests accept at most 32 chunks, 16,000 UTF-8 bytes per chunk, and
64,000 UTF-8 bytes of chunk text in total. `sanitized_chunks` is returned only
when the existing firewall chooses `sanitize` and the sanitizer actually
changes content. Quarantined context is restricted without returning a
sanitized continuation.

Phase 8A accepts bounded generated content with `stage="output"` and reuses the
existing output firewall and DLP implementation for synthetic credential,
system-prompt, sensitive-classification, and canary leakage.

```python
result = await client.inspect_output(
    request_id="<same-application-request-id>",
    channel="public",
    content="<generated-output>",
    security_context={"user_role": "public"},
)
```

Output content and `security_context` use the same 16,000-character,
32-field, and 8,192-byte bounds as input inspection. `sanitized_content` is
returned only for an existing `sanitize` action that actually changes the
content. Blocked or quarantined output never includes a continuation.

While protection is enabled, the response includes the existing classification,
risk score, action, and reasons. `decision` is `allow` for existing `allow`/`log` actions and
`restrict` for `sanitize`/`quarantine`/`block`. Severity is a presentation
mapping (`safe` → `none`, `suspicious` → `medium`, `malicious` → `high`). The
current input hybrid result has no stable threat category, so its `threat_type`
is truthfully `null`. Unsafe context uses the existing
`retrieved_context` threat source. Reusing an application request ID within a
stage returns HTTP 409 and does not create a second telemetry row.

Input telemetry stores only application ID, channel, request ID,
classification, risk score, action, and timestamp. Context telemetry adds the
decision and bounded source/chunk identifiers. Output telemetry adds only the
decision. Input/output content, `security_context`, context text, context
metadata, and sanitized content are not stored in these telemetry tables. A
request ID may be used once per application at each stage, allowing one logical
request to correlate input, context, and output decisions.

When an authenticated backend supplies `security_context.session_id`, LLMGuard
uses a server-keyed HMAC to store only an application/channel-scoped session
digest. One shared session-risk service correlates real input, context, and
output outcomes by session digest and request ID. Ingestion is included only
when its backend explicitly supplies session context. Aggregate storage tracks
first/last seen timestamps, unique request count, suspicious/malicious event
counts, latest/max reported risk score, and cumulative `SAFE`, `SUSPICIOUS`, or
`MALICIOUS` state. Event evidence contains only request ID, stage,
classification, risk score, action, and timestamp—never prompts, retrieved
context, generated output, or application identity records.

At the input boundary, a separate Phase 12B session policy uses only this
non-content evidence. By default, three suspicious input events or two
malicious input events within a 900-second window temporarily restrict a later
input that the per-request detector would otherwise allow. A single suspicious
event cannot trigger this policy, expired evidence cannot create a permanent
lockout, and application, channel, and HMAC session scopes remain isolated.
Detector decisions are retained separately; policy enforcement is returned as
`action=session_restrict` with `session_enforced`, `session_policy_code`, and
the recent-window `session_state`. Configure the bounded policy with
`LLMGUARD_SESSION_ENFORCEMENT_WINDOW_SECONDS`,
`LLMGUARD_SESSION_SUSPICIOUS_EVENT_THRESHOLD`,
`LLMGUARD_SESSION_MALICIOUS_EVENT_THRESHOLD`, and
`LLMGUARD_SESSION_RECENT_EVENT_LIMIT`. Bypassed requests neither create
detector evidence nor run session enforcement. Configure a private
`LLMGUARD_SESSION_HASH_SECRET` outside source control for shared deployments;
the built-in value is for local development only.

### Unified security events and incidents

LLMGuard projects existing input, context, output, ingestion, session-policy,
protection-bypass, integration-failure, and enabled security-path-failure
outcomes into one LLMGuard-owned security event stream. This projection never
re-runs a detector and cannot change a firewall decision. Events contain only
application/channel identifiers, request ID, an optional HMAC session digest,
stage/type/classification/severity/risk/action metadata, optional source and
chunk IDs, and a timestamp. Raw prompts, retrieved text, generated output,
document text, credentials, and University personal data are excluded.

Incidents are opened only for malicious `BLOCK`, `QUARANTINE`, or `REJECT`
events, session restrictions, and critical enabled-mode security-path
failures. Events with the same application and request ID correlate to one
incident; when no request ID exists, application/channel/session digest is the
fallback correlation scope. Event deduplication prevents retries from
inflating incident counts. Incident status progresses from `OPEN` to
`ACKNOWLEDGED` or `RESOLVED`, with every change recorded in a separate audit
table. The authenticated Super Admin backend API is available at:

- `GET /admin/api/security-events`
- `GET /admin/api/security-events/trace/{request_id}?application_id=...`
- `GET /admin/api/incidents`
- `GET /admin/api/incidents/{incident_id}`
- `PATCH /admin/api/incidents/{incident_id}/status`

The Phase 13B SOC console renders these records without copying raw content.
The overview uses a real 24-hour event window and current open-incident count;
all tables and breakdowns are derived from persisted rows. `BYPASSED` and
enabled-mode security-path failures have distinct operational styling, and
quarantine pages show only request/source/chunk identifiers. Super Admin access
uses the existing LLMGuard authorization boundary, and incident lifecycle
changes continue through the audited Phase 13A service.

Authenticated SOC views are available at:

- `GET /admin/security-dashboard` — security overview
- `GET /admin/soc/events` — filterable unified event stream
- `GET /admin/soc/incidents` and `/admin/soc/incidents/{incident_id}`
- `GET /admin/soc/trace?request_id=...&application_id=...`
- `GET /admin/soc/quarantine` — metadata-only quarantine references

### Security normalization

Input, retrieved context, and ingestion text pass through one bounded security
normalizer before their existing detectors run. It applies deterministic NFKC
Unicode normalization, removes zero-width and directional controls, cleans
control characters, normalizes whitespace, and safely decodes HTML entities,
URL encoding, recognized escaped text, and confidently identified Base64
attack instructions. Decode depth and normalized output are bounded; malformed
encodings remain safe inputs and no decompression, OCR, or file parsing occurs.

The raw application content remains unchanged and available to the calling
security boundary. Detectors receive canonical inspection content. Raw text is
replaced only when an existing sanitizer explicitly returns a sanitize action.
Internal decisions track whether normalization was applied and the names of
the transformations, while telemetry excludes raw, normalized, and sanitized
content fields. Detector models, weights, thresholds, and risk scoring are
unchanged.

### Secure pre-index document inspection

`POST /api/v1/ingestion/inspect` authenticates with the same application ID,
key ID, and API secret as the Guard API. It accepts already-extracted text only;
it does not upload, extract, store, chunk, or index files. The endpoint reuses
the existing retrieved-context firewall and sanitizer before an external
application admits content to RAG.

```python
result = await client.inspect_document(
    request_id="<unique-ingestion-request-id>",
    channel="public",
    source_id="<application-source-id>",
    filename="policy.txt",
    mime_type="text/plain",
    text="<already-extracted-text>",
    metadata={"category": "policy"},
)
```

Text is limited to 128,000 UTF-8 bytes. Metadata is limited to 32 fields and
8,192 encoded bytes. Supported text-oriented formats are TXT, Markdown, CSV,
JSON, XML, and YAML. Results use `APPROVE`, `SANITIZE`, `QUARANTINE`, or
`REJECT`; `sanitized_text` appears only when the existing sanitizer materially
changes content. Quarantine and rejection never return a safe-to-index
continuation. With protection disabled, the endpoint skips inspection and
returns explicit `BYPASSED` instead of claiming approval.

Ingestion telemetry stores only application ID, channel, source ID, request ID,
classification, risk score, action, and timestamp. Raw document text,
filenames, metadata, and sanitized text are not persisted by this API.

### Per-application protection control

LLMGuard Super Admins can enable or disable enforcement from
`/admin/applications/{application_id}`. Disabling requires a reason and every
state change is stored in the LLMGuard-owned protection audit. The control is
not exposed by the University application or any browser-supplied chatbot
field.

When protection is disabled, the authenticated Guard API skips its detectors
and returns an explicit `decision="bypassed"`,
`classification="bypassed"`, `action="bypass"`, and `risk_score=null`.
This is intentionally distinct from a detector `allow`. The University SDK
continues its normal RBAC, retrieval, and model flow only after validating that
exact authenticated bypass contract. Configured connection or inspection
failures continue to fail closed.

Application status separates connection from runtime protection:

- `INTEGRATION_PENDING`: no valid heartbeat has ever been accepted.
- `DISCONNECTED`: the latest heartbeat is stale.
- `BYPASSED`: connected while protection is disabled.
- `DEGRADED`: connected and enabled, but input/context/output availability has
  not all been verified or a later path error is recorded.
- `PROTECTED`: connected, enabled, and all three Guard stages have completed
  successfully after any stage-specific error.

A heartbeat alone never produces `PROTECTED`.

The standalone University backend uses this API for Public, Student, and
Employee chatbot input, authorized retrieval context, and model-generated
output when both integration credential environment variables are configured.
Input inspection happens before its database, retrieval, structured-data tools,
and main-model boundaries. Restricted inputs receive a generic response;
configured integration failures fail closed. Channel and portal identity are
derived from the backend route and signed session rather than prompt or
browser-supplied identity fields. University RBAC remains a separate, later
authorization check after an input is allowed.

For model-generated answers, only University-authorized retrieval evidence is
sent to the context API. Allowed evidence continues unchanged; sanitized
evidence replaces raw chunks before prompt construction; quarantine, block,
missing safe continuation, and configured inspection failures stop before
Qwen. After Qwen, the shared response boundary sends generated content to the
output API with the same request ID used for input and context. Allowed output
continues unchanged, sanitized output fully replaces the raw answer, and
blocked/quarantined output or configured inspection failure returns only a
generic safe response. Sanitized responses omit source links because the API
does not provide source-level provenance for the rewritten text. Detector
reasons and scores are never returned to chatbot users. With both credentials
absent, the University retains its local standalone input, context, and output
behavior. LLMGuard does not decide University record ownership or portal
permissions.

The University knowledge-index rebuild validates its already-extracted text,
filename/MIME pair, size, control characters, and bounded metadata before
calling `inspect_document()` at its single prepared-source boundary. An
approved or sanitized whole document is split with the existing deterministic
text chunker, and every chunk is inspected again under a stable
`<source-id>::chunk:<index>` identity. Only approved or sanitized chunk text is
written to `ChatKnowledgeChunk` or supplied to vector indexing. A whole-source
quarantine stops before chunking; a chunk quarantine/rejection omits that
chunk; and a configured failure stops the rebuild before database replacement.
Explicit `BYPASSED` and fully unconfigured standalone mode retain the previous
unchunked University indexing behavior. The University has no file-upload
extraction path, so this phase adds no PDF/DOCX parser or OCR.

Legacy fictional-university route modules and test data remain in the repository
for controlled regression coverage, but `/student/*`, `/employee/*`, and
`/demo/*` are not mounted by the LLMGuard process.

## Legacy Education Demo Assets

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

## Run LLMGuard

Start the FastAPI app with the existing Qwen3 1.7B Ollama setup:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000/
```

## Protected Vs Unprotected

The active comparison workspace is `/admin/compare`. `POST /ask` remains the
real LLMGuard pipeline with retrieval, prompt/content firewalling, ML
classification, tool-call firewall metadata, Qwen call/skipped status, logs,
and dashboard telemetry. The legacy `/demo/ask-unprotected` route is preserved
in source but is not exposed on port 8000.

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

## Legacy UOH-Inspired Security Assets

The earlier `/demo/uoh` route is no longer mounted by LLMGuard. The standalone
University application is available at `http://127.0.0.1:8001`.

Disclaimer shown on the page:

```text
Academic security demo only — not an official University of Haripur website. All private records are synthetic demo data.
```

This isolated academic demonstration locally recreates the referenced public University of Haripur layout and reuses the public logo asset solely for the requested local UI study. It does not connect to the real university portal, authentication, or private data. Restricted records use synthetic demo data only and start with:

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

The preserved direct tests cover safe admissions and portal-help prompts plus
controlled synthetic attacks for prompt injection, role impersonation, data
exfiltration, restricted tool misuse, encoded instructions, multilingual
injection, and policy conflicts. These legacy modules are not HTTP routes on
port 8000.

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

### Reproducible security benchmark

Phase 14A adds a synthetic-only benchmark harness that compares individual
detectors with the protected pipeline and the intentional BYPASSED state. It
uses real firewall decisions and University RBAC, but instrumented downstream
boundaries instead of a live database or Qwen call. RBAC denials are reported
separately and are never counted as LLMGuard blocks.

```powershell
.\.venv\Scripts\python.exe -m evaluation.run
```

Select modes or an output location when needed:

```powershell
.\.venv\Scripts\python.exe -m evaluation.run --modes hybrid full_protected_pipeline bypassed --output-dir reports/evaluation/phase14a
```

The deterministic dataset is in `evaluation/datasets/security_cases.jsonl`.
The ignored report directory receives `benchmark.json` and a content-free
per-case `cases.csv`; neither report contains prompt, context, output, or
University record content. Scores are computed from the observed run and are
not fixed benchmark claims.

Phase 6 scenarios remain available through the evaluation scripts and direct
security tests; they are not exposed through a University demo route on port
8000.

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
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/auth/login -ContentType "application/json" -Body '{"username":"admin1","password":"Admin@123"}'
```

This foundation does not allow arbitrary OS file access and does not contain real student, employee, admin, university, credential, or portal data.

## Legacy Multi-Portal Modules

Seed the database first:

```powershell
.\.venv\Scripts\python.exe scripts\seed_testbed.py
```

The student and employee route modules are retained for later migration history
and regression work, but are not mounted by `app.main`. Active LLMGuard admin
routes include:

```text
GET  /admin/dashboard
GET  /admin/all-records
POST /admin/ai/ask
POST /admin/documents/upload
GET  /admin/security/events
GET  /admin/redteam/cases
```

The LLMGuard security dashboard remains available at
`/admin/security-dashboard`. Student and employee business portals are served
only by the standalone University application on port 8001.

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

## Phase 9 Enterprise Product Shell

The FastAPI template UI presents LLMGuard as a standalone AI security product.

Product routes:

```text
GET /                         Product landing page
GET /login                    Local testbed sign-in
GET /admin/dashboard          Super admin control plane
GET /admin/compare            Protected vs vulnerable comparison
GET /admin/documents          Controlled RAG document manager
GET /admin/security-dashboard Security operations dashboard
GET /admin/redteam            Red-team case workspace
GET /admin/audit              Investigation and audit views
```

The browser login is the LLMGuard security-administrator console:

```text
admin1    / Admin@123
```

The security console includes live AI Gateway response metadata: action, label,
risk score, threat source, blocked stage, Qwen call status, sources, tool
decisions, output firewall action, sanitization state, and human-readable
reasons.

### Security Console Workflow

1. Open `/login` and authenticate as the synthetic security administrator.
2. Use the dashboard and SOC views to inspect enforcement outcomes.
3. Run controlled comparison or red-team cases.
4. Manage synthetic documents through the document-security workspace.
5. Review security events and audit history.

### Protected vs Vulnerable Comparison

Sign in as `admin1` and open `/admin/compare`. The comparison sends the same
synthetic prompt through vulnerable and protected gateway modes and displays both
answers, actions, blocked stages, risk scores, model-call status, sources, tool
decisions, and the final verdict.

Vulnerable execution remains unavailable unless one of these local red-team
controls is enabled:

```powershell
$env:REDTEAM_MODE="true"
# or
$env:APP_ENV="local_redteam"
```

When neither control is enabled, the vulnerable panel shows the gateway's real
rejection response. Protected mode remains active and blocked or quarantined
requests do not call Qwen.

### Document And Security Operations

The document manager accepts controlled synthetic TXT, PDF, and DOCX uploads,
portal scope and classification selection, FAISS rebuilds, chunk counts, role
metadata, quarantine state, and database-backed document deletion.
`restricted_secret` content remains excluded from Qwen and cannot be managed as
ordinary AI context.

The security dashboard provides summarized enforcement KPIs, filters, recent
critical events, and expandable event details. The audit page separates AI
interactions, firewall events, tool calls, and repository changes into focused
investigation tabs. All `/admin/*` product and telemetry routes require the
`super_admin` identity.

### Red-Team Lab

`/admin/redteam` displays persisted structured cases and expected outcomes. If a
reusable backend runner is not installed, run controls return an explicit
unavailable response and the UI does not fabricate completed results. The export
endpoint still provides the stored case manifest.

Run the Phase 9 route and product-shell tests:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_frontend tests.test_portals tests.test_product_frontend -v
```

## Phase 10 Ultra Futuristic AI Firewall Interface

The product shell now uses a responsive futuristic AI cybersecurity design
system across the landing page, secure login, role portals, comparison lab,
document manager, security dashboard, red-team lab, and audit views.

The landing page is built from original HTML, CSS, and SVG layers. It uses the
provided visual reference only as a style target and does not copy external
text, logos, screenshots, CSS, images, or third-party assets.

Interface behavior includes:

- A cinematic curved-monitor hero with a floating glass navigation bar.
- Main hero copy: `LLMGUARD: THE NEXT GENERATION AI FIREWALL`.
- Code-native holographic shield, AI brain network, radar rings, binary
  telemetry, red attack streams, cyan deflection particles, and packet-flow
  animations.
- Glowing "How It Works" cards for Hybrid Firewall, Data Isolation, and
  Document Scanning connected by an electric arc.
- Animated security grid, node patterns, scan lines, and premium glass
  surfaces on every product route.
- Readable 17px base typography, larger dashboard metrics, and high-contrast
  action, severity, role, scope, and classification badges.
- Reduced-motion support through `prefers-reduced-motion`.
- Student and employee navigation sidebars with animated portal boundary locks.
- AI Gateway progress states for authorized retrieval, security scanning, and
  protected generation.
- Animated allow, block, quarantine, and sanitize decision states.
- Structured source evidence, human-readable reasons, and tool authorization
  cards.
- Protected and vulnerable comparison panels with a final verdict banner.
- Drag-and-drop styled document upload, scanning progress, FAISS rebuild, and
  clean, poisoned, quarantined, or restricted repository states.
- A six-stage Prompt, RBAC, RAG, Context, Tool, and Output pipeline view.
- Red-team pending states that never fabricate results when no runner exists.
- Audit timelines plus focused firewall, tool-call, and repository tabs.

The primary workflow remains:

1. Sign in through `/login` using a synthetic seed identity.
2. Work inside the identity's Student, Employee, or Super Admin portal.
3. Inspect complete AI Gateway security metadata after each request.
4. Use `/admin/compare` for controlled protected/vulnerable analysis.
5. Govern synthetic RAG content through `/admin/documents`.
6. Investigate enforcement through `/admin/security-dashboard` and
   `/admin/audit`.
7. Review stored adversarial cases through `/admin/redteam`.

Run all frontend route, static asset, RBAC, empty-state, gateway, and security
regression tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

### Ultra Visual Theme Notes

The Phase 10 Ultra interface uses an original futuristic AI security design.
The supplied image is treated as a visual target for mood, hierarchy, and
cybersecurity language only. The implementation remains original and
code-native.

The LLMGuard theme includes:

- Background `#020611`, deep navy panels, cyan borders, attack-red streams,
  amber-gold highlights, and secure green enforcement states.
- Original line icons for shield, AI brain/chip, firewall, portals, documents,
  PDF/DOC, vector database, vault/lock, warning, tools, red-team, audit, RAG,
  radar, neural network, and output controls.
- Numbered landing sections for Overview, Access Portals, Core Protection, AI
  Firewall Pipeline, SOC Operations, and Process.
- A six-stage Prompt Intake, RBAC Boundary, RAG Isolation, Context Firewall,
  Tool Authorization, and Output DLP pipeline.
- Animated title reveal, shield pulse, brain-node pulse, radar sweep, binary
  snippets, packet flow, document scan, protected/block/quarantine/sanitize
  states, and reduced-motion support.
- Shared top status bar, breadcrumbs, role and portal badges, and left command
  navigation on authenticated dashboards.
- A secure-access terminal login workflow for Student, Employee, and Super
  Admin seed identities.
- A six-stage AI Assistant status path with copy, clear, sources, reasons,
  security metadata, and tool authorization decisions.

`/app` now redirects to `/login`, preventing the retired console interface from
appearing as a primary product surface.

### Premium UI Design Pass

The shared product shell was refined with the local UI/UX Pro Max design system
and interaction ideas adapted from 21st.dev Magic. The implementation remains
original FastAPI templates, CSS, and JavaScript with no copied external assets.

This pass adds an accessible responsive navigation menu, 17px base typography,
hero gateway telemetry, live risk visualization, and narrated AI Gateway stages
for prompt inspection, RBAC, RAG filtering, context scanning, tool
authorization, and output inspection. Final assistant states visibly distinguish
allowed, sanitized, blocked, and quarantined outcomes.

Frontend motion remains CSS/JavaScript-only and respects
`prefers-reduced-motion`. Verify the product shell and portal workflows with:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_product_frontend tests.test_frontend tests.test_portals -v
```

### LLMGuard Premium Product Interface

The visible product brand remains **LLMGuard**. **Neural Defense OS** is used
only as the product mode subtitle for the dark cybersecurity SaaS interface.
The current shell uses an asymmetric command-center hero built from original
HTML, CSS, and inline SVG.

The refreshed interface includes:

- An animated neural policy core with orbital firewall rings, hostile request
  paths, safe packet deflection, and floating model/RAG/DLP telemetry.
- A modern product bento for intent inspection, role-aware RAG isolation, tool
  authorization, and output release control.
- A seven-stage Prompt, Intent, RBAC, RAG, Tool, Output, and Evidence pipeline.
- Role-aware Student, Employee, and Super Admin workspaces using the same
  responsive SaaS shell.
- An AI Security Workbench that explicitly reports when Qwen was called or
  skipped, including the message `Qwen skipped / blocked before model call`.
- Motion-enhanced document scanning, comparison, SOC metrics, policy stages,
  and audit timelines with `prefers-reduced-motion` support.
- A consistent premium card and icon system with readable metadata, restrained
  glass surfaces, and balanced dashboard density.
- Cache-busted product assets using UI asset version `18`.

The landing hero renders the reusable
`templates/components/neural_defense_spline.html` component. By default it
uses the original CSS/SVG/JavaScript interactive neural-core fallback. To use
a hosted Spline scene, set an HTTPS URL from the `spline.design` domain:

```powershell
$env:LLMGUARD_SPLINE_SCENE_URL="https://my.spline.design/example/"
```

Invalid or non-Spline URLs are ignored and the local fallback remains active.

Primary routes remain unchanged:

```text
/                         LLMGuard AI Firewall landing page
/login                    Secure synthetic identity access
/admin/dashboard          Super Admin command center
/admin/security-dashboard SOC security overview
/admin/soc/events         Filterable live security events
/admin/soc/incidents      Incident console and lifecycle
/admin/soc/trace          Request-stage trace search
/admin/soc/quarantine     Quarantine metadata only
/admin/compare             Protected/vulnerable proof view
/admin/documents           Document security console
/admin/redteam             Controlled cyber range
/admin/audit               Audit evidence timeline
```

The redesign does not alter `app/llmguard/`, AI Gateway decisions, RAG access
policy, model settings, or vulnerable-mode gating.

### Standalone University Website Demo

An isolated University of Haripur public-site and database-backed synthetic
Student/Employee Portal is available under `university_site/`. It runs
independently and does not mount, modify, or replace any LLMGuard route:

```powershell
.\.venv\Scripts\python.exe -m university_site
```

Open `http://127.0.0.1:8001`. Deterministic seed/reset instructions, separate
login routes, local demo accounts, role behavior, and QA commands are in
`university_site/README.md`. The portal never submits credentials or personal
information to the production university website.

The isolated module also includes a role-aware University AI Assistant for the
public site and both authenticated portals. It uses live structured queries,
an isolated authorization-filtered semantic index, the approved local
`qwen3:1.7b` model, persistent conversations/sources/feedback, and an
employee-only analytics view. It reuses read-only LLMGuard inspection
interfaces without changing LLMGuard routes, detectors, model artifacts, or
vector-store data. The assistant derives private identity from the signed
portal session, uses exact fee/course/payroll/policy retrieval, resets entity
references on New Chat, suppresses sources on denied or unsupported answers,
and uses the existing local UoH logo and site colors in its accessible widget.
