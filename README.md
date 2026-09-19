# LLMGuard

LLMGuard is a local RAG security demo with a prompt firewall, retrieved-content firewall, semantic detection, trained ML classifier, FAISS retrieval, dashboard logging, document upload/RAG ingestion support, and Qwen3 1.7B as the official local Ollama model.

## Runtime Boundary

LLMGuard runs on `http://127.0.0.1:8000` and exposes only product, security,
evaluation, authentication, and administration routes. The standalone University
application runs on `http://127.0.0.1:8001`.

LLMGuard owns an external-application registry in `logs/llmguard.db`. The
authenticated `/admin/applications` page lists registered application identity,
organization, environment, integration status, and channels. Registration is
not evidence of an active connection or protection state; credentials,
heartbeat, and the security-decision API are intentionally separate concerns.

An authenticated application detail page at
`/admin/applications/{application_id}` manages per-application API credentials.
Credential secrets are cryptographically generated, stored only as SHA-256
hashes, and displayed once in a non-cacheable creation response. Normal views
show only the key ID and lifecycle metadata. These credentials are not accepted
by a security-decision API yet; heartbeat and `/api/v1/guard` remain
unimplemented.

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
/admin/security-dashboard Live SOC operations
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
