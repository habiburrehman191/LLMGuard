# Current Baseline Before Service Separation

**Phase:** 0B — Freeze Current Baseline

**Captured:** 2026-09-20T01:20:30+05:00

**Repository:** `C:/Users/Habib UR Rehman/LLMGuard`

**Branch / HEAD:** `main` / `2b89450edc4ce344df5871552e9a23c2a8ba1720`

**Baseline status:** Documented; runtime starts, University tests pass, and two known LLMGuard frontend assertions fail.

This document records the current working tree as found. It does not describe a completed service boundary and does not authorize route moves, schema changes, authentication changes, or security-logic changes.

## Scope and Evidence

The audit covered:

- FastAPI application entrypoints and router composition.
- LLMGuard security, dashboard, authentication, RBAC, RAG, model, and persistence modules.
- The standalone `university_site/` application, its public site, student and employee portals, authentication, chatbots, data, and persistence.
- All route decorators under `app/` and `university_site/`.
- Current Git tracking state for `university_site/` and the classifier artifact.
- Read-only database counts, both unit-test suites, and live startup probes on ports 8000 and 8001.

No architecture, route, authentication, chatbot, detector, model, or database code was changed during this phase. The only intended repository addition is this document.

## Entrypoints

| Owner | Entrypoint | Current command | Default address | Startup behavior |
| --- | --- | --- | --- | --- |
| LLMGuard, currently mixed host | `app.main:app` | `.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000` | `http://127.0.0.1:8000` | Mounts `/static`; includes security/admin, legacy student/employee, demo, frontend, and auth routers; initializes both LLMGuard SQLite stores. |
| University | `university_site.__main__` → `university_site.main:app` | `.\.venv\Scripts\python.exe -m university_site` | `http://127.0.0.1:8001` | Runs Uvicorn; module import calls `ensure_seeded()` and `ensure_knowledge_index()` before creating the app. |

Operational command entrypoints also exist for evaluation, classifier training/testing, retrieval/index rebuilding, synthetic testbed seeding, and University access-control/zero-trust evaluation. They are support tools, not separate services. The relevant modules are `app/evaluation.py`, `app/ml_firewall.py`, `app/retriever.py`, `scripts/rebuild_index.py`, `scripts/seed_testbed.py`, `scripts/load_*`, and `scripts/evaluate_university_*`.

## Ownership Classification

### LLMGuard

- Security application composition and API: `app/main.py`, `app/frontend.py`.
- Security pipeline: `app/llmguard/`.
- Existing hybrid/rule/semantic/ML firewall stack: `app/hybrid_firewall.py`, `app/firewall.py`, `app/semantic_firewall.py`, `app/ml_firewall.py`.
- AI gateway and approved local-model client: `app/ai/`.
- Security RAG and ingestion implementation: `app/rag/` plus the legacy `app/retriever.py` path.
- Security policy, output, and tool controls: `app/policy_engine.py`, `app/output_firewall.py`, `app/tool_firewall.py`.
- Security dashboard, SOC, logs, audit, detector comparison, document security, and red-team templates/static assets.
- Security telemetry database `logs/llmguard.db`.
- Classifier artifacts under `models/hybrid_firewall/`.

### University

- Standalone public site and portals: `university_site/main.py`, `university_site/templates/`, and `university_site/static/`.
- University-specific session authentication: `university_site/auth.py`.
- University domain models, repository, deterministic seed, and database: `university_site/models.py`, `repository.py`, `seed.py`, `database.py`, and `demo_data/university_demo.sqlite3`.
- Public, student, and employee chatbot routes, conversations, retrieval logic, and UI: `university_site/chatbot/` and its chatbot template/static assets.
- University route and chatbot test suites: `university_site/tests/`.
- Legacy University/demo surfaces still hosted by LLMGuard: `app/portals/student.py`, `app/portals/employee.py`, `app/demo_routes.py`, `app/demo_university.py`, and their University-facing templates. These belong to the University domain even though they are currently mounted by `app.main`.

### Shared or coupled

- `app/main.py` is the current composition root for LLMGuard and the legacy student/employee/demo route surfaces.
- `app/portals/admin.py` mixes LLMGuard security/SOC/evaluation/document routes with portal-record and portal-AI operations.
- `app/portals/common.py`, `app/auth.py`, `app/rbac.py`, `app/models.py`, and `app/database.py` combine testbed user/portal concepts with security gateway records.
- `logs/university_testbed.db` contains both security telemetry and legacy portal/testbed identity/data.
- The standalone University chatbot imports LLMGuard code in-process:
  - `app.llmguard.pipeline.inspect_prompt`
  - `app.llmguard.pipeline.inspect_retrieved_context`
  - `app.llmguard.pipeline.inspect_output`
  - `app.rag.vector_store.build_index`
  - `app.rag.vector_store.search`
  - `app.config.get_settings` for the Ollama URL/model
- The University chatbot maps its public/student/employee contexts onto LLMGuard roles. Employee chatbot requests currently map to `super_admin` for pipeline checks.

## Route Ownership

### LLMGuard route surface on port 8000

| Routes | Ownership | Notes |
| --- | --- | --- |
| `GET /`, `GET /login`, `GET /app`, `GET /favicon.ico` | LLMGuard | Product landing, console sign-in, redirect, and icon. |
| `GET /health`, `POST /ask` | LLMGuard | Health and protected AI gateway entrypoint. |
| `GET /admin/dashboard`, `GET /admin/security-dashboard`, `GET /admin/dashboard/data`, `GET /admin/logs/recent` | LLMGuard | Security overview, SOC, and telemetry. Implementations still depend on shared user/database abstractions. |
| `GET /admin/audit`, `GET /admin/security/events` | LLMGuard | Audit/history and security-event views/API. |
| `/admin/compare`, `/admin/compare/run` | LLMGuard | Detector comparison/evaluation. |
| `/admin/redteam`, `/admin/redteam/run`, `/admin/redteam/export`, `/admin/redteam/cases` | LLMGuard | Red-team UI, execution/export, and case data. |
| `/admin/documents`, `/admin/documents/upload-manager`, `/admin/documents/rebuild`, `DELETE /admin/documents/{document_id}` | LLMGuard with shared persistence | Document security and RAG administration. |
| `/auth/login`, `/auth/logout`, `/auth/me` | Shared/coupled | LLMGuard console authentication also models student/employee/admin portal scope in `university_testbed.db`. |
| `/admin/all-records`, `/admin/ai/ask`, `/admin/documents/upload` | Shared/coupled | Legacy portal-record and portal-AI operations inside the admin router. |
| `/student/dashboard`, `/student/records`, `/student/ai/ask`, `/student/documents/upload` | University legacy surface | Still mounted by `app.main`; preserved for later migration. |
| `/employee/dashboard`, `/employee/records`, `/employee/ai/ask`, `/employee/documents/upload` | University legacy surface | Still mounted by `app.main`; preserved for later migration. |
| `/demo/university`, `/demo/uoh`, `/demo/ask-unprotected`, `/demo/audit` | University/security testbed coupling | University-themed vulnerable/protected demonstration and audit paths hosted inside LLMGuard. |

The `/admin` router cannot be moved as one unit: it contains legitimate LLMGuard security pages and coupled legacy portal operations.

### University route surface on port 8001

These routes are University-owned:

- Public website: `/`, `/university`, `/university/about`, `/university/academics`, department/faculty pages, contact, information pages, search, policy pages, and admissions pages.
- Portal selection/authentication: `/portal`, `/portal/login`, student login/logout, employee login/logout, and generic logout.
- Student portal: dashboard, profile, courses/detail, attendance, results, fees/receipt, timetable, notices, and documents/download.
- Employee portal: dashboard, profile, attendance, leave submission, assignments/detail, department, notices, policies/detail/acknowledgement, controlled records/detail, directory, students/detail, organogram, and assistant feedback.
- University chatbot API: `/api/university/chat/{portal_context}` plus conversation, message, deletion, and feedback endpoints.
- Health: `/health` and `/health/data`.

The port-8001 application does not import or mount the LLMGuard FastAPI app, but its chatbot implementation imports selected LLMGuard Python modules directly, so it is not process-independent yet.

## Database Ownership

| Store | Owner | Current contents and observations |
| --- | --- | --- |
| `logs/llmguard.db` | LLMGuard | Low-level SQLite tables `logs`, `demo_events`, and `access_events`; used for request/security telemetry and dashboard aggregation. |
| `logs/university_testbed.db` | Shared/coupled | SQLAlchemy tables `users`, `portal_records`, `documents`, `document_chunks`, `ai_interactions`, `firewall_events`, `tool_calls`, `redteam_cases`, and `audit_logs`. It mixes identity/portal records with LLMGuard enforcement and evaluation data. |
| `university_site/demo_data/university_demo.sqlite3` | University | Standalone University academic, HR, policy, controlled-record, audit, and chatbot tables. Current read-only verification found exactly **200 students** and **30 employees**. |
| `data/semantic_index/` and other configured LLMGuard retrieval paths | LLMGuard | LLMGuard retrieval indexes and controlled document data. |
| `university_site/demo_data/chat_vector_store/` | University data, LLMGuard implementation dependency | University-owned generated indexes, currently built/searched by importing `app.rag.vector_store`. |

All three SQLite files are runtime-mutable and ignored from normal source review. Test/startup verification added operational records and therefore changed database hashes; row counts for telemetry/chat activity are intentionally not treated as immutable baseline values. The required University entity counts remained 200 and 30 after verification.

## Authentication and RBAC Baseline

- LLMGuard uses `app/auth.py` with bearer or `llmguard_token` cookie authentication backed by `logs/university_testbed.db`.
- LLMGuard roles/scopes are defined in `app/models.py`; `app/rbac.py` and the LLMGuard pipeline enforce portal, classification, owner, tool, and retrieval rules.
- The LLMGuard development seed contains separate student, employee, and super-admin testbed users, so its auth model is not yet security-console-only.
- The standalone University app uses `university_site/auth.py`, its own `uoh_demo_session` cookie, signed session payloads, and explicit `student`, `employee`, or `administration` portal realm.
- University student and employee login realms are separate and cross-portal access is rejected by backend checks.
- No cross-process service identity, signed security decision request, API key, heartbeat, or application registration contract exists yet.

## Chatbot and Security Baseline

- LLMGuard retains prompt, access, context, tool, and output firewalls; DLP; heuristic and semantic detectors; hybrid ML detection; risk aggregation; sanitization; RBAC; secure RAG; audit/event logging; and Qwen access through the AI gateway.
- The configured official local model remains `qwen3:1.7b`.
- Protected LLMGuard requests prevent model invocation when prompt or retrieved context is blocked/quarantined.
- The University app owns three chatbot contexts: public, authenticated student, and authenticated employee.
- University chatbot authorization/retrieval/conversation storage is local to the University database, but security inspection, vector indexing/search, and Ollama settings are imported from LLMGuard modules in the same Python environment.
- University chatbot security wrappers catch LLMGuard import/runtime exceptions and fall back to their local authorization/sparse-retrieval behavior. This keeps the demo usable but means security posture differs depending on whether LLMGuard dependencies load.

## Verification Results

### Data

- `students = 200` — verified directly from `university_demo.sqlite3` and again through `GET /health/data`.
- `employees = 30` — verified directly from `university_demo.sqlite3` and again through `GET /health/data`.
- `/health/data` also reported zero duplicate IDs/usernames/emails, zero cross-realm duplicate usernames/emails, zero foreign-key errors, and full student coverage for enrollments, attendance, results, fees, and timetable.

### Tests

| Suite | Command | Result |
| --- | --- | --- |
| LLMGuard | `.\.venv\Scripts\python.exe -m unittest discover -s tests -v` | **64 run: 62 passed, 2 failed** in 51.336 seconds. |
| University | `.\.venv\Scripts\python.exe -m unittest discover -s university_site\tests -v` | **26 passed** in 25.664 seconds. |

The two LLMGuard failures are baseline expectation drift, not detector failures:

1. `test_frontend.FrontendRouteTests.test_dashboard_page_renders_live_log_data` expects `/static/security_dashboard.js?v=22`; the rendered page uses `v=23`.
2. `test_frontend.FrontendRouteTests.test_user_console_page_renders` expects `/static/product.css?v=22`; the rendered page uses `v=23`.

The modified `tests/test_product_frontend.py` suite already accepts the current product shell and passed all of its tests, but the older `tests/test_frontend.py` assertions have not been updated. This phase intentionally did not edit either file.

### Startup

Both applications were started using their documented commands, probed, and then the exact started process IDs were stopped. Ports 8000 and 8001 were confirmed free afterward.

- LLMGuard: `GET /health` → 200 with `LLMGuard API is running`; `GET /` → 200.
- University: `GET /health` → 200; `GET /health/data` → 200; `GET /` → 200; `GET /portal` → 200; student login page → 200; employee login page → 200.
- Authenticated student/employee journeys and cross-realm denial are covered by the passing University route tests.

## `university_site/` Finding

`university_site/` is a complete standalone application in the working directory but is **not represented in Git at all**:

- Tracked paths under `university_site/`: **0**.
- Non-ignored untracked paths: **221**.
- No nested `.git` repository.
- No Git history for the directory on any currently visible ref.
- The non-ignored set includes Python source, 26 templates, 52 static assets, 119 test assets/files, documentation, and `demo_data/.gitignore` plus one recovery text file.
- The directory had 1,349 total files and approximately 228 MB during inspection because it also contains ignored caches, generated data, browser profiles, the SQLite database, and vector indexes.
- `university_site/demo_data/.gitignore` intentionally excludes `*.sqlite3`, SQLite sidecars, `chat_vector_store/`, browser profiles, and `test_models/`.

Consequence: the running University code, tests, templates, and static assets cannot currently be recreated from the repository commit. This is the largest source-control blocker to a safe split. No files under `university_site/` were added, removed, restored, or staged during this investigation.

## Classifier Artifact Finding

`models/hybrid_firewall/logistic_regression.joblib` was already modified in the working tree and was preserved as-is.

| Property | Committed `HEAD` artifact | Working artifact |
| --- | --- | --- |
| Size | 10,548 bytes | 10,548 bytes |
| Git blob | `80908e135f6d7221beb825487e3c2413ab927fd3` | `39b9946e98d1464615dc1018ff397329507be75c` |
| SHA-256 | `52eb28d62bb0d2b4be0d7da60ef144bce7b8ea04ef41524ff006cd42a800b4ae` | `a2f02502df46d42f0d578292fc51b213dde3c8f2da30857ae6eb91bf210bcef2` |

A trusted local `joblib` object comparison found the same dictionary keys and equal values for:

- classifier type and constructor parameters;
- class labels;
- all 3×384 learned coefficients;
- all three intercepts;
- feature count;
- configured embedding model (`all-MiniLM-L6-v2`);
- label list, local-files-only flag, and batch size.

The byte difference therefore appears serialization-level rather than a learned-behavior change. Its generating command/provenance is not recoverable from Git inspection alone. The artifact must remain dirty until its owner chooses and records a canonical build; it was not restored, retrained, staged, or replaced here.

## Exact Separation Blockers

1. **University source is untracked.** The complete `university_site/` source/assets/tests must be reviewed and placed under deliberate version control before either process can be reproduced or released independently; generated database/vector/browser files must remain excluded.
2. **Direct security-pipeline imports cross the intended process boundary.** University chatbot prompt, retrieved-context, and output checks call `app.llmguard.pipeline` Python functions rather than a stable service contract.
3. **Direct vector-store imports cross the boundary.** University index construction/search imports `app.rag.vector_store` and relies on its local index format and dependencies.
4. **Ollama configuration is borrowed from LLMGuard.** The University chatbot imports `app.config.get_settings`; configuration ownership and model-call responsibility are not separated.
5. **Port 8000 still mounts University routes.** `app.main` includes student, employee, and University demo routers alongside LLMGuard routes.
6. **The admin router is mixed.** `app/portals/admin.py` contains both LLMGuard SOC/evaluation/document operations and legacy portal-record/portal-AI endpoints; moving the whole router would break one side.
7. **The testbed SQLAlchemy database is mixed.** `logs/university_testbed.db` combines users/portal records/documents with interactions, firewall events, red-team cases, tool calls, and audit logs. Table ownership, migration, retention, and read/write contracts must be decided first.
8. **Authentication and role concepts are coupled.** LLMGuard auth still owns student/employee/admin identities and portal scopes, while the standalone University has a second session realm. A process boundary needs an explicit identity/assertion contract without weakening either RBAC implementation.
9. **No inter-service security contract exists.** There is no authenticated request schema, correlation ID contract, timeout/failure policy, decision schema/version, or auditable application identity for University-to-LLMGuard inspection.
10. **Startup performs import-time University mutation.** `university_site.main` seeds the database and ensures the knowledge index at module import. Independent deployment needs an explicit initialization/migration lifecycle.
11. **The current LLMGuard test baseline is not green.** Two stale asset-version assertions must be reconciled before using the suite as a clean separation regression gate.
12. **Classifier provenance is unresolved.** The dirty artifact is semantically equal to `HEAD` under inspected attributes but byte-different; a canonical source/build decision is needed for reproducible packaging.

## Next-Phase Readiness

The baseline is sufficiently documented to plan the next phase, but implementation should not begin as if the repository were clean or the services were independent. Before moving routes or creating integration APIs, the next phase should:

1. Establish a reviewed, reproducible Git baseline for `university_site/` while excluding generated/private runtime artifacts.
2. Resolve the two stale frontend test expectations and decide the canonical classifier artifact without discarding existing work.
3. Approve a route/table/module ownership matrix, especially for `app/portals/admin.py`, `/auth/*`, and `logs/university_testbed.db`.
4. Define the inter-process identity and security-decision contract, including failure behavior that never silently weakens protection.
5. Replace direct University imports of LLMGuard pipeline/RAG/config only during the authorized service-separation phase.

No service separation, API-key generation, heartbeat, route move, database migration, or security/authentication change was performed in Phase 0B.
