# Service Separation Plan

## Scope

This plan defines the next boundary; it does not implement it. Phase 0C does not move routes or files, split databases, change authentication/RBAC, add API keys, or create security APIs.

## Target Processes

| Process | Address | Future responsibility |
| --- | --- | --- |
| LLMGuard | `127.0.0.1:8000` | AI security product, enforcement decisions, security telemetry, SOC, audit/history, detector evaluation, red-team tooling, document security, and security administration. |
| University | `127.0.0.1:8001` | Public University website, student and employee portals, University sessions/RBAC, academic and HR data, University chatbot UI/conversations, domain retrieval, and University-owned presentation. |

The University remains an application protected by LLMGuard. It must not share LLMGuard's Python process, database session, cookies, or internal modules after separation.

## Future Ownership

### LLMGuard

- Prompt, retrieved-context, and output inspection.
- Hybrid, rule, semantic, and ML detectors; risk scoring and sanitization.
- Tool, access, DLP, context, and output firewalls.
- Security decision records, request correlation, audit evidence, and SOC views.
- LLMGuard operator authentication and product settings.
- LLMGuard evaluation/red-team datasets and controlled security RAG assets.
- The future authenticated security-decision API.

### University

- All code currently under `university_site/` except generated/runtime data.
- `/university*`, admissions, search, policy, and public content routes.
- `/portal*`, student and employee authentication, sessions, and authorization.
- University domain database, seed lifecycle, documents, policies, and audit of University business actions.
- Public/student/employee chatbot conversations, authorized domain retrieval, citations, UI, and response presentation.
- University-specific configuration. It must no longer import `app.config`.

## Legacy Routes to Remove From `app.main` Later

Remove these only after their replacement paths on port 8001 and regression coverage are confirmed:

- `student_portal_router`: `/student/dashboard`, `/student/records`, `/student/ai/ask`, `/student/documents/upload`.
- `employee_portal_router`: `/employee/dashboard`, `/employee/records`, `/employee/ai/ask`, `/employee/documents/upload`.
- `demo_router`: `/demo/university`, `/demo/uoh`, `/demo/ask-unprotected`, `/demo/audit`.

Do not remove `admin_portal_router` as a unit. It mixes LLMGuard SOC/evaluation/document-security routes with legacy portal-record operations; those handlers must first be classified and tested individually. `/auth/*` must remain until LLMGuard operator authentication is separated from legacy student/employee identities.

## Persistence Separation Later

| Current store/table | Target disposition |
| --- | --- |
| `logs/llmguard.db` | Remains LLMGuard-owned security telemetry. |
| `university_site/demo_data/university_demo.sqlite3` | Remains University-owned domain/chatbot storage. |
| `university_testbed.db.users` | Split LLMGuard operators from legacy student/employee testbed identities; do not share session storage. |
| `portal_records` | Decide whether each synthetic record remains an LLMGuard evaluation fixture or migrates to University-owned domain data. |
| `documents`, `document_chunks` | Partition LLMGuard security/evaluation documents from University application documents and indexes. |
| `ai_interactions`, `firewall_events`, `tool_calls`, `redteam_cases` | LLMGuard-owned security/evaluation telemetry. |
| `audit_logs` | Split security-decision audit from University business-action audit. |

The separation phase must use explicit migrations or data-copy scripts with rollback and count checks. It must not point both running processes at the same mutable SQLite database.

## Direct Imports to Replace

University security calls that must become authenticated API calls:

| Current University import | Future boundary |
| --- | --- |
| `app.llmguard.pipeline.inspect_prompt` | Security decision request with `stage: input`. |
| `app.llmguard.pipeline.inspect_retrieved_context` | Security decision request with `stage: context`. |
| `app.llmguard.pipeline.inspect_output` | Security decision request with `stage: output`. |

Other cross-owner imports must also disappear:

- `app.rag.vector_store.build_index/search`: move retrieval implementation/configuration under University ownership, or define a separately approved retrieval contract. Do not expose it implicitly through the security-decision API.
- `app.config.get_settings`: University must own its runtime configuration. If model generation later belongs behind an LLMGuard gateway, define that as a separate contract rather than importing configuration.

## Future Security Decision Contract Shape

Conceptual endpoint: `POST /v1/security/decisions`. This is a proposed shape only; no route exists in Phase 0C.

### Request

```json
{
  "application_id": "university-of-haripur",
  "channel": "student_chat",
  "request_id": "application-generated-opaque-id",
  "stage": "input",
  "content": "content to inspect",
  "security_context": {
    "actor_ref": "opaque-application-local-reference",
    "role": "student",
    "session_ref": "opaque-correlation-reference",
    "classifications": ["student_self"],
    "source_metadata": []
  }
}
```

Required top-level fields:

- `application_id`: registered caller identity; never a secret by itself.
- `channel`: application channel such as `public_chat`, `student_chat`, or `employee_chat`.
- `request_id`: unique idempotency/correlation identifier generated by the University.
- `stage`: exactly `input`, `context`, or `output`.
- `content`: the exact bounded content to inspect.
- `security_context`: structured, minimal authorization and provenance metadata. It must never contain passwords, session cookies, bearer tokens, signing keys, or unrelated records.

Stage order is input before retrieval/generation, context before model generation, and output before release to the user.

### Response

```json
{
  "decision": "allow",
  "classification": "safe",
  "threat_type": null,
  "severity": "none",
  "risk_score": 0.0,
  "action": "allow",
  "reasons": [],
  "request_id": "application-generated-opaque-id"
}
```

Required response fields:

- `decision`: overall authorization result, proposed values `allow` or `restrict`.
- `classification`: proposed values `safe`, `suspicious`, or `malicious`.
- `threat_type`: stable threat category or `null`.
- `severity`: proposed values `none`, `low`, `medium`, `high`, or `critical`.
- `risk_score`: number from 0 through 1.
- `action`: existing enforcement vocabulary `allow`, `sanitize`, `quarantine`, or `block`.
- `reasons`: ordered, machine-safe explanation strings/codes.
- `request_id`: exact echo of the caller's correlation identifier.

A later specification may add `decision_id`, `policy_version`, detector signals, and `sanitized_content` when `action` is `sanitize`; these are not implemented or finalized here.

## Authentication and Failure Rules

- Authenticate the University as a service using a reviewed mechanism such as mTLS or a short-lived signed service token. Do not treat `application_id` as proof of identity.
- Bind the authenticated service identity to its allowed `application_id` and channels.
- Add timestamp/nonce or equivalent replay protection, request-size limits, schema versioning, timeouts, and auditable correlation IDs.
- Never send University login credentials, cookies, raw tokens, or signing secrets to LLMGuard.
- Fail closed for protected chatbot flow: if LLMGuard is unavailable or returns an invalid response, do not call Qwen and do not release uninspected output.
- Preserve the invariant that blocked or quarantined input/context never reaches Qwen.
- Log decisions with data minimization and explicit retention rules; do not duplicate the full University database into LLMGuard.

## Separation Exit Criteria

- Port 8000 exposes only LLMGuard-owned product/security routes.
- Port 8001 retains all University public, portal, and chatbot journeys.
- No `university_site` module imports `app.*` at runtime.
- Processes use separate authentication realms and mutable databases.
- Input, context, and output decisions are authenticated, correlated, tested, and fail closed.
- Existing LLMGuard and University suites remain green, with new contract and end-to-end tests added during the authorized separation phase.
