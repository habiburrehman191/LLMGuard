# LLMGuard Release Readiness

This document is the final reproducibility and security checklist for the
controlled local LLMGuard and synthetic University testbed. It does not claim
that the current local demo configuration is suitable for an Internet-facing
production deployment.

## Runtime requirements

- Python 3.11 (the audited environment uses Python 3.11.0).
- Dependencies pinned in `requirements.txt`.
- Ollama available at `LLMGUARD_OLLAMA_URL` (default
  `http://localhost:11434/api/chat`).
- `qwen3:1.7b` installed in Ollama. This is the only supported application
  model; University model invocation rejects a different configured model.
- Writable local directories for ignored SQLite databases, logs, reports, and
  vector indexes.

Install dependencies and the approved model:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
ollama pull qwen3:1.7b
```

## Start the two processes

Start LLMGuard on port 8000:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Start the standalone University application on port 8001 from a second shell:

```powershell
.\.venv\Scripts\python.exe -m university_site
```

LLMGuard initializes its application/security SQLite schemas and default
registered University application at startup. Importing the University app
currently seeds its synthetic SQLite data and ensures its knowledge index.

## Integration configuration

The University operates in documented standalone compatibility mode only when
both integration credentials are absent. If either credential is present, an
incomplete or failing security integration fails closed at protected request
and ingestion boundaries.

Required for University-to-LLMGuard integration:

| Variable | Purpose |
| --- | --- |
| `UOH_LLMGUARD_KEY_ID` | Active application credential key ID. |
| `UOH_LLMGUARD_API_SECRET` | One-time application secret, supplied only from the University backend environment. |

Set these explicitly for shared/non-local deployment:

| Variable | Local default / purpose |
| --- | --- |
| `UOH_LLMGUARD_BASE_URL` | `http://127.0.0.1:8000`; LLMGuard service URL. |
| `UOH_LLMGUARD_APPLICATION_ID` | `university-of-haripur`; registered application identity. |
| `UOH_LLMGUARD_ENVIRONMENT` | `development`; must match the registry. |
| `UOH_LLMGUARD_TIMEOUT_SECONDS` | `5`; backend inspection timeout. |
| `UOH_LLMGUARD_HEARTBEAT_INTERVAL_SECONDS` | `30`; University heartbeat interval. |
| `UOH_APPLICATION_VERSION` | Optional deployed University version. |
| `UOH_LLMGUARD_INTEGRATION_VERSION` | `heartbeat-v1`; integration contract version. |
| `LLMGUARD_AUTH_SECRET` | Local development token-signing default exists; replace it outside local use. |
| `LLMGUARD_SESSION_HASH_SECRET` | Local session-correlation default exists; replace it outside local use. |
| `UOH_DEMO_SESSION_SECRET` | Local University session-signing default exists; replace it outside local use. |
| `LLMGUARD_DB_PATH` | LLMGuard-owned registry, telemetry, and incident SQLite path. |
| `LLMGUARD_TESTBED_DATABASE_URL` | Legacy LLMGuard testbed SQLAlchemy database URL. |
| `LLMGUARD_OLLAMA_URL` | Local Ollama chat endpoint. |
| `LLMGUARD_OLLAMA_MODEL` | Must remain `qwen3:1.7b`. |

Do not place integration secrets in browser JavaScript, templates, URLs,
request bodies, logs, or reports. Application credentials are generated with a
cryptographically secure source, persisted as SHA-256 hashes only, compared in
constant time, and displayed in plaintext only once at creation.

## Audited request architecture

The configured University chatbot flow is:

```text
backend-derived channel/session
  -> authenticated input Guard call
  -> LLMGuard per-request decision and session policy
  -> University session identity and RBAC
  -> authorized retrieval and source filtering
  -> authenticated context Guard call
  -> approved/sanitized evidence only
  -> shared trusted prompt builder
  -> local qwen3:1.7b
  -> authenticated output Guard call
  -> approved/sanitized response persistence
  -> user response
```

One backend-generated `request_id` is reused for input, context, output, and
the final response. Browser content cannot select the application, channel,
role, identity, session authority, or protection state.

The University ingestion flow is:

```text
University-owned source
  -> filename/MIME/text/metadata validation
  -> whole-document LLMGuard inspection
  -> deterministic chunking
  -> per-chunk LLMGuard inspection
  -> approved/sanitized chunks only
  -> atomic University SQLite replacement
  -> University-owned vector-index rebuild
```

Configured inspection failures stop before database replacement. `BYPASSED`
continues the established University indexing behavior only when LLMGuard
protection was intentionally disabled; it is never recorded as approval.

## Security invariant checklist

| Boundary | Required result |
| --- | --- |
| Blocked or session-restricted input | University database, retrieval, tools, and main LLM are not called. |
| Quarantined context | Trusted prompt construction and the main LLM are not called. |
| Sanitized context | Only returned sanitized chunks are rebuilt into evidence; raw chunks are not restored. |
| Blocked output | Only the generic safe response is returned and persisted; raw generated content is neither returned nor stored. |
| Sanitized output | Only sanitized content is returned and persisted; source links are removed when rewritten provenance is unavailable. |
| Rejected/quarantined ingestion | Rejected content receives no persistence or vector-index write. |
| Sanitized ingestion | Only sanitized document/chunk text reaches persistence and vector indexing. |
| Configured dependency failure | Input/context/output and ingestion fail closed. |
| Standalone compatibility | Available only when both University integration credential variables are absent. |

University RBAC remains authoritative for record ownership and access in both
protected and intentionally bypassed modes. LLMGuard detects security attacks;
it does not convert ordinary unauthorized record requests into prompt attacks.

## Protection-state truth table

- `INTEGRATION_PENDING`: no accepted heartbeat exists.
- `DISCONNECTED`: an accepted heartbeat exists but is stale.
- `BYPASSED`: heartbeat is current and protection is intentionally disabled.
- `DEGRADED`: heartbeat is current and protection is enabled, but all required
  Guard stages have not succeeded or a later stage failure is recorded.
- `PROTECTED`: heartbeat is current, protection is enabled, and input,
  context, and output stages are all currently available.

A heartbeat or registration alone cannot produce `PROTECTED`. An enabled-mode
inspection exception records a security-path failure, returns HTTP 503, and
moves a connected application to `DEGRADED`; it never silently bypasses.

## Verification commands

Run the complete LLMGuard suite:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

Run the complete University suite:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s university_site\tests
```

Run the evaluation-harness tests explicitly:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_phase14a_evaluation tests.test_phase14b_evaluation
```

Validate Python syntax/import compilation:

```powershell
.\.venv\Scripts\python.exe -m compileall -q app sdk evaluation university_site tests
```

Reproduce the final synthetic benchmark without overwriting historical runs:

```powershell
.\.venv\Scripts\python.exe -m evaluation.run --output-dir reports/evaluation/final
```

The benchmark must continue to use 54 synthetic cases, seeds `42, 43, 44`,
dataset SHA-256
`ec3cb54648f2f94909c5dd1dc7c27ce0df1588deadbcacdf769a049777bf11e8`,
and deterministic case-order SHA-256
`e582f6a921f8c7ae2681573ce93c30bc10e101ae8a66c98e56876bdcb49468a0`.
Generated reports remain under the ignored `reports/` tree.

## Repository and artifact status

- Root and University ignore rules exclude generated databases and sidecars,
  logs, reports, uploads, processed data, caches, browser profiles, and vector
  indexes.
- `.venv_broken/` and `.vscode/` are local, untracked directories and must not
  be included in a release checkpoint.
- No `.env`, PEM/key file, database, vector index, log, report, or Python cache
  is tracked.
- `models/hybrid_firewall/logistic_regression.joblib` has unresolved
  serialization provenance. The working artifact is byte-different from
  `HEAD`, while the earlier deterministic comparison found identical learned
  coefficients, intercepts, labels, configuration, and predictions. Its
  working SHA-256 is
  `a2f02502df46d42f0d578292fc51b213dde3c8f2da30857ae6eb91bf210bcef2`.
  Do not restore, retrain, stage, or publish it until a canonical artifact and
  reproducible generation process are approved.

## Known deployment limitations

- The application-to-LLMGuard contract uses an application ID, key ID, and API
  secret over HTTP headers. Per-request cryptographic signing is not currently
  implemented. Request IDs prevent same-stage duplicates, but are not a full
  signed replay-protection protocol. Add authenticated request signing as
  future work before crossing an untrusted network.
- Local defaults use HTTP and cookies with `secure=False`. Terminate TLS and
  make cookies Secure before an Internet-facing deployment.
- Development seed accounts and passwords are synthetic conveniences, not
  production identity management.
- LLMGuard and University use local SQLite/FAISS storage. Multi-instance
  deployment, backup/restore, migrations, retention, and concurrent writer
  behavior require an explicit production design.
- University seeding and knowledge-index checks currently run during module
  import rather than through an external deployment migration job.
- The security benchmark is synthetic and local; it is not production traffic
  evidence or a guarantee against unseen attacks.
- Authorization-boundary and attack rules have finite language coverage. The
  semantic and ML layers remain active, but adversarial testing must continue.

## Release decision boundary

The repository may be released as a controlled local synthetic research/demo
baseline only after all verification commands pass and the intended source
changes are checkpointed without local/generated files. It is not ready for an
Internet-facing production deployment until the secret defaults, TLS/cookie
transport, request signing, storage/migration design, seed identities, and
classifier artifact provenance are resolved.
