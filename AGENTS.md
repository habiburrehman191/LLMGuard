# LLMGuard Development Rules

LLMGuard is a controlled university AI security testbed for evaluating prompt injection defense, secure RAG, role-based access control, tool-call authorization, output filtering, and red-team replay in a synthetic environment.

## Data Safety

- Use only synthetic data.
- Never use real student, employee, admin, university private data, real credentials, real tokens, or real secrets.
- Vulnerable mode is allowed only for local red-team testing with synthetic data.
- Never expose `.env`, local user files, operating system files, credentials, tokens, or real secrets.

## File Access

- Do not allow arbitrary OS filesystem reading.
- Only read files uploaded through controlled upload routes or files inside controlled repository folders.
- Keep document ingestion scoped to the project-controlled data locations.

## Model Policy

- Keep `qwen3:1.7b` as the only official local Ollama model.
- Do not add Kimi, Gemma, Llama fallback, or multiple model profiles unless explicitly requested.
- Blocked or quarantined prompts must not call Qwen.

## Security Invariants

- Do not remove existing RAG, firewall, ML classifier, semantic detector, dashboard, logs, evaluation, or document ingestion.
- Do not weaken LLMGuard detection.
- Preserve prompt firewall, retrieved-content firewall, RBAC, DLP/output firewall, tool firewall, dashboard logging, and evaluation behavior.

## Architecture Preferences

- Do not use RabbitMQ or Kafka.
- Prefer FastAPI, SQLAlchemy, SQLite, FAISS, and direct async/background tasks.

## Engineering Expectations

- All new code must include tests where practical.
- Update `README.md` when changing setup, architecture, commands, or demo flows.
