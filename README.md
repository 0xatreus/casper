# Casper

## Web Vulnerability Scanner (Python)

Initial scaffold for the scanning service described in the brief. The goal is to provide a FastAPI front-end, worker-backed pipelines, capability-gated modules, and normalized lifecycle data (targets, scans, endpoints, findings, evidence, tech components, CVE candidates, exceptions, audit).

### Layout
- `scanner/app.py` – FastAPI entrypoint and dependency wiring.
- `scanner/core/` – capability model, schemas, orchestrator skeleton, audit & baseline helpers.
- `scanner/modules/` – pluggable modules (discovery, passive checks, fingerprinting, CVE correlator, manual export stubs).
- `scanner/plugins/` – plugin interface for module registration.

### Quick start (dev)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn scanner.app:app --reload
```

### Libraries
- `fastapi`: Web framework for the API service and routes.
- `uvicorn[standard]`: ASGI server for running the FastAPI app.
- `sqlmodel`: ORM/data layer built on SQLAlchemy + Pydantic.
- `psycopg[binary]`: PostgreSQL driver used by SQLModel/SQLAlchemy.
- `pydantic`: Data validation/serialization (requests/responses, settings types).
- `pydantic-settings`: Load configuration from environment variables.
- `httpx`: HTTP client for outbound requests during scanning.
- `structlog`: Structured logging with metadata.
- `celery`: Background task queue for async scan execution.
- `redis`: Redis client (broker/results/caching).
- `python-dotenv`: Loads `.env` files for local development.
- `PyYAML`: YAML parsing for config/signatures.
- `psycopg`: Duplicate/unpinned entry; redundant with `psycopg[binary]==3.1.18`.

### Next steps
- Fill worker queue plumbing (Celery/RQ) and connect orchestrator tasks.
- Flesh out module implementations and add migrations for the SQLModel schema.
- Hook audit logging to every route/task and wire object storage for response bodies.
