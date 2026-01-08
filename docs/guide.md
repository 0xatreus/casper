# Project Guide

## Vision

This is not "just a vulnerability scanner." It is a scanning ecosystem that turns messy real-world data
(assets, endpoints, configs, versions, auth, edge cases) into repeatable, auditable security decisions.

Core product goals:
- Trustworthy results (low noise, high evidence)
- Repeatability (baselines, exceptions, rechecks)
- Safety (profiles, rate limits, allowlists, audit logs)
- Extensibility (plugins, modular checks, tech matchers)
- Governance (who ran what, when, against what, with what permissions)

If any stage is missing, you get noise and confusion instead of outcomes.

## Architecture (factory line)

1) Target intake + policy gate
   - allowlists, auth profiles, rate limits, scan mode controls, legal/consent enforcement
2) Discovery
   - crawl, enumerate, collect endpoints, forms, APIs
3) Fingerprinting
   - tech stack signals, versions, WAF hints, framework patterns
4) Check execution (plugins)
   - checks run based on profile + fingerprints + endpoint type
5) Normalization
   - every plugin emits standardized Findings + Evidence
6) Storage + intelligence
   - baselines, exceptions, historical trends, asset inventory
7) Reporting + workflow
   - actionable output: what matters, why, proof, fix, retest

## Current State (M0)

M0 is implemented. It locks the schema, formalizes the plugin contract, wires storage for response bodies,
adds core APIs, and introduces Alembic migrations.

Key files:
- `scanner/core/models.py`: canonical schema
- `scanner/core/events.py`: event contract
- `scanner/plugins/contract.py`: plugin interface and module context
- `scanner/core/orchestrator.py`: orchestration, persistence, audit
- `scanner/core/storage.py`: storage backend (local)
- `scanner/api/routes.py`: endpoints
- `alembic/`: migrations

## Data Model (M0)

Targets and scans:
- `Target`: base_url, environment, auth_profiles (JSON)
- `Scan`: mode, profile_name, profile_capabilities, status, baseline_scan_id, started_at, finished_at

Discovery and evidence:
- `Endpoint`: method, url, params_hash, source, first_seen, last_seen
- `Fetch`: request (JSON), response_meta (JSON), storage_mode, body_path, body_hash, redaction_version
- `Evidence`: kind, snippet, location, hash, details (JSON)

Findings and context:
- `Finding`: dedupe_key, type, title, description, severity, confidence, status, remediation,
  references (JSON list), cwe_id, cve_id, evidence_ids, source_module, timestamps

Tech and CVE:
- `TechComponent`: name, version, cpe, confidence, evidence_ids
- `CVECandidate`: cpe, cve_id, source, confidence, status, linked_component_id

Governance:
- `ExceptionRecord`: finding_key, expires_at, approver, ticket, status, reason, owner
- `AuditEvent`: actor, action, scan_id, params (JSON), immutable

Enums:
- `StorageMode`: none, sampled, full
- `FindingStatus`: open, fixed, soft_deleted
- `Confidence`: low, medium, high
- `AuditAction`: scan.started, scan.completed, module.run, export.generated, exception.created,
  exception.expired, recheck.triggered

## Event Contract (M0)

Modules emit events; the orchestrator persists them:
- `EndpointDiscovered`
- `FetchEvent`: includes request/response + optional body
- `EvidenceEvent`: includes `details` JSON
- `FindingEvent`: includes title/description/remediation/references/cwe/cve
- `TechComponentEvent`
- `CVECandidateEvent`
- `RecordPack`

## Plugin Contract (M0)

Plugins implement:
- `name`, `description`, `version`, `required_capabilities`
- `run(scan, context) -> AsyncIterator[Event]`

`ModuleContext` gives read-only access to:
- settings (env config)
- DB session factory
- storage backend + default storage mode

## Orchestration Flow (M0)

1) `POST /targets` creates a target.
2) `POST /scans`:
   - selects capability profile
   - validates module names
   - writes Scan record
   - audits `scan.started`
3) Orchestrator runs modules (async) with capability gating.
4) Module events are persisted:
   - `FetchEvent` stores response bodies (redaction + sampling).
   - `EvidenceEvent`, `FindingEvent`, `TechComponentEvent`, `CVECandidateEvent` are saved.
5) Audit logs `module.run` and `scan.completed`.

## Storage (M0)

Local storage backend stores response bodies under `object_store_base` (file path or file:// URI).
Redaction and sampling rules are applied before storage.

## APIs (M0)

Targets:
- `POST /targets`
- `GET /targets`
- `GET /targets/{id}`

Scans:
- `POST /scans`
- `GET /scans`
- `GET /scans/{id}`

Core records:
- `GET /findings`
- `GET /findings/{id}`
- `GET /evidence`
- `GET /evidence/{id}`
- `GET /audit`
- `GET /audit/{id}`
- `GET /exceptions`
- `GET /exceptions/{id}`
- `POST /exceptions`

## Configuration

Env vars (prefix `SCANNER_`):
- `DATABASE_URL` (Postgres)
- `REDIS_URL`
- `OBJECT_STORE_BASE` (file:// or path)
- `STORAGE_MODE_DEFAULT` (none/sampled/full)
- `RECORD_ONLY_DEFAULT` (bool)

## Dev Boot (clean run)

1) Create venv and install requirements:
   - `python3 -m venv .venv`
   - `source .venv/bin/activate`
   - `pip install -r requirements.txt`

2) Start Postgres:
   - Docker example:
     `docker run --name scanner-db -e POSTGRES_USER=scanner -e POSTGRES_PASSWORD=scanner -e POSTGRES_DB=scanner -p 5432:5432 -d postgres:16`

3) Run migrations:
   - `export SCANNER_DATABASE_URL=postgresql+psycopg://scanner:scanner@localhost:5432/scanner`
   - `./.venv/bin/alembic -c alembic.ini upgrade head`

4) Start API:
   - `uvicorn scanner.app:app --reload`

5) Smoke test:
   - Create a target
   - Start a scan
   - Read `/scans`, `/findings`, `/evidence`, `/audit`

## Common Errors and Fixes

1) Missing columns (500 on /findings or /evidence)
   - Cause: DB schema older than M0 models.
   - Fix: reset DB and run migrations OR add missing columns and stamp Alembic.

2) Alembic cannot import `scanner`
   - Fix: run in venv and use `./.venv/bin/alembic -c alembic.ini upgrade head`.

3) `pydantic_settings` not found
   - Cause: running outside venv.
   - Fix: `source .venv/bin/activate` and `pip install -r requirements.txt`.

## Roadmap Summary

M1: Trustworthy results
- Baselines, exceptions, rechecks, dedupe/correlation, evidence-driven confidence rules.

M2: Safe scale
- Worker queue, budgets, allowlists, isolation, deterministic versioning.

M3: Intelligence and prioritization
- Fingerprints with confidence, CVE correlation gated by evidence, risk scoring,
  asset context (criticality, owner, exposure).

M4: Workflow automation
- Jira/GitHub/GitLab, Slack, SIEM, CI gates, fix guidance, reporting/trends.

## Final Product Definition

The mature platform:
- Runs safe scans (passive/active/intrusive) with enforced policy gates.
- Produces evidence-first findings with remediation guidance.
- Supports exceptions with expiry and rechecks.
- Tracks baselines and regressions.
- Supports authenticated scans without leaking secrets.
- Audits every action and preserves reproducibility.
- Scales via workers with isolation and budgets.
- Prioritizes risk with context and exploitability.
- Integrates into org workflows and CI/CD.
