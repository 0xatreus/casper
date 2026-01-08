# Roadmap

This roadmap turns the current scaffold into a deployable, trusted internal scanning platform.
The sequencing is deliberate: reliability and safety before scale and intelligence.

## Milestones

### M0: Foundation and schema lock (now)
Focus: lock the data model and plugin contract so everything else can build on it.

Key deliverables:
- Canonical Finding + Evidence schema (dedupe keys, confidence, severity, remediation fields).
- Plugin contract and SDK (inputs, outputs, capability requirements, error handling).
- Persistence and migrations (Alembic or SQLModel migrations, versioned schema).
- API coverage for Findings, Evidence, Audit, Exceptions.
- Storage wiring for response bodies (local path + pluggable object store).

Definition of done:
- One end-to-end scan run persists Targets, Scans, Findings, Evidence, Audit.
- Schema is versioned and migratable.
- Plugins can be loaded with a stable interface and capability gating.

### M1: Trustworthy results (Level 1 -> Level 2)
Focus: reduce noise and make output trustworthy enough for teams to act on.

Key deliverables:
- Evidence-driven confidence scoring (high/med/low with clear rules).
- Dedupe and correlation (one root cause, not many duplicates).
- Baseline diff and regression view (new vs fixed vs still present).
- Exceptions with expiry + ownership + reason.
- Retest/recheck workflow.

Definition of done:
- Default view is "new findings since last scan".
- Exceptions can be created, reviewed, and expired.
- Recheck can be scheduled and recorded.

### M2: Safe scale (Level 2 -> Level 3)
Focus: scale execution without losing safety or stability.

Key deliverables:
- Job queue + workers (Celery/RQ + Redis).
- Per-target budgets (RPS, concurrency, max runtime).
- Rate limits, allowlists, and auth profile enforcement.
- Plugin isolation (subprocess or sandbox runner).
- Deterministic plugin versioning and config hashing per scan.

Definition of done:
- Distributed scans run reliably and safely.
- One plugin crash does not kill the scan.
- Every scan records plugin versions + config hash.

### M3: Intelligence and prioritization (Level 3 -> Level 4)
Focus: become a risk engine, not just a findings generator.

Key deliverables:
- Fingerprinting improvements with confidence tracking.
- CVE correlation gated by version confidence.
- Risk scoring (severity x exploitability x exposure x asset criticality).
- Asset context (owner/team, criticality, data sensitivity).

Definition of done:
- Default output ranks "what to fix first this week".
- CVE correlation never asserts certainty without evidence.

### M4: Workflow automation and enterprise integration (Level 4 -> Level 5)
Focus: integrate into org workflows and CI/CD.

Key deliverables:
- Integrations: Jira/GitHub Issues/GitLab, Slack, SIEM hooks.
- Actionable fix guidance (headers, config snippets, settings examples).
- CI gates (block on new High/Critical findings).
- Reporting and trend dashboards.

Definition of done:
- Teams can consume results where they already work.
- New critical findings can block release with clear rationale.

## Immediate next actions (suggested order)

1) Lock schema + plugin contract (M0).
2) Add migrations + API endpoints for Findings/Evidence/Audit/Exceptions (M0).
3) Implement baseline diff + exceptions + recheck (M1).
4) Introduce worker queue + budgets + isolation (M2).

If you want, we can turn M0 into concrete tickets and start implementing immediately.
