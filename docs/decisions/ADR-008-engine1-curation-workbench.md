# ADR-008: Engine 1 curation workbench

## Status

Proposed. This records an audit of the local prototype and the architecture for the next Engine 1 slice. It does not implement PostgreSQL, a React workbench, source adapters, or an AI checker.

## Date

2026-10-03

## Context

The branch checkpoint `639f34f` preserves a tested local prototype. On 2026-10-03, `ruff check`, `ruff format --check` (79 files), `pytest` (115 passed), and `mypy` (37 source files) passed on that tree. The product direction chosen for this slice is a pipeline portal. Reviewer-role login is not the main idea.

Engine 1 today is a local intake pin plus a compact catalog. It is not yet a curation and approval workbench.

## Audit

Reusable, and left in place:

- Pydantic contracts, the T1548 allowlisted candidate, hash pins, and fail-closed intake.
- The 50-row ATT&CK 19.2 technique file, OWASP CNAS-1 through CNAS-10 short names, the five-row NVD page, and the CISA KEV catalog header.
- The human approval function that exports an `ApprovedRule` only for an approved decision. Engine 3 already consumes that export on the positive fixture.
- Engine 2–4 local fixture behavior. This ADR does not change those engines.

Misleading if read as the workbench:

- `strength` is only the count of distinct source families. It is not authority, relevance, mapping confidence, freshness, corroboration, or an overall confidence.
- The curated MITRE–OWASP and OWASP–NVD links are local associations. They do not make a technique, a weakness, a CVE, and a KEV row the same kind of object.
- Approval events are computed in memory and returned by the API. They are not stored, and they disappear on restart.
- `reviewer_id` is supplied by the caller. There is no session and no authentication.
- The review UI is server-rendered HTML. It is not an analyst workbench.
- Remote fetch is refused. The feed scripts are maintainer tools, not idempotent source runs.
- AWS Threat Technique Catalog is named in the strength formula and is not ingested.
- Almost every technique row is `no_rule_yet`. One hardcoded mapping exists: `mitre-attack` / `T1548` to `rule_t1548_assume_chain`. T1548 is not one of the 50 catalog rows.
- No model checker runs. `checker` on the catalog is `not_used`.

Blocked for the persistence phase:

- This machine has neither `psql` nor `docker`. A PostgreSQL runtime cannot be started here until one of those is available. Tests must not pretend a database ran.

## Decision

- Keep the prototype modules working. New workbench code sits beside them until a stored path can replace a behavior with tests.
- The workbench is a pipeline portal: ingest, preserve, normalize, correlate, candidate, validate, review, publish. Login roles are deferred.
- PostgreSQL, SQLAlchemy 2, and Alembic are the intended runtime store. Domain logic stays independent of FastAPI and of ORM classes.
- Source families stay distinct. Relations are typed. A later confidence record separates source count from authority, relevance, mapping confidence, freshness, corroboration, and an overall result computed from those parts.
- Rule candidates stay deterministic and allowlisted. Unsupported evidence stays unsupported. Nothing auto-approves.
- An AI checker, if added, is optional, schema-validated, and unable to approve or silently edit a rule. The deterministic path must run with the checker disabled.
- A published rule must point at the exact candidate version and evidence snapshot that was approved. That publication is not implemented yet.
- No production password, token, or NVD API key is stored in the repository. An optional NVD key, when a later adapter needs one, comes from the environment.

## Consequences

- Phase 0 is this audit and checkpoint. The workbench screens, database, adapters, and checker remain unimplemented.
- Phase 1 starts when a PostgreSQL server can be reached from this checkout. Until then, persistence work is blocked rather than simulated.
- Engine 2–4 contracts stay as they are unless a published-rule export forces a compatible change.
