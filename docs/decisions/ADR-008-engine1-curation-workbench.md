# ADR-008: Engine 1 curation workbench

## Status

Proposed. This records the audit and the first vertical slice. The checkout contains the PostgreSQL mapping, Alembic migration, and first React pending-review screen. A local PostgreSQL server has not been run. Source adapters and an AI checker are not in this slice.

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

Local execution limit:

- This machine has neither `psql` nor `docker`. The migration and the PostgreSQL tests are in the checkout. They run in GitHub Actions. Local commands must not pretend a database ran.

## Decision

- Keep the prototype modules working. New workbench code sits beside them until a stored path can replace a behavior with tests.
- The workbench is a pipeline portal: ingest, preserve, normalize, correlate, candidate, validate, review, publish. Login roles are deferred.
- PostgreSQL, SQLAlchemy 2, and Alembic are the workbench store. Domain records and the repository protocol do not import a driver. The API uses PostgreSQL only when `FYP_DATABASE_URL` is a reachable PostgreSQL URL. SQLite is rejected. There is no production fallback that pretends a write succeeded.
- Locally, `psql` and Docker are unavailable. That limits local execution. It does not remove the migration, the repository, or the GitHub Actions PostgreSQL job.
- A read-only fixture endpoint shows the T1548 path without writing. The import endpoint returns `database_unavailable` when PostgreSQL cannot be reached.
- Source families stay distinct. Relations are typed. The current catalog `strength` field remains a source count until a later confidence model replaces it.
- Rule candidates stay deterministic and allowlisted. Unsupported evidence stays unsupported. Nothing auto-approves.
- An AI checker, if added, is optional, schema-validated, and unable to approve or silently edit a rule. The deterministic path must run with the checker disabled.
- A published rule must point at the exact candidate version and evidence snapshot that was approved. The publication table exists. This slice does not write a publication.
- No production password, token, or NVD API key is stored in the repository. `compose.yaml` requires `FYP_POSTGRES_PASSWORD` from the environment. The CI workflow uses an ephemeral `ci-only` password for its service container.

## Implementation status

- Implemented in the checkout: SQLAlchemy models, Alembic migration, repository protocol, in-memory unit-test store, PostgreSQL store, health detail, fixture preview, import endpoint, and the first React pending-review screen.
- Locally unavailable infrastructure: this machine has no `psql` and no Docker. The migration has not been applied here, and `compose.yaml` has not been run here.
- CI-verified PostgreSQL behavior: GitHub Actions run [37054187538](https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier/actions/runs/37054187538) on commit `edf546e` is green. The `postgres` job applied the migration and the import test passed. The `unit` job passed without a database URL. An earlier run on `d41074a` failed and is not the verification.

## Consequences

- Phase 0 remains the audit. The first vertical slice adds the store and the pending T1548 screen without claiming a local database.
- Engine 2–4 contracts stay as they are unless a published-rule export forces a compatible change.
