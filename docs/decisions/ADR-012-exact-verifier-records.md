# ADR-012: Retain exact verifier inputs and results separately from legacy AI rows

## Status

Proposed, locally implemented and verified on disposable PostgreSQL. Not applied
to Supabase and not a team acceptance or shared-deployment claim.

## Date

2026-10-03

## Context

Legacy AI rows retain selected response fields, not the full request. The old
compiler snapshot reader also omits source metadata and payloads. Reconstructing
a historical critique using today's pins would silently change its inputs.

## Decision

Add a version-scoped snapshot reader and a separate `foundry.verifier_packets`
table through migration 0006. The reader accepts explicit source-version IDs,
checks stored artifact bytes, sizes and hashes, and selects only their entities,
claims and internal relations. Missing bytes never trigger a current-file fallback.

The packet binds canonical typed candidate JSON, selected public evidence bytes,
request digest and checked response digest to a rule version and pipeline run.
Application writes append records, revalidate existing identities and never update
prior records. Reads recheck content and metadata and return sanitized failures
on corruption. This is not tamper-proof storage against a database administrator.

Normal persisted GUI/CLI runs now select this path with the schema-only fake;
`verify-run` remains a compatible explicit alias. The old opt-in keyword remains
accepted as true, but false is rejected before a database is opened. There is no
unbound fallback for new runs. Migration 0006 and exact stored payloads are
required. No provider or AWS call, approval or stable publication is enabled.

## Alternatives considered

- Reload current pins for old runs: rejected because it falsifies historical inputs.
- Rewrite legacy AI rows: rejected because they lack enough input information to
  reconstruct exact requests; absent history must remain absent.
- Store only digests: rejected because a digest alone cannot reproduce a critique.
- Add object storage or a queue: deferred; these small public inputs fit the
  bounded PostgreSQL record and no real-provider worker is enabled.

## Consequences and verification

Migration 0006 is additive and revokes access from PUBLIC and existing anonymous/
authenticated API roles. It handles migration 0002's current-metadata table
creation with `IF NOT EXISTS`. Downgrade refuses to delete archival records;
recovery requires a reviewed forward migration or database restore.

Local evidence: 298 non-PostgreSQL tests passed, six PostgreSQL tests passed,
fresh migration through 0006 and a reconstructed populated 0005 upgrade passed.
Actual stop/start preserved exact packet contents in both test environments.
The reconstructed older-schema check is not proof against every historical schema.

An additive nullable dossier field now exposes rechecked metadata, not raw
evidence text. Generated frontend types and the GUI distinguish unavailable,
mismatched and schema-only fake records. Database-backed HTTP tests and separate
fixture-driven browser checks passed; they do not establish live AWS acceptance.

The default-run checkpoint passed seven isolated PostgreSQL tests, the ordinary
CLI, a real local portal/API/database flow and actual stop/start retention.
Corrupted stored bytes fail the transaction without appending pipeline or packet
rows. Historical rows still do not acquire invented verifier records.

Remaining work includes durable failed-provider observations, prompt/schema evolution, deployment/backup
verification and evaluated real critique. No new historical packets are inferred.
