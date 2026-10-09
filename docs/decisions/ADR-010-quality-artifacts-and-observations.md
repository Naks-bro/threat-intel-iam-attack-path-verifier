# ADR-010: Separate immutable quality artifacts from run observations

## Status

Proposed. Implemented in this worktree with unit, SQL-generation, and live
PostgreSQL 17.11 checks. Fresh migration, reconstructed older-schema upgrade,
stored reports, and actual restart durability passed locally; managed deployment
and current remote CI remain unverified. See `../19_POSTGRES_VERIFICATION.md`.

## Date

2026-10-03

## Context

P6.2 requires repeatable report storage without losing validator/corpus history.
The P6.1 report excludes runtime measurements from its semantic hash. Storing
timings in an immutable artifact would either discard subsequent measurements
or mutate content identified by the same hash. Legacy validation rows also
contain enumeration indices in `duration_ms`, not actual measurements.

## Decision

Store one semantic artifact per rule-version/report hash in
`foundry.quality_reports`, with timings normalized to null. Store each run's
observed report separately in `foundry.quality_observations`, unique by run and
report. Each observation references its pipeline run, artifact, and rule version.
Use a bounded indexed latest-observation query for rule detail. Validate the
report's content hash, rule binding, and artifact metadata on reads; do not infer
quality from missing rows. Conflicting/corrupt stored content must fail closed.

Migration 0005 is additive, uses frozen SQL rather than current ORM metadata,
and revokes access from PUBLIC and existing API roles. It allows nullable legacy
validation durations; new writes use null until measured. It does not rewrite
old placeholder durations or backfill synthetic reports from old checks.

## Alternatives

- Overwrite one report per rule: rejected because validator/corpus changes lose history.
- Store timings in semantic identity: rejected because identical checks would create new semantic artifacts merely due to runtime variance.
- Infer reports from legacy checks: rejected because those rows do not establish a frozen evidence snapshot or reliable measurements.

## Consequences and deployment

An identical write for the same run/report keeps the first observation; a new
run adds an observation without duplicating semantic content. Changed validator
versions, corpus outcomes, or evidence produce a separate artifact. Stored
reports are not approval records or publication authority.

Both fresh and reconstructed existing-schema upgrades passed on disposable
PostgreSQL. The earlier migration 0002 imports current metadata; 0005 tolerates
tables already created by that fresh-install path. This is not a production-data
or managed deployment check. No managed database has been changed.

Downgrade deliberately refuses to delete archival quality history. Rollback is
an application rollback plus a reviewed forward migration if schema repair is
needed; do not restore NOT NULL by inventing durations. Existing validation-row
indices must remain excluded from runtime experiments.
