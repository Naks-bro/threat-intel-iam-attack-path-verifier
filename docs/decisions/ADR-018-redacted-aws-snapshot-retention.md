# ADR-018: Ninety-day maximum for redacted AWS snapshot evidence

**Status:** Design default selected by the user by delegation, 2026-10-09.
Not an authorization to import data into Supabase before the account owner and
team approve the collector, exact fields, purge path and access roles.

## Decision

The first read-only AWS pilot may retain **at most 90 days** of redacted IAM
policy text and topology in the private backend database, solely to reproduce
analyst findings and the FYP evaluation. A sealed snapshot records its own
`retention_expires_at`; the proposed 0009 DDL checks that **real-account**
snapshots expire after the seal and no more than 90 days later. Synthetic
snapshots have a separate two-year ceiling. Never store credentials, access-key
values, session tokens, raw AWS account IDs or raw ARNs in these tables. The
frontend does not connect directly to `foundry`.

This is a maximum, not a minimum. A smaller period or immediate purge may be
chosen for a specific dataset. Snapshot hashes and sanitized audit tombstones
may remain only under a separately reviewed retention policy. An expired
snapshot must not be used for a new finding or IT export. The deletion process,
dependent-record behavior, backups and report-retention rules remain to be
designed and tested before any real-account import.

## Implementation boundary

Migration `20261009_0009` is **authored locally only**. It adds an empty
collection/snapshot shell with an expiry check, private grants and RLS enabled
without browser policies. It stores no IAM policy bodies. The managed FYP
database remains at 0004. The collector, account-owner consent, real-data
retention workflow and scheduled purge do not exist yet.

The local 0004→0009 rehearsal is evidence that the proposed DDL can be applied
on a disposable reconstructed boundary; it is not a sanitized copy of the
managed database and does not authorize applying the migration there.

**Code checkpoint, 2026-10-09:** `snapshot_retention.py` seals a redacted
handoff hash to a private HMAC key without storing the key, rejects use after
expiry or purge, and plans a tombstone plus deletion of policy/topology body
tables. Migration `20261009_0012` adds `foundry.snapshot_purge_tombstones` and
is **not applied** on the managed database. The disposable synthetic writer can
purge only a synthetic snapshot on an opted-in loopback `fyp_iam` database.
Scheduled purge and backup restoration remain unbuilt. `engine2.real_account_store` can retain one redacted `real_account_observed` handoff on an opted-in disposable loopback `fyp_iam` database. That writer is not authorization to import into the managed database.
