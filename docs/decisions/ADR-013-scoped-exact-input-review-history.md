# ADR-013: Retain scoped exact-input review history separately from legacy aliases

## Status

Proposed, repository operations locally verified on disposable PostgreSQL.
Not shared deployment, authenticated review, stable publication or AWS authority.

## Date

2026-10-03

## Context

The legacy foundry review table does not bind a decision to evidence or assurance
digests and has no scope. The legacy intake approval API is a separate local
fixture feature; it must not be used as evidence of durable foundry review.
The intended primary scope is real read-only account analysis, with separate
isolated-lab validation and synthetic benchmark scopes. A lab-scope review does
not authorize a cloud mutation or replace account-owner lab/spending approval.

## Decision

Add migration 0007's `foundry.scoped_reviews`, preserving legacy rows unchanged.
`ReviewCommand` binds rule version, semantic/evidence digests, quality-report
digest, verifier request/result digests, explicit scope and operator request id.
Reject/revision decisions require a comment. Extra caller-supplied identity and
unsupported scopes/decisions fail the closed contract.

`append_review(session, command, reviewer_alias)` is a repository operation in a
caller-owned transaction. The alias comes separately from the trusted operator
boundary and is explicitly labelled `local_operator_alias`, not authentication.
New requests compare currently rechecked quality/verifier records and serialize
with pipeline runs using the same transaction advisory lock. Missing/stale
assurance conflicts; storage corruption fails closed.

Identical request+operator retries return the original immutable record. A
different decision or operator with that request id conflicts. A new request may
append an opposing decision; earlier history remains. Scope-specific reads never
borrow approval from another scope. Retried history is not current eligibility:
future publication/export must independently compare the active assurance and
latest decision, not treat a historical approved record as a timeless allow.

Stored JSON and indexed metadata are rechecked against a record digest on read.
This is application append-only history, not cryptographic protection from a DBA.
Migration revokes PUBLIC/existing anonymous API-role access; downgrade refuses
to erase archival history. No legacy approval is inferred.

## Alternatives

- Reuse the legacy table with inferred scope: rejected; old rows lack the input
  binding needed for trustworthy review.
- Let a browser alias establish identity: rejected as a production security claim.
- Publish whenever a stored decision says approved: rejected; required quality,
  verifier policy, current binding and target scope must remain separate gates.
- Add login roles now: outside the selected local pipeline-portal slice. A shared
  deployment needs an explicit verified authorization design later.

## Verification and remaining work

Nineteen contract/storage unit tests passed. The full backend check passed 347
non-PostgreSQL tests, lint/format, mypy (76 source files) and consumer contracts.
Nine separate PostgreSQL tests passed, including idempotency, conflicting/stale
requests, scope isolation and preserved opposing history. A reconstructed
populated 0006 upgraded to 0007 without changing the earlier dossier. Actual
stop/start preserved exact review records; the test cluster is stopped.

The subsequent opt-in local API uses a process-configured alias (not a body field),
loopback peer/Host checks and a fixed development Origin allowlist. Proxy headers
are rejected and absent Origin allows local CLI use. Ordinary API/preview leave
review disabled. Fixed errors redact validation input and driver details; OpenAPI
matches that error shape. These checks do not authenticate a user or defend a
public/shared deployment. See the runbook for explicit enablement.

The database `.env` loader explicitly skips the operator-alias key; tests show
it cannot enable review or replace an explicitly configured process alias.

375 non-PostgreSQL tests and ten isolated PostgreSQL tests passed at this API
checkpoint, including real HTTP persistence/retry, stale conflicts and corrupted
history as unavailable. The state says release eligibility is not evaluated.

The subsequent GUI reads scoped latest history and records confirmed decisions
using frozen dossier digests. Its generated types are checked in local/CI gates.
Missing assurance/disabled mode are read-only; uncertain outcomes retain the same
request id and stale conflicts block further recording until dossier reload.
24 frontend tests and build passed, alongside 379 non-PostgreSQL and ten isolated
PostgreSQL tests. A real local browser flow recorded a synthetic-scope revision
and read it after page reload. Keyboard submission, four widths and a screenshot
were checked; this is not full accessibility or visual-regression certification.

Stable eligibility/export, deployment/backup and shared authorization
remain open. No real human decision or real-account analysis was performed by
the development tests, and no AWS/provider/managed-database call was made.
