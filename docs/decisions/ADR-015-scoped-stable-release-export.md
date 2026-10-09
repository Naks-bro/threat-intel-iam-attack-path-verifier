# ADR-015: Durable stable releases and current-input export

## Status and date

Proposed, local API and isolated PostgreSQL/restart behavior verified, 2026-10-07.
Adds a stable-only release path to ADR-014; does not replace legacy fixture APIs.

## Context

Readiness alone neither publishes a rule nor ensures an older release remains
eligible. Legacy experimental publications lack scope/exact review binding. The
canonical compiler candidate must remain proposed and immutable.

## Decision

Migration `20261007_0008` adds private `foundry.stable_releases`: rule/review
references, bounded closed JSON and record digest. Preserve old publications
without inferred approval. Revoke PUBLIC/existing anonymous API-role access;
archival downgrade refuses deletion. This is application append-only history,
not a signature or protection against database administrators.

Portable Proposed `StableRuleRelease 0.1` lives under `contracts/`, not in Engine 1
tables. It retains canonical proposed candidate JSON and a separate approved
representation. Structural fields must match; only status/bound approval metadata
differ. It binds scope, exact review id/hash, evidence, quality/verifier hashes,
operator aliases, timestamps and policy. The approved comment references the exact
review rather than copying arbitrary prose. Candidate bytes remain unchanged.

`POST /v1/foundry/releases` accepts only request id, rule version, scope and exact
review id/hash. No rule body, status, policy override or browser identity is
accepted. Under the shared transaction lock it recomputes stable readiness and
verifies the latest review. New ineligible/stale requests conflict. Same command
and configured publisher retries preserve archival history; changed input/operator
with that id conflicts. No canonical rule is mutated.

`GET /v1/foundry/releases/{release_id}/export?scope=...` rechecks current quality,
verifier and latest scoped review under that lock, comparing all retained bindings.
Later rejection/revision, changed review/assurance or corruption prevents export.
Archival retry does not restore eligibility. No legacy experimental row can be
selected by this stable-only route.

Only the explicit synthetic fake-harness policy can publish today. Real-account/
lab policy fails closed even with an approved test review. Real read-only analysis
remains the primary project target, not replaced by benchmark acceptance.

Engine 3's `analyze_published_release` calls a trusted current-input export loader
on every analysis, reparses the portable contract and checks target id/scope. The
benchmark policy requires explicit synthetic snapshot metadata. Do not supply a
cached JSON loader. This is point-in-time eligibility, not distributed revocation
or proof of snapshot origin: trusted collection/API callers must establish origin;
arbitrary callers can forge labels. No live graph or cloud action is enabled.

Generic `analyze(rules, snapshot)` remains the earlier fixture adapter, not a
freshness-enforcing foundry gateway. It does not support `target_is_iam_user` yet;
integration expects `unsupported_precondition`, not a security finding.

## Alternatives

- Mutate proposed JSON to approved: rejected; breaks immutable input hashes.
- Export timeless archival approvals: rejected; ignores later changes.
- Promote unscoped experimental rows or trust provider names: rejected.
- Infer live/lab execution permission from approval scope: rejected.

## Evidence and remaining work

467 non-PostgreSQL tests, Ruff, mypy (83 source files) and four existing generated
contracts passed. Twelve isolated PostgreSQL tests passed, including real HTTP
creation/retry/export, scope refusal, corruption, later rejection blocking export/
new publication, real-scope refusal and actual Engine 3 consumption. Populated
0007→0008 preserved the previous dossier. Actual stop/start retained exact review/
packet history and an eligible benchmark release with byte-identical gated export.
The owned cluster is stopped. The first database attempt had a test-only raw JSON
whitespace comparison error; the corrected test proves both unchanged stored bytes
and matching canonical semantics. No failed attempt is reported as a pass.

No real human approval, real AI, managed migration, AWS/MCPO operation, browser
release flow or remote CI verification occurred. Aliases are local operator
configuration, not shared authentication. GUI controls, registry integration,
legacy experimental-policy migration, broader verifier policy, family-specific
Engine 3 support and release provenance in analysis reports remain open. This
checkpoint does not complete P8.2 or product acceptance.
