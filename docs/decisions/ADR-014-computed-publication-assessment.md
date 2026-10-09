# ADR-014: Compute current scoped readiness separately from publication

## Status

Proposed, local assessment API and isolated PostgreSQL checks verified.
Not a stable publisher, Engine 3 exporter, real critic policy or cloud capability.

The subsequent stable-only release/export path is recorded in ADR-015. This
assessment endpoint remains a pre-publication response, not a release artifact.

## Date

2026-10-03

## Context

An immutable approved review may refer to older quality, evidence or verifier
inputs. Reading historical approval alone cannot establish current eligibility.
The current verifier is schema-only; changing its provider label would not prove
independent AI verification. Legacy experimental rows have no approval scope.

## Decision

Add a pure `assess_publication` policy and an explicit local operator GET route:
`/v1/foundry/rules/{version_id}/publication-assessment`.
Require `scope`; channel defaults to `stable`. Experimental assessment requires
`channel=experimental&allow_experimental=true`. The repository reads the current
version, rechecked quality/verifier records and latest scoped decision under the
same transaction lock as pipeline/review writes. Busy reads return 409, not a
potentially mixed assurance snapshot. Corruption returns sanitized unavailable.

Stable readiness requires passing quality and verifier verdict, exact current
assurance hashes and an approved latest decision in the requested scope.
Experimental readiness may omit a human decision, but an existing negative,
stale or wrong-scope decision blocks it. It never bypasses a reviewer rejection.
Optional tool disagreement remains `needs_review` and blocks readiness.

The only implemented verifier policy is `local-benchmark-gate-0.1`: the explicit
synthetic benchmark with the `fake` / `schema-only` harness. Every real-account
or lab scope remains blocked with `verifier_policy_unconfigured`, even if stored
metadata claims a real provider. This is not a decision that real AI must always
be mandatory: a reviewed deterministic-only or real-critic release policy remains
a separate team decision. No query parameter can select or disable that policy.

The response's `eligible_for_publication` means readiness under this policy at
read time, not publication. `published=false` and `export_available=false` are
closed contract values. GET creates no release, review, canonical approval or AWS
operation. Local alias/loopback boundaries are not multi-user authentication.

## Alternatives

- Treat latest approval as a timeless allow: rejected; evidence/assurance changes
  would escape review.
- Treat any non-fake provider name as independent AI: rejected; names are not proof.
- Reuse unscoped experimental rows as scoped stable releases: rejected; binding
  and channel authority would be invented.
- Implement shared authentication or enable a paid provider implicitly: outside
  this slice and not authorized by an assessment requirement.

## Evidence and remaining work

58 policy tests cover quality/verdict/decision/channel combinations, stale review
digests, scope boundaries, missing inputs and experimental defaults. Seven API/
repository tests cover safe errors, disabled/Origin boundaries, lock-first reads,
driver redaction and the closed output schema. The full backend check passed 444
non-PostgreSQL tests, Ruff, mypy (80 source files) and four generated contracts.
Eleven isolated PostgreSQL tests passed, including actual HTTP benchmark readiness,
real-scope refusal and latest revision blocking both channels. An actual restart
retained exact history/packets and recomputed the same blocked assessment.
The owned cluster is stopped. No AWS, provider or managed-database call occurred.

P8.2 remains open: legacy experimental publication still follows its earlier
pipeline path, not this policy. Durable scoped release creation, assurance binding,
transactional recheck at release/export, Engine 3 consumption and release restart
proof must follow. Existing review-state/UI `not_evaluated` refers to that unfinished
release/export path; this additive API does not silently change that contract.
