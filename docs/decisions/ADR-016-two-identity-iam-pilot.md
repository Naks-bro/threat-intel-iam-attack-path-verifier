# ADR-016: Paired IAM identity pilot in one authorized AWS sandbox

**Status:** Paired identity journey and same-project/account topology accepted by the user, 2026-10-09. This does **not** approve AWS writes, real-account data retention, a Supabase migration, an academic ground-truth label, or real-account rule publication.

## Decision

The first real-AWS experience compares **two starting IAM identities in the same authorized Fyp - AWS project/account**. One is intentionally configured as the *exposed comparator* for the selected IAM behavior; the other is the *control comparator* without that supported path. The analyst investigates **one identity at a time** and can return to a two-row overview. Both identities belong in **one sealed account snapshot**, minimizing environmental differences. Both analyses must cite the exact rule release and analyzer version. Other IAM objects (for example a target user) may exist; “two” counts starting identities, not the whole inventory.

The working label should be “candidate path found” versus “no supported path for this rule and snapshot,” **not** “vulnerable account” versus “secure account.” A collection gap or unevaluated policy condition produces **unknown**, not a clean result. The exposed side is a controlled *test condition*; it is not proof that an attack succeeded. No access key needs to be created to demonstrate the structural candidate. AWS's `CreateAccessKey` API would create an active key and return the secret only at creation, so the product must never call it during read-only analysis ([AWS API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html)).

## Why this is the right first comparison

- The existing deterministic additional-credentials family and synthetic credential-creation fixture give one traceable starting point, but do not themselves prove effective AWS authorization.
- A positive-looking case alone is weak research evidence. A matched control case helps expose false positives and missing-context behavior.
- The proposed one-account snapshot reduces environmental differences between comparators. The UI still studies identities individually, so it can explain each path and its evidence rather than presenting an unsupported whole-account posture score.
- AWS evaluates applicable identity, resource, boundary, organization and session controls; a policy `Allow` alone is not an effective-permission verdict ([AWS IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)).

## Schema and contract consequences — proposed implementation, not yet migrated

1. `account_snapshots` contains both starting principals and any required target objects; one `CollectionManifest` summarizes the run and policy-layer coverage. The collector does **not** assign “exposed” or “secure” labels. A later two-account experiment would need a separate design and fairness review.
2. Add `start_node_id` (or a snapshot-scoped principal FK) to proposed `analysis_runs`; enforce that the start node belongs to its snapshot. Index `(snapshot_id, start_node_id, started_at DESC)`. An analysis run covers **one** start identity, one release, one snapshot. Run the two comparators independently with identical limits and code version, whether the snapshots are shared or separate.
3. The overview queries two pinned analysis runs, displaying status, coverage and unknowns side by side. It must not derive an account-wide score from these two cases. The IT report may initially export one reviewed finding at a time; a combined comparison export requires its own versioned contract and review gate.
4. Store any expected positive/control labels in the **evaluation manifest** with who established them and how, never in AWS inventory tables. For real AWS, a configured permission edge is an observed configuration; effective authorization remains unknown unless supported by a separately scoped validation method.

## Acceptance evidence

- The same sealed real-account snapshot contains both starting principals, with redacted display aliases and complete/partial collection labels.
- An eligible **real-account** rule release exists under an authenticated review/publish policy. A benchmark-only release is not silently promoted.
- The exposed analysis shows its policy-linked candidate path; the control analysis shows no supported path **for that rule** or an honest unknown, depending on observed coverage. Each has the same pinned release and analyzer version; snapshot identity follows the confirmed account topology.
- A negative/unknown test prevents an `Allow` statement, absent SCP, missing policy version, or unread boundary from being called effective permission.
- The analyst can select either identity, inspect a bounded branch and its evidence, and export a redacted, reviewed IT handoff without mutating AWS.

### Local implementation checkpoint, 2026-10-09

Engine 3's local `analyze` and bounded discovery now accept an optional `start_node_id`, and the report retains that selector even for an empty result. It also includes input rule references and a deterministic digest of the supplied rule JSON, so a no-path result names the inputs tested; this digest is **not** a publication record or authenticated release. The local `/v1/analyses`, `/v1/analyses/synthetic`, and fixture analysis routes accept the selector; missing or non-principal starts return 422. A unit test uses one synthetic snapshot with an exposed user, a control user, and a target: the exposed start yields one path and the control start yields none. Incomplete collection emits a `collection_incomplete` issue even when no paths are found. This is **fixture-only evidence**. It does not establish a real AWS collector, eligible real-account release, effective-permission evaluation, or the analyst overview.

The local portal now has a **synthetic two-row investigation ledger** at `/#/investigate`. The checked-in credential-creation fixture includes both starts; the page fetches separate scoped analyses, refuses to compare mismatched snapshot/rule digests, and asks the analyst to select one identity before showing details. It labels the control “no path for tested rule,” not secure. Frontend unit/build checks and desktop plus 320px Edge browser journeys passed on 2026-10-09. This is a demonstration of the interaction and contract, **not** a live account overview, durable analysis run, or IT handoff.

The portal's fixture-result classifier now fails closed when path/finding/verification counts disagree, no rule was tested, or an unfamiliar issue code appears. Incomplete collection displays `Unknown / partial` and its issue text even if no path appears; a structural path with denied or unresolved fixture verification is not called a candidate. The control's clean label requires a complete aligned packet for the same tested rule. This hardens claim wording only; it does not evaluate AWS permissions. Thirty frontend unit tests, the build, and both Edge end-to-end journeys passed after the change. Bundled Chromium was unavailable locally, so the browser journey used installed Edge.

A separate, proposed Engine 2 policy-text comparison contract now accepts two distinct user/role questions from sealed handoffs. A shared snapshot requires the same target user and identical manifest; different snapshots are flagged as environmentally uncontrolled and cannot produce the matched contrast. It preserves whole-handoff digests, per-case analyzer versions, evidence references and coverage cautions, while setting `authorization_evaluated=false` and `account_security_assessment=not_assessed`. This is fixture-tested backend preparation, **not** the real AWS comparison, an authenticated analyst review, or a portal API.

The local fixture analyzer now rejects snapshots whose collection profile is not explicitly synthetic, and the generic local API answers `422 local_fixture_only` for a real-account profile. This is an accidental-use guard, not authenticated provenance: a caller can forge metadata. Real-account input must wait for a separate collection/evidence boundary and verifier status, not be relabelled `supported_by_fixture`.

The local `AnalysisReport` now includes `graph_input_digest` over canonicalized graph input. The fixture investigation refuses to compare two responses with a missing or unequal graph digest even if their snapshot IDs and rule digests match. It displays the digest alongside the rule-input digest for reproducibility. The digest is neither a sealed Engine 2 handoff nor authenticated AWS origin. Real-account analysis must separately pin the sealed inventory/handoff digest, graph projection, eligible rule release, analyzer version and coverage.

The proposed real-account handoff now has an additive per-user `group_traversals` declaration. A user with no membership rows but no complete traversal is **unknown**, not an observed no-group control. Complete traversal requires a source digest and a count that matches the membership rows; the group result remains collector-declared until exact source-run evidence is retained. Missing traversal makes the one-user policy-text screen uncertain and prevents a matched candidate-versus-control contrast. A separate role view is not penalized for an unrelated user's missing group read. The old 0.1 empty-field digests remain compatible; nonempty traversal evidence changes both inventory and whole-handoff digests. Fixture tests cover these boundaries, not real AWS ingestion or effective permission. See [handoff contract](../27_AWS_INVENTORY_HANDOFF_CONTRACT.md#current-lab-handoff-gap).

## Non-decisions and safety boundaries

The account owner/team must create or authorize any deliberately weak IAM configuration outside this application. The product's AWS role stays non-root and read-only. This ADR does not authorize provisioning, keys, CloudGoat, simulator writes, or lab exploitation. Retention, authenticated actor identity, guide-required number of rule families, and managed schema migration remain separate decisions.
