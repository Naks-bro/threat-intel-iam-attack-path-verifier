# Engine 2 — AWS IAM Collection and Graph

**Status:** synthetic normalizer implemented; live AWS collection, sealed inventory persistence, and real-account graph analysis are not implemented. The pipeline and acceptance criteria below describe the intended target unless a section says otherwise.

## Purpose

Engine 2 takes a controlled AWS authorization environment and produces a validated, reproducible `IAMGraphSnapshot`. It does not decide that an account is vulnerable.

## Pipeline

```text
collection scope + read-only credentials
 -> AWS API collectors
 -> raw responses + scan metadata
 -> normalized policy/principal/resource model
 -> authorization relationship resolver
 -> serializable graph snapshot
 -> proposed PostgreSQL snapshot/graph persistence (not yet implemented)
 -> graph validation and coverage report
```

## Initial collection scope

- IAM users, groups, roles, managed and inline policies.
- Role trust policies and instance profiles.
- Permissions boundaries.
- Organizations/SCP context only when explicitly authorized and available.
- Resource policies only for services supported by the first rule set.
- Relevant tags and account metadata, redacted in shareable artifacts.

Do not claim “effective permissions” unless all policy layers required for that claim are collected and evaluated. AWS authorization can involve identity policies, resource policies, permissions boundaries, SCPs, RCPs, session policies, context keys, and service-specific behavior.

## Development order

1. Accept `IAMGraphSnapshot v0.1` and one rule pattern with Engine 3.
2. Create synthetic fixtures with expected paths and explicit negatives.
3. Build normalization and graph generation from fixtures.
4. Add graph integrity and contract tests.
5. Define a least-privilege collector policy.
6. Collect a dedicated lab account read-only.
7. Compare the observed graph against expected fixture semantics.
8. Add AWS services and relationships only when required by approved rules.

## Graph modeling guidance

- Nodes represent stable domain entities; edges represent direct or derived relationships.
- A direct policy attachment is different from an inferred capability. Preserve both.
- Capability edges require derivation metadata, policy references, conditions, and coverage limitations.
- ARN values may contain sensitive account information; use hashes/aliases in published datasets.
- Every snapshot is immutable and tied to a collection run.
- Unknown/missing policy layers produce warnings and lower confidence; they do not default to allow.

## Persistence boundary — current direction

The earlier Neo4j/Cypher plan is superseded by the proposed PostgreSQL-first schema in [the whole-product design](24_WHOLE_PRODUCT_SCHEMA_PROPOSAL.md). No Neo4j persistence or Cypher compiler exists in the current code. Contract fixtures remain portable JSON so Engine 3 tests do not require a live database. Four observed-graph/evidence tables are now locally drafted in unapplied 0011 and rehearsed on a disposable cluster; there is no graph writer or real-account resolver. The managed `foundry` schema remains at Alembic 0004 as rechecked on 2026-10-09.

## Validation

- Stable IDs are unique.
- Every edge endpoint exists.
- No duplicate semantic edges after canonicalization.
- Policy references resolve.
- Counts reconcile with normalized collector records.
- Fixtures include explicit allow, explicit deny, wildcard, condition, trust, boundary, and missing-context cases.
- Snapshot metadata reports completeness per supported policy layer/service.

## Acceptance criteria

- A deterministic fixture produces the expected portable graph.
- Re-importing a sealed snapshot into the future PostgreSQL graph tables preserves node/edge identity (proposed acceptance test; not implemented).
- Engine 3 can discover the known positive path and reject known negatives.
- Live collection succeeds using a documented read-only policy in a lab account.
- Logs and exported fixtures contain no credentials or unnecessary account identifiers.

## Synthetic normalizer (implemented)

`normalize_synthetic_account` turns fixture identity and trust statements into an `IAMGraphSnapshot`. It does not call AWS.

A `CAN_ASSUME` edge is emitted only when both sides are exact `sts:AssumeRole` statements, the resource is a known role, and the role trust lists that principal. An explicit deny on either side wins. Condition keys are copied as `unevaluated` and are not interpreted. The edge stays `deterministic` confidence so a caller can mark that one edge satisfied, unsatisfied, or unsupported. A permissions boundary still forces `unknown` confidence. Wildcards and every other action are skipped and make `collection.complete` false. A standing warning records that SCPs, RCPs, session policies, and resource policies were not evaluated. That warning alone does not mark the snapshot incomplete.

`HAS_POLICY` edges record that statements were attached. Their `effect` is not an authorization verdict.

A `boundary_id` on an identity becomes one shared policy node and a `HAS_BOUNDARY` edge. That edge is not evaluated. Any `CAN_ASSUME` edge that starts at that identity is marked `unknown` confidence, so a path through it stays `inconclusive`. The boundary does not create an allow.

An exact trust principal `service:<name>.amazonaws.com` becomes one shared service node and a `TRUSTS` edge. That is the relationship the approved assume-chain precondition `role_trusts_service` checks. A deny trust is recorded and does not satisfy the precondition. A condition key on that trust stays `unevaluated`, so the finding stays `inconclusive` until a caller resolves it. Any other service id is skipped and marks collection incomplete. This does not look the service up in AWS.

`capability_pairs` compares `CAN_ASSUME`, `TRUSTS`, `HAS_BOUNDARY`, and `CAN_ACCESS` by type, source, target, and effect. Tests build synthetic records for the positive, explicit-deny, condition, missing-context, and cyclic fixtures and require the same pairs and the same local verdict. The hard-negative fixture uses `CAN_ACCESS`, which this normalizer does not invent; both analyses return no finding. Equal pairs are not exploitability.

`normalize_with_coverage` also returns a layer report. Exact `sts:AssumeRole` statements are `limited`. A skipped wildcard or other action is `partial`. A recorded boundary is `recorded_not_evaluated`. SCPs, RCPs, session policies, and resource policies stay `not_collected`. Before the snapshot is returned, principal, policy, attachment, and boundary counts are checked against the input records. A mismatch raises `RuntimeError`.

`collect_live_account` raises `LiveCollectionDisabled` and imports no AWS SDK.

The separate operator-only `aws_preflight` command verifies a named profile and
expected account before two bounded IAM list probes. It rejects root and wrong
accounts and returns redacted status, never a graph or a complete-collection
claim. No API route invokes it. See [connection safety](20_AWS_CONNECTION_SECURITY.md).

## Collector policy (defined, not attached)

`docs/policies/iam-readonly-collector.json` lists twelve `iam:Get*` and `iam:List*` actions. `READ_ONLY_ACTIONS` in `src/fyp_iam/engine2/collector_policy.py` is the allowlist, and tests reject a write action, a simulator action, an account ID, or an ARN. `iam:GetRole` and `iam:GetUser` are the reads that would show a trust policy and a boundary attachment. The template does not grant group, SCP, RCP, session-policy, or resource-policy reads, and it is not attached to an account.

`POST /v1/analyses/synthetic` normalizes a `SyntheticAccount`, then runs the existing local verifier. The response includes the snapshot, the coverage report, and the findings. It does not contact AWS.

## Explicit non-goals

- Reconstructing every AWS service authorization model in the first version.
- Treating graph reachability as proof of action authorization.
- Mutating the target account.
- Making the graph schema expand automatically from generated text.
