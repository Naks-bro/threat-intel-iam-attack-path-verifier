# Engine 2 — AWS IAM Collection and Graph

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
 -> Neo4j persistence/indexing
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

## Neo4j boundary

Neo4j is the query/persistence implementation, not the only representation. Contract fixtures must be portable JSON so Engine 3 tests do not require a live database. Cypher is compiled from allowlisted rule predicates by trusted code, parameterized, and tested; it is never accepted directly from an LLM.

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
- Re-importing the snapshot into Neo4j preserves node/edge identity.
- Engine 3 can discover the known positive path and reject known negatives.
- Live collection succeeds using a documented read-only policy in a lab account.
- Logs and exported fixtures contain no credentials or unnecessary account identifiers.

## Explicit non-goals

- Reconstructing every AWS service authorization model in the first version.
- Treating graph reachability as proof of action authorization.
- Mutating the target account.
- Making the graph schema expand automatically from generated text.

