# ADR-004: Local Fixture Vertical Slice

## Status

Proposed. The behavior below is implemented and covered by tests in this checkout. The contract additions are not an accepted team schema until this ADR is accepted.

## Date

2026-10-02

## Context

The curated baseline had documents and no application source. Phase 1 and Phase 2 ask for shared fixtures and one local path from an approved rule and a graph snapshot to a finding. AWS, Neo4j, Redis, PostgreSQL, an LLM, and CloudGoat are not required to prove that path.

The proposed verification vocabulary uses Policy Simulator and mapped-sandbox statuses. A fixture-only adapter must not reuse those statuses, or a passing test could be mistaken for cloud verification.

Python 3.12 is the requested baseline. This machine also has Python 3.14. The project pins `>=3.12,<3.13` because the curated notes report an unverified Python 3.14 `ensurepip` failure, and the slice should target one supported runtime.

The chat-export directory name is long enough that a virtual environment nested inside it is a poor Windows path. The Git root is the sibling directory `threat-intel-iam-attack-path-verifier`.

## Decision

- Implement the first slice as a local Python 3.12 package: FastAPI, Pydantic v2, pytest, Ruff, and mypy.
- Keep domain models independent of Neo4j, SQL, and AWS SDK types.
- Match only rules whose status and approval decision are `approved`.
- Discover paths with bounded breadth-first search over the rule's allowlisted edge types.
- Defaults are `max_hops=4`, `max_paths_per_start=100`, `max_paths=100`, `timeout_ms=5000`, and `max_expansions=10000`. The extra path and expansion limits are proposed additive fields.
- Traverse explicit-deny edges during discovery. Verification, not search, assigns the security verdict.
- Prevent cycles by rejecting a walk that repeats a node or edge.
- Sort adjacency by edge type and edge id, then sort accepted walks, so insertion order does not change the result.
- Deduplicate walks by their edge-id sequence.
- Add optional `GraphEdge.effect` with default `allow`. This is how a fixture records an explicit deny without a new edge type.
- Do not evaluate IAM condition values. A non-empty `condition_summary` is unresolved unless the caller supplies `condition_resolutions[edge_id]` as `satisfied`, `unsatisfied`, or `unsupported`.
- Local verdict precedence is: operational error, then missing or unsupported context, then explicit deny or an unsatisfied resolution, otherwise `supported_by_fixture`.
- Verification records `policy_simulation.status = not_run` and `sandbox.status = not_mapped`.
- Findings use the transparent `baseline-v1` score `severity_weight * status_weight`. That score is not verification.
- `required_capabilities` are stored as provenance and are not evaluated as policy statements.
- The only supported precondition is `role_trusts_service`. Any other type is reported as `unsupported_precondition` and is not guessed.
- Policy document slots accept redacted hash references only.
- Account IDs, raw ARNs, and access-key-shaped strings are rejected by the models.

## Alternatives considered

- Calling the fixture result `supported_by_policy_simulation`: rejected because no simulator request is made.
- Treating graph reachability as `verified_in_mapped_sandbox`: rejected because no scenario runs.
- Evaluating a small subset of IAM condition operators: deferred. The slice would otherwise invent authorization semantics it does not implement.
- Placing the Git root inside the chat-export folder: rejected because of Windows path length.

## Consequences

- Engines 1 and 2 can still be developed against the same JSON fixtures.
- A later simulator or sandbox adapter must add its own evidence and must not relabel fixture results.
- Accepting this ADR, or revising the added fields, is still a team decision.
