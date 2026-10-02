# Engine 3 — Attack-Path Discovery and Verification

## Purpose

Engine 3 combines approved structural rules with a validated IAM graph snapshot, discovers bounded candidate paths, evaluates available authorization evidence, and records an honest verification status.

## Pipeline

```text
ApprovedRule[] + IAMGraphSnapshot
 -> rule applicability and pattern matching
 -> vulnerable nodes/edges
 -> bounded path discovery
 -> canonicalize/deduplicate paths
 -> deterministic authorization checks
 -> IAM Policy Simulator pre-check where supported
 -> optional mapped sandbox scenario
 -> VerificationResult
```

## Path discovery

- Start and goal predicates come from an allowlisted rule compiler.
- Use a bounded traversal. Record maximum hops, expansions, paths per start, and timeout in every result.
- Prevent cycles through visited-state/path canonicalization.
- Produce the same paths in a stable order for the same snapshot, rules, and settings.
- Keep discovery separate from prioritization. A path is not discarded solely because a learned model ranks it low.

The exact algorithm and bounds remain proposed until benchmarked. Begin with bounded breadth-first search because shortest understandable paths are useful for explanations, then compare alternatives only if needed.

## Policy Simulator interpretation

AWS IAM Policy Simulator evaluates supplied/in-scope policies without making a real service request. Its result depends on actions, resources, policy layers, and context values supplied. It does not support every advanced configuration; AWS documents differences for RCPs, VPC endpoint policies, role chaining, multiple resource policies, and context.

Therefore:

- `Denied` under complete inputs is useful negative evidence for that evaluated action/resource/context.
- `Allowed` means the evaluated policy set permits the request; it is not proof that the API call or multi-hop exploit will succeed.
- Missing conditions or unsupported policy layers produce `inconclusive` or `allowed_with_gaps`, not `verified`.
- Keep each hop's simulator request, sanitized response, missing context, and policy coverage.

## Sandbox boundary

CloudGoat creates curated intentionally vulnerable cloud scenarios. It is not a universal executor for arbitrary graph paths.

- Map a path to a specific scenario and expected steps before execution.
- Use a dedicated disposable account with explicit authorization, budget alarms, region restrictions, unique run IDs, and teardown verification.
- Record resources created, exact scenario/version, sanitized commands/API calls, expected vs observed result, and cleanup outcome.
- If no scenario maps to a path, record `not_mapped`; do not synthesize an unsafe exploit plan automatically.
- Never deploy CloudGoat beside production or sensitive resources.

## Verification precedence

```text
operational error        -> error
missing/unsupported data -> inconclusive
simulator deny           -> denied_by_policy_simulation
simulator allow only     -> supported_by_policy_simulation
mapped lab steps succeed -> verified_in_mapped_sandbox
```

A sandbox result verifies only the mapped scenario under its recorded configuration. It does not prove the same path in every account.

## Acceptance criteria

- Positive, negative, cyclic, duplicate, over-depth, timeout, and missing-context fixtures pass.
- Every result can be reproduced from rule version, graph snapshot, configuration, and evidence.
- Simulator limitations are represented in the result schema.
- Sandbox execution is disabled by default and impossible without explicit environment configuration.
- Cleanup status is visible and failed cleanup is treated as a high-priority operational incident.

## Local fixture adapter (implemented)

The code in `src/fyp_iam/engine3/` is the first adapter. It is not the Policy Simulator and it cannot run a sandbox.

Search is bounded breadth-first search. Explicit-deny edges are traversable; the verdict is applied afterwards. A repeated node or edge ends that walk. Limits and ordering are recorded in ADR-004.

Local precedence:

```text
operational error                 -> error
missing or unsupported context    -> inconclusive
explicit deny or unsatisfied      -> denied_by_fixture
otherwise                         -> supported_by_fixture
```

`required_capabilities` are not evaluated. Unknown precondition types are reported and skipped. Sandbox execution has no code path in this adapter.

