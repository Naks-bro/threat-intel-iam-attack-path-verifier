# Cross-Engine Contracts

All schemas in this file are **Proposed v0.1**. They are precise enough for fixtures and contract tests, but they become accepted only after team review and an ADR update.

## Contract rules

- JSON field names use `snake_case`.
- IDs are opaque strings; consumers must not parse meaning from them.
- Timestamps use UTC RFC 3339.
- Contracts carry `schema_version` and producer metadata.
- Enumerations reject unknown values at ingestion but support an explicit `unknown` state where domain uncertainty is valid.
- Evidence is referenced by ID/hash, not copied inconsistently into every object.
- Breaking changes increment the major version. Additive optional fields increment the minor version.

## `ApprovedRule v0.1`

Purpose: a human-approved, structural IAM condition that Engine 3 can evaluate against an IAM graph. It is not Cypher and does not contain executable shell, Terraform, SDK, or AWS CLI instructions.

```json
{
  "schema_version": "0.1",
  "rule_id": "rule_01J...",
  "rule_version": 1,
  "title": "Pass a privileged role to a new Lambda function",
  "description": "A principal may pivot to a more privileged role through PassRole and Lambda creation/invocation.",
  "status": "approved",
  "severity": "high",
  "technique_refs": [
    {"framework": "mitre-attack", "external_id": "T1548", "version": "pinned-at-ingestion"}
  ],
  "required_capabilities": [
    {"action": "iam:PassRole", "resource_selector": {"kind": "role", "constraint": "target_role"}},
    {"action": "lambda:CreateFunction", "resource_selector": {"kind": "function", "constraint": "creatable"}},
    {"action": "lambda:InvokeFunction", "resource_selector": {"kind": "function", "constraint": "created_function"}}
  ],
  "preconditions": [
    {"type": "role_trusts_service", "subject": "target_role", "value": "lambda.amazonaws.com"}
  ],
  "path_pattern": [
    {"from": "principal", "relationship": "CAN_PASS_ROLE", "to": "target_role"},
    {"from": "principal", "relationship": "CAN_CREATE_AS", "to": "target_role"}
  ],
  "evidence_refs": ["evidence_01J..."],
  "limitations": ["Resource and condition semantics must be evaluated before verification."],
  "approval": {
    "decision": "approved",
    "reviewer_id": "reviewer_alias",
    "decided_at": "2026-10-02T12:00:00Z",
    "comment": "Approved for the synthetic benchmark only."
  },
  "created_by": {"kind": "hybrid", "model_or_method": "recorded-at-runtime"},
  "created_at": "2026-10-02T11:00:00Z"
}
```

Valid status flow:

```text
draft -> proposed -> approved
                  -> rejected
approved -> deprecated -> superseded
```

Only `approved` rules are eligible for Engine 3. Approval is scoped: a rule approved for a benchmark is not automatically approved for production analysis.

## Scoped stable release envelope (Proposed additive contract)

`contracts/releases.py` defines `StableReleaseCommand` and `StableRuleRelease 0.1`.
This does not alter `ApprovedRule` or make any Proposed contract Accepted. Stable
release history binds the immutable proposed candidate, separately approved rule
representation, exact review id/hash, scope, quality/verifier/evidence hashes,
timestamps and local aliases. Structural fields cannot differ between candidate
and export; digests provide integrity checks, not signatures or authorization.

Only `local-benchmark-gate-0.1` exists, so this contract currently requires
`synthetic_benchmark` and `channel=stable`. A reviewed real/lab policy needs explicit
contract/policy extension; labels cannot enable it. Engine 3's fresh export-loader
seam invokes the trusted exporter for each analysis. Cached envelopes cannot
establish current eligibility. Generic fixture analysis is separate and does not
enforce this freshness boundary. ADR-015 records behavior and remaining work.

## `IAMGraphSnapshot v0.1`

The proposed **pre-graph** read-only AWS handoff is separate from this graph contract: [`CollectionHandoff`](../src/fyp_iam/contracts/inventory.py) binds a redacted `InventorySnapshot` to a sealed `CollectionManifest` and rejects dangling references or changed inventory bytes. See [the handoff guide](27_AWS_INVENTORY_HANDOFF_CONTRACT.md). It is fixture-tested, not a live collector, persisted account snapshot, or authorization evaluator.

Purpose: a reproducible representation of collected AWS authorization state. Graph storage is a separate implementation concern; PostgreSQL is the current proposed system of record. This contract must remain serializable for fixtures and tests.

```json
{
  "schema_version": "0.1",
  "snapshot_id": "snapshot_01J...",
  "scope": {
    "provider": "aws",
    "account_alias": "lab-account",
    "regions": ["global", "ap-south-1"],
    "collected_at": "2026-10-02T12:30:00Z"
  },
  "nodes": [
    {
      "node_id": "principal:user/alice",
      "node_type": "principal",
      "subtype": "iam_user",
      "display_name": "alice",
      "arn_hash": "sha256:...",
      "properties": {}
    }
  ],
  "edges": [
    {
      "edge_id": "edge_01J...",
      "edge_type": "CAN_ASSUME",
      "source_id": "principal:user/alice",
      "target_id": "principal:role/developer",
      "derivation": "policy_analysis",
      "policy_refs": ["policy_01J..."],
      "condition_summary": {},
      "confidence": "deterministic"
    }
  ],
  "policy_documents": [],
  "collection": {
    "collector_version": "git-sha-or-release",
    "permissions_profile": "documented-read-only-policy",
    "complete": false,
    "warnings": ["resource policies outside the selected services were not collected"]
  },
  "validation": {"status": "valid_with_warnings", "errors": [], "warnings": []}
}
```

Initial node types: `principal`, `policy`, `resource`, `account`, `organization_unit`, `service`.

Initial edge vocabulary is intentionally small: `MEMBER_OF`, `HAS_POLICY`, `HAS_BOUNDARY`, `TRUSTS`, `CAN_ASSUME`, `CAN_PASS_ROLE`, `CAN_ACCESS`, `CAN_MODIFY_POLICY`, `CAN_CREATE_AS`.

Every derived capability edge must reference the policy material and assumptions that produced it. Unsupported authorization layers must be recorded as coverage gaps, not treated as implicit allows.

## `AttackPath v0.1`

```json
{
  "schema_version": "0.1",
  "path_id": "path_01J...",
  "snapshot_id": "snapshot_01J...",
  "rule_refs": [{"rule_id": "rule_01J...", "rule_version": 1}],
  "start_node_id": "principal:user/alice",
  "goal_node_id": "principal:role/admin",
  "hops": [
    {
      "position": 0,
      "edge_id": "edge_01J...",
      "required_action": "sts:AssumeRole",
      "resource": "principal:role/developer"
    }
  ],
  "discovery": {
    "algorithm": "bounded_bfs",
    "max_hops": 4,
    "limits": {"max_paths_per_start": 100, "timeout_ms": 5000}
  },
  "deduplication_key": "sha256:..."
}
```

Traversal bounds above are placeholders and must be benchmarked before acceptance.

## `VerificationResult v0.1`

```json
{
  "schema_version": "0.1",
  "verification_id": "verify_01J...",
  "path_id": "path_01J...",
  "status": "inconclusive",
  "policy_simulation": {
    "status": "allowed_with_gaps",
    "evaluations": [],
    "missing_context": [],
    "unsupported_controls": ["resource_control_policy"]
  },
  "sandbox": {
    "status": "not_mapped",
    "scenario_id": null,
    "run_id": null,
    "evidence_refs": []
  },
  "evidence_refs": ["evidence_01J..."],
  "limitations": [],
  "started_at": "2026-10-02T13:00:00Z",
  "finished_at": "2026-10-02T13:00:01Z"
}
```

Result status values:

- `verified_in_mapped_sandbox`: all required steps succeeded in an authorized, mapped lab scenario.
- `supported_by_policy_simulation`: simulator supports the necessary checks and returned allow, but no real request was made.
- `denied_by_policy_simulation`: at least one required action/resource was denied under the supplied context.
- `inconclusive`: missing context, unsupported controls, partial data, or conflicting evidence prevents a conclusion.
- `not_applicable`: rule/path does not apply to this snapshot.
- `error`: verification failed operationally; this is not a security verdict.

Never collapse `supported_by_policy_simulation` into `verified_in_mapped_sandbox`.

The offline branch walker in `docs/28_ENGINE_3_BRANCH_WALK.md` uses a separate proposed status set. Those values do not replace this contract and must not be read as a real-account verdict.

## `Finding v0.1`

Engine 4 combines immutable references rather than rewriting evidence:

```json
{
  "schema_version": "0.1",
  "finding_id": "finding_01J...",
  "verification_id": "verify_01J...",
  "priority": "high",
  "priority_model": {"name": "baseline-v1", "features": {}, "score": 0.81},
  "summary": "A limited principal may pivot to an administrative role.",
  "explanation": {"what": "...", "why": "...", "evidence": ["evidence_01J..."]},
  "remediation": [{"proposal": "Narrow PassRole resources and conditions.", "requires_human_review": true}],
  "review_state": "open"
}
```

## Local-slice extensions (Proposed)

ADR-004 implements the models above with these additions. They remain Proposed:

- `GraphEdge.effect`: `allow` (default) or `deny`.
- `DiscoveryLimits.max_paths` and `DiscoveryLimits.max_expansions`.
- `AttackHop.effect` and `AttackHop.condition_keys`. `required_action` is the graph edge type, not an AWS API call.
- `VerificationResult.local_fixture` records fixture context gaps. `policy_simulation.status` is `not_run` for this adapter. `sandbox.status` is `not_mapped`.
- Local statuses `supported_by_fixture` and `denied_by_fixture` sit beside the simulator and sandbox statuses. The local adapter does not emit the simulator or sandbox statuses.
- `Finding.explanation` includes `simulator: not_run` and `sandbox: not_mapped`.
- `priority_model.features` is a typed baseline feature object. `baseline-v1` score is `severity_weight * status_weight`.
- Policy documents, when present, are redacted hash references. Raw policy JSON is rejected.
- Condition-key values are not interpreted. Callers pass an explicit per-edge resolution or the result stays inconclusive.
- `AnalysisReport.graph_input_digest` pins the normalized `IAMGraphSnapshot` JSON actually analyzed. Object keys are sorted and list order is retained before SHA-256 hashing. This is a local input-integrity reference, **not** an authenticated collector seal, AWS provenance, or proof of effective permission. The two-identity fixture comparison requires equal valid graph and rule-input digests, not merely equal snapshot IDs.
