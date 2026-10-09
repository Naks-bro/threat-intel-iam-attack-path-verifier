# Engine 3 branch walk — proposed sandbox boundary

**Status: PROPOSED design, with one verified offline slice.** 2026-10-09.
Sarvesh’s write-up is a design hypothesis. It is not an approved implementation
and it is not authorization to run Terraform, Pathrunner, or any AWS write.

## Verdict

**Partially feasible as an offline contract. Not feasible, as written, in the
current `ap-southeast-2` FYP project.**

Evidence:

- Engine 3 today verifies fixtures only. `docs/06_ENGINE_3_VERIFICATION.md` says
  sandbox execution and Policy Simulator calls are not implemented.
- pathfinding.cloud documents `sts-001` as one-hop `sts:AssumeRole`. Pathfinding
  Labs deploy **named scenarios** such as `sts-001-to-admin`, not an arbitrary
  branch JSON. A public Pathrunner gap-check exists because some lab scenarios
  have **no** Pathrunner module. Module id is therefore not a proven direct key
  for every hop.
- Creating a Lambda function and passing it an execution role does **not** change
  the caller’s credentials to that role. The Lambda service assumes the role
  when it runs the function. The caller remains the previous principal.
- `docs/20_AWS_CONNECTION_SECURITY.md` records that an organization SCP denied
  `iam:CreateGroup` in this new-experience project. That does not prove which
  other creates are allowed. This task did not call AWS.
- IAM API objects are not a blank cheque for “free.” S3 and Lambda can still
  create cost or be denied. No cost ceiling or cleanup proof exists for a live run.

## Corrected three-hop example

| Hop | Proposed claim | Corrected meaning |
|---|---|---|
| 1. UserA `sts:AssumeRole` BuildRole | Caller becomes BuildRole | Possible **only if** the role trust names UserA and UserA is allowed to assume it. This can be a sandbox identity change. It is not automatically module `sts-001` for an arbitrary role. |
| 2. BuildRole `lambda:CreateFunction` + `iam:PassRole` LambdaExecutionRole | Caller becomes LambdaExecutionRole | **Invalid.** The caller stays BuildRole. The new function may later run as LambdaExecutionRole. That is a different hop, not this one. |
| 3. LambdaExecutionRole `s3:GetObject` SandboxTestObject | Goal reached as that role | **Does not follow from hop 2.** A read is possible only for a caller that already has that permission. A sandbox object read is not evidence about the original project. |

A chain this offline walker can record is UserA `sts:AssumeRole` BuildRole, then
BuildRole `sts:AssumeRole` AuditRole, using a mock adapter. The status is
`synthetic_chain_recorded`, not exploitable.

## Compatibility matrix

| Proposed hop | Public path / module | Required input | Identity / evidence | Gap |
|---|---|---|---|---|
| `sts:AssumeRole` | pathfinding path `sts-001`. Pathrunner module **unverified** in this checkout | caller credentials, role, matching trust | new caller only after a successful assume | lab scenario ids are not arbitrary targets |
| `lambda:CreateFunction` + `iam:PassRole` | no single confirmed module | create plus pass a role the Lambda service can assume | caller unchanged; function may run as the role | must not be recorded as “become LambdaExecutionRole” |
| `s3:GetObject` | not a privesc module | current caller and one named object | data-plane read by the current caller | not a new identity and not another account |

## S0–S8 boundary

Engine 1 supplies an exact rule release. Engine 2 supplies one sealed snapshot.
Engine 4 may order or explain results later. It does not decide the status.

```text
S0 Bind rule release + snapshot + sandbox manifest. Missing any -> incomplete.
S1 Match hop actions to that rule. No silent pathfinding-id match.
S2 Keep unknown when trust, boundary, group, SCP/RCP, or condition context is missing.
S3 Emit a candidate branch. Ranking must not delete an unverified branch.
S4 Policy simulation is its own evidence class. Deny stays policy_denied.
   Allow stays simulation-only.
S5 Sandbox execution is a separate class and stays disabled until a reviewed
   project, permission plan, cost ceiling, stop switch, and explicit approval exist.
   Check the caller before each hop. Stop on failure. Reject impossible identity changes.
S6 Cleanup must be verified. Unverified cleanup is cleanup_unverified, even if hops were recorded.
S7 Store the trail bound to the three ids, the action, the identity, and the evidence class.
S8 Engine 4 may explain the record. It must not upgrade it to safe or exploitable.
```

S4 and S5 stay separate. A sandbox execution failure is `sandbox_failed`, not
`policy_denied`. `policy_denied` is only a simulator denial.

## Status taxonomy

`policy_denied`, `sandbox_failed`, `unsupported`, `incomplete`, `unknown`,
`identity_mismatch`, `invalid_identity_transition`, `sandbox_not_authorized`,
and `cleanup_unverified` are never a safe verdict. `synthetic_chain_recorded`
means a mock adapter walked a possible identity chain. It is not
`verified_in_mapped_sandbox` and not a real-account finding.

## What is verified in this checkout

`engine3/branch_walk.py` and `tests/unit/test_branch_walk.py` implement the
offline walker, the three-hop rejection, stop-on-denial, and cleanup failure.
No cloud call is made.

## Still proposed

Terraform generation, Pathrunner execution, a live module catalog, and any
sandbox in the FYP project. Those wait for a separate reviewed account and
explicit authorization.
