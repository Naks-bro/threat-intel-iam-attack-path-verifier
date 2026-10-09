# Proposed AWS inventory handoff — collector to graph resolver

## Latest private-profile preview — 2026-10-09

After the owner supplied an independent AWS Settings project reference, the
`fyp-aws` STS identity matched it privately and the bounded non-root preflight
passed. An opt-in, **in-memory only** read with per-user group traversal and
bounded AWS-managed policy reads then observed two users, 17 roles, zero
groups, and two local managed policies in one authorization-details page. The
redacted handoff validated with 19 principals, 28 identity statements, 17 trust
statements and 36 observed-only relations; both user group traversals and three
managed-policy reads completed. The draft row mapper accepted 95 rows without
writing a database. One or more managed policies remained unfetched under the
read budget, and policy/trust evaluation remains unknown. The HMAC key was
ephemeral and discarded; **no reproducible snapshot, effective-permission
finding, or secure/vulnerable comparison exists yet**.

This preview exposed and resolved a proposed-contract issue: multiple
`GetPolicy`/`GetPolicyVersion` tasks cannot all use the account-wide uniqueness
scope. `CollectionTask.subject_policy_fingerprint` now carries a keyed,
non-identifying scope for each managed policy; the pure 0009 row mapper keeps
their attempts distinct. The migration remains unapplied. The earlier one-user
preview below is retained as historical evidence, not the current inventory.

An additional opt-in `--stable-key-preview` mode accepts a privately injected
32-byte HMAC key as 64 hex characters in `FYP_AWS_HMAC_KEY_HEX`. It rejects a
missing, malformed, or degenerate key **before contacting AWS**, and never
prints the key. With that key, the preview seals the redacted handoff hash in
memory and sets the 90-day real-account expiry. The ordinary
`--normalize-preview` still uses a throwaway key and stays unsealed. Neither
mode writes a database, authenticates AWS provenance, or evaluates effective
access. No production key has been provisioned.

**Status: PROPOSED, fixture-tested with an opt-in, read-only in-memory AWS preview; no retained real-account snapshot or database import.** Expiry and purge are now a local gate: a private key seals the handoff hash, an expired or purged snapshot cannot be replayed, and `20261009_0012` would store only a hash tombstone. That migration is not applied. The types in [`contracts/collection.py`](../src/fyp_iam/contracts/collection.py) and [`contracts/inventory.py`](../src/fyp_iam/contracts/inventory.py) define an integration seam for the Engine 2 teammate. A separate synthetic-only disposable database writer now exists; it does **not** approve retention of real-account records or change Supabase. Confirm this shape with the collector owner before treating it as a stable team contract. The paired-identity journey and one-project/account topology are accepted in [ADR-016](decisions/ADR-016-two-identity-iam-pilot.md).

## Boundary and lifecycle

The teammate has stopped the collector work; the current implementation owner
may use the existing `fyp-aws` profile for **read-only** collection. The profile
was reachable on 2026-10-09, but that alone does not confirm the intended AWS
project/account owner or authorize persistence of raw responses. At this check,
read-only IAM queries returned one user, 17 roles, zero groups and one local
managed policy; `ListGroupsForUser` completed for the lab user with zero groups.
`GetAccountAuthorizationDetails` was also callable. These are point-in-time
aggregate observations, **not** a sealed snapshot or a two-identity pilot.
AWS documents that the latter API returns IAM configuration relationships and
policy details and can paginate, so a collector must verify every page before
declaring completeness ([AWS API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)).

For any private redacted handoff file, the offline checker can test both the
schema and the **proposed, unapplied** 0009–0010 row mapping without reading AWS
or writing PostgreSQL:

```powershell
.\.venv\Scripts\python.exe -m fyp_iam.contracts.handoff_check --file <private-json-path> --draft-store-check
```

`draft_0010_rows_valid` means only that the in-memory row mapper accepts the
file; it does not authenticate AWS provenance, authorize retention, or prove
effective IAM permissions. The command prints fixed status codes and aggregate
counts, never input values or raw parse errors.

`engine2.aws_authorization_read.read_authorization_details` is a new internal
transport draft. Given a privately configured expected account, it runs the
existing non-root preflight, makes only bounded `GetAccountAuthorizationDetails`
reads through the local stop/rate guard, checks every pagination marker, caps
response size and returns raw pages **in memory only**. Its opt-in operator
entrypoint (`python -m fyp_iam.engine2.aws_authorization_read`) requires the
privately set `FYP_AWS_PROFILE` and `FYP_AWS_EXPECTED_ACCOUNT_ID` values and
prints only aggregate counts. It has no API route and does not persist or seal
a real snapshot. `--normalize-preview` runs the pure redactor with a throwaway
HMAC key and checks the handoff, observed-only graph and proposed row mapping
in memory. It prints fixed aggregate counts/gap codes, not pseudonyms or
documents. This preview **must not** be persisted: the ephemeral key cannot
reproduce fingerprints on a later run. AWS-managed policies omitted by the
current `LocalManagedPolicy` filter remain an explicit evidence gap, not an
effective-permission evaluation. A reviewed private stable HMAC key,
owner-confirmed target ID, source lineage, retention/purge controls and managed
migration remain gates for durable data.

`--normalize-preview --read-groups` additionally makes bounded, individually
paginated `ListGroupsForUser` calls for up to six observed users. The resulting
task and per-user traversal must match on pseudonymous subject, group count
and response digest before the handoff can call that traversal complete. A
denial, rate stop, malformed page or missing marker becomes a partial/unknown
record, never an empty-group assertion ([AWS API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListGroupsForUser.html)).

`--normalize-preview --read-managed-policies` additionally reads at most three
distinct AWS-managed policies referenced by observed attachments or permissions
boundaries. It uses `GetPolicy` to pin the default version and
`GetPolicyVersion` to read that exact document; missing, denied, oversized,
changed or over-budget reads remain explicit gaps. This does not enumerate the
whole AWS policy catalog, resolve a permissions boundary, or prove an Allow is
effective ([GetPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicy.html),
[GetPolicyVersion](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicyVersion.html)).
This optional path is fixture-tested but has not yet been run on the live FYP
project. The earlier live preview's `managed_policy_unfetched` gap remains an
observed fact until a fresh read changes it.

The opt-in command was run on 2026-10-09 after the user confirmed the profile
targets the intended FYP project. Its preflight and one IAM authorization page
succeeded and emitted only aggregates: one user, 17 roles, zero groups and one
local managed policy. An in-memory preview with a discarded HMAC key produced
a contract-valid redacted handoff with 18 principals, two identity statements,
17 trust statements and 31 observed-only relations. It reported unfetched
managed policies, unresolved trust selectors, unevaluated statements and
incomplete per-user group traversal; source coverage and authorization
evaluation were false. A subsequent opt-in group read completed for the one
observed user with zero groups and removed the group-traversal gap. The pure
0009–0010 mapping accepted 58 redacted
inventory rows, but no database insert was attempted. No raw page or handoff
was written. For this probe,
the expected account ID came from an initial private STS read and was compared
again during preflight, then removed from the process environment. That checks
target stability within the run; it is **not** an independent owner-supplied
account-ID match. This does not establish least privilege of the collector
role, full AWS-managed policy coverage, a durable/reproducible snapshot, or a
finding. The two pilot starting identities have not yet been selected or
validated from these counts.

```text
authorized, read-only AWS API responses (private, untrusted input)
  → collector validates/paginates and records task/coverage gaps
  → pseudonymized InventorySnapshot 0.1 (no raw policy JSON)
  → canonical digest bound to CollectionManifest.snapshot_digest
  → CollectionHandoff validation
  → observed-only graph projection (local, fixture-tested; no CAN_* edges)
  → future immutable PostgreSQL import + authorization resolver (not implemented)
  → future real-account verifier (not the local fixture verifier)
```

The `CollectionManifest` describes the run, tasks, policy-layer coverage, and whether the observation is synthetic or real-account. Its `authorization_evaluated` value remains false for every layer. `InventorySnapshot` carries bounded, redacted principals, policy versions, statements, attachments, group memberships, **optional per-user group-traversal declarations**, and role trust statements. `CollectionHandoff` rejects different snapshot IDs, mismatched bytes **when parsed/revalidated**, invalid references, duplicate keys, and oversized payloads. `InventorySnapshot.content_digest()` hashes normalized inventory JSON; `CollectionHandoff.content_digest()` additionally pins run/task/coverage metadata that can change an interpretation without changing inventory rows. Both use sorted object keys and original list order. When `group_traversals` is absent/empty, both digests retain their earlier 0.1 values; nonempty traversal evidence is included in both hashes. These SHA-256 digests are integrity checks, **not** signatures, proof that AWS supplied the data, or evidence of effective permission. These mutable Python objects are not themselves immutable storage; the future persistence transaction must revalidate and seal exact bytes. The collector must supply authenticated provenance separately through its approved connection/run controls.

Do not send raw AWS responses, credentials, access keys, session tokens, account IDs, ARNs, unredacted policy documents, or customer names to the browser, Git, or chat. Construct opaque `p_`, `pol_`, and `st_` keys and pseudonymous display aliases before validating this handoff. Principal fingerprints use keyed HMAC-SHA256 with the key outside this repository and database; ordinary SHA-256 of a guessable ARN is not a privacy boundary. `source_digest` identifies the exact source material used to derive one record but does not make that source available or authentic by itself. Select a retention/redaction policy before persisting real-account rows.

## What each record means

| Record | Meaning; downstream use | Deliberate limit |
|---|---|---|
| `InventoryPrincipal` | Snapshot-local user, role, or group with opaque key, HMAC fingerprint, alias, and source digest; future `iam_principals`. | No raw AWS name, path, ID, or ARN. Identity is not a starting-role approval. |
| `InventoryPolicy` | Versioned managed policy or inline/trust policy, parse state and source digest; future `iam_policies`. | Only a managed policy has a version label/default flag; an unsupported policy cannot emit parsed statements. |
| `PolicyStatementEvidence` | Identity-policy `Allow`/`Deny`, explicit `Action` versus `NotAction`, `Resource` all/linked/unresolved versus `NotResource`, condition-key presence, and digest. | No raw policy body or condition values. `NotAction`, `NotResource`, wildcards, unsupported parsing, and unevaluated conditions must not generate an effective-allow edge. |
| `InventoryAttachment` | Principal to **default** managed policy, inline policy, or permissions boundary; future `iam_attachments`. | A group cannot have a boundary. An attachment is not a permission verdict. |
| `InventoryMembership` | User-to-group relation, so inherited policy evidence can be traced. | No membership is inferred from names or aliases. |
| `UserGroupTraversal` | Optional, snapshot-local per-user collector declaration that group membership traversal was complete, partial, unavailable or not collected; complete carries a source digest and count matching stored memberships. | A digest and count cannot independently prove all AWS pages/group policies were read. Missing/incomplete declaration makes real-account user policy-text interpretation uncertain. |
| `TrustStatementEvidence` | Role's trust-policy statement, linked same-snapshot principal/service selector or unresolved selector, action mode, condition state, and source digest; future `iam_trust_statements`. | External/cross-account principals are unresolved until separately modelled; trust alone does not grant `sts:AssumeRole`. |

AWS policy statements may use mutually exclusive `Action`/`NotAction` and `Resource`/`NotResource` elements. Treating those forms as a simple positive action/resource list would be unsafe ([AWS policy element reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html)). AWS evaluates identity/resource policies with boundaries and organization controls; an observed `Allow` is not the final authorization decision ([AWS policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)).

The contract has no `vulnerable`, `secure`, `effective_allow`, exploit, or remediation field. The test harness uses synthetic values only. The future resolver must cite statement/attachment/trust IDs and manifest coverage for every derived graph edge. When a policy version, group inheritance, boundary, condition, resource selector, SCP/RCP, or required API page is unknown, produce a coverage gap and an unknown analysis state rather than a clean result.

`engine2.observed_graph.project_observed_inventory` is the first consumer of a sealed handoff. It revalidates the digest and emits snapshot-local principal/policy/service nodes plus directly recorded attachment, membership, role-trust-policy, and trust-selector-reference relations. Trust relations retain the statement's `Allow` or `Deny` as **document content**, not a grant. It emits fixed incomplete-reason codes and always sets `authorization_evaluated=false`. Its `source_coverage_complete` flag means only that the **collector's declared** policy-layer coverage and supported parsing have no recorded gaps; it does not prove the collector reached AWS, found every relevant policy, or evaluated permission. This type is intentionally **not** `IAMGraphSnapshot`, cannot be passed into the current Engine 3 fixture verifier, and is not a finding. An opt-in synthetic-only disposable database import/readback covers this projection. An opted-in real-account writer can store the same redacted handoff and observed graph on disposable loopback `fyp_iam` only. There is no public portal import path.

`engine2.identity_observation.observe_identity` builds a second, **one-user-or-role-at-a-time** view from that sealed handoff. It links direct attachments and user→group→policy inherited attachments to the exact recorded statement keys, retains `Action` versus `NotAction`, `Resource` versus `NotResource`, conditions and trust statement references, and binds the result to the inventory digest. A group is context, not an investigable starting identity. An empty control view is `not_evaluated`, **not** “secure”; an `Allow` or `Deny` row is policy text, not an AWS authorization decision. This internal proposed contract has no real-account API route or persisted reader yet; it is the input shape to review with the snapshot teammate before portal exposure.

The next pure, fixture-tested consumer is `engine2.credential_policy_text.inspect_create_access_key_policy_text`. For **one selected source user/role and a different target IAM user**, it screens attached identity-policy statement text for `iam:CreateAccessKey`, including group inheritance and case-insensitive action wildcard matching. It emits exact statement and attachment references, a sealed inventory digest, fixed uncertainty/coverage codes, and one of `policy_text_candidate`, `recorded_explicit_deny`, `uncertain_policy_text`, or `no_observed_identity_allow` (plus a bounded-analysis failure state). These are **not** AWS authorization, exploit, vulnerability, or stable-rule findings. A permissions-boundary `Allow` cannot grant an identity permission. A policy-text candidate can still be blocked by a boundary, SCP, session policy, context condition or service behavior; a control with no observed Allow is not certified safe. Conditional/unsupported selectors never silently become positive matches. The function has no AWS API call, no `CAN_*` edge and no portal route. It is a narrow preparation step for the first rule family, not a general IAM evaluator. AWS describes action wildcard/case semantics in its [Action reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html) and explicit-deny/boundary/organization evaluation in its [policy evaluation reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html).

`engine2.paired_policy_text.compare_credential_policy_text` runs **two** such questions. When both starts share one sealed snapshot and target, it can report a *policy-text contrast*; it never declares one identity vulnerable or the other secure. Different snapshots remain inspectable but are flagged `different_snapshot_context` because environmental differences are uncontrolled. Mixed synthetic/real data, reused snapshot IDs with different content, divergent manifests for one snapshot, duplicate starts, or different targets within one snapshot fail closed. Each case carries the whole-handoff digest and an analyzer version; the pair carries its comparison version. Those version strings identify this proposed logic contract, not an immutable deployed binary or approved real-account release. There is still no public endpoint, persisted analysis run, real AWS authorization decision, or IT export for this pair.

`engine2.paired_observation.observe_additional_credentials_pair` applies only `rule_additional_cloud_credentials` to two starting identities on one revalidated handoff. Each result is `candidate_from_policy_text`, `no_matching_statement`, or `unknown`. An Allow stays policy text. A missing real-account group traversal forces `unknown`. Both results share one snapshot digest and one rule digest, and `authorization_evaluated` stays false. The function does not call `analyze()` or emit `supported_by_fixture`. **Verified** for this in-memory function. **Proposed** for a retained real-account snapshot. A loopback reviewer may later accept, reject, or mark needs-context against that report digest and export one redacted handoff; that export says local operator review is not authenticated authority and not exploit proof. It is not public approval.

## Teammate delivery and acceptance

### Current lab handoff gap

On 2026-10-09 the teammate reported a partial Terraform apply: group creation was denied by an AWS-managed SCP; four non-group resources were reportedly created. Independent read-only calls through `fyp-aws` observed a lab user with no direct policy and no group membership, a role with one managed policy, and a direct, unconditional `sts:AssumeRole` trust link from that role to the user. The project had zero groups at that observation time. This is **not** a sealed inventory snapshot, proof of effective role assumption, or proof of a safe baseline. The user's lack of an attached identity policy must not suppress the role-trust relation in the graph; a fixture regression now pins that behavior. See [AWS connection checkpoint](20_AWS_CONNECTION_SECURITY.md#read-only-lab-checkpoint--2026-10-09) and [AWS same-account AssumeRole guidance](https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html).

`iam:CreateGroup` denied during provisioning does not establish the result or completeness of `iam:ListGroupsForUser`. The collector should record the latter per relevant user, including pagination completion and sanitized failures; if groups are present, it must also inspect both managed and inline group policies. An empty group-membership list may be treated as *observed absent for that user* only after the read finished, not because group creation failed. [AWS `ListGroupsForUser`](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListGroupsForUser.html), [`ListAttachedGroupPolicies`](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedGroupPolicies.html), and [`ListGroupPolicies`](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListGroupPolicies.html) document these distinct read operations. The repository's current [12-action policy template](policies/iam-readonly-collector.json) does **not** grant these group reads; review an expanded least-privilege collector policy with the owner before depending on them. The additive `InventorySnapshot.group_traversals` record binds a declared state, digest, and membership count to each local user. A missing or incomplete record makes the real-account observed graph incomplete and that user's `iam:CreateAccessKey` policy-text result uncertain; a role's one-identity view does not inherit an unrelated user's group gap. For real-account data, a `complete` traversal now requires **one matching successful `iam:ListGroupsForUser` task** for that same pseudonymous user with complete pagination, the same item count and response digest. This is a fail-closed **collector-declared lineage** check, not independent verification that AWS supplied the response: the raw response is not retained or authenticated here. Do not claim effective permission or a clean real-account control from the traversal field alone.

A bounded `fyp-aws` read-only probe on 2026-10-09 successfully listed zero group
memberships and zero direct managed/inline user-policy attachments for the
reported lab user. It printed only counts. This establishes the profile could
perform those three reads at that moment; it does **not** certify the teammate's
collector role, snapshot completeness, future AWS state, or the user's ability
to assume a role. The group-create SCP denial is a separate write restriction.

If the owner accepts the revised Terraform design, the collector should represent a direct managed-policy grant as `InventoryAttachment` on the user with no `InventoryMembership`, and preserve the separate trust statement on the role. Re-plan and review the Terraform diff before any teammate apply; do not convert an experimental publication, Terraform state, or an unreviewed lab label into an Engine 3 rule release. No real-account JSON handoff file has arrived in this checkout.

When the teammate has a **private redacted JSON handoff file**, validate its shape locally from the repository root:

```powershell
.\.venv\Scripts\python.exe -m fyp_iam.contracts.handoff_check --file 'D:\private\redacted-handoff.json'
```

The command reads at most 2 MB, performs no AWS or database call, and prints one JSON status with fixed error codes. A valid result says `schema_valid_only`, with aggregate principal/policy counts and unresolved-layer count; it explicitly reports `authorization_evaluated: false`. Invalid JSON, oversized/unreadable files, or contract/digest failures return a nonzero exit code without echoing file contents, the path, or validation exceptions. **Passing this check does not authenticate the producer, prove the data came from AWS, approve retention, or verify permissions.** Keep the file outside Git and do not paste it into chat.

After the teammate supplies one valid sealed handoff and identifies two distinct
redacted starting-principal keys plus a different redacted target-user key,
operators can run a **private offline policy-text preview**:

```powershell
.\.venv\Scripts\python.exe -m fyp_iam.contracts.handoff_preview --file 'D:\private\redacted-handoff.json' --first 'p_<32 lowercase hex characters>' --second 'p_<32 lowercase hex characters>' --target 'p_<32 lowercase hex characters>'
```

Replace the placeholders with keys from the private handoff, not AWS names or
ARNs. The tool uses the same bounded validator, then asks both identity-policy
text questions on that **one** snapshot. Output contains fixed states, aggregate
uncertainty/coverage counts, `authorization_evaluated: false`, and
`account_security_assessment: not_assessed`; it does not print the keys, file
path, digests, statements, or policy content. Bad file or selection returns a
fixed error code and nonzero exit. This is **not** an effective-permission check,
finding, authenticated source attestation, portal import, or IT report. A
real-account user without a complete group traversal remains uncertain even if
no group is visible in the inventory.

The local, pure `engine2.shell_import.prepare_shell_import` bridge can now map
a validated handoff to the proposed 0009 metadata tables **without writing**.
It verifies the pre-registered account fingerprint, converts a task's local
principal key to its HMAC scope key, requires response digests for successful
tasks, rejects duplicate task attempts, preserves task order and all seven
declared layer states, and pins a separate digest of the whole handoff. It
marks a real user with no complete group traversal as a snapshot coverage gap.
Older fixture handoffs that omit
successful-task digests still pass the v0.1 shape check but are explicitly
**not importable**; the teammate should include those digests in the sealed
handoff. This bridge does not authenticate AWS provenance, enforce database
ownership, store normalized inventory/policy evidence, or approve a managed
migration. Its synthetic insert is rehearsed only inside a rolled-back,
disposable local PostgreSQL transaction.

The separate proposed 0010 inventory draft now has nine normalized private
tables and `engine2.inventory_import.prepare_inventory_import` maps all nine
record classes from one revalidated handoff. It refuses a changed 0009 shell
plan, oversized action text, duplicate linked principals and complete group
traversals without exactly one matching read task. Snapshot-scoped composite
FKs reject cross-snapshot attachment and statement-resource references in a
disposable PostgreSQL rehearsal. A separate synthetic-only writer now proves
one atomic commit, full ordered reconstruction with digest verification,
tamper rejection, and duplicate-request refusal on a disposable loopback
database. Order is stored for all hashed lists (including coverage and
linked-principal references), not inferred from primary keys. The current
fixture exercises all nine inventory tables and an observed-only graph
projection, but not every collector shape. It requires explicit
opt-in, refuses real-account input,
and is not exposed through the API. `engine2.real_account_store` is the opted-in disposable counterpart for `real_account_observed`: it reuses migrations 0009–0012, refuses credentials, raw policy bodies, and evaluated authorization before opening a transaction, and rebuilds the snapshot digest on readback. It does not add a migration, an API route, or a managed-database write. The actual teammate handoff has not arrived.

1. Hand back the proposed type mapping from the collector's actual read API responses to `CollectionManifest` and `InventorySnapshot`, including which actions are paginated and which policy layers remain unavailable. Do **not** hand over credentials or live account payloads in chat.
2. Supply one small **synthetic or irreversibly redacted** replay sample and negative cases for access denied, throttling, missing policy version, `NotAction`, `NotResource`, conditional trust, and incomplete pagination. No unsupported form may silently disappear.
3. Demonstrate deterministic pseudonymization, duplicate detection, referential checks, bounded size, digest mismatch rejection, and source-to-record lineage. HMAC key handling and rotation need account-owner approval before real data.
4. After the schema/retention/actor gates are approved, import additively into the proposed Engine 2 PostgreSQL tables. Reconcile counts and digest; keep the original manifest and gaps. No managed migration or database write is authorized by this contract.
5. Use the observed-only graph and one-identity observation view for inspecting recorded topology, then build an authorization resolver and a **separate** verifier behind an explicit acceptance gate. The current `engine3.analyze`/`supported_by_fixture` path rejects non-synthetic profiles and must not be relabelled for AWS observations.

**Not covered yet:** raw-response encryption/storage, verified HMAC provenance, policy JSON canonicalization across AWS encodings, per-object authorization context, cross-account trust resolution, actual AWS collector code, managed schema migration, authenticated analyst decisions, or an IT export. These are explicit follow-on decisions, not implied by a passing contract test.
