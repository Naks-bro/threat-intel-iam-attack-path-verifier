# AWS connection and real-account analysis foundation

## Independent project match and preflight — 2026-10-09

The owner supplied the AWS Settings Projects page for the intended FYP project.
Its account ID was compared privately with a fresh `sts:GetCallerIdentity` result
from `fyp-aws`; they matched. The profile Region is `ap-southeast-2`, the principal
is a non-root assumed role, and the explicit repository preflight returned
`ready` with both bounded `iam:ListUsers` and `iam:ListRoles` probes passing.
Neither the account ID nor the role ARN is recorded here. This supersedes the
earlier **unverified target-account match** note below, but does not establish
least-privilege credentials, complete collection, an account snapshot, or a
real-account finding. The profile uses a broadly privileged project role;
do not treat a successful read-only command as proof that its *credentials*
cannot write. No AWS resource was changed in this checkpoint.

## Read-only lab checkpoint — 2026-10-09

The teammate **reported** that Terraform created a user, a managed policy, a role, and a role-policy attachment, then stopped when an organization SCP denied `iam:CreateGroup`. Terraform configuration/state and a collector snapshot are **not present in this checkout**, so the four-resource Terraform claim is not independently reconciled here. No retry, attach, destroy, key creation, policy simulation, or other AWS write was run by this project agent.

The dedicated `fyp-aws` profile was reachable as a non-root assumed role. Read-only IAM calls independently observed the named lab user and role, zero attached/inline **user** policies, zero groups on that user, zero groups in the selected profile's project at the time of the query, zero user access keys, one managed policy attached to the role, and zero inline role policies. The role's trust document has an `Allow` for `sts:AssumeRole` naming the lab user directly, without a condition. These are point-in-time configuration observations; the profile target has **not** been independently matched to an owner-supplied account ID, and the role policy's actions, permissions boundaries, SCP/RCP effects, console-login state, and actual assumption outcome were **not evaluated**. In particular, “no user policy” is not a safe-user verdict when a same-project role directly trusts the user ([AWS same-account AssumeRole guidance](https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html)). No account ID, ARN, access-key ID, or raw policy body was printed or saved.

The project reports `FREE` from `freetier:GetAccountPlanState`. AWS's [managed policy reference for the new experience](https://docs.aws.amazon.com/accounts/latest/reference/scps-and-rcps-for-projects.html) lists `iam:CreateGroup`, `iam:AttachGroupPolicy`, and `iam:AddUserToGroup` under `DenyIAMRestrictedActions` in both Free and Paid plan SCPs. Thus retrying the same group Terraform resource, or merely upgrading to Paid, is not an evidenced fix. A reviewed direct user-policy attachment is a possible revised lab design, **not** an action taken here. An SCP denial of group creation is not proof that read-only group enumeration is denied or that an empty collector result is complete.

The team still needs the private Terraform plan/state reconciliation and a separate redacted, sealed collection handoff. The current CLI observations are not that handoff and cannot be labelled a real-account finding, a secure control, or an approved stable-rule input. See [the inventory handoff contract](27_AWS_INVENTORY_HANDOFF_CONTRACT.md#current-lab-handoff-gap).

## Earlier connection checkpoint — 2026-10-09

**Verified:** the owner completed browser-based `aws login` for the dedicated
`fyp-aws` CLI profile. Its configured project Region is `ap-southeast-2`.
`sts:GetCallerIdentity` succeeded and the returned principal was **not root**;
the account ID and ARN were not printed or recorded. The AWS Agent Toolkit wizard
completed, and its remote catalog listed 113 available skills. Existing Cursor
and Codex `aws-mcp` entries and the wizard-added Claude Code entry have
`AWS_MCP_PROXY_PROFILES=fyp-aws`. The toolkit service used `us-east-1` as required
by its setup guide; that does not change the selected project Region.

**Not verified:** the CLI principal's permissions have not been shown to be
read-only; the intended project/account ID has not been checked against an
independent owner-provided value; no IAM inventory probe, MCP call from a
restarted agent, snapshot collection, or real-account analysis was run. A
non-root STS result does **not** establish any of those claims. The teammate's
redacted snapshot handoff has not arrived in this checkout. Do not treat the
toolkit's broad capability as approval to make AWS changes or to bypass the
three-operation preflight allowlist.

Before running the bounded preflight, the owner should confirm the target
project in [AWS Settings](https://settings.aws.com/) and provide its account ID
**privately in the invoking process**, not in chat or Git. The two values are:

```powershell
$env:FYP_AWS_PROFILE = 'fyp-aws'
$env:FYP_AWS_EXPECTED_ACCOUNT_ID = '<independently confirmed 12-digit account ID>'
.\.venv\Scripts\python.exe -m fyp_iam.engine2.aws_preflight
```

Do not derive `FYP_AWS_EXPECTED_ACCOUNT_ID` from the very STS response the
preflight must check: that would make the target-account guard circular. A
`ready` preflight result only proves two bounded reads under this profile;
the account owner must separately review the profile's effective permission
scope before approving it for real-account collection. Share any teammate
handoff only as a private, redacted file outside Git and validate it using
[`27_AWS_INVENTORY_HANDOFF_CONTRACT.md`](27_AWS_INVENTORY_HANDOFF_CONTRACT.md).

## Earlier observed state — 2026-10-03

**Verified:** the locally configured AWS CLI successfully returned a caller
identity. That identity was root. Collection was stopped before any IAM inventory
request. No resource was provisioned, no permission attached, and no credentials
were rotated. Account identifiers and ARNs are deliberately not recorded here.

**Reported/unverified:** the user reports an AWS connection through MCPO. No AWS
MCP tool is exposed to this agent session. An `aws-mcp` entry exists in the local
Codex configuration, but its header is not connection-health evidence and does
not establish that it is an MCPO bridge. A candidate local endpoint did not
provide an OpenAPI document and belonged to an unrelated process; it was not used
as a bridge. A reachable MCPO URL, reviewed tool inventory, and safe credential
scope are still needed. Do not discover the bridge by blindly invoking tools or
scanning ports.

**Accepted user direction:** prioritize a strong product foundation rather than
implementing every engine immediately. Real-account read-only analysis remains
the primary demonstration target. Synthetic fixtures remain regression and
reproducibility inputs, not a substitute for live-account acceptance. The user
also wants eventual write testing; that does not authorize mutation of this
account. Write validation remains separately authorized, isolated and budgeted.

## Implemented preflight boundary

`fyp_iam.engine2.aws_preflight` is an explicit operator command, not an API route
or automatic startup task. Configure these values privately in the invoking
process environment:

- `FYP_AWS_PROFILE`: a named, dedicated read-only AWS CLI profile.
- `FYP_AWS_EXPECTED_ACCOUNT_ID`: the intended account ID. Never commit it or paste
  it into a project issue, command transcript, or chat.

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m fyp_iam.engine2.aws_preflight
```

This command does not load `.env`, configure credentials, create roles, attach
policies, or perform login. Configure the profile using your trusted AWS workflow;
prefer temporary role/SSO credentials. Review the existing twelve-action
`docs/policies/iam-readonly-collector.json` with the account owner before use; it
remains a template, not an attached policy. Never use root for project collection.

The preflight:

1. Requires an explicit profile and target account before contacting AWS.
2. Calls STS caller identity, rejects root, unsupported identity formats and
   non-commercial partitions, and checks the target account before IAM reads.
3. Probes only `iam:ListUsers` and `iam:ListRoles`, one page of at most one item
   each. CLI queries return counts/truncation flags, not names or policy documents.
4. Uses the regional STS endpoint in `ap-southeast-2` and the global IAM
   endpoint, shell-free argument lists, per-command
   timeouts, disabled pagination/pager, and one configured request attempt.
5. Does not inherit ambient keys, container credentials, web-identity tokens,
   custom AWS endpoints, or unrelated project secrets. It disables instance
   metadata fallback. Trusted profile/config files and required OS/proxy settings
   remain available. Credential processes that require other environment
   variables are not supported by this boundary.
6. Emits a closed JSON status with no raw identity, account ID, ARN, credential,
   CLI stderr, or exception message. Failed reads stay partial, not an empty
   account or a permission verdict.

At most three CLI commands are launched. Profile credential acquisition may
itself require additional authentication requests. `ready` means only the
identity and these two bounded reads passed. It does **not** prove least
privilege, completion of all twelve reads, policy evaluation, collection,
simulation, approval, exploitability, or a zero-dollar bill. Every result says
`collection_complete=false`. Profiles with administrator permissions can pass
these read probes; the operator must separately verify their effective grants.

The CLI transport rejects all operations outside its three-operation allowlist.
Neither an LLM response nor source prose supplies CLI arguments. Ordinary API and
preview paths remain offline. `collect_live_account` still refuses collection.

## Free-tier and MCPO boundaries

The preflight also enforces persistent local call limits, a stop switch and
transport-failure cooldowns. See [AWS usage guardrails](22_AWS_USAGE_GUARDRAILS.md)
for exact limits, operator commands, verification and important coverage limits.
These controls do not establish account-side budgets or Free Tier eligibility.

No compute, database, graph host, managed AI provider, logging service, trail,
Access Analyzer analyzer, sandbox, or paid scan is enabled by this slice. Existing
AWS usage and free-tier eligibility are not verified by a caller-identity check.
Free tier is not a spending cap. New billable services and lab runs need an
explicit cost and cleanup decision before provisioning.

MCPO transport reachability is not permission enforcement. Before using it,
review its advertised operations, authentication and network exposure, ensure it
uses the intended read-only identity, and bind results to the target account.
Do not register a broad write-capable toolset as an automatic execution path.
Bridge support must not bypass the profile/root/account safety checks.

## Foundation and extension boundaries

This preflight adds safe connection handling to the existing deterministic
compiler, immutable quality artifacts, tested PostgreSQL storage, bounded path
search and multi-page control plane. It does not complete the product foundation
by itself. Durable exact-version review, channel/scope enforcement, critic failure
handling, evidence lineage, operational readiness and real-account coverage still
need implementation and end-to-end proof.

Future collection must be bounded, privately handle raw evidence, report missing
policy layers, and produce reproducible snapshots. Engine 3 must consume only
eligible rules and preserve inconclusive outcomes. Simulator support, remaining
rule families, advanced graph persistence and evaluation studies remain separately
tracked extension work; a polished interface is not proof that they exist.

## Verification and sources

At the 2026-10-03 checkpoint, the new boundary had 25 offline tests for root/account gating, assumed roles,
configuration validation, bounded calls, unsupported-operation refusal,
timeouts, missing CLI, malformed/oversized output, partial reads, environment
isolation, and redaction. No test contacts AWS. At that checkpoint the real
non-root path and MCPO were unverified; the later STS/toolkit checkpoint above
does not establish preflight or MCP end-to-end readiness.

Observed regression: 225 non-PostgreSQL tests passed, five database tests were
deselected, and one existing Starlette test-client deprecation warning remains.
Ruff lint/format, mypy (69 source files), and diff whitespace checks passed.
Frontend and PostgreSQL checks were not rerun for this CLI-only change; earlier
database evidence is recorded separately in `19_POSTGRES_VERIFICATION.md`.

AWS CLI primary references, consulted 2026-10-03:
[caller identity](https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html)
and [ListUsers pagination](https://docs.aws.amazon.com/cli/latest/reference/iam/list-users.html).
Caller identity does not require IAM permissions; success is not evidence that
inventory reads are allowed. The probes deliberately disable automatic pagination.
