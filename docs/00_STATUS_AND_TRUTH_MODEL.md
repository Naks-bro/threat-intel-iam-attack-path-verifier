# Project Status and Truth Model

Last curated: 2026-10-09

**Latest AWS read checkpoint:** the owner supplied an independent AWS Settings
project reference, and the refreshed `fyp-aws` STS identity matched it privately.
The bounded non-root preflight passed. A later one-page, read-only IAM preview
observed two users, 17 roles, zero groups and two local managed policies; two
user-group traversals and three bounded AWS-managed policy reads completed.
The in-memory redacted handoff and observed-only graph validated with 19
principals and 36 direct relations; draft mapping accepted 95 rows. The HMAC
key was discarded and **nothing was persisted**. Managed-policy read-budget,
unresolved-trust and unevaluated-statement gaps remain, so source coverage and
authorization evaluation are false. This is not a durable real-account
snapshot, a two-identity comparison, or an IAM authorization verdict. See
[handoff boundary](27_AWS_INVENTORY_HANDOFF_CONTRACT.md).

**Repeatable-key preparation:** the opt-in AWS normalizer now supports a
private, 32-byte HMAC key for repeatable **in-memory** pseudonyms; malformed
or degenerate configuration fails before any AWS read. No production key or
retained real-account handoff exists. A local seal can bind that key to a
handoff hash and refuse expired or purged use. On 2026-10-09 the managed
FYP database was migrated from `20261003_0004` through `20261009_0012`.
Scheduled purge remains unbuilt. `engine2.real_account_store` can store one opted-in redacted `real_account_observed` handoff, including its observed graph, on disposable loopback `fyp_iam` only. It rejects credentials, raw policy bodies, and `authorization_evaluated=true` before a transaction. That PostgreSQL roundtrip stays unverified until a disposable loopback is configured. It is not a managed import.

**Engine 3 branch proposal, 2026-10-09:** a teammate design for Terraform plus
Pathrunner is **proposed, not approved**. Public lab docs show predefined
scenarios, not an arbitrary branch executor, and creating a Lambda function
does not make the caller assume its role. The current project is not a
sandbox target. An offline walker in `engine3/branch_walk.py` records a
synthetic AssumeRole chain and rejects the invalid Lambda identity hop. See
[docs/28_ENGINE_3_BRANCH_WALK.md](28_ENGINE_3_BRANCH_WALK.md).

**Latest schema preparation:** the user delegated the first AWS snapshot
retention choice; the selected design maximum is 90 days for redacted policy/
topology evidence, with owner consent and purge still outstanding ([ADR-018](decisions/ADR-018-redacted-aws-snapshot-retention.md)).
An unapplied 0011 observed-graph draft now adds four snapshot-scoped private
tables. Its projection row retains bounded incomplete-reason codes so its
stored digest can eventually be reconstructed. A pure row mapper binds an
exact redacted handoff to observed nodes, direct edges and policy/trust
evidence; it makes no database write or permission claim. A fresh disposable
rehearsal again reached 0011 from both empty and reconstructed-0004 paths with
matching 46-table catalogs, 19 empty RLS-enabled Engine 2/graph tables and
five synthetic legacy rows preserved. An opt-in **synthetic-only** writer now
commits the handoff and observed graph in one disposable-database transaction;
readback reprojects the exact stored handoff, compares every graph row, and
rejects a changed edge. An opted-in real-account writer can store that observed graph with the handoff on disposable loopback only. There is no permission resolver, public import route, or managed migration.
Migrations `20261009_0009`–`20261009_0010` are locally authored but **not
applied to Supabase**. 0010 adds nine normalized IAM evidence tables with
snapshot-scoped foreign keys and no raw policy body storage. A pure mapper
converts a validated handoff into all nine row types. A separate synthetic-only
writer now atomically commits and reads back a small redacted fixture on an
owned disposable loopback database, reconstructs its original ordered lists,
rechecks both digests, and rejects a changed statement digest and duplicate
request. A separate opted-in writer stores `data_kind=real_account_observed` on an `external_profile` connection in those same tables. It has no API route and is not a managed DB migration.
0009 adds six empty private Engine 2 connection/run/ordered-task/snapshot/
layer-coverage/gap tables,
no IAM policy bodies or credentials, a snapshot expiry constraint, explicit
browser-role revocations and RLS enabled with no browser policies. Fresh and
reconstructed-0004 disposable PostgreSQL 17.11 paths matched at 42 tables;
five synthetic legacy rows were retained exactly, and the new tables were
empty with RLS enabled. The rehearsal also rejected cross-snapshot policy and
statement references. The test server was stopped and its one-time password
file removed. That rehearsal was not itself a managed migration. Later on
2026-10-09 the owner asked for a live registry, and Alembic applied
`0005` through `0012` on the FYP database. The loopback API then reported
`database available` and `storage postgres`. That is not a published rule
or a real-account snapshot.
The backend-only gate passed with 598 tests, 12 opt-in PostgreSQL tests
deselected, Ruff, mypy (100 source files), and four generated contract checks.

**Latest handoff-to-schema bridge:** a pure local preparation function now
revalidates mutable `CollectionHandoff` bytes and maps sanitized run, ordered
task, snapshot, all seven policy-layer summaries and scoped coverage-gap
metadata to proposed 0009 columns. The snapshot records separate inventory
and whole-handoff digests. The bridge rejects
unrecorded successful-task digests, duplicate task attempts, unknown scoped
principals and registered-account fingerprint mismatch. A real user with no
complete group traversal yields a scoped gap, not a clean seal. A synthetic
insert of these rows passed in rolled-back transactions on both disposable
PostgreSQL rehearsal paths. No real inventory or normalized policy was stored;
no AWS call,
Supabase write, authenticated actor or IT export is provided by this bridge.

**Accepted identity direction:** the user chose individual Supabase Auth
accounts for real-account analyst review and IT export ([ADR-017](decisions/ADR-017-supabase-auth-analyst-identity.md)).
No login, deployed backend token verification, application role matrix, managed actor
table, or real-account decision/export route has been enabled. Local aliases
remain benchmark-only.
An isolated, mocked-test backend Auth-server identity resolver now exists;
this does **not** mean a deployed login or backend route is enabled. Live
Supabase session verification remains untested.

**Latest group-read checkpoint:** a bounded read-only `fyp-aws` probe found
zero memberships and zero direct managed/inline policy attachments for the
reported lab user at the observation time. For a real-account handoff,
`complete` user-group traversal now requires a matching successful,
fully-paginated `ListGroupsForUser` task with the same pseudonymous user,
count, and response digest. This improves collector-declared lineage, but
does not independently authenticate the AWS response or evaluate permission.

**Latest offline handoff checkpoint:** a private redacted handoff can now be
validated and compared for two selected IAM identity-policy-text questions by
`fyp_iam.contracts.handoff_preview`. It emits only fixed observation states and
aggregate uncertainty/coverage counts; it does not echo keys or policy content,
contact AWS/PostgreSQL, evaluate authorization, create a finding, or authorize
an IT export. The backend gate passed with 556 non-PostgreSQL tests and 12
database tests deselected, plus Ruff, mypy (95 sources), and four generated
contract checks. No teammate sealed snapshot or Terraform file was found under
`D:\FYP` at this checkpoint; real-account ingestion and the managed schema
migration remain unverified.

**Latest reproducibility checkpoint:** local Engine 3 fixture reports bind the
normalized graph input digest as well as the rule-input digest. The paired
investigation refuses missing or unequal graph digests for a reused snapshot
ID. The full routine check passed: 545 non-PostgreSQL tests, 12 database tests
deselected, 32 frontend tests, Ruff, mypy (94 sources), four generated contract
checks, and a production frontend build. Two installed-Edge browser journeys
passed against a separate live loopback preview on ports 5174/8766, including
the selected identity's two displayed digests and a 320px ledger view. The older
5173/8765 processes were not replaced. This remains a fixture-only guard, not
a real-account snapshot seal or IT export.

**Proposed schema refinement:** schema v0.1 now separates an authenticated
analyst actor, append-only exact-finding review decision, and immutable IT
report export. The first pilot exports one current accepted finding at a time;
local aliases, stale evidence and synthetic fixture results cannot authorize a
real-account IT handoff. These are design constraints, not migrated tables or an
implemented authentication/export service.

**Latest AWS/pilot checkpoint:** the user accepted two starting IAM identities
in one authorized AWS project/account and one sealed snapshot, investigated
individually and compared on a two-row overview ([ADR-016](decisions/ADR-016-two-identity-iam-pilot.md)).
The dedicated `fyp-aws` CLI profile authenticated through the browser in
`ap-southeast-2`; STS returned a non-root identity without exposing its account
details. Agent Toolkit installed, and its catalog listed 113 available skills.
The bounded preflight now uses the regional Sydney STS endpoint while retaining
global IAM reads. Its focused tests passed; the full backend gate reported
544 passed, 12 deselected, Ruff, mypy (94 sources), and four contract checks.
The profile's least-privilege scope, independent target-account match, post-restart
MCP call, teammate snapshot, managed schema migration, and real-account analysis
remain **unverified/not implemented**. No IAM inventory probe or AWS write was
performed in this checkpoint. See [connection security](20_AWS_CONNECTION_SECURITY.md)
and [schema-first gates](26_SCHEMA_FIRST_DELIVERY_GATES.md).

**Latest scoped stable-release checkpoint:** migration 0008, closed portable
release contract and opt-in local publish/export routes retain exact approval
without mutating the proposed candidate. Export rechecks current assurance/latest
scoped decision; later rejection or corruption fails closed. Engine 3 has a fresh
export-loader seam excluding legacy experimental records and requiring explicit
synthetic snapshot metadata under the only implemented benchmark fake policy.
467 non-PostgreSQL tests, twelve isolated PostgreSQL tests, Ruff, mypy (83 sources)
and four existing generated contracts passed. Populated 0007→0008 and actual
restart preserved an eligible benchmark release and exact gated export.
Engine 3 still reports the candidate's precondition as unsupported; no finding
or exploitability is inferred. GUI controls, legacy experimental-policy migration,
real verifier policy, managed deployment and live AWS/MCPO remain open.
No frontend/browser check was rerun for this backend-only slice. See ADR-015.

**Latest publication-assessment checkpoint:** an opt-in local GET computes
current quality/verifier/latest scoped decision readiness under the shared
transaction lock. Stale or negative decisions block; experimental defaults off.
The fake policy is benchmark-only; real/lab policy remains unconfigured.
444 non-PostgreSQL tests, eleven isolated PostgreSQL tests, Ruff, mypy (80 source
files) and four generated-contract checks passed. Actual restart retained history
and reproduced a blocked assessment. No frontend change or browser check was
made for this slice. Durable stable publication/export and migration of legacy
experimental publication remain open; the response explicitly cannot claim either.
AWS preflight separately returned `not_configured`: only the default CLI profile
was listed, and neither project profile nor expected account was configured in
process/user/machine environment. No AWS request was made for that check.

**Latest operator-review GUI checkpoint:** the dossier now reads scoped history
and records confirmed exact-input decisions in explicit local operator mode.
Missing assurance/disabled mode remain read-only. Uncertain outcomes retry the
unchanged request id; stale conflicts block new submissions until reload.
379 non-PostgreSQL tests, ten PostgreSQL tests, 24 frontend tests and build passed.
A real portal/API/database browser test recorded a synthetic-scope revision and
read it after page reload, with keyboard interaction and four tested widths.
The screenshot was inspected; no full accessibility/visual-baseline claim follows.
Stable/export eligibility, managed deployment and live AWS/MCPO remain open.

**Latest local-review API checkpoint:** opt-in loopback routes now record and
read scoped exact-input review history. Reviewer alias comes from operator
process configuration, not the browser, and is not authenticated identity.
Disabled, unsafe-boundary, invalid-input, conflict and unavailable responses are
explicit and sanitized. 375 non-PostgreSQL tests and ten isolated PostgreSQL
tests passed, including real HTTP retention/retry/stale/corruption behavior;
actual restart retained history. Review UI and stable/export eligibility remain
unfinished. No real human approval, managed migration or AWS/provider call occurred.

**Latest scoped-review foundation:** migration 0007 and typed repository
operations retain exact version/evidence/quality/verifier bindings with explicit
read-only-account, isolated-lab and benchmark scopes. Alias identity is not
authentication. Stale/conflicting requests fail; identical retries preserve the
original decision and opposing decisions append history. 347 non-PostgreSQL and
nine isolated PostgreSQL tests, additive upgrade and actual restart retention
passed. Review API/UI, current eligibility and stable export remain unfinished;
these test records are not real human approvals or cloud-write authorization.

**Latest default persistence checkpoint:** normal portal/API and CLI runs now
use exact version-scoped stored inputs and append bound schema-only fake packets.
Unbound selection is rejected before connecting; corrupt/missing stored bytes
roll back instead of invoking a legacy fallback. Migration 0006 is required.
328 non-PostgreSQL and seven isolated PostgreSQL tests passed, as did the ordinary
CLI, real local portal/API/database browser flow and actual restart retention.
Offline preview still has no stored record; historical packets are not inferred.
No managed migration, AWS collection, independent AI or stable approval is claimed.
The dated checkpoints below describe earlier states unless superseded here.

**Latest dossier checkpoint:** the rule API exposes nullable, rechecked exact
verifier metadata and the GUI renders its input/output digests, versions,
citations and findings. Missing historical packets stay unavailable and
mismatched bindings cannot supply a valid displayed verdict. Raw source text
is not returned. The fake is explicitly schema-only, not independent critique.
317 non-PostgreSQL tests, six isolated PostgreSQL tests (including HTTP),
20 frontend tests, production build and the verifier browser test passed.
Database-backed API and fixture-driven browser checks are separate evidence;
neither establishes real AWS acceptance or stable human-approved publication.
See the foundation runbook for remaining work and verification limitations.

## Why this file exists

The source material is a set of AI conversation exports. It mixes user decisions, assistant proposals, generated code that may never have been saved, copied document text, and claims about work completed elsewhere. This file defines what future collaborators may safely treat as fact.

## Evidence labels

| Label | Meaning | May drive implementation? |
|---|---|---|
| **Verified** | Confirmed by a primary source, an inspected project file, or observed command/test output | Yes |
| **Accepted decision** | Clearly selected by the team and recorded here or in an ADR | Yes, until superseded |
| **Proposed** | Sensible design needing team acceptance or implementation validation | For prototypes only |
| **Reported/unverified** | Claimed in chat but not supported by files in this folder | No; verify first |
| **Rejected/corrected** | Superseded, contradicted, unsafe, or misleading | No |

## Current verified inventory

**Exact verifier persistence checkpoint, 2026-10-03:** migration 0006 adds an
application-append-only packet table without replacing old AI records. The opt-in
`verify-run` path reads explicit stored source versions and checks artifact bytes,
metadata and scope before preserving the full bound request/result. Packet reads
revalidate rule JSON, content and response digests; missing history is not inferred.
Verified: 298 non-PostgreSQL tests, Ruff and mypy passed; six PostgreSQL tests
passed separately. Fresh migration through 0006, reconstructed populated 0005
upgrade and actual stop/start packet retention passed on owned disposable clusters.
The first local migration failure was caught and corrected; see the database record.
Supabase, remote CI, default-run/API/GUI integration, failed-provider observations,
real AI and stable publication remain unverified or unfinished. P7.1 is partial.

**Opt-in pinned-verifier integration, 2026-10-03:**
`compile_verified_snapshot` now selects actual bytes from the three reviewed
redacted pins and verifies hashes, versions and origin metadata before invoking
the request-bound critic. Missing or tampered payloads fail closed without a
provider call or fallback to current files. Deterministic validators run once;
their disagreement cannot be overridden by a passing critique. The explicit
`verify-preview` command exercises this path without reading database configuration
or persisting anything. Verified: 285 non-PostgreSQL tests, Ruff and mypy passed,
and the command returned a deterministic fake result. Five PostgreSQL tests were
deselected; frontend/database/browser code was unchanged and their earlier evidence
is not a verification of this new path. Ordinary GUI and database runs retain the
legacy compiler. Stored evidence reconstruction/request persistence, defect
evaluation, real AI and stable publication remain open; P7.1 is still partial.

**Local verifier-boundary checkpoint, 2026-10-03:** wrong prompt versions and
malformed, duplicate, oversized or conservatively unsafe response content cannot
produce a passing checked verdict. A frozen public-evidence request and optional
provider-neutral async runner bind selected bytes to replies, sanitize provider
errors, handle cooperative deadlines and disable external invocation by default.
The fake remains schema-only. The legacy compiler is not integrated with the new
runner; its evidence hash is unchanged and is not a full content snapshot digest.
No real AI, live AWS collection or stable-publication claim follows from this
boundary. P7.1 remains partial; see the foundation runbook for exact limitations.
Verification: 275 non-PostgreSQL tests passed, five database tests deselected,
16 frontend tests and production build passed; Ruff and mypy passed. The existing
Starlette warning remains. No browser or PostgreSQL rerun was needed for this
internal boundary change; earlier results retain their separately stated scope.

**Latest shared-foundation checkpoint, 2026-10-03:** Windows setup/check entry
points and `21_PRODUCT_FOUNDATION_RUNBOOK.md` now separate dependency setup,
offline preview, persistence and cloud preflight. Routine checks isolate database
URL selectors and exclude PostgreSQL tests. Marked database bodies require an
explicit disposable-loopback gate; 21 guard tests pass, including a subprocess
body-execution check. The Docker port is loopback-only in configuration; Docker
was not run. CI migration/reset steps use the same gate, but the changed remote
workflow has not run. Latest local check: 247 non-PostgreSQL tests, 16 frontend
tests, frontend build, Ruff and mypy passed. Three Edge browser flows passed and
the desktop architecture screenshot was inspected; no full accessibility,
performance, or visual-baseline certification is claimed. The offline run
deselected five database tests; a separate fresh owned PostgreSQL cluster then
passed the target gate, migrations 0001–0005, all five database tests and actual
restart durability. The existing Starlette deprecation warning remains. Dependency
audit found zero high/critical and two moderate test-tooling findings, tracked
in the runbook. Fresh-machine install, managed deployment, AWS/MCPO acceptance,
review/publication gates and commit/push remain open. Foundation readiness is
not yet a completed product claim.

**Latest AWS foundation checkpoint, 2026-10-03:** caller identity succeeded but
was root; no IAM inventory was collected. The separate operator preflight now
requires a named profile and expected target, blocks root/wrong accounts, bounds
its two IAM probes, isolates child-process credentials, and redacts output.
Live collection remains disabled. Non-root account acceptance and MCPO are
unverified. The user now prioritizes a strong product foundation over immediate
implementation of every engine; real read-only analysis remains the target.
See `20_AWS_CONNECTION_SECURITY.md` for the implementation and remaining gaps.

The statements in this section describe this implementation repository after the local slice was added. The original curation folder still holds the raw conversation exports and the pre-implementation baseline. Those exports are not in this Git tree.

- Python package `fyp_iam` implements the local fixture pipeline: contract models, six synthetic cases, bounded path discovery, fixture verification, baseline findings that cite hop policy refs and gaps, server-rendered review pages, an RQ3 fixture manifest, and a FastAPI boundary.
- Engine 1 can load one pinned local technique file, reject a hash mismatch or unsafe text, propose a pending rule from a code allowlist, show that proposal on a review page, and export an `ApprovedRule` only after a separate human approval request. It also loads a pinned 50-row Enterprise ATT&CK 19.2 IaaS dataset and joins pinned OWASP short names, one keyless NVD page, and CISA KEV catalog metadata into source nodes. Strength counts distinct source families. The automated join stores a compact catalog whose rows are stated as technique, weakness, vulnerability, or catalog. A model checker has not run. Those rows stay `no_rule_yet`. `POST /v1/rules/intake` does not approve and does not fetch a URL. Request handling does not download the feeds. The reported HTML parser remains **Reported/unverified**.
- Engine 2 can normalize synthetic IAM records into an `IAMGraphSnapshot`, record an unevaluated permissions boundary, emit an exact `service:*.amazonaws.com` trust, reconcile node and edge counts, match the local verdict of the hand-built fixtures, and report capability-edge precision and recall. A twelve-action read-only IAM template is tested and not attached. Live AWS collection is disabled and makes no API call. Neo4j is not implemented.
- The reported Engine 1 parser from the chats remains **Reported/unverified**. It was not present in the curated folder and was not imported.
- ADRs 001–009 are **Proposed**. ADR-009 supersedes the product direction in ADR-008. The first foundry slice is in this checkout: a pinned Enterprise ATT&CK 19.2 extract, an AWS Service Reference v1.4 extract for selected IAM and STS actions, and a redacted Stratus metadata extract. It derives three attack primitives, compiles `rule_additional_cloud_credentials` as proposed, and marks an experimental publication when the deterministic checks and the fake verifier pass. T1548 is rejected as an IAM mapping. The AWS Threat Technique Catalog is registered as disabled; historical failed attempts remain in the database audit log. The other rule families, optional validators, scheduler, and stable publication are not implemented. Migration `20261003_0002` replaces the checkpoint tables. Migration `20261003_0003` widens entity and source checks and adds suggestion rows.
- Confirm the slice with `python -m pytest`, `python -m ruff check .`, and `python -m mypy src` from a Python 3.12 virtual environment.

**Verified** on 2026-10-03 with Python 3.12.10 in this checkout. The foundry PostgreSQL test is deselected locally because `FYP_DATABASE_URL` is not set. GitHub Actions run [37068170700](https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier/actions/runs/37068170700) passed the unit job, the frontend job, and the PostgreSQL job, including migration `20261003_0003`, stored-row compilation, and the portal flow from an empty registry. The earlier run [37061261254](https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier/actions/runs/37061261254) covers the pin-computed slice only. The earlier checkpoint run [37054187538](https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier/actions/runs/37054187538) does not cover migration `20261003_0002`.

- `python -m ruff check .` — all checks passed
- `python -m ruff format --check .` — files already formatted
- `python -m pytest -m "not postgres"` — 126 passed, 1 deselected, with one Starlette deprecation warning about the `httpx` test client
- `python -m mypy src` — no issues found in 53 source files
- `npm test` in `frontend` — 2 passed
- `npm run build` in `frontend` — type-check and Vite build completed

## Engine 1 foundry slice

**Verified local quality persistence, 2026-10-03:**
Migration 0005 and `quality_store.py` add immutable semantic reports and separate
run observations. Rule detail reads the latest stored report and rejects corrupt
content; missing reports remain null. Nineteen storage-boundary/route tests pass,
including additive PostgreSQL SQL generation and null/partial API contracts.
Five PostgreSQL integration tests passed on an isolated 17.11 cluster; fresh
migration, reconstructed older-schema upgrade, and actual restart durability
passed. The initial database skips were superseded by these observed checks.
New validation writes
use null rather than fabricated row-index timings; historical placeholders remain
excluded from experiments. P6.2's local checks are satisfied. No managed migration,
production-scale durability, or current remote CI result is claimed. ADR-010 is
Proposed; see `19_POSTGRES_VERIFICATION.md` for the exact environment and evidence.

**Verified version-bound quality artifact, 2026-10-03:** Task P6.1 now has a typed immutable deterministic report bound to the rule version, semantic hash, and evidence snapshot hash. Missing required checks become skipped/incomplete; optional disagreement and unavailable tools remain visible; empty or contradictory passing corpus results fail. The preview API and React dossier expose the report, and generated frontend types/fixtures are checked by pytest against the provider schema. The persisted response stays nullable when no stored report exists. Local verification passed 181 non-PostgreSQL tests, 16 frontend tests, the frontend build, three Edge browser flows, Ruff, mypy, and diff whitespace checks. That P6.1 checkpoint did not itself prove coverage, measured validator timings, PostgreSQL report storage, human approval, or stable publication. The later local persistence result is the paragraph above. See `docs/18_RULE_QUALITY_REPORT.md`.

**Verified multi-page control plane, 2026-10-03:** the React portal now renders seven separate hash-routed workspaces with deep links, active navigation, route-heading focus, and an architecture view that labels implemented, partial, and planned capabilities. Thirteen frontend tests, the production build, and three Edge browser flows passed, including all-page overflow checks at 320/768/1024/1440px. Pipeline assurance no longer appears complete when a required check fails; stage statuses have text labels. The overview no longer embeds the full candidate dossier. The backend regression suite passed 158 non-PostgreSQL tests, mypy, Ruff lint, and formatting. See `docs/17_ENGINE_1_ARCHITECTURE.md` for the page map and completion audit. This does not verify current PostgreSQL durability, real AI critique, the remaining rule families, exact-version review, stable publication, or production deployment.

**Verified local GUI preview, 2026-10-03:** `fyp_iam.api.preview_app:app` serves the pinned Engine 1 result without connecting to PostgreSQL. The portal at `http://127.0.0.1:5173/` labels this state “OFFLINE PREVIEW”; its button recomputes in memory. The one candidate has six scenario outcomes but no publication or Engine 3 export in preview. This is not evidence that the Supabase-backed registry, durable reviews, or a real AI critic work. The separate normal API remains database-backed for foundry runs. Local checks passed: non-Postgres Python tests, mypy, Ruff, frontend unit tests/build, and a live Edge browser test of the preview route and button. A full-page screenshot was inspected. Do not use the preview status as a persisted-run claim.

**Verified assurance view, 2026-10-03:** the rule API now exposes check scope and textual findings. The current pinned candidate has ten passing required checks and four unavailable optional external tools; the six scenario cases are shown separately. The portal distinguishes those unavailable tools from passing checks and labels the fake verifier as a schema-only harness. A local Edge test and desktop/mobile screenshots confirmed the rendered panel; this is still not a real model critique or live AWS validation.

**Current worktree, offline verified:** the additional-credentials compiler now checks a versioned closed vocabulary and retains its prior semantic hash. A pinned six-case corpus records positive, near-negative, missing-context, and adversarial outcomes; confusion counts are calculated from observed outcomes. Repeated runs can append validation versions for the same immutable rule. An opt-in verifier result must bind to the exact candidate/evidence version and cite known evidence IDs; the default verifier remains a deterministic fake with no external model call. The operator dossier renders case outcomes, evidence references, and limitations. A bounded CLI supports offline preview and persisted runs; PostgreSQL transaction locking is implemented but has not been verified through the application against a live database. The AWS Threat Technique Catalog is disabled in new runs, so it no longer creates a synthetic partial failure. Existing PostgreSQL rows are updated only when the new pipeline runs. A read-only Supabase query on 2026-10-03 confirmed the managed database still holds the prior catalog row as enabled with a failed last attempt. The direct PostgreSQL integration test could not connect because host resolution failed during the attempt; the new persisted behavior remains unverified here. The earlier three-case and failed-ingestion statements below describe prior checkpoints, not the current code.

**Verified** locally for the compiler, the empty-registry API response, and the React component tests. **Proposed** as the product direction in ADR-009. PostgreSQL persistence is verified in GitHub Actions run [37068170700](https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier/actions/runs/37068170700), including migration `20261003_0003`, one experimental publication compiled from stored rows, and the Playwright portal flow. A local PostgreSQL server has still not been run. Supabase is an optional PostgreSQL host described in ADR-009. This checkout has not been given `FYP_DATABASE_URL`, so the managed-host path is implemented and not exercised here. CI PostgreSQL remains the reproducible verification environment.

- Sources in the pin: MITRE ATT&CK Enterprise 19.2 parent collection `sha256:dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`, reduced to T1098, T1098.001, T1098.003, and T1548. AWS Service Reference `v1.4` for `iam` and `sts`, limited to the actions the three behaviors name. Stratus Red Team metadata for `aws.persistence.iam-backdoor-user`, `aws.persistence.iam-backdoor-role`, and `aws.persistence.iam-create-backdoor-role`, stored as a redacted field extract. The original markdown is not committed because an example account ARN was present.
- Primitives: `additional_cloud_credentials` mapped to T1098.001 and compiled; `backdoored_role_creation` mapped to T1098.003 and not compiled; `trust_policy_backdoor` left unmapped because a trust-policy edit is not additional role creation.
- The compiled rule stays `status=proposed`. Engine 3 does not receive it unless experimental consumption is explicitly requested. The AI path is a fake schema verifier. It does not call a model and it ignores source text.
- Corpus `iam-corpus-0.2` has one positive, three near-negative, one missing-context, and one adversarial scenario for `iam:CreateAccessKey`. Its counts and precision/recall describe only these project-curated cases. The source hash is checked before evaluation.
- The compiler reads stored entities and relations. It does not select the candidate by a pinned behavior id. `GET /v1/foundry/overview` reads the registry. Without `FYP_DATABASE_URL` the registry state is `unavailable` and the candidate list is empty. `POST /v1/foundry/runs` returns 503 and does not pretend to save. Rule detail is `GET /v1/foundry/rules/{version_id}` using the id returned by the registry.
- AWS Threat Technique Catalog is disabled in new runs because no stable versioned input is confirmed. The historical 2026-10-03 failed probe remains available as audit history. A disabled source is excluded from active source health and does not cause `partial` status.
- AWS Threat Technique Catalog HTML exists. On 2026-10-03 `https://github.com/aws-samples/threat-technique-catalog-for-aws` returned 404 and no versioned JSON export was confirmed. It is not an adapter.

## Engine 1 audit

**Verified** for the local prototype. **Proposed** for the checkpoint in ADR-008, which ADR-009 supersedes as product direction. The checkpoint routes remain. Migration `20261003_0002` drops those tables on the next upgrade. A local PostgreSQL server has not applied either migration.

- Reuse the pinned artifacts, the T1548 allowlist, fail-closed intake, and the in-memory approval export.
- `strength` in the current catalog is a distinct-source count. It is not an overall confidence score.
- Approval is not durable. The reviewer id is caller-supplied. The older review pages remain server-rendered HTML.
- AWS Threat Technique Catalog ingestion, scheduled source runs, and an AI checker are not in this checkout. The PostgreSQL mapping, Alembic migration, and first React screen are in this checkout.
- On 2026-10-03 this machine had no `psql` and no `docker`. That is a local execution limit. GitHub Actions run [37054187538](https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier/actions/runs/37054187538) applied the migration and passed the PostgreSQL import test. A local database has not been exercised here.

## Accepted project baseline

- Working title: **Human-Approved, Threat-Intelligence-Driven Rule Generation with Explainable Cloud IAM Attack-Path Verification**.
- First implementation is scoped to AWS.
- The academic narrative has two stages: rule curation, then detection/verification.
- Engineering work is divided into four engines to permit parallel ownership.
- Human approval gates rule activation and final remediation decisions.
- Live AWS collection is read-only.
- Machine-learning or graph-ranking output prioritizes investigation; it does not prove exploitability.
- Cross-engine communication uses versioned, validated contracts.

## Reported but unverified implementation status

The chats claim an Engine 1 parser prototype exists with MITRE STIX, AWS Threat Technique Catalog HTML, and OWASP HTML parsing; AWS filtering; provenance; hashing; bounded references; input/security controls; and automated tests. They also report a Python 3.14 `ensurepip` failure that prevented execution.

None of those implementation files or test outputs exist in this folder. Treat the whole claim as **Reported/unverified** until the repository is supplied and tests run successfully.

## Important corrections

1. **NVD + CISA KEV + MITRE is not the agreed primary source set.** It was an assistant proposal later corrected in the same chat. NVD and KEV are optional enrichment candidates.
2. **OWASP Cloud-Native Top 10 is guidance, not a live CTI feed.** It may supply curated patterns and controls, but requires a versioned extraction/curation process.
3. **AWS Threat Technique Catalog HTML is not an ingestion source.** The public HTML catalog exists. On 2026-10-03 the expected `aws-samples` GitHub repository returned 404, and no maintained machine-readable export was confirmed. Keyword scraping is not a substitute.
4. **IAM Policy Simulator is a pre-check, not ground truth.** It does not make a real service request and can differ from live behavior for advanced configurations.
5. **CloudGoat cannot generically validate every discovered path.** It provides curated intentionally vulnerable scenarios. A path can be sandbox-tested only if it maps to an available or deliberately implemented scenario.
6. **Betweenness centrality is not a vulnerability score.** It measures how often a node lies on shortest paths. Any use in security prioritization requires an empirical hypothesis and ablation against simpler baselines.
7. **A GNN is optional.** It should be included only if a labeled dataset, baseline, evaluation plan, and measurable gain exist.
8. **“No prior work combines these ideas” remains unverified.** Absence claims require a documented systematic search, not a handful of examples.

## Local slice still open

- Team acceptance of Proposed v0.1 and of ADR-004.
- The reported Engine 1 parser, if it exists outside this folder.
- Live read-only collection, Policy Simulator, and any mapped sandbox. None of those are part of the local slice.
