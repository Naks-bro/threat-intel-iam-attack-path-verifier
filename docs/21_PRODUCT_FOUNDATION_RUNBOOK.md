# Product foundation: setup, operation and extension

## Scope

The current goal is a dependable base for the complete four-engine product, not
an assertion that all final features exist. Keep the two research stages and four
ownership boundaries. Real AWS read-only analysis is the intended target; fixture
and preview modes are reproducible development tools, not live analysis.

The latest verified building blocks are a deterministic Engine 1 foundry,
immutable quality reports with PostgreSQL storage, portable contracts, Engine 2
fixture normalization, bounded Engine 3 discovery/fixture verification, Engine 4
baseline evidence-grounded findings, and a seven-page React control plane.
Cross-engine contracts and ADRs remain Proposed unless separately accepted.

## Start here

Use the Git root, not the raw chat-export folder. Prerequisites for Windows:
Python 3.12, PowerShell 7, Git, and Node 22 or newer. CI uses Python 3.12 and Node
22; the latest local check used Python 3.12.10 and Node 26.5.1. Local evidence on
one runtime is not proof of compatibility with every newer Node release.

```powershell
.\scripts\setup.ps1 -CheckOnly
.\scripts\check.ps1
```

For a new checkout, run `scripts\setup.ps1` without `-CheckOnly`. It creates a
missing project virtual environment, installs `.[dev]` there, and runs `npm ci`
in `frontend`. It does not overwrite `.env`, rotate credentials, migrate/seed a
database, install system services, register MCP servers, or provision AWS.
An existing virtual environment with a different Python version is preserved;
setup fails with guidance rather than deleting it.

Both scripts accept `-BackendOnly`. The setup check-only path imports the
declared backend dependencies and checks local frontend tools without reinstalling.
The routine check runs Ruff, format checking, mypy, consumer-contract drift checks,
non-PostgreSQL pytest,
frontend tests, and the production frontend build. It temporarily blanks database
URL selectors for its own process so a private `.env` cannot redirect offline
checks. The original environment and working directory are restored afterward.

These are Windows entry points. On Linux, use the equivalent install/check
commands in README and `.github/workflows/workbench.yml`.

The drift gate checks quality types, the quality fixture and verifier types before
pytest. It never repairs stale artifacts automatically: review generated stdout
and the provider change together. CI's unit job has the same three checks, and
its portal selection now includes the verifier metadata browser test. The edited
workflow has not yet been pushed or observed running remotely.

## Choose the operating mode explicitly

| Mode | Entry point | What it proves / does not prove |
|---|---|---|
| Local fixtures | Normal API without database; `/v1/analyses/fixtures/{case_id}` | Four-engine contract flow on synthetic inputs, not AWS authorization |
| Foundry preview | `fyp_iam.api.preview_app:app` | Pinned evidence and deterministic dossier, no storage or publication |
| Persistent foundry | `fyp_iam.api.app:create_app --factory` with private PostgreSQL configuration | Stored runs/reports, not stable approval or live account analysis |
| AWS preflight | `fyp_iam.engine2.aws_preflight` | Root/account checks and two bounded IAM read probes, not collection |
| MCPO | Not integrated/verified in this session | Requires reviewed endpoint, operations, identity and permission scope |

For GUI preview, run in two terminals from the repository root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn fyp_iam.api.preview_app:app --host 127.0.0.1 --port 8765
```

```powershell
Push-Location frontend
npm.cmd run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Open `http://127.0.0.1:5173/`. The “OFFLINE PREVIEW” label is intentional in this
mode. Open `/#/architecture` for the implementation-status diagram. Stop only
the processes you started; do not kill every Python/Node process or replace an
occupied port automatically. API documentation is at `http://127.0.0.1:8765/docs`.
Loopback development servers are not an authenticated production deployment.

If those ports belong to another running preview, leave it alone and use a
separate pair. For example, start the same offline API on `127.0.0.1:8766`,
then in the frontend terminal set `$env:FYP_API_PORT = '8766'` before
`npm.cmd run dev -- --host 127.0.0.1 --port 5174 --strictPort`. Open
`http://127.0.0.1:5174/#/investigate`. `FYP_API_PORT` accepts only a local
non-privileged port; it changes Vite's loopback proxy, not application database
or AWS configuration. To run the paired browser test against that instance,
set `$env:FYP_E2E_PORT = '5174'` and `$env:FYP_E2E_EDGE = '1'`, then run
`npx.cmd playwright test e2e/investigation-pair.spec.ts --workers=1` from
`frontend`. The test runner also constrains its target to loopback.

## Database setup and tests are separate workflows

PostgreSQL is the persistence contract; Supabase is optional hosting, not a
browser data-access dependency. Configure application credentials privately as
documented in README. Keep migration credentials separate when appropriate.
Do not use transaction pooling on port 6543. Check the selected database before
explicitly authorizing migration/seed commands. Setup never performs them.

For a **fresh disposable local test database only**, configure the URL in the
invoking process and explicitly set `FYP_ALLOW_DISPOSABLE_DATABASE_TESTS=1`.
The database name must be `fyp_iam`, host must be literal loopback, and driver
must be `postgresql+psycopg`. Query-based endpoint overrides and libpq connection
selectors are rejected. Alternative application, test and migration URLs must
not redirect to another target. The gate does not read `.env` or contact a host.

```powershell
.\.venv\Scripts\python.exe -m fyp_iam.persistence.test_guard
.\.venv\Scripts\python.exe -m alembic upgrade head
.\scripts\check.ps1 -IncludePostgres
```

The check command does not migrate, truncate, or seed the database. PostgreSQL
tests do write rows and alter test roles; do not point them at Supabase, a
shared developer database, or a local proxy to a managed host. Loopback plus an
opt-in flag cannot prove that a proxy's remote backend is disposable: the
operator must verify ownership and isolation.

The pytest gate runs before marked database test bodies. A missing URL skips
those tests; a configured but unsafe/non-opted-in target fails with a fixed code.
Routine non-PostgreSQL checks exclude them explicitly. CI uses its ephemeral
PostgreSQL service, and gates both migrations and the CI-only row reset.
`compose.yaml` binds PostgreSQL to `127.0.0.1`, not the LAN. Docker execution on
this machine has not been verified; portable PostgreSQL evidence is in
[the database verification record](19_POSTGRES_VERIFICATION.md).

## Local operator review mode

Normal API/preview entry points leave review disabled. After explicitly reviewing
the application database and applying migration 0007 through the separate
migration workflow, the operator can start this loopback-only mode:

```powershell
$env:FYP_LOCAL_REVIEWER_ALIAS = "team_operator_alias"
.\.venv\Scripts\python.exe -m uvicorn fyp_iam.api.local_review_app:create_local_review_app --factory --host 127.0.0.1 --port 8765 --no-proxy-headers
```

The alias is process configuration, not a browser field or a secret. The database
`.env` loader explicitly skips this key, so database configuration cannot enable
or replace the operator alias. Database configuration follows the
ordinary private application configuration. Do not replace an occupied server or
expose this mode on a LAN, tunnel or reverse proxy. Any local process can act
inside this operator boundary: this is not multi-user authentication.

- `POST /v1/foundry/reviews` accepts the closed `ReviewCommand`; obtain its exact
  rule/evidence/quality/verifier digests from the selected dossier. The operator
  request id is an idempotency key. Identical retries return the same record;
  changed requests using that id conflict. No browser-supplied identity is accepted.
- `GET /v1/foundry/rules/{version_id}/review?scope=read_only_account_analysis`
  returns the latest scoped history, or `latest: null` for a known unreviewed
  version. Other explicit scopes are `isolated_lab_validation` and
  `synthetic_benchmark`. A missing version is 404.
- Success returns 200; rejected boundary is 403; stale/reused-key or busy-run
  conflicts are 409; invalid input is sanitized 422; disabled/unavailable mode
  is 503. OpenAPI documents the fixed error-code shape and closed inputs.

Review requests require a literal loopback peer and a loopback Host. Forwarded
headers are rejected. A supplied browser Origin must match HTTP localhost,
127.0.0.1 or `[::1]` on development ports 5173/8765; absent Origin supports local
CLI use. These are development exposure checks, not a substitute for auth or
request/resource limits in a future shared service. Use non-sensitive plain-text
comments; marker rejection is not a general secret detector.

The dossier's operator-review panel uses generated backend types and renders
loading, disabled/unavailable, empty, historical, conflict and saved states.
Missing/mismatched stored assurance blocks the form. The default scope is
read-only account analysis; revision/rejection require a comment and all decisions
require exact-input confirmation. An uncertain recording outcome freezes the
command and idempotency key for retry; stale conflicts require a dossier reload.
The browser never sends reviewer identity. Source/comment prose stays plain text.

Stored approvals do not publish or mutate canonical rules. The state explicitly
returns `release_eligibility: not_evaluated`; stable-release UI integration remains
open. The separate scoped stable API is described below.
The legacy fixture approval route is a separate demo path.

### Read-only publication assessment

In the same explicit local operator mode, call
`GET /v1/foundry/rules/{version_id}/publication-assessment?scope=read_only_account_analysis`.
The required scope has the same three values as review; channel defaults to stable.
For explicit benchmark experimentation use `scope=synthetic_benchmark&channel=experimental&allow_experimental=true`.
The server checks current quality/verifier bindings and latest scoped history
under the pipeline/review transaction lock; busy returns 409. Missing/corrupt
storage is unavailable, not eligible. Boundary and sanitized validation errors
match the review API. No write or external call occurs.

`eligible_for_publication` describes current policy readiness only. The closed
response says `published=false` and `export_available=false`; it is not a release
token. Real/lab policy remains unconfigured regardless of provider labels.
Benchmark fake readiness is a harness result, not an independent AI evaluation.
Legacy experimental publication has not been migrated to this policy. The later
scoped stable store/export and Engine 3 loader seam are described below; the
assessment itself remains a pre-publication response.
See [ADR-014](decisions/ADR-014-computed-publication-assessment.md).

## Scoped stable release operations

In explicit local operator mode with a privately reviewed database migrated
through `20261007_0008`, `POST /v1/foundry/releases` takes the closed
`StableReleaseCommand`. Obtain `review_decision_id` and `review_record_hash` from
the latest scoped review, not a prior dossier or caller-invented approval. Supply
an operator request id, rule version and scope. Stable readiness is rechecked
under the pipeline/review lock. The server's configured alias is the publisher;
no browser identity or rule body is accepted. Success/retry returns 200; changed
request/operator or ineligible inputs conflict with 409 `release_conflict`.

`GET /v1/foundry/releases/{release_id}/export?scope=synthetic_benchmark` returns
the portable `StableRuleRelease` only after rechecking current assurance and
the latest exact review. Wrong scope, later rejection/revision or changed inputs
returns 409; missing release returns 404; corrupted storage returns sanitized 503.
Both routes use the same local exposure checks as review. This is not shared auth.
Release creation is explicit; routine setup/check/preview commands never perform it.

Only benchmark fake policy currently passes. Real-account/lab release requests
remain ineligible even if a test reviewer says approved. The assessment response's
`published=false`/`export_available=false` remains a pre-publication response, not
a claim that these separate explicit routes do not exist. Registry/review-state/UI
still do not resolve or operate these stable releases; GUI integration remains open.

Engine 3's `analyze_published_release` requires a trusted loader that calls the
current export service for each analysis. Never use cached JSON as that loader.
It checks id/scope/channel and explicit synthetic snapshot metadata. The existing
generic fixture `analyze` is not a release gateway. This family still yields
`unsupported_precondition`, not a detection or proof. Export eligibility is checked
at a point in time and is not distributed revocation or a signature.
See [ADR-015](decisions/ADR-015-scoped-stable-release-export.md).

## AWS and cost protection

Follow [the connection safety guide](20_AWS_CONNECTION_SECURITY.md). The observed
CLI identity was root; no account inventory was collected. Await a dedicated
non-root read-only profile before further account work. No setup/check command
provisions resources, enables a paid AI service, calls Policy Simulator, creates
an analyzer/trail, or runs a vulnerable lab. Free-tier eligibility is unverified
and is not a spending cap. AWS write testing needs separate isolated-lab approval.

An `aws-mcp` entry exists in local Codex configuration, but no AWS tool is
currently exposed to this session; MCPO transport health is unverified. A user's report
that it is connected is not evidence of reviewed operations or least privilege.
Do not work around this by installing a broad toolset or accepting LLM-generated
cloud commands. Cloud credentials never go into the browser or a chat prompt.

## Extension seams and remaining foundation gates

| Boundary | Existing base | Required before a real product claim |
|---|---|---|
| Engine 1 → Engine 3 | Proposed typed rule contract, first-family compiler, scoped review API/GUI and benchmark-only stable store/current export/consumer seam | Real release policy, legacy experimental migration, supported family semantics and GUI/report provenance |
| AI critic → Engine 1 | Frozen request, async runner, exact stored-input compilation/packet retention for normal persisted runs and typed dossier metadata | Failed-provider observations and defect evaluation; provider/privacy/cost decision before a real call |
| Engine 2 → Engine 3 | Portable graph snapshots and fixture normalization | Bounded live collection, private evidence handling and explicit policy-layer coverage |
| Engine 3 → Engine 4 | Bounded paths, fixture verdicts and evidence references | Live verification adapters without relabeling reachability as exploitability |
| API → React | Typed responses, seven workspaces and quality dossier | Real run/scan pages, security model and operational readiness before shared deployment |

Do not expose incomplete seams as working live capabilities. Add one tested
vertical slice at a time, preserving contract versions and explicit unknown
states. Do not add Redis, a GNN, a graph host, authentication or another managed
service merely to make the stack look larger. Each needs a justified requirement.

## Security and release checklist

- Never commit `.env`, account identifiers, raw ARNs/policies, private keys or tokens.
- Review staged files explicitly; preserve unrelated changes and generated outputs.
- Human approval and target-account safety checks are code boundaries, not prompts.
- Local alias review is not authenticated identity. No shared/public deployment
  until an explicit authorization and exposure model is chosen and verified.
- Unit, integration, browser and migration evidence must match their claimed scope.
- Run dependency audits before a release; track findings instead of claiming zero
  vulnerabilities from a successful build.
- Use GitHub `engine1-curation-workbench` for preservation. Current changes are
  staged/local until an authorized Git author identity permits commit and push.

## Verifier adapter boundary — local foundation only

`VerifierRequest` freezes canonical typed rule JSON and selected public evidence
excerpts, checks candidate/content digests and reference resolution, and limits
the serialized input to 64 KiB. `request_hash` binds those selected bytes,
versions and identifiers. It does not establish source truth, completeness,
independence or cloud-account coverage. The legacy compiler's
`evidence_snapshot_hash` is not a full evidence-content digest; it is unchanged.

`run_verifier` rejects external adapters by default, binds response metadata to
the configured adapter and exact request, and produces non-publishing results
for stale responses, provider errors and cooperative timeouts. Caller cancellation
propagates. The deadline is not process isolation: future adapters must avoid
blocking work and set their own transport deadlines. No real provider ships here.

The schema-only `FakeVerifier` ignores source instructions and depends on an
explicit deterministic-validation input. It is a wiring harness, not an AI proof
of semantics. Response checks reject unsupported prompt versions, unknown or
duplicate citations, oversized/blank text and conservative unsafe markers.
These marker checks are not a complete prompt-injection defense. Imported prose
remains untrusted data, and no response runs commands or mutates canonical rules.

The explicit `compile_verified_snapshot` path compiles once, selects the actual
bytes of all three small redacted source extracts, verifies their hashes,
versions and origin metadata against the reviewed local manifest, then runs the
bound critic. Missing or changed payloads fail before provider invocation; there
is no fallback to newer files when a historical snapshot lacks raw bytes. The
selector is deliberately limited to the current credential rule family. Supporting
source citations are request-local identifiers, not newly persisted evidence rows.

Exercise this full offline path from the repository root:

```powershell
.\.venv\Scripts\python.exe -m fyp_iam.engine1.foundry.runner verify-preview
```

This command uses the schema-only fake, prints only operational status and the
request digest, never loads database configuration and never persists or calls a
cloud/provider. Exit 0 means the bounded fake critique passed; exit 2 means it did
not. Neither is a live-AI or independent semantic-verification claim. The regular
`preview` and GUI preview remain in-memory legacy-compatible presentations;
they do not claim stored verifier history. Ordinary database `run` and the portal
pipeline action now require exact stored inputs and append bound fake packets.

For an explicitly configured application database migrated through 0006,
`python -m fyp_iam.engine1.foundry.runner verify-run` selects exact stored source
versions and preserves a full checked request/result in `foundry.verifier_packets`.
It uses the schema-only fake and never calls a provider or AWS. Unlike preview,
this command intentionally reads the private database configuration and commits
a run; it is not part of routine offline checks. Do not invoke it against an
unreviewed target. No managed database was used to verify this increment.

The scoped reader restores sources, exact artifact bytes, entities, claims and
relations for the requested versions. Packet reads verify candidate JSON and
semantic hash, evidence content digests, citation binding and response digest.
Application-level append-only behavior is not tamper resistance against a DBA.
Old AI rows remain historical; no packet is fabricated for them. The existing
rule-dossier GET endpoint now returns nullable `verifier_record` metadata after
rechecking the stored packet. It does not expose raw source text or candidate JSON.
The generated frontend contract and dossier show digests, source versions,
citations, findings and provider/prompt identity. Missing history is unavailable;
a mismatched binding is not displayed as a valid verdict. The schema-only fake
is explicitly labelled and does not establish independent AI verification.

P7.1 remains partial: failed-provider
observations, independent semantic critique and evaluated defect detection remain
open. Historical reads currently accept the implemented prompt/schema versions;
future evolution needs explicit compatibility handling. See ADR-012.
Stable publication still requires durable exact-version human approval and scope
enforcement; a passing fake or adapter result is not that approval.

## Observed verification — 2026-10-03

- Operator GUI checkpoint: 379 non-PostgreSQL tests, ten isolated PostgreSQL
  tests, 24 frontend tests, production build, Ruff/mypy and four generated
  consumer-contract checks passed. The actual portal/API/database browser flow
  recorded a synthetic-scope revision with keyboard controls and read it after
  page reload. Four viewport widths had no horizontal overflow; page errors were
  absent and observed review responses were 200. The panel screenshot was
  inspected. This is not a real human approval or complete QA certification:
  axe, screen-reader audit, measured vitals and committed visual baselines were
  not run. Test API/database were stopped and temporary init password removed.
  CI's edited portal selection includes this flow with one worker to avoid
  concurrent mutating test runs; remote execution is not yet observed.
- Local review API checkpoint: 375 non-PostgreSQL tests and ten isolated
  PostgreSQL tests passed; Ruff, format, mypy (78 source files) and consumer
  contracts passed. Real database-backed HTTP checks retained an idempotent
  record, isolated scopes, rejected stale assurance and returned sanitized 503
  for corrupt history. Actual database restart preserved review/verifier records.
  The test cluster is stopped. Frontend was unchanged; no browser review UI,
  managed deployment, shared authentication, stable export or cloud action was tested.
- Scoped-review repository checkpoint: 347 non-PostgreSQL tests, nine isolated
  PostgreSQL tests, Ruff lint/format, mypy (76 source files) and consumer contracts
  passed. Populated reconstructed 0006→0007 upgrade preserved the earlier
  dossier; actual stop/start retained exact review history. No API/UI review or
  stable export is implemented by this slice. See ADR-013 for alias/idempotency
  and scope boundaries. Frontend source was unchanged and its checks were not rerun.
- Default persistence checkpoint: 328 non-PostgreSQL tests, seven isolated
  PostgreSQL tests, Ruff lint/format, mypy and all consumer contracts passed.
  The normal CLI `run` and actual portal → API → PostgreSQL browser flow passed;
  the dossier displayed retained three-source metadata. A corrupt stored payload
  produced a sanitized 503 with no new pipeline/packet rows and preserved the
  earlier record. Stop/start retained the exact request/result. Test API and
  database were stopped; no managed migration, AWS or provider call occurred.
  Browser interaction evidence is not full accessibility, visual-regression or
  performance certification. Frontend source/build were unchanged in this slice.
- Routine entry-point checkpoint: `scripts/check.ps1` exited successfully with
  327 non-PostgreSQL tests (six deselected), 20 frontend tests, production build,
  three consumer-contract checks, Ruff lint/format and mypy (74 source files).
  Ten added gate tests cover matching/stale/missing artifacts and invalid option
  combinations without rewriting files. PostgreSQL and browser tests were not
  rerun for this check-script change; their earlier evidence has its own scope.
  No cloud or managed database was invoked. The Starlette deprecation warning remains.
- Dossier metadata checkpoint: 317 non-PostgreSQL tests and six isolated
  PostgreSQL tests passed, including the real database-backed HTTP response.
  Ruff lint/format and mypy (74 source files) passed in the shared tree.
  Twenty frontend tests, production build and the verifier browser test passed.
  Browser fixtures cover missing/mismatched records, keyboard disclosure and
  four viewport widths; they are not live PostgreSQL or AWS browser acceptance.
  Vite emitted refused-backend proxy messages during the browser run despite
  intercepted fixture responses passing. No full accessibility, visual-baseline
  or performance certification is claimed. The test database was stopped.
- Unified offline check at the response-boundary checkpoint: 275 backend tests,
  type/lint/format, 16 frontend tests and
  production build passed. Five PostgreSQL tests were deselected in that run.
- Subsequent pinned-verifier integration: 285 non-PostgreSQL tests, Ruff lint and
  format, and mypy (71 source files) passed; `verify-preview` succeeded with three
  source payloads and `persisted: false`. Frontend and database code were unchanged
  in this increment; those checks were not rerun. The existing Starlette warning remains.
- Exact verifier storage: 298 non-PostgreSQL tests passed, six PostgreSQL tests
  passed separately, Ruff and mypy (73 source files) passed. Fresh migration
  through 0006, a populated reconstructed 0005 upgrade, the `verify-run` CLI and
  actual packet retention after stop/start passed. The test clusters are stopped;
  see the PostgreSQL record for scope and the initial caught migration failure.
- Database guard: 21 tests passed, including a subprocess proving a managed target
  cannot execute the marked test body. No managed database was contacted by the test.
- Windows setup `-CheckOnly`: passed against existing dependencies. Clean-machine
  creation/installation was not re-run; that path is not an observed fresh-install proof.
- Database durability/migrations: a fresh owned PostgreSQL cluster passed the new
  gate, migrations 0001–0005, five database tests and actual restart durability.
  It was stopped afterward. This is not a managed deployment or proof that the
  updated remote CI workflow has run; see the database verification record.
- Browser preview: three Edge flows passed, including seven pages at four
  breakpoints, keyboard focus, deep links and the quality dossier. The desktop
  architecture screenshot was inspected. Full axe/accessibility, measured Core
  Web Vitals and committed visual-baseline comparison were not run.
- Dependency audit: zero high/critical, two moderate findings in Vitest test tooling
  for [GHSA-82fw-gwwq-j7x9](https://github.com/advisories/GHSA-82fw-gwwq-j7x9).
  The registry recommends a major upgrade. The project uses `vitest run`, not a
  publicly exposed Vitest mock server; this is not proof of non-reachability in
  every environment. Track the upgrade and review before release, by 2026-10-10.

Foundation readiness remains **in progress** while persistence deployment,
non-root AWS/MCPO acceptance, review/publication gates and preservation are open.
This guide is a runnable handoff, not a declaration that the entire product works.
