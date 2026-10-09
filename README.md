# Human-Approved, Threat-Intelligence-Driven Rule Generation with Explainable Cloud IAM Attack-Path Verification

This repository is the implementation checkout for the final-year project. It currently contains one local vertical slice:

For whole-project installation, operating modes, safety gates and extension
boundaries, start with [the product foundation runbook](docs/21_PRODUCT_FOUNDATION_RUNBOOK.md).
Windows collaborators can validate installed dependencies with
`scripts\setup.ps1 -CheckOnly` and run backend/frontend checks with `scripts\check.ps1`.

## Collaborate

Use branch `engine1-curation-workbench`. `main` is an older fixture baseline. GitHub is the source of truth for code. The shared application database is the existing FYP Supabase Postgres project, not a file in this repo and not Docker.

1. Clone the repository and check out `engine1-curation-workbench`.
2. Install Python 3.12 and the frontend dependencies in [Commands](#commands).
3. Copy `.env.example` to `.env`. Ask the maintainer for the session-pooler URL and put it only in that file. Never commit `.env`, certificates, AWS credentials, or account identifiers.
4. From the repository root, run `python -m fyp_iam.persistence check`. On 2026-10-09 the shared database was migrated through Alembic `20261009_0012`. Do not run `migrate` against it again unless the team has reviewed the migration diff.
5. Run `scripts\check.ps1`. That check does not need Docker.
6. Start the API and the portal in two terminals, then open `http://127.0.0.1:5173/`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn fyp_iam.api.app:app --host 127.0.0.1 --port 8765
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

Supabase is the shared registry. It is the wrong place for disposable tests: those tests write rows and run migrations, so they belong on the local Postgres in `compose.yaml` or on the GitHub Actions `postgres` job. Docker is optional. A collaborator can read and continue the product without it.

The analyst demo still needs a human to name the two starting identities. A policy-text match is not exploit proof. Review stays on the local machine. Do not approve a rule from a public host.

Engine 1 also has an experimental evidence foundry in `src/fyp_iam/engine1/foundry/` and a React control plane in `frontend/`. It ingests three pinned extracts (MITRE ATT&CK, AWS Service Authorization Reference, and redacted Stratus metadata), derives three attack primitives, and compiles one additional-credentials candidate. The canonical candidate stays proposed; the legacy registry exposes experimental publications. The AWS Threat Technique Catalog entry is disabled until a stable versioned input exists. The foundry has a closed vocabulary for the first rule family and a six-case pinned scenario corpus; the other two planned rule families, a real AI critic, and real-account stable publication remain open. A separate benchmark-only scoped stable release API is described below. See `docs/14_ENGINE_1_RESEARCH_GRADE_FOUNDRY_SPEC.md` and `docs/00_STATUS_AND_TRUTH_MODEL.md` for the boundary between the current code and planned work.

An opt-in verifier result must bind to the exact candidate version and evidence snapshot and cite known evidence IDs. Malformed or unbound results move to `needs_review` and cannot publish experimentally. No external model provider is configured or called in ordinary runs.

`python -m fyp_iam.engine1.foundry.runner verify-preview` exercises the new
request-bound verifier path over the exact bytes of all three reviewed pins.
It uses only a schema-only fake and prints a small status summary with its request
digest; no database configuration, persistence or network is used. This is an
adapter-wiring check, not a real AI evaluation. Ordinary persisted GUI/CLI runs
now use this bound schema-only verifier over explicitly selected stored inputs.
Offline GUI preview remains in-memory and does not manufacture stored records.

With an explicitly reviewed application database migrated through 0006,
`python -m fyp_iam.engine1.foundry.runner verify-run` commits a bound fake-verifier
run and stores its exact request/result. Ordinary `run` and the portal pipeline
button now use the same exact stored-input path. Migration 0006 is required;
missing or corrupted stored inputs fail the transaction without a legacy fallback.
It intentionally uses private database configuration, unlike `verify-preview`.
See the foundation runbook and ADR-012 before invoking it. No managed migration
or real AI is implied by the local PostgreSQL verification.

The rule dossier can inspect rechecked verifier metadata from persisted runs:
input/output digests, source versions, citations and findings. Legacy rows and
offline previews show exact records as unavailable rather than inventing history.
The fake remains a schema-only harness, not independent AI verification.

Exact-input scoped review now has an opt-in local API. It is disabled in the
ordinary API and preview. For operator configuration, endpoints and limitations,
see [local review mode](docs/21_PRODUCT_FOUNDATION_RUNBOOK.md#local-operator-review-mode).
Migration 0007 is required for review storage. A recorded decision is not stable
publication, authenticated identity or authority to execute AWS writes.

The dossier now includes a scoped operator-review panel in that explicit local
mode. It freezes the displayed assurance digests, requires confirmation, renders
retained history, and retries uncertain outcomes with the same request id.
Missing inputs/disabled mode are read-only; stale conflicts require reloading
the dossier. Stable publication/export enforcement is still unfinished.

A separate local operator endpoint now computes current scoped publication
readiness from rechecked quality/verifier inputs and the latest decision:
`GET /v1/foundry/rules/{version_id}/publication-assessment?scope=read_only_account_analysis`.
Real-account/lab verifier policy is not configured and fails closed. Only an
explicit synthetic benchmark can satisfy the current fake-harness policy.
The endpoint does not publish or export; legacy experimental publication has
not yet been migrated to this gate. See ADR-014 and the foundation runbook.

The follow-up [scoped stable release API](docs/decisions/ADR-015-scoped-stable-release-export.md)
adds durable, exact-review-bound release creation and a separately gated export.
Migration 0008 is required. Only the explicit benchmark fake policy is implemented;
real-account stable publication remains disabled. The proposed candidate is never
mutated, and later rejection prevents export. Stable releases are separate from
the legacy experimental registry and have no GUI controls yet. Engine 3's new
fresh-export consumer still reports this family's precondition as unsupported.

The foundry command can preview the deterministic result without a database: `python -m fyp_iam.engine1.foundry.runner preview`. With a private `FYP_DATABASE_URL`, `python -m fyp_iam.engine1.foundry.runner run` persists one bounded run. A transaction lock rejects overlapping runs. External scheduling can invoke the `run` command; no always-on scheduler is installed by this checkout. The command prints only a small status summary, not source payloads or connection strings.

To preview the Engine 1 GUI without a database, run these in separate terminals from the repository root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn fyp_iam.api.preview_app:app --host 127.0.0.1 --port 8765
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

Open `http://127.0.0.1:5173/`. This explicit preview entry point ignores `FYP_DATABASE_URL`, uses only checked-in pinned evidence, and never stores a run or publishes a rule. The “Recompute preview” button recalculates in memory. The normal API entry point still requires a configured PostgreSQL database for foundry runs.

The portal now has seven URL-addressable workspaces: Overview, Pipeline, Source intelligence, Attack primitives, Evidence map, Rule registry, and Architecture. Open `http://127.0.0.1:5173/#/architecture` for the implementation-status diagram. The [architecture and page map](docs/17_ENGINE_1_ARCHITECTURE.md) records which capabilities are implemented, partial, or planned; navigation improvements do not imply production readiness.

The candidate dossier separates required deterministic checks from optional external tools. Each result shows its status and any textual finding; scenario outcomes appear separately. In the pinned preview, ten required checks pass, while four optional tools are unavailable because they are not installed. Neither the unavailable tools nor the schema-only fake verifier should be described as independent validation or a live AI review.

The preview also exposes a [version-bound quality report](docs/18_RULE_QUALITY_REPORT.md), with an integrity hash, validator/corpus versions, explicit missing checks, and nullable timings. Frontend types and its test fixture are generated from the backend contract. Migration 0005 and the new run writer add report storage/history; [isolated PostgreSQL migration and restart checks passed](docs/19_POSTGRES_VERIFICATION.md). Managed deployment remains unverified. Historical versions without reports remain unavailable. A passing deterministic report is not human approval or stable publication.

```text
pinned local technique
  -> proposed rule
  -> human approval event
  -> ApprovedRule
ApprovedRule + IAMGraphSnapshot fixture
  -> rule matching
  -> bounded breadth-first path discovery
  -> VerificationResult
  -> evidence-grounded Finding
```

The slice runs on synthetic JSON fixtures and one checked-in technique pin. It does not need AWS credentials, Neo4j, Redis, PostgreSQL, an LLM API, or CloudGoat.

Engine 2 can also build an `IAMGraphSnapshot` from synthetic identity and trust statements. That normalizer understands an exact `sts:AssumeRole` plus a matching trust, and an exact `service:<name>.amazonaws.com` trust. Those records are checked against the hand-built fixture verdicts. `collect_live_account` refuses to run and does not call AWS.

Raw ChatGPT exports are not part of this repository. Curated project documents live in `docs/`. Labels in those documents still mean what `docs/00_STATUS_AND_TRUTH_MODEL.md` says: **Verified**, **Accepted decision**, **Proposed**, **Reported/unverified**, and **Rejected/corrected**.

Real AWS analysis is the intended next target, with product-foundation work first.
An explicit [connection preflight](docs/20_AWS_CONNECTION_SECURITY.md) now requires
a named profile and expected account, blocks root/mismatched identities, and
performs two bounded IAM read probes. It is not account collection or policy
analysis. MCPO integration remains unverified. Ordinary API and preview paths do
not invoke the preflight or contact AWS.

Coding agents should start with [AGENTS.md](AGENTS.md). The optional [ECC skill map](docs/16_ECC_SKILL_WORKFLOW.md) lists the project-local Cursor skills and how to use them without overriding this project's evidence and approval boundaries; the full native Codex plugin is a separate per-user installation.

## What this slice does

- Validates Proposed v0.1 models for `ApprovedRule`, `IAMGraphSnapshot`, `AttackPath`, `VerificationResult`, and `Finding`.
- Matches only `approved` rules against derived graph edges.
- Searches with bounded breadth-first search: hop limit, cycle prevention, deterministic ordering, deduplication, path-count limit, expansion limit, and timeout.
- Returns local verdicts: `supported_by_fixture`, `denied_by_fixture`, `inconclusive`, and `error`.
- Writes each finding from the rule, hop policy refs, and fixture gaps. Simulator status stays `not_run` and sandbox status stays `not_mapped`.
- Exposes `GET /health`, `POST /v1/rules/intake`, `POST /v1/rules/approval`, `GET /v1/datasets/cloud-techniques`, `GET /v1/datasets/opportunities`, `GET /v1/datasets/source-catalog`, `POST /v1/analyses`, `GET /v1/fixtures`, `POST /v1/analyses/fixtures/{case_id}`, `POST /v1/analyses/synthetic`, `GET /v1/experiments/local-fixtures`, `GET /reviews`, `GET /reviews/experiment`, `GET /reviews/datasets/cloud-techniques`, `GET /reviews/datasets/opportunities`, `GET /reviews/rules/{artifact_id}`, and `GET /reviews/fixtures/{case_id}`.
- Records a permissions boundary as `HAS_BOUNDARY` and reports which policy layers were read. An unevaluated boundary does not become an allow.
- Loads one pinned technique file and proposes a pending rule. The intake route does not approve a rule and does not fetch a URL.

`supported_by_fixture` means the synthetic graph and supplied fixture context matched a rule. It is not AWS IAM Policy Simulator output, not a sandbox run, and not proof of exploitability.

## What this slice does not do

- Engine 2 live AWS collection or Neo4j persistence. A twelve-action read-only policy template is tested and not attached.
- IAM policy-document evaluation, including condition-key logic. A condition value of `"true"` is not treated as satisfied unless fixture context says so.
- A general-purpose CTI parser, a live ATT&CK download, or an LLM rule writer. The legacy intake path pins one local technique; the separate foundry uses the three pinned extracts described above.
- Policy simulation, CloudGoat, remediation, or any AWS write.

Contract additions used by the slice are **Proposed** and recorded in [ADR-004](docs/decisions/ADR-004-local-fixture-vertical-slice.md) and [ADR-005](docs/decisions/ADR-005-local-cti-intake.md). ADRs 001-003 remain **Proposed** for team acceptance.

## Repository location

The Git root is this directory, beside the raw chat-export folder. A `project/` directory inside that export folder would put the virtual environment on a very long Windows path, so the implementation root is `threat-intel-iam-attack-path-verifier` instead.

## Layout

```text
src/fyp_iam/contracts/    portable models
src/fyp_iam/engine1/      pinned technique intake and human approval export
src/fyp_iam/engine2/      synthetic IAM records, coverage, live-collection refusal
src/fyp_iam/engine3/      matching, bounded search, fixture verification
src/fyp_iam/engine4/      baseline finding text and priority
src/fyp_iam/api/          FastAPI boundary
tests/fixtures/           synthetic cases
```

`engine1` loads a pinned local technique and does not fetch ATT&CK. Engine 2 normalizes local records and does not call AWS.

## Commands

Python 3.12 is required (`requires-python` is `>=3.12,<3.13`).

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe scripts\write_synthetic_fixtures.py
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format .
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\python.exe -m uvicorn fyp_iam.api.app:app
.\scripts\check.ps1
```

`scripts/check.ps1` runs Ruff, mypy, generated consumer-contract checks,
non-PostgreSQL pytest, frontend tests and build. Quality types, the quality
fixture and verifier types must match their provider schemas; stale/missing
artifacts fail without being overwritten. Regenerate to stdout with
`scripts/quality_contract_types.py` (optionally `--fixture` or `--verifier`),
then review the diff before replacing the corresponding generated artifact.
It isolates database URL selectors for routine checks. `-BackendOnly` skips the
frontend; `-IncludePostgres` requires an explicitly opted-in disposable loopback
database and does not migrate or seed it. Marked database test bodies have the
same fail-closed target gate. See ADR-011 and the foundation runbook.

The checked-in fixtures are the six cases `positive`, `hard_negative`, `explicit_deny`, `condition_dependent`, `cyclic`, and `missing_context`. Regenerate them with `scripts/write_synthetic_fixtures.py` after changing `src/fyp_iam/fixtures/cases.py`. A contract test fails if the JSON drifts from the builders.

## Workbench persistence

PostgreSQL is the workbench store. SQLAlchemy, Psycopg, and Alembic are the implementation. The application talks to Postgres through `FYP_DATABASE_URL`. Supabase is the shared host for that database. The Python package does not import a Supabase client. Copy `.env.example` to `.env` and set the variables there. Do not commit `.env`.

The FYP Supabase database was migrated from Alembic `20261003_0004` through `20261009_0012` on 2026-10-09. Migrations `0009`–`0012` are the Engine 2 collection shell, normalized inventory, observed graph, and snapshot-purge tables. A read-only AWS normalizer can build a redacted in-memory preview. A synthetic writer can store a handoff in an opted-in disposable loopback database. The real-account writer reuses those same tables and refuses any database that is not that disposable loopback, so the shared Supabase project is not the test target. Saving a real-account snapshot there, and proving the digest roundtrip, is still open. Supabase Auth is the chosen analyst identity direction. Login is not enabled. Review and IT export stay local.

- `FYP_DATABASE_URL` is the application URL. Use a direct host, or a session pooler on port 5432. Do not use port 6543.
- `FYP_MIGRATION_DATABASE_URL` is optional. Alembic uses it when it is set.
- `FYP_DATABASE_DIRECT_URL` and `FYP_DATABASE_SESSION_URL` are an optional pair. When both are set, the API prefers the direct URL if IPv6 can reach it, and otherwise the session URL.
- `FYP_DATABASE_SSLROOTCERT` is an optional CA file. When it is set, connections use `sslmode=verify-full`.
- Commands, from the repository root: `python -m fyp_iam.persistence check`, `python -m fyp_iam.persistence migrate`, `python -m fyp_iam.persistence seed`, and `python -m fyp_iam.persistence verify-restart`.
- `GET /health` reports `database` as `not_configured`, `connecting`, `available`, `migration_required`, or `unavailable`. The detail is a short code. Connection strings are not returned.
- With no database, `POST /v1/workbench/imports/{pin_id}` and `POST /v1/foundry/runs` return 503 `database_unavailable` and write nothing.
- `compose.yaml` is for a machine with Docker. It reads `FYP_POSTGRES_PASSWORD` from the environment and does not contain a password.
- The React screen is `frontend/`. It calls FastAPI. It does not open a database connection.
- GitHub Actions job `postgres` migrates its own PostgreSQL service and runs the tests marked `postgres`. That job does not use a managed-host secret. Local `pytest` skips that mark when `FYP_DATABASE_URL` is unset.

## Safety

- No credentials, account IDs, raw ARNs, or raw policy documents belong in Git or fixtures.
- Live AWS access stays read-only. Ordinary fixture/API/preview paths do not call
  AWS; only the explicit operator preflight performs the three allowlisted probes.
- Remediation proposals always require human review.
- Rule text is data. Relationship types are an allowlist, not executable queries.
- Do not provision CloudGoat or vulnerable resources from this checkout.

License: not yet selected.
