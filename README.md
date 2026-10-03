# Human-Approved, Threat-Intelligence-Driven Rule Generation with Explainable Cloud IAM Attack-Path Verification

This repository is the implementation checkout for the final-year project. It currently contains one local vertical slice:

Engine 1 also has an experimental evidence foundry in `src/fyp_iam/engine1/foundry/` and a React control plane in `frontend/`. It ingests three pinned extracts (MITRE ATT&CK, AWS Service Authorization Reference, and redacted Stratus metadata), derives three attack primitives, and compiles one additional-credentials candidate. The candidate remains experimental. The AWS Threat Technique Catalog entry is disabled until a stable versioned input exists. The foundry has a closed vocabulary for the first rule family and a six-case pinned scenario corpus; the other two planned rule families, a real AI critic, and stable publication remain open. See `docs/14_ENGINE_1_RESEARCH_GRADE_FOUNDRY_SPEC.md` and `docs/00_STATUS_AND_TRUTH_MODEL.md` for the boundary between the current code and planned work.

An opt-in verifier result must bind to the exact candidate version and evidence snapshot and cite known evidence IDs. Malformed or unbound results move to `needs_review` and cannot publish experimentally. No external model provider is configured or called in ordinary runs.

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

The preview also exposes a [version-bound quality report](docs/18_RULE_QUALITY_REPORT.md), with an integrity hash, validator/corpus versions, explicit missing checks, and nullable timings. Frontend types and its test fixture are generated from the backend contract. Historical database rows do not yet have persisted reports; the UI labels those reports unavailable. A passing deterministic report is not human approval or stable publication.

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

`scripts/check.ps1` runs Ruff, mypy, and pytest.

The checked-in fixtures are the six cases `positive`, `hard_negative`, `explicit_deny`, `condition_dependent`, `cyclic`, and `missing_context`. Regenerate them with `scripts/write_synthetic_fixtures.py` after changing `src/fyp_iam/fixtures/cases.py`. A contract test fails if the JSON drifts from the builders.

## Workbench persistence

PostgreSQL is the workbench store. SQLAlchemy, Psycopg, and Alembic are the implementation. A managed host such as Supabase is optional and is not imported by the application. Copy `.env.example` to `.env` and set the variables there. Do not commit `.env`.

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
- Live AWS access stays read-only, and this slice does not call AWS at all.
- Remediation proposals always require human review.
- Rule text is data. Relationship types are an allowlist, not executable queries.
- Do not provision CloudGoat or vulnerable resources from this checkout.

License: not yet selected.
