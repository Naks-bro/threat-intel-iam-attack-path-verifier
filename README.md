# Human-Approved, Threat-Intelligence-Driven Rule Generation with Explainable Cloud IAM Attack-Path Verification

This repository is the implementation checkout for the final-year project. It currently contains one local vertical slice:

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
- A multi-source CTI parser, a live ATT&CK download, or an LLM rule writer. Engine 1 currently pins one local technique file.
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

## Safety

- No credentials, account IDs, raw ARNs, or raw policy documents belong in Git or fixtures.
- Live AWS access stays read-only, and this slice does not call AWS at all.
- Remediation proposals always require human review.
- Rule text is data. Relationship types are an allowlist, not executable queries.
- Do not provision CloudGoat or vulnerable resources from this checkout.

License: not yet selected.
