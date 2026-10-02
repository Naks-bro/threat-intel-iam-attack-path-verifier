# Human-Approved, Threat-Intelligence-Driven Rule Generation with Explainable Cloud IAM Attack-Path Verification

This repository is the implementation checkout for the final-year project. It currently contains one local vertical slice:

```text
ApprovedRule fixture + IAMGraphSnapshot fixture
  -> rule matching
  -> bounded breadth-first path discovery
  -> VerificationResult
  -> evidence-grounded Finding
```

The slice runs on synthetic JSON fixtures. It does not need AWS credentials, Neo4j, Redis, PostgreSQL, an LLM API, or CloudGoat.

Raw ChatGPT exports are not part of this repository. Curated project documents live in `docs/`. Labels in those documents still mean what `docs/00_STATUS_AND_TRUTH_MODEL.md` says: **Verified**, **Accepted decision**, **Proposed**, **Reported/unverified**, and **Rejected/corrected**.

## What this slice does

- Validates Proposed v0.1 models for `ApprovedRule`, `IAMGraphSnapshot`, `AttackPath`, `VerificationResult`, and `Finding`.
- Matches only `approved` rules against derived graph edges.
- Searches with bounded breadth-first search: hop limit, cycle prevention, deterministic ordering, deduplication, path-count limit, expansion limit, and timeout.
- Returns local verdicts: `supported_by_fixture`, `denied_by_fixture`, `inconclusive`, and `error`.
- Exposes `GET /health`, `POST /v1/analyses`, `GET /v1/fixtures`, and `POST /v1/analyses/fixtures/{case_id}`.

`supported_by_fixture` means the synthetic graph and supplied fixture context matched a rule. It is not AWS IAM Policy Simulator output, not a sandbox run, and not proof of exploitability.

## What this slice does not do

- Engine 1 CTI ingestion and rule generation.
- Engine 2 live AWS collection or Neo4j persistence.
- IAM policy-document evaluation, including condition-key logic. A condition value of `"true"` is not treated as satisfied unless fixture context says so.
- Policy simulation, CloudGoat, remediation, or any AWS write.

Contract additions used by the slice are **Proposed** and recorded in [ADR-004](docs/decisions/ADR-004-local-fixture-vertical-slice.md). ADRs 001–003 remain **Proposed** for team acceptance.

## Repository location

The Git root is this directory, beside the raw chat-export folder. A `project/` directory inside that export folder would put the virtual environment on a very long Windows path, so the implementation root is `threat-intel-iam-attack-path-verifier` instead.

## Layout

```text
src/fyp_iam/contracts/    portable models
src/fyp_iam/engine3/      matching, bounded search, fixture verification
src/fyp_iam/engine4/      baseline finding text and priority
src/fyp_iam/api/          FastAPI boundary
tests/fixtures/           synthetic cases
```

`engine1` and `engine2` are package boundaries only.

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
