# Version-bound rule-quality report

Status: **Implemented and locally verified for the credential-family compiler and preview API. PostgreSQL report persistence is not implemented.** The contract is a local proposed addition, not team acceptance of the broader cross-engine contracts.

## Purpose and authority

Task P6.1 in [the execution plan](15_ENGINE_1_EXECUTION_PLAN.md) makes deterministic quality an inspectable artifact. The canonical contract is `QualityReport` in `src/fyp_iam/engine1/foundry/quality.py`; its Pydantic schema drives the generated frontend types. The compiler creates it after deterministic and optional-tool results. It never approves or publishes a rule.

The preview rule API includes `quality_report`. After migration 0005, new persisted runs write a report and rule detail reads the latest stored observation. Historical versions with no report remain null; the portal shows “Versioned quality report unavailable.” It does not manufacture a passing report from counts or old rows. Live storage and restart verification passed on isolated PostgreSQL 17.11; managed deployment remains unverified.

## Bound identity

The report includes an opaque rule-version ID, the rule semantic hash, and the evidence-snapshot hash. Its SHA-256 identity covers the schema/report versions, bindings, normalized stages, findings, scenarios, and computed summary. Stages are ordered by unique stage ID and scenarios by scenario ID. A changed binding, validator/corpus version, finding, or outcome changes report identity. The API rejects a report that does not match the surrounding rule version/hash; the UI also refuses to render that mismatch as assurance.

`duration_ms` is nullable and excluded from semantic identity. An actual measurement can differ between identical computations without creating a new semantic report. The current checks do not measure per-validator runtime, so the report shows null / “Not measured.” A duration cannot be negative, boolean, or a coerced numeric string. This is an integrity hash, not a signature or authenticated reviewer identity.

The earlier validation-row writer stored its enumeration index in `duration_ms`. Historical values are not measured runtime and must not be used for experiments. Migration 0005 permits null and the writer now uses null, without rewriting historical rows. Semantic artifacts normalize timings to null; separate run observations preserve actual measurements when supplied. See [ADR-010](decisions/ADR-010-quality-artifacts-and-observations.md).

Evidence IDs attached to a quality stage identify its scoped candidate inputs. They do not constitute independent proof that every source entails every rule field. Field-level evidence coverage and independent research labeling remain separate requirements.

## Status policy

| Condition | Report status |
|---|---|
| A required check fails or errors | `fail` |
| A required check is missing, skipped, or unavailable | `incomplete` |
| Required checks pass but an optional tool fails or errors | `needs_review` |
| Required checks pass, with no optional disagreement | `pass` |

Unavailable optional tools remain listed and counted even when the deterministic report passes. Required-check names cannot be waived into optional scope. Missing required results become explicit skipped stages with a finding. Duplicate validator rows are rejected rather than silently overwriting disagreement. An empty “passing” scenario corpus or a passing aggregate containing a failed/mismatched scenario becomes failure. Unknown statuses, forged summaries/identities, malformed bindings, and contradictory passing stages fail schema validation.

This report currently covers ten checks and the six credential-family cases. It is not the complete three-family quality gate, a real AI opinion, human approval, or proof of exploitability. Task P6.1 does not change the publication policy; P8.2 will require a stored quality report and exact-version approval as part of centralized stable eligibility.

## Consumer contract and fixtures

`scripts/quality_contract_types.py` has no network access, arbitrary reference resolution, or file writes. It derives TypeScript from the quality model's local schema definitions and prints the reviewed output. Its `--fixture` mode creates a contract-valid incomplete report from the pinned compiler by omitting the ontology check, then recomputing the report. Tests use this fixture instead of inventing a payload that cannot pass the provider contract.

```powershell
.\.venv\Scripts\python.exe scripts/quality_contract_types.py --check
.\.venv\Scripts\python.exe scripts/quality_contract_types.py --fixture --check
```

Both checks run in pytest, so stale generated consumer types or fixtures fail the repository test suite. The generator supports this bounded schema; unsupported schema constructs fail rather than silently becoming `any`.

## Verification evidence

ECC `contract-first` and `python-testing` shaped the canonical model, schema-derived consumer artifacts, and test-first invariants. The existing React/accessibility skills shaped the visible nullable state, binding error, and keyboard-operable metadata disclosure.

RED evidence: tests initially could not import the missing quality module or render the missing panel. A subsequent runtime test proved the rule-response schema accepted a report bound to a different surrounding rule version; it failed with “DID NOT RAISE.” The binding validator now rejects that mismatch. The first live browser attempt encountered a duplicate text selector after the new report repeated an existing summary; the selector was scoped and the behavior reverified.

Backend tests cover determinism, version/evidence binding, required failure/error/unavailability/absence, optional disagreement, contradictory and empty corpus results, malformed/forged artifacts, invalid timing, duplicate checks, API output, nullable compatibility, and generated-contract freshness. Frontend tests cover report absence, exact binding and metadata, and mismatch refusal. Live Edge testing opens the report, expands all 14 stage metadata entries, confirms unknown timings and ontology version, recomputes preview, and checks every page for overflow at 320/768/1024/1440px. The rendered report screenshot was inspected.

At the P6.1 checkpoint, remaining verification included live PostgreSQL persistence/restart and report history; the later P6.2 checks below supersede those gaps. Measured runtime, automated accessibility auditing, coverage measurement (the `coverage` package is absent), and production deployment/security controls remain open. The preview API was restarted for P6.1; no managed database or credentials were changed. That checkpoint was local and uncommitted at the time; inspect current Git history before assuming its commit state.

Final local checkpoint: 181 non-PostgreSQL tests passed (two PostgreSQL tests deselected), 16 frontend tests passed, three Edge browser flows passed, the frontend production build passed, mypy passed 67 source files, Ruff lint/format passed, and `git diff --check` passed. One existing Starlette/httpx deprecation warning remains. These are local checks, not a current remote CI or production-readiness claim.

## P6.2 implementation checkpoint

`quality_store.py` now validates exact rule-version/hash binding before inserts,
writes immutable artifacts and per-run observations in the caller's transaction,
and reads the latest indexed observation. Missing data returns null; malformed
content or inconsistent artifact metadata is rejected. Rule detail translates
that rejection to a sanitized database-unavailable response, not a passing report.
Validator/corpus versions remain inside immutable report JSON.

ECC migration guidance shaped additive frozen DDL and archival rollback policy;
the Python/TDD skills shaped tests for binding, corruption, timing separation,
missing rows, and SQL generation. RED was the missing `quality_store` module.
`tests/unit/test_foundry_quality_storage.py` now has 19 cases, including the
null and incomplete route contracts. No coverage percentage is claimed.

The initial attempt to run two additional PostgreSQL tests skipped because no
disposable database was configured. A later isolated PostgreSQL 17.11 run passed
all five database tests, including the added stored API test and tamper rejection.
Quality integration tests accept only a loopback `fyp_iam` database and roll back
deliberate partial-report writes. Fresh migration, reconstructed old-schema
upgrade, and actual restart durability also passed. P6.2's local checks are now
satisfied; managed deployment and current remote CI remain unverified. See
[the database evidence](19_POSTGRES_VERIFICATION.md).

Local regression checkpoint after this storage change: 198 non-PostgreSQL tests
passed, four PostgreSQL tests deselected; 16 frontend tests and the frontend build
passed; mypy passed 68 source files; Ruff lint/format and diff whitespace checks
passed. The existing Starlette/httpx warning remains. No browser test was rerun
for this backend-only storage change, and SQL-generation tests are not live
migration evidence.

Latest storage/route test count is 19, including real non-preview API serialization
with a mocked repository for null and incomplete reports. These contract tests do
not replace the separately passing live database checks. The earlier 17-test and
skipped-database checkpoint above records the initial state, not the final result.
