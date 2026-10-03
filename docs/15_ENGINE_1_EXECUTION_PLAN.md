# Engine 1 Execution Plan

## Purpose

This is the implementation plan for `14_ENGINE_1_RESEARCH_GRADE_FOUNDRY_SPEC.md`. It is written for humans and coding agents. Each task is a small vertical slice with explicit dependencies, likely files, acceptance criteria, and verification.

Do not execute all tasks in one giant agent conversation or commit. “Single plan” means one source of truth, not one uncontrolled code change.

## Assumptions

1. The selected direction is the research-grade vertical foundry with a CI-style quality gate.
2. The working branch and uncommitted Cursor/Codex changes are preserved.
3. ADR-009 remains Proposed until team review; this plan does not silently accept cross-engine contracts.
4. Three rule families are the required scope. More families are stretch work.
5. Supabase is an optional PostgreSQL host, not an SDK dependency.
6. The real-model verifier is provider-neutral and opt-in; the fake verifier remains the deterministic CI path.
7. No implementation task may claim research success before the evaluation artifacts exist.

If any assumption is rejected, update the spec and affected tasks before coding.

## Required reading and context order

Every implementation session starts with:

1. `AGENTS.md`
2. `docs/00_STATUS_AND_TRUTH_MODEL.md`
3. `docs/14_ENGINE_1_RESEARCH_GRADE_FOUNDRY_SPEC.md`
4. only the current task in this document
5. the listed source and test files for that task
6. one existing implementation pattern named by the task

Do not load the raw chat exports. Do not load every source file “just in case.” Refresh test output after each slice instead of carrying stale failures through the conversation.

## Quality commands

Run the narrow test first, then the appropriate checkpoint suite.

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\python.exe -m pytest -m "not postgres"

Push-Location frontend
npm test
npm run build
Pop-Location
```

PostgreSQL tasks additionally run the `postgres` tests against a freshly migrated disposable database. Supabase verification uses only private environment variables and never prints a connection URL.

## Dependency graph

```text
P0 Baseline and contract freeze
 ├─ P1 Rule ontology
 │   ├─ P3 Additional-credentials family hardening
 │   ├─ P4 Trust-policy-backdoor family
 │   └─ P5 Service-mediated escalation family
 ├─ P2 Evaluation artifact contracts
 │   ├─ P3, P4, P5 scenario corpora
 │   └─ P11 Experiment runner
 └─ P6 Quality-report contract
     ├─ P7 AI verifier
     ├─ P8 Review and publication
     ├─ P9 Run and dossier UI
     └─ P10 Version comparison and review UI

P3 + P4 + P5 + P7 + P8 -> P11 Evaluation
P9 + P10 + P11          -> P12 End-to-end hardening
P12                      -> P13 FYP evidence package
```

## Phase 0 — Protect the baseline

### Task P0.1: Reconcile current truth and selected scope

**Description:** Update project-facing documentation so the current foundry, the legacy intake path, and the selected three-family research scope are not confused.

**Acceptance criteria:**

- `README.md` accurately distinguishes the legacy local slice from the foundry.
- The status document reports only code and test evidence observed at that time.
- ADR-009 links to the selected spec and records that broad platform features are deferred.

**Verification:**

- Review every changed status sentence against source or command output.
- `rg -n "implemented|verified|complete|production" README.md docs` finds no unsupported claim in the edited sections.

**Dependencies:** None.

**Files likely touched:**

- `README.md`
- `docs/00_STATUS_AND_TRUTH_MODEL.md`
- `docs/decisions/ADR-009-threat-to-rule-foundry.md`

**Estimated scope:** Medium, 3 files.

### Checkpoint 0

- Working tree reviewed; unrelated user changes remain untouched.
- Documentation describes one selected direction.
- Team reviews the Proposed contract before persisted enum or API-breaking changes.

## Phase 1 — Freeze semantics and evaluation artifacts

### Task P1.1: Introduce the closed rule ontology

**Description:** Add one typed module that owns supported actions, resource selectors, preconditions, state transitions, resulting capabilities, and Engine 3 path predicates. Replace scattered string acceptance only for the first existing family.

**Acceptance criteria:**

- Unknown action, resource, precondition, or predicate values fail closed.
- The additional-credentials rule compiles to the same semantic document and hash.
- Ontology version is recorded in validation output.

**Verification:**

- Focused unit tests cover accepted and rejected vocabulary.
- Existing foundry unit tests remain green.
- Ruff and mypy pass.

**Dependencies:** P0.1.

**Files likely touched:**

- `src/fyp_iam/engine1/foundry/ontology.py` (new)
- `src/fyp_iam/engine1/foundry/compiler.py`
- `src/fyp_iam/engine1/foundry/models.py`
- `tests/unit/test_foundry_ontology.py` (new)
- `tests/unit/test_foundry.py`

**Estimated scope:** Medium, 5 files.

### Task P2.1: Define corpus and experiment artifact schemas

**Description:** Create typed, portable records for scenario cases, expected verdicts, seeded defects, reviewer tasks, and experiment manifests. These are files/contracts first, not database tables.

**Acceptance criteria:**

- Invalid case ids, duplicate scenario ids, unknown expected outcomes, and missing evidence references are rejected.
- Artifacts include schema version, dataset version, source hash, and labeling metadata.
- The existing three-scenario corpus can be represented without losing meaning.

**Verification:**

- Round-trip and invalid-fixture tests pass offline.
- JSON examples validate deterministically.
- Ruff and mypy pass.

**Dependencies:** P0.1.

**Files likely touched:**

- `src/fyp_iam/evaluation/models.py` (new)
- `src/fyp_iam/evaluation/loaders.py` (new)
- `tests/unit/test_evaluation_models.py` (new)
- `tests/fixtures/evaluation/additional_credentials.json` (new)

**Estimated scope:** Medium, 4 files.

### Checkpoint 1

- Ontology and evaluation contracts are reviewed before parallel rule-family work.
- All non-PostgreSQL Python checks pass.
- No API or migration work starts with unresolved enum conflicts.

## Phase 2 — Complete three vertical rule families

### Task P3.1: Harden the additional-credentials family

**Description:** Move the existing rule through the new ontology and expanded scenario contract. Preserve its current evidence lineage while adding missing-context and adversarial cases.

**Acceptance criteria:**

- The family has at least one positive, two near-negative, one missing-context, and one adversarial scenario.
- Every required action and precondition links to evidence or a recorded deterministic compiler decision.
- Semantic output is stable across two identical runs.

**Verification:**

- Focused compiler and corpus tests pass.
- A repeated offline run produces the same semantic hash.
- Existing PostgreSQL storage test still stores one version idempotently.

**Dependencies:** P1.1, P2.1.

**Files likely touched:**

- `src/fyp_iam/engine1/foundry/compiler.py`
- `src/fyp_iam/engine1/foundry/pipeline.py`
- `tests/fixtures/evaluation/additional_credentials.json`
- `tests/unit/test_foundry_additional_credentials.py` (new)
- `tests/integration/test_foundry_postgres.py`

**Estimated scope:** Medium, 5 files.

### Task P4.1: Add the trust-policy-backdoor family

**Description:** Implement a separate primitive and compiler template for a supported trust-policy modification. Do not mislabel it as additional role creation.

**Acceptance criteria:**

- Mapping requires explicit evidence for the policy-changing action and resulting assumption capability.
- Near-negative scenarios reject unsupported principals, missing target control, and irrelevant trust changes.
- The resulting rule is a new immutable family, not a conditional branch hidden inside the credential rule.

**Verification:**

- Focused mapping/compiler/scenario tests pass.
- The old `trust_policy_backdoor` unmapped behavior changes only when the new evidence requirements are met.
- Ruff and mypy pass.

**Dependencies:** P1.1, P2.1.

**Files likely touched:**

- `src/fyp_iam/engine1/foundry/compiler.py`
- `src/fyp_iam/engine1/foundry/adapters.py`
- `src/fyp_iam/engine1/foundry/pins/stratus-iam-redacted.json`
- `tests/fixtures/evaluation/trust_policy_backdoor.json` (new)
- `tests/unit/test_foundry_trust_policy.py` (new)

**Estimated scope:** Medium, 5 files.

### Task P5.1: Add one service-mediated role-escalation family

**Description:** Select one supported service pattern and compile the required `iam:PassRole`, service action, trust precondition, and resulting capability into a bounded rule.

**Acceptance criteria:**

- The selected service and all actions exist in pinned AWS service-reference evidence.
- The compiler rejects missing trust, wildcard assumptions that exceed the ontology, and incomplete action chains.
- The rule’s limitations state which condition/resource semantics Engine 3 cannot evaluate.

**Verification:**

- Positive, near-negative, missing-context, and adversarial cases pass expected verdicts.
- An Engine 3 contract test parses the proposed rule without treating it as approved.
- Ruff and mypy pass.

**Dependencies:** P1.1, P2.1. The exact service requires team review before fixture creation.

**Files likely touched:**

- `src/fyp_iam/engine1/foundry/compiler.py`
- `src/fyp_iam/engine1/foundry/pins/aws-service-reference-extract.json`
- `tests/fixtures/evaluation/service_mediated_role.json` (new)
- `tests/unit/test_foundry_service_mediated.py` (new)
- `tests/integration/test_api.py`

**Estimated scope:** Medium, 5 files.

### Checkpoint 2

- Three families compile independently.
- Every family has the required scenario classes.
- Engine 3 parses proposed output but receives no stable rule without approval.
- Full Python suite and PostgreSQL integration suite pass.

## Phase 3 — Make quality a first-class artifact

### Task P6.1: Add a versioned rule-quality report

**Implementation checkpoint, 2026-10-03:** locally implemented in `quality.py`, the compiler, typed rule API, and React dossier. A canonical report binds to the exact candidate/evidence, preserves optional disagreement and missing required checks, and drives schema-generated frontend types/fixtures. See `18_RULE_QUALITY_REPORT.md` for semantics and verification. P6.2 storage/history, measured timing, and the broader three-family completion gate remain open.

**Description:** Aggregate deterministic validation and corpus results into one typed report without changing publication policy yet.

**Acceptance criteria:**

- Each stage records status, version, duration, findings, and evidence references.
- Required, optional, unavailable, error, and skipped are distinguishable.
- Report computation is deterministic for frozen inputs.

**Verification:**

- Unit tests cover pass, failure, unavailable optional tool, and contradictory findings.
- API schema rejects malformed reports.
- Ruff and mypy pass.

**Dependencies:** P1.1, P2.1.

**Files likely touched:**

- `src/fyp_iam/engine1/foundry/quality.py` (new)
- `src/fyp_iam/engine1/foundry/compiler.py`
- `src/fyp_iam/api/schemas.py`
- `tests/unit/test_foundry_quality.py` (new)
- `tests/unit/test_foundry.py`

**Estimated scope:** Medium, 5 files.

### Task P6.2: Persist and expose the quality report

**2026-10-03 local verification checkpoint:** migration 0005,
immutable report/per-run observation tables, transactional writer, and bounded
latest-report reader are in the worktree. Rule detail exposes stored reports and
keeps missing reports null. New legacy validation writes use unknown/null timings
instead of row indices. Nineteen storage-boundary/route tests pass. Five PostgreSQL
integration tests passed on an isolated 17.11 cluster, including report history,
deduplication, tamper rejection, and stored API serialization. Fresh migration,
reconstructed older-schema upgrade, and actual stop/start durability passed.
P6.2's listed local acceptance/verification checks are satisfied; permanent
restart orchestration, current remote CI, and managed deployment remain broader
release work. See `18_RULE_QUALITY_REPORT.md`, `19_POSTGRES_VERIFICATION.md`, and
Proposed ADR-010. No managed database was changed.

**Description:** Store the report against the exact rule version and expose it through rule detail.

**Acceptance criteria:**

- Repeated writes are idempotent by rule version and report semantic hash.
- Historical reports remain linked to their validator/corpus versions.
- API responses never infer a pass from missing rows.

**Verification:**

- Alembic upgrade succeeds on a fresh database.
- PostgreSQL integration tests prove persistence and repeat behavior.
- API contract tests cover missing and partial reports.

**Dependencies:** P6.1.

**Files likely touched:**

- `alembic/versions/<next>_foundry_quality_reports.py` (new)
- `src/fyp_iam/engine1/foundry/models.py`
- `src/fyp_iam/engine1/foundry/store.py`
- `src/fyp_iam/api/app.py`
- `tests/integration/test_foundry_quality_postgres.py` (new)

**Estimated scope:** Medium, 5 files.

## Phase 4 — Add the bounded AI critic

### Task P7.1: Freeze the verifier interface and threat model

**Description:** Replace the fake function-shaped interface with a provider-neutral protocol, closed request/response models, citation validation, and explicit data-handling configuration. Keep the fake implementation for CI.

**Acceptance criteria:**

- The verifier receives only the candidate, selected evidence snapshot, ontology version, and prompt version.
- Output citations must resolve inside that snapshot.
- Extra fields, tool calls, executable text, invalid verdicts, and prompt-injection instructions fail closed.

**Verification:**

- Unit tests cover schema violations, bad citations, hostile evidence text, timeout, and provider error.
- Existing fake-verifier behavior remains deterministic.
- No network call occurs in the default test suite.

**Dependencies:** P6.1.

**Files likely touched:**

- `src/fyp_iam/engine1/foundry/verifier.py`
- `src/fyp_iam/engine1/foundry/verifier_models.py` (new)
- `src/fyp_iam/engine1/foundry/quality.py`
- `tests/unit/test_foundry_verifier.py` (new)
- `tests/fixtures/evaluation/ai_defects.json` (new)

**Estimated scope:** Medium, 5 files.

### Task P7.2: Add one opt-in real-model adapter and recorded evaluation

**Description:** Implement one adapter only after provider, privacy, cost, and supervisor decisions are recorded. The adapter never runs in ordinary CI.

**Acceptance criteria:**

- Missing credentials return `unavailable` without leaking configuration.
- Provider, model, prompt hash, decoding settings, response hash, latency, and estimated cost are recorded.
- Raw public evidence sent to the model is identifiable; private policy data is excluded.

**Verification:**

- Contract tests use a stub transport.
- One explicitly invoked evaluation produces a redacted manifest and metrics artifact.
- Re-running ordinary tests makes zero external requests.

**Dependencies:** P7.1 and an explicit human decision on provider/data/cost.

**Files likely touched:**

- `src/fyp_iam/engine1/foundry/providers/<provider>.py` (new)
- `src/fyp_iam/engine1/foundry/verifier.py`
- `src/fyp_iam/engine1/workbench/config.py`
- `tests/unit/test_foundry_provider.py` (new)
- `.env.example`

**Estimated scope:** Medium, 5 files.

### Checkpoint 3

- AI can criticize only.
- Fake CI and real evaluation are clearly separated.
- Injection, invalid citations, timeout, and provider failure have tests.
- No external model is enabled by default.

## Phase 5 — Complete review and publication

### Task P8.1: Implement exact-version review decisions

**Description:** Add typed review commands for approve, reject, and revision request, bound to rule version and evidence snapshot hash.

**Acceptance criteria:**

- Stale evidence or version ids produce a conflict, not a decision.
- Rejection and revision require a comment.
- Repeated identical requests are idempotent; conflicting decisions are auditable.

**Verification:**

- Unit tests cover lifecycle transitions and stale decisions.
- PostgreSQL tests verify immutable decision history.
- API tests verify typed success, validation, conflict, and unavailable responses.

**Dependencies:** P6.2.

**Files likely touched:**

- `src/fyp_iam/engine1/foundry/review.py` (new)
- `src/fyp_iam/engine1/foundry/store.py`
- `src/fyp_iam/api/schemas.py`
- `src/fyp_iam/api/app.py`
- `tests/integration/test_foundry_review_postgres.py` (new)

**Estimated scope:** Medium, 5 files.

### Task P8.2: Enforce computed publication eligibility

**Description:** Centralize experimental/stable eligibility and make Engine 3 export call that policy.

**Acceptance criteria:**

- The compiler, verifier, API, and UI cannot set `approved` directly.
- Stable export requires a passing required quality gate and approved exact version.
- Experimental export remains opt-in for Engine 3.

**Verification:**

- Matrix tests cover quality state × AI policy × human decision × channel.
- Engine 3 default excludes every experimental rule.
- Stable publication and export survive restart.

**Dependencies:** P8.1, P7.1.

**Files likely touched:**

- `src/fyp_iam/engine1/foundry/publication.py` (new)
- `src/fyp_iam/engine1/foundry/pipeline.py`
- `src/fyp_iam/engine1/foundry/store.py`
- `tests/unit/test_foundry_publication.py` (new)
- `tests/integration/test_foundry_postgres.py`

**Estimated scope:** Medium, 5 files.

## Phase 6 — Turn the GUI into a review instrument

### Task P9.1: Add pipeline-run detail to the control plane

**Description:** Let a reviewer inspect source attempts, partial failures, counters, retry ancestry, and semantic changes from one run.

**Acceptance criteria:**

- Loading, empty, partial, failure, and success states are visible.
- Sanitized failures do not expose credentials or connection strings.
- A failed connector does not visually invalidate successful connectors.

**Verification:**

- Component tests cover all states.
- API response has a typed frontend representation.
- Browser test opens one run and inspects a failed and successful source.

**Dependencies:** P6.2.

**Files likely touched:**

- `src/fyp_iam/api/schemas.py`
- `src/fyp_iam/api/app.py`
- `frontend/src/FoundryScreen.tsx`
- `frontend/src/FoundryScreen.test.tsx`
- `frontend/e2e/foundry.spec.ts`

**Estimated scope:** Medium, 5 files.

### Task P9.2: Render the complete quality dossier

**Description:** Add quality stages, scenario matrix, AI citations, limitations, and publication eligibility to the rule dossier.

**Acceptance criteria:**

- Source fact, deterministic derivation, AI opinion, and human decision have distinct labels.
- Missing/unavailable checks never appear as passes.
- Long evidence text, zero findings, partial reports, and hostile markup render safely.

**Verification:**

- Component tests cover pass, fail, unavailable, partial, and hostile content.
- Frontend tests and build pass.
- Keyboard and accessible-name checks cover interactive controls.

**Dependencies:** P6.2, P7.1, P8.2.

**Files likely touched:**

- `frontend/src/FoundryScreen.tsx`
- `frontend/src/FoundryScreen.test.tsx`
- `frontend/src/styles.css`
- `frontend/e2e/foundry.spec.ts`

**Estimated scope:** Medium, 4 files.

### Task P10.1: Add version comparison and review action

**Description:** Provide a focused diff and exact-version decision flow. Do not add authentication in this task.

**Acceptance criteria:**

- The user sees rule, evidence, compiler, corpus, prompt, and model changes.
- The confirmation identifies the exact rule version, evidence hash, scope, and decision.
- Stale submission displays the conflict and reload path without losing the reviewer comment.

**Verification:**

- API and component tests cover no prior version, changed evidence, and stale submission.
- Browser test completes a decision and confirms restart persistence.
- Frontend tests and build pass.

**Dependencies:** P8.1, P9.2.

**Files likely touched:**

- `frontend/src/RuleReview.tsx` (new)
- `frontend/src/RuleReview.test.tsx` (new)
- `frontend/src/App.tsx`
- `frontend/src/styles.css`
- `frontend/e2e/foundry-review.spec.ts` (new)

**Estimated scope:** Medium, 5 files.

### Checkpoint 4

- A reviewer can trace and decide one exact rule version without using the database directly.
- Desktop and narrow viewport browser flows pass with no console or failed-network errors.
- Approval is presented as a demo alias boundary, not authenticated identity.

## Phase 7 — Automation and research evaluation

### Task P11.1: Add a bounded pipeline command and source-diff policy

**Description:** Provide one CLI entry point for version discovery, ingestion, diff, compilation, quality evaluation, and manifest output. Scheduling remains an external invocation concern.

**Acceptance criteria:**

- Concurrent invocation is locked or rejected clearly.
- Unchanged inputs do not create duplicate semantic versions.
- Partial source failure produces a partial run and retains successful results.

**Verification:**

- Unit tests use fake transports and time.
- PostgreSQL integration tests cover first run, unchanged rerun, changed source, and partial failure.
- The command exits nonzero only for documented operational failures.

**Dependencies:** P3.1, P4.1, P5.1, P6.2.

**Files likely touched:**

- `src/fyp_iam/engine1/foundry/runner.py` (new)
- `src/fyp_iam/engine1/foundry/pipeline.py`
- `src/fyp_iam/engine1/foundry/store.py`
- `tests/unit/test_foundry_runner.py` (new)
- `tests/integration/test_foundry_runs_postgres.py` (new)

**Estimated scope:** Medium, 5 files.

### Task P11.2: Implement the experiment runner and metric export

**Description:** Run extraction, mapping, verifier, reproducibility, and reviewer-study analyses from frozen manifests.

**Acceptance criteria:**

- Train/development/test or pilot/final partitions are explicit and overlap checks fail closed.
- Metrics include counts and per-family breakdowns, not accuracy alone.
- Every output records code revision, input hashes, schema/compiler/corpus versions, and deviations.

**Verification:**

- Metric functions have hand-calculated unit cases.
- Two identical offline runs produce identical semantic metrics artifacts.
- A deliberately contaminated split is rejected.

**Dependencies:** P2.1, P3.1, P4.1, P5.1, P7.1.

**Files likely touched:**

- `src/fyp_iam/evaluation/runner.py` (new)
- `src/fyp_iam/evaluation/metrics.py` (new)
- `scripts/run_engine1_experiment.py` (new)
- `tests/unit/test_evaluation_metrics.py` (new)
- `tests/integration/test_engine1_experiment.py` (new)

**Estimated scope:** Medium, 5 files.

## Phase 8 — End-to-end hardening and handoff

### Task P12.1: Add the full CI quality gate

**Description:** Make Python, frontend, PostgreSQL migration/integration, and Playwright checks required in one reproducible workflow without using Supabase secrets.

**Acceptance criteria:**

- CI starts from an empty PostgreSQL service and applies every migration.
- It runs one pipeline, inspects a quality dossier, records a review, restarts the API, and verifies persistence.
- Failed artifacts are retained without exposing secrets.

**Verification:**

- A GitHub Actions run passes all required jobs.
- A deliberately broken migration or frontend contract fails the relevant job.

**Dependencies:** P8.2, P9.2, P10.1, P11.1.

**Files likely touched:**

- `.github/workflows/workbench.yml`
- `frontend/playwright.config.ts`
- `frontend/e2e/foundry.spec.ts`
- `frontend/e2e/foundry-review.spec.ts`
- `tests/integration/test_foundry_postgres.py`

**Estimated scope:** Medium, 5 files.

### Task P12.2: Run the private Supabase durability check

**Description:** Apply migrations and exercise the approved flow against the configured Supabase PostgreSQL project without adding Supabase-specific application code.

**Acceptance criteria:**

- Secrets exist only in the ignored `.env` or private environment.
- The private `foundry` schema is inaccessible to anonymous/authenticated API roles.
- A rule, quality report, and decision remain after API restart.

**Verification:**

- `python -m fyp_iam.persistence check`, `migrate`, and `verify-restart` succeed.
- Database URLs and passwords do not appear in logs, screenshots, Git diff, or artifacts.

**Dependencies:** P12.1. This is an operational verification task and should not change product code unless it reveals a defect.

**Files likely touched:** None normally; verification evidence only.

**Estimated scope:** Small.

### Task P13.1: Produce the FYP evidence package

**Description:** Freeze the evaluated artifacts and update the report-facing documentation with claims supported by actual runs.

**Acceptance criteria:**

- The package contains anonymized fixtures, manifests, metrics, expected outputs, exact commands, limitations, and claim-to-evidence links.
- Proposed, Verified, and unverified items remain visibly distinct.
- Novelty and accuracy claims stay within the measured dataset.

**Verification:**

- A fresh clone can reproduce the offline experiment from documented commands.
- All cited artifact hashes resolve.
- A teammate who did not implement Engine 1 can explain one rule’s complete lineage.

**Dependencies:** P11.2, P12.1, completed evaluation runs.

**Files likely touched:**

- `docs/00_STATUS_AND_TRUTH_MODEL.md`
- `docs/04_ENGINE_1_CTI_RULES.md`
- `docs/09_RESEARCH_AND_EVALUATION.md`
- `README.md`
- `artifacts/engine1/<frozen-run>/manifest.json` (new, if redistribution permits)

**Estimated scope:** Medium, 5 files.

### Final checkpoint

- Three rule families complete the same quality lifecycle.
- Stable publication and Engine 3 policy are proven end to end.
- CI and private PostgreSQL durability checks pass.
- Research metrics are reproducible and bounded.
- The GUI supports the reviewer task rather than hiding uncertainty.
- The repository contains no credential or sensitive AWS material.

## Parallel work plan

After Checkpoint 1:

- **Lane A:** P3.1 additional credentials.
- **Lane B:** P4.1 trust-policy backdoor.
- **Lane C:** P5.1 service-mediated escalation after service selection.
- **Lane D:** P6.1 quality-report contract.

After P6.2:

- **Lane A:** P7.1 verifier.
- **Lane B:** P8.1 review service.
- **Lane C:** P9.1 run-detail UI against the frozen API schema.
- **Lane D:** P11.2 metric functions against frozen evaluation models.

Rules for parallel lanes:

- Freeze shared models and API responses before parallel implementation.
- One owner at a time edits `compiler.py`, `store.py`, `api/app.py`, or `FoundryScreen.tsx`.
- Each lane uses a separate branch or managed worktree.
- Do not copy migrations between branches; assign migration ownership.
- Merge foundation tasks before feature tasks that consume them.

## Agent context packets

Use one packet per task. Replace bracketed values; do not paste the entire plan into every session.

```text
PROJECT: AWS IAM Threat-to-Rule Foundry
TASK: [task id and exact title]
OUTCOME: [one sentence from the task description]

READ IN ORDER:
1. AGENTS.md
2. docs/00_STATUS_AND_TRUTH_MODEL.md
3. relevant section of docs/14_ENGINE_1_RESEARCH_GRADE_FOUNDRY_SPEC.md
4. task [id] in docs/15_ENGINE_1_EXECUTION_PLAN.md
5. [listed implementation files]
6. [listed test files]

TRUST ORDER:
Observed code/tests/commands > curated docs > ADR proposals > chat history.

BOUNDARIES:
- Preserve unrelated dirty-worktree changes.
- AI may verify but never author, approve, publish, or execute a rule.
- No live AWS writes, arbitrary fetches, executable generated content, or secrets.
- Supabase is PostgreSQL hosting only.
- Do not broaden scope beyond this task.

DELIVERABLE:
- Implement only task [id].
- Add the listed failure-path tests.
- Run narrow verification, then the task checkpoint commands.
- Update docs only if observed truth changed.
- Report changed files, commands, outputs, and anything unverified.

STOP IF:
- a persisted enum or cross-engine contract needs incompatible change;
- a new external service or sensitive-data flow is required;
- the task needs more than five implementation files;
- repository behavior contradicts the specification.
```

## Starter prompt for Cursor or another coding agent

```text
Work only on Task P0.1 from docs/15_ENGINE_1_EXECUTION_PLAN.md.

First read AGENTS.md, docs/00_STATUS_AND_TRUTH_MODEL.md,
docs/14_ENGINE_1_RESEARCH_GRADE_FOUNDRY_SPEC.md, Task P0.1, README.md,
and docs/decisions/ADR-009-threat-to-rule-foundry.md. Inspect git status and preserve
all unrelated uncommitted changes. Source code, tests, schemas, and observed command
output outrank chat claims.

Goal: reconcile project-facing documentation so the legacy local intake slice, the
implemented foundry slice, and the selected three-family research scope are clearly
separated. Do not change application code. Do not claim a feature is implemented
without repository evidence. Keep ADR-009 Proposed. After editing, inspect the diff
and run the verification listed in P0.1. Report exact files changed, evidence used,
and any claim that remains unverified. Stop if existing uncommitted edits overlap in
a way that would overwrite another agent's work.
```

After P0.1 is reviewed, start a fresh session for P1.1. Do not ask an agent to “build the whole foundry” in one prompt.

## Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Rule semantics are unsupported by primary evidence | High | Closed ontology, evidence links, negative mappings, human review |
| Platform breadth consumes evaluation time | High | Three required families; stretch work blocked until final checkpoint |
| AI output is mistaken for truth | High | Critic-only contract, citation validation, fake CI, exact-version approval |
| Small or contaminated dataset inflates metrics | High | Frozen manifests, split-overlap checks, counts, per-family reporting |
| Shared files create agent merge conflicts | Medium | Task ownership, worktrees, frozen contracts, one owner per hotspot |
| Supabase becomes accidental vendor coupling | Medium | SQLAlchemy/Psycopg/Alembic boundary and CI PostgreSQL service |
| UI polish hides incomplete semantics | Medium | Quality dossier exposes unknown, unavailable, disagreement, limitations |
| External source changes break reproducibility | Medium | Pinned raw artifacts, hashes, parser versions, offline evaluation |
| Reviewer alias is represented as authenticated identity | Medium | Explicit demo boundary; no security claim without authentication |
| Real-model evaluation leaks data or cost | High | Public evidence only, opt-in configuration, human provider decision |

## Open decisions with owners

These do not block P0.1, P1.1, P2.1, P3.1, P6.1, or P7.1.

| Decision | Needed before | Owner/evidence |
|---|---|---|
| Exact service-mediated escalation pattern | P5.1 | Engine 1 + Engine 3 owners; AWS service-reference evidence |
| Final rule ontology v0.1 | Checkpoint 1 | Engine 1 owner and team contract review |
| Real AI provider, data policy, and budget | P7.2 | Team/supervisor; provider terms and cost cap |
| Stable approval scope vocabulary | P8.1 | Team and academic reviewer |
| Final gold-set size and reviewer availability | Evaluation freeze | Research lead after pilot labeling |
| Whether authentication is future work | Final report | Team; not required for current slice |

## Definition of plan completion

This plan is complete when every task is either verified complete, explicitly deferred with rationale, or rejected through a recorded decision; every checkpoint has evidence; and the final repository truth documents match observed code and experiments.
