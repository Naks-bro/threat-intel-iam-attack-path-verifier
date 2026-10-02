# Roadmap and Team Plan

## Strategy

Build one narrow vertical slice before adding breadth. Parallel work is enabled through shared contract fixtures, not by waiting for upstream engines to finish.

## Phase 0 — Recover and establish the repository

- Locate the reported Engine 1 prototype, if it exists.
- Inventory code, tests, licenses, dependencies, secrets, and generated artifacts.
- Choose a supported Python version based on dependencies; do not assume the reported Python 3.14 environment is suitable.
- Add reproducible dependency management and local commands.
- Add secret scanning, `.env.example`, and a safe test configuration.
- Accept ADRs 001–003 and assign named owners.

Exit: a clean checkout can run a minimal test command and all unverified legacy code is classified.

## Phase 1 — Contract-first fixtures

Owners: all four members.

- Review and accept/revise `ApprovedRule v0.1`, `IAMGraphSnapshot v0.1`, `AttackPath v0.1`, and `VerificationResult v0.1`.
- Select one privilege-escalation pattern.
- Create a positive graph fixture, hard negative, condition-dependent case, explicit-deny case, cycle, and missing-context case.
- Add JSON Schema/Pydantic validation and consumer contract tests.

Exit: Engines 1–4 can work against the same versioned fixtures.

## Phase 2 — First end-to-end vertical slice

### Member 1 / Engine 1

- Pin one official source artifact.
- Normalize one relevant technique.
- produce a constrained rule candidate with evidence.
- implement approval and export one accepted fixture.

### Member 2 / Engine 2

- build the portable IAM graph from synthetic AWS records;
- import it into Neo4j;
- validate identity, edge, and policy provenance.

### Member 3 / Engine 3

- match the accepted rule;
- discover the expected bounded path;
- evaluate deterministic policy fixtures;
- produce a verification result without sandbox execution.

### Member 4 / Engine 4

- display rule, path, evidence, status, gaps, and remediation;
- calculate a transparent baseline priority;
- produce the first reproducible experiment manifest.

Exit: one local command or documented sequence demonstrates the whole data lineage using fixtures.

## Phase 3 — Controlled AWS integration

- Create a dedicated lab account and least-privilege read-only collector policy.
- Collect only the services/policy layers needed by the first rule.
- Compare the live snapshot to the synthetic expectation.
- Integrate IAM Policy Simulator with explicit context and limitation reporting.
- Add cost, throttling, retry, pagination, and failure tests.

Exit: an authorized lab account can be analyzed read-only and results remain reproducible.

## Phase 4 — Mapped sandbox evidence

- Select an existing CloudGoat scenario that maps to the rule, or document why a custom scenario is required.
- Threat-model provisioning, execution, and teardown.
- Add explicit enablement, account allowlist, region restrictions, budget alert, and cleanup verification.
- Run only with guide/account-owner approval.

Exit: one path has recorded sandbox evidence and successful teardown; unsupported paths remain `not_mapped`.

## Phase 5 — Breadth and experiments

- Add a small set of rules and fixtures covering distinct escalation categories.
- Add AWS TTC and curated OWASP inputs only through tested adapters.
- Benchmark traversal bounds and ranking features.
- Run extraction, detection, verification, explanation, runtime, and reviewer studies.
- Decide whether Redis, GDS centrality, or a GNN has demonstrated value.

## Phase 6 — Finalization

- Freeze dataset and code revisions for reported results.
- Re-run from a clean environment.
- Complete limitations, ethics, threat model, and reproducibility appendix.
- Verify every citation and remove unsupported novelty claims.
- Produce demo script, failure fallback, architecture diagram, and artifact manifest.

## Dependency policy

| Change | Owner can decide | Discuss with affected engines | Team/guide approval |
|---|:---:|:---:|:---:|
| Internal parser/query/UI refactor | Yes |  |  |
| Additive optional contract field |  | Yes |  |
| Breaking contract/schema semantics |  |  | Yes |
| New paid/hosted service |  |  | Yes |
| Live AWS permission expansion |  |  | Yes |
| Sandbox provisioning/exploitation |  |  | Yes |
| Research labels/metrics/dataset split |  |  | Yes |

## Weekly integration rhythm

- Each member maintains fixtures and contract tests.
- Merge only when shared contract tests pass.
- Demonstrate a thin integrated flow weekly.
- Record decisions and rejected alternatives immediately.
- Report blockers as evidence gaps, not vague “AI issues.”

