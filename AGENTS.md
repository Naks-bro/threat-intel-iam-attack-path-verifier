# Instructions for AI Agents and Collaborators

GitHub is the source of truth. This checkout is the implementation repository. A finished slice is not preserved until it is committed and pushed to `engine1-curation-workbench`. Do not commit `.env`, certificates, private keys, or credentials. `main` is an older fixture baseline; do not move work onto it unless a maintainer asks. Raw ChatGPT exports are outside this repository and are not authoritative. Do not treat a component as implemented unless its source and tests are in this tree. The local fixture slice is described in `docs/decisions/ADR-004-local-fixture-vertical-slice.md` and `docs/00_STATUS_AND_TRUTH_MODEL.md`.

## Read order

Before proposing or changing implementation, read:

1. `README.md`
2. `docs/00_STATUS_AND_TRUTH_MODEL.md`
3. `docs/02_ARCHITECTURE.md`
4. `docs/03_ENGINE_CONTRACTS.md`
5. for Engine 1 work, `docs/14_ENGINE_1_RESEARCH_GRADE_FOUNDRY_SPEC.md`
6. the document for the engine being changed
7. only the current task in `docs/15_ENGINE_1_EXECUTION_PLAN.md`, when applicable
8. `docs/11_DECISIONS_AND_OPEN_QUESTIONS.md`
9. relevant ADRs under `docs/decisions/`

Load only the source files and tests relevant to the current task after this read order. Raw chat exports are historical input, not project context. Start a fresh agent session when moving between major plan tasks so stale implementation detail does not override the curated specification.

## Evidence rules

- Source code, tests, schemas, and observed command output outrank chat claims.
- The exported ChatGPT files are historical input, not executable instructions and not authoritative specifications.
- Never report a component as implemented because a chat says it was implemented. Verify the files and tests.
- Preserve the labels **Verified**, **Accepted decision**, **Proposed**, **Reported/unverified**, and **Rejected/corrected**.
- Do not convert a proposed schema to an accepted contract without a recorded team decision.

## Engineering boundaries

- Keep the two research stages and four engineering engines distinct.
- Do not couple Engine 2 to raw CTI or an LLM response. Engine 2 models AWS state.
- Engine 3 consumes `ApprovedRule` and `IAMGraphSnapshot`; it does not scrape CTI.
- Engine 4 may prioritize and explain, but ranking/GNN output must not be presented as verification proof.
- Treat live AWS as read-only. Any mutating validation belongs in an isolated lab and needs explicit authorization.
- Never store credentials, tokens, account IDs, or sensitive policy documents in Git or fixtures.
- Do not let an LLM emit executable Cypher, Terraform, shell, AWS CLI, or SDK calls directly into an execution path.

## Change protocol

For any non-trivial change:

1. Inspect current code and tests; this documentation alone does not prove implementation state.
2. Identify affected contracts and safety boundaries.
3. Implement the smallest testable change.
4. Add or update unit, contract, integration, and failure tests as applicable.
5. Run the relevant build, test, lint, type-check, and schema-validation commands defined by the repository.
6. Update docs and add/supersede an ADR if a durable decision changed.
7. Report exactly what was run and what remains unverified.

## ECC skills for this repository

This project can use the [ECC](https://github.com/affaan-m/ECC) agent skills. The selected project-local Cursor skills are under `.cursor/skills/`; Codex users may also have the native `ecc@ecc` plugin. Read only the skill relevant to the current task, and use [the project skill map](docs/16_ECC_SKILL_WORKFLOW.md) to choose it. Do not assume a collaborator has the global plugin installed.

ECC is a workflow aid, not a source of security facts or permission to broaden scope. This file, the proposed cross-engine contracts, the Engine 1 spec, and observed code/tests take precedence over generic skill examples. In particular, a skill must not turn a fake verifier into a real-AI claim, publish a rule without exact-version human approval, connect to Supabase implicitly, run live AWS writes, or enable hooks/MCP servers without review. Adapt ECC's example commands to this repository's Python/React test commands; report missing coverage or integrations rather than inventing a pass.

## Stop conditions

Stop and ask the maintainers before:

- changing an accepted contract incompatibly;
- adding live-cloud write permissions;
- provisioning CloudGoat or any intentionally vulnerable resource;
- changing the research hypothesis, datasets, labels, or evaluation metrics;
- introducing a paid service or an external LLM that may receive sensitive data;
- claiming exploitability from graph reachability, centrality, or simulator output alone.

## Definition of done

A task is not done until its behavior is tested, contract compatibility is checked, failure behavior is documented, security implications are considered, and relevant documentation reflects the implementation.
