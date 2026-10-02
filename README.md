# Human-Approved, Threat-Intelligence-Driven Rule Generation with Explainable Cloud IAM Attack-Path Verification

This folder contains the curated project baseline derived from the raw ChatGPT exports that sit beside this file. The project proposes an AWS-focused research prototype that converts selected cyber-threat intelligence (CTI) into reviewable IAM misconfiguration rules, applies only human-approved rules to a model of an AWS IAM environment, discovers candidate privilege-escalation paths, and produces evidence-backed findings for human review.

This is a defensive research project. The baseline excludes autonomous changes to live AWS environments and treats sandbox execution as an optional, scenario-bounded validation method—not universal proof of exploitability.

## Start here

1. [Project status and evidence model](docs/00_STATUS_AND_TRUTH_MODEL.md)
2. [Project charter](docs/01_PROJECT_CHARTER.md)
3. [Architecture](docs/02_ARCHITECTURE.md)
4. [Cross-engine contracts](docs/03_ENGINE_CONTRACTS.md)
5. [Roadmap and team plan](docs/08_ROADMAP_AND_TEAM_PLAN.md)
6. [Decisions and open questions](docs/11_DECISIONS_AND_OPEN_QUESTIONS.md)
7. [Source register](docs/12_SOURCE_REGISTER.md)

AI coding tools must also read [AGENTS.md](AGENTS.md).

## Current reality

- The raw folder contains conversation exports only; no application source, test suite, dependency manifest, Docker configuration, or database schema was found here.
- Conversations report that an Engine 1 parser prototype exists elsewhere, but that claim cannot be verified from this folder.
- The architecture and contracts in these docs are an implementation-ready baseline, not evidence of completed code.
- Exact schemas are marked **Proposed v0.1** until the team records acceptance.
- The literature review in the chats contains incomplete and potentially incorrect citations. Do not submit it academically without checking each paper and bibliographic field.

## Project shape

The synopsis is easiest to explain as two research stages, implemented through four engineering engines:

```text
Stage 1: rule curation
  Engine 1: CTI -> proposed IAM rule -> explanation -> human approval

Stage 2: detection, verification, and presentation
  Engine 2: AWS read-only collection -> normalized IAM graph
  Engine 3: approved rules + IAM graph -> candidate paths -> verification evidence
  Engine 4: risk prioritization -> explanation -> UI -> research evaluation
```

## Non-negotiable boundaries

- AWS-only for the first demonstrable version.
- Read-only access to the live AWS target account.
- No LLM-generated Cypher or executable cloud commands are accepted without deterministic validation.
- No candidate rule becomes active without human approval.
- A policy-simulator `Allowed` result is not proof that an exploit succeeds.
- CloudGoat runs only in a dedicated, disposable account or lab with explicit authorization and cleanup controls.
- Every rule and finding retains provenance, schema version, timestamps, and evidence references.

## Documentation maintenance

These are living documents. When code contradicts a document, stop and resolve the discrepancy; do not silently assume either side is correct. Update the relevant document and add or supersede an ADR in `docs/decisions/` whenever a cross-engine contract, safety boundary, major dependency, or research method changes.

