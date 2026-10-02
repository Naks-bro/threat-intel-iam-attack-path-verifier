# ADR-001: Two Research Stages and Four Engineering Engines

## Status

Proposed

## Date

2026-10-02

## Context

The synopsis describes two stages, while team discussions divide work among four engines. Treating these as competing architectures creates unclear ownership and inconsistent diagrams.

## Decision

Keep the two-stage academic framing and implement it through four engineering engines:

- Stage 1: Engine 1, CTI to human-approved IAM rules.
- Stage 2: Engine 2 IAM graph, Engine 3 path verification, and Engine 4 prioritization/explanation/UI/evaluation.

## Alternatives considered

- Two monolithic implementation stages: simpler diagram, but poor parallel ownership and integration risk.
- Four independent projects: permits ownership but breaks end-to-end traceability.

## Consequences

- Reports can use the approved two-stage methodology.
- Team members own coherent engines.
- Versioned contracts are required at engine boundaries.
- Engine 4 is more than a frontend but cannot override Engine 3 evidence states.

