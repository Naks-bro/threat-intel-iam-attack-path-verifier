# ADR-002: Human Approval and Read-Only Live AWS

## Status

Proposed

## Date

2026-10-02

## Context

Generated rules and remediation can be wrong. IAM changes can cause outages or privilege escalation. Sandbox validation intentionally creates vulnerable resources.

## Decision

- A candidate rule cannot become active without a recorded human decision.
- The production/target AWS collector uses read-only least privilege.
- The system does not auto-remediate.
- Mutating verification is permitted only in an isolated, explicitly authorized, disposable lab with cleanup controls.

## Alternatives considered

- Fully automated rule activation: rejected because model and extraction errors can propagate directly into findings.
- Auto-remediation: rejected from initial scope because of operational and security risk.
- Testing against the target account: rejected because verification could modify or expose real resources.

## Consequences

- Approval and audit records are first-class data.
- Demonstrations need fixtures and a dedicated sandbox account.
- Findings may remain inconclusive when safe evidence is unavailable.

