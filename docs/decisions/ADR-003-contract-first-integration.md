# ADR-003: Contract-First Integration

## Status

Proposed

## Date

2026-10-02

## Context

Four owners need to work in parallel even when upstream engines are incomplete. The chats repeatedly identify interface drift as a major risk.

## Decision

Use versioned portable contracts and shared fixtures for `ApprovedRule`, `IAMGraphSnapshot`, `AttackPath`, `VerificationResult`, and `Finding`. Internal storage and implementation may change without breaking consumers. Breaking changes require a new major contract version and migration plan.

## Alternatives considered

- Shared database tables across engines: rejected because it couples internal persistence and makes ownership unclear.
- Wait for each upstream engine: rejected because it serializes the project schedule.
- Pass raw LLM/source/AWS data downstream: rejected because formats are unstable and unsafe.

## Consequences

- Every engine needs contract tests.
- Synthetic fixtures unblock parallel development.
- Data lineage and reproducibility improve.
- Initial schema design work is required before feature implementation.

