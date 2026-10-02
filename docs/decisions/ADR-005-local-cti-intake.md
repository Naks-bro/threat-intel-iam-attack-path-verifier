# ADR-005: Local CTI intake for one pinned technique

## Status

Proposed. The behavior below is implemented and covered by tests in this checkout. It does not accept a new cross-engine contract.

## Date

2026-10-02

## Context

`docs/04_ENGINE_1_CTI_RULES.md` asks for one source fixture, one proposed rule, a human review, and an `ApprovedRule v0.1` export before any broader connector exists. The chats report a multi-source parser. That parser is not in this tree and stays **Reported/unverified**.

The local verification slice already evaluates a two-hop `CAN_ASSUME` rule. Engine 1 should produce that same structural pattern from a pinned technique id, without fetching ATT&CK and without a model call.

## Decision

- Store one curated JSON pin per technique under `src/fyp_iam/engine1/artifacts/`. The pin cites `https://attack.mitre.org/techniques/T1548/` and is not downloaded at runtime.
- Accept an artifact only when its SHA-256 matches a hash constant in code, its reference is `https://attack.mitre.org/techniques/Tdddd/`, and its text has no credential, markup, or command marker.
- Treat the excerpt as evidence. The structural rule comes from a code allowlist keyed by framework and technique id.
- Map `mitre-attack` / `T1548` to the existing two-hop assume-chain pattern with `role_trusts_service` for `lambda.amazonaws.com`. Unmapped ids normalize as not AWS/IAM relevant and are not proposed.
- `POST /v1/rules/intake` returns a `proposed` rule with approval `pending`. It has no URL field and cannot mark a rule approved.
- `GET /reviews/rules/{artifact_id}` displays that pending rule. `POST /v1/rules/approval` is the only request that can export it, and only when the decision is `approved`.
- Export an `ApprovedRule` only from `export_approved_rule` after an `approved` event whose scope is `synthetic-benchmark`. A rejected event raises and returns no rule.
- `fetch_remote_source` always raises. This slice does not import an HTTP or AWS client.

## Alternatives considered

- Fetching the ATT&CK STIX bundle: deferred. The first slice has to parse with no network access.
- Copying the excerpt into the rule title or description: rejected. Source text would then become the rule.
- Approving inside the intake endpoint: rejected. Human approval stays a separate audited event.

## Consequences

- Engine 3 can consume the exported rule against the existing positive fixture. The verdict remains `supported_by_fixture`.
- A later STIX or catalog adapter must keep this fail-closed path and must not replace the pin check with an unauthenticated download.
- Accepting this ADR is still a team decision.
