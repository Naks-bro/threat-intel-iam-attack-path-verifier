# ADR-017: Individual Supabase Auth identities for real-account review

**Status:** Identity-provider direction accepted by the user, 2026-10-09.
Role matrix, enrollment, retention, migrations, and deployment remain proposed.

## Decision and boundary

Real-account rule approval and finding-to-IT handoff will identify the human
analyst through an **individual Supabase Auth account**. A caller-supplied alias,
browser label, or the existing loopback review mode is not authenticated
identity. This choice does not authorize creating users, changing Supabase Auth
settings, granting database privileges, applying migrations, or enabling
real-account publication/export today.

The React client may obtain a user session from Supabase Auth, but it must not
receive the application database URL or a service-role credential. The FastAPI
backend remains the only application writer to private `foundry` data. Before a
real-account decision, the backend must verify the bearer session and bind the
trusted issuer and subject to an active `analyst_actors` row. It must check a
server-controlled application role/assignment on every approval and export,
not trust user-editable metadata or a submitted `actor_id`. The precise
verification method, role matrix, and session-revocation behavior are an
implementation decision to test before enabling the route. Supabase documents
the difference between permanent and anonymous users and cautions against
using user-editable metadata for authorization in its [user model](https://supabase.com/docs/guides/auth/users).

An accepted analyst decision remains append-only and bound to the exact
finding, explanation, evidence, coverage, rule release, and account snapshot.
The export transaction must re-evaluate role eligibility and those bindings;
authentication alone is never approval. Synthetic benchmark aliases remain
separate and cannot authorize a real-account IT report. The proposed table
shape and gate are in [schema v0.1](../24_WHOLE_PRODUCT_SCHEMA_PROPOSAL.md#engine-4--explanations-research-and-exports).

## Required acceptance evidence before enabling real-account review

1. Individual non-anonymous team accounts, enrollment/deactivation owner, and
   an explicit reviewer/exporter role matrix approved by the team.
2. Backend tests for missing, expired, wrong-issuer, wrong-audience, anonymous,
   disabled, and insufficient-role sessions; no caller-controlled actor alias.
3. A reviewed additive migration for `analyst_actors` and exact-version
   append-only review/export tables, rehearsed against a disposable copy of
   the existing 0004 database after 0005–0008 reconciliation.
4. Tests that a changed explanation/evidence/coverage or newer rejection makes
   an old acceptance stale; export remains idempotent and writes no AWS state.
5. A privacy/retention decision for actor identifiers, account evidence, and
   generated IT reports, plus a verified `foundry` grant/RLS posture.

Until all gates pass, real-account review and IT export stay disabled. Auth UI
alone would not satisfy this ADR. Supabase describes JWT verification and
custom claims in its [JWT documentation](https://supabase.com/docs/guides/auth/jwts)
and [RBAC guide](https://supabase.com/docs/guides/api/custom-claims-and-role-based-access-control-rbac);
those are implementation references, not proof this repository has integrated
either feature.

## Local implementation checkpoint — identity only

`src/fyp_iam/api/analyst_identity.py` now has a backend-only resolver for an
individual Supabase Auth session. It calls the configured project's
`GET /auth/v1/user` over HTTPS with a **modern publishable key** and the
presented bearer token, rejects redirects, bounds response size/time, rejects
anonymous or malformed user records, and returns only the provider issuer and
opaque subject. It never reads caller-supplied roles, email, or user metadata
as authority. This follows Supabase's [Auth-server verification guidance](https://supabase.com/docs/guides/auth/jwts#verifying-with-a-shared-secret-signing-key),
which also supports projects using a legacy symmetric signing key. The
installed FYP project has a modern publishable key available; its value was
not printed or stored in this repository.

The resolver is **not wired to a public route**, frontend sign-in, actor table,
role authorization, or review/export transaction. Tests mock Auth responses;
no live human token was supplied or verified. A resolved identity is not an
`analyst_actors` row or permission to approve anything.
