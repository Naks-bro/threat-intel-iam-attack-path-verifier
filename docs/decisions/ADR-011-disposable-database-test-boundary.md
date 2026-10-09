# ADR-011: Separate routine checks from disposable database tests

## Status

Proposed. The safety gate and check scripts are implemented and locally tested;
this does not accept or alter cross-engine contracts.

## Date

2026-10-03

## Context

The application may use a managed PostgreSQL database. Existing integration
tests write rows and change test roles. A configured application URL must not
silently make a routine project check mutate that database. The user wants a
strong product foundation without accidental cloud writes or spending.

## Decision

Routine checks isolate their database URL environment and select non-PostgreSQL
tests. Explicit database checks require an operator opt-in, a literal loopback
target named `fyp_iam`, matching endpoint selectors, and no query/libpq overrides.
A pytest autouse gate refuses unsafe marked test bodies without printing URLs.
CI migration and reset steps check the same gate against their ephemeral service.
The local container binds only to loopback. Setup never migrates or seeds.

## Alternatives and consequences

- A warning-only guard was rejected: warnings do not prevent destructive test code.
- Reusing Supabase for CI was rejected: CI owns a disposable local service.
- Silently changing credentials or creating a managed test project was rejected.
- Loopback and the opt-in flag cannot prove that a proxy's backend is disposable;
  the operator must verify isolation. Missing configuration is not a database pass.
- Manual migrations outside these test workflows remain explicit operator actions.
- The guard is tested offline; the changed remote CI workflow still needs execution.
