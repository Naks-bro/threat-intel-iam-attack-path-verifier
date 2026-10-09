# Schema-first delivery gates and AWS snapshot handoff

**Status: PROPOSED / not authorization to migrate.** 2026-10-09. This is the implementation sequence for the [IAM analyst refocus](25_IAM_ANALYST_REFOCUS_PLAN.md), not a replacement for the [full schema specification](24_WHOLE_PRODUCT_SCHEMA_PROPOSAL.md). The teammate building AWS snapshot collection owns that implementation; this document defines the boundary they can build against without coupling to portal work.

## Gate 0 — what is actually there

The live Alembic revision was read-only rechecked on 2026-10-09 and remains `20261003_0004`. No teammate-produced AWS snapshot or inventory manifest was present in the repository at this check; only checked-in synthetic fixtures and the proposed metadata contract were found. This is a repository observation, not a claim about the teammate's separate workspace.

Read-only inspection of the existing **FYP** Supabase project on 2026-10-09 found PostgreSQL 17.11, `foundry.alembic_version = 20261003_0004`, 21 application tables plus `alembic_version`, and no application tables in `public`. The repository now has eleven sequential Alembic revisions through locally authored `20261009_0011`; revisions 0005–0011 are **not applied** on the managed database. The Supabase migration list is empty because it is not the Alembic ledger. The private repo `.env` contains the `FYP_DATABASE_URL` key; no value was displayed. The process environment did not set that variable directly. These facts were checked read-only; they do not imply application database connectivity or a successful upgrade. Compare with the prior [schema audit](23_SCHEMA_CURRENT_STATE_AUDIT.md), which found the same revision on 2026-10-08.

Supabase flags all 22 `foundry` tables as having RLS disabled. A separate privilege check found `anon` and `authenticated` have **no `USAGE` on `foundry` and no table grants**. Therefore this check does **not** support the advisory's stronger claim that browser roles can currently read/write every row. RLS being off is still a real defense-in-depth and future-exposure concern, especially before storing AWS data. Current design: private backend-only PostgreSQL access; do not put the database URL or service-role key in the React app. Grant/RLS posture must be rechecked for each new table and whenever Data API exposure changes. Supabase documents that grants determine reachability and RLS policies determine row access ([Securing your API](https://supabase.com/docs/guides/api/securing-your-api)).

**Read-only reconfirmation, 2026-10-09:** a fresh catalog query returned revision
`20261003_0004`, 22 `foundry` tables including `alembic_version`, a primary
key on every table, zero RLS-enabled tables, and zero tables with `SELECT`
privilege for either `anon` or `authenticated`. Per-table counts of foreign
keys, unique constraints, checks, and indexes were inspected and remain
consistent with the 0004 inventory in [the current-state audit](23_SCHEMA_CURRENT_STATE_AUDIT.md).
This does not prove policy-content safety, backend role scoping, or readiness
for real-account retention. No DDL, DML, or migration was run.

A further read-only connector check on 2026-10-09 again found revision 0004,
22 `foundry` tables, zero RLS-enabled tables and zero browser-role `SELECT`
grants. The repository's direct `schema_audit` now reports those three aggregate
security-posture counts alongside its catalog fingerprint when a direct
connection succeeds. Its `available` status still means only that the model
table/column inventory matches the repository head; it is **not** a security
approval or proof that constraints, indexes and policy content are safe.

**Do not run the following now.** This is the blanket RLS remediation for existing `foundry` tables, provided for security review only. Enabling it without an access-policy/role plan may break non-owner readers; RLS also does not substitute for revoked grants or backend authentication. Approve an exact role matrix, test on a disposable copy, then choose whether to apply this or keep the private-schema boundary:

```sql
DO $$
DECLARE target_table record;
BEGIN
  FOR target_table IN
    SELECT schemaname, tablename
    FROM pg_tables
    WHERE schemaname = 'foundry'
  LOOP
    EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY',
                   target_table.schemaname, target_table.tablename);
  END LOOP;
END $$;
```

## Gate 1 — decisions before DDL or real-account retention

| Decision | Recommended default | Effect if not approved |
|---|---|---|
| Boundary | One FYP project, one authorized AWS sandbox account, private backend-only DB; no direct Supabase client in browser. | Do not implement tenant/browser RLS or claim tenant isolation. |
| Snapshot evidence | **Chosen design default, 2026-10-09:** at most 90 days of redacted, bounded IAM policy/topology with stable keyed fingerprints; never access-key values, session tokens, or raw account IDs. See [ADR-018](decisions/ADR-018-redacted-aws-snapshot-retention.md). | Collector field list, purge/backups, and account-owner consent are still required before importing real data. |
| Approval identity | **Accepted direction, 2026-10-09:** individual Supabase Auth accounts identify analysts; the backend must verify sessions and consult an application-controlled role/assignment before real-account rule release or finding handoff. Local alias stays benchmark-only. See [ADR-017](decisions/ADR-017-supabase-auth-analyst-identity.md). | Until authentication, roles, and the review/export transaction are implemented and tested, real-account publication/approved handoff remains disabled. Read-only collection may be demonstrated as observation only. |
| Effective permission | Explicit `unknown` whenever required layers/conditions were not collected or evaluated. | Do not describe graph reachability as an effective allow or exploit. |
| **Selected first journey and topology** | [ADR-016](decisions/ADR-016-two-identity-iam-pilot.md): two starting identities, one exposed and one control, in one authorized project/account and one sealed snapshot; investigate one at a time and compare on a two-row overview. Additional credentials is the proposed first family. | Whole-account posture and the academic minimum number of rule families remain open; this choice does not approve AWS writes or retention. |

These defaults align with the proposed [whole-product schema](24_WHOLE_PRODUCT_SCHEMA_PROPOSAL.md#decisions-requiring-human-approval-priority-order); they are not accepted decisions. The user/team must choose before retaining real account records or applying schema changes.

## Gate 2 — reconcile old migrations on a disposable database

1. Preserve the current dirty worktree and existing Supabase data. Record the live 0004 schema fingerprint, grants, counts, and migration head again immediately before deployment. No credential values or sensitive rows in logs.
   The read-only command `python -m fyp_iam.persistence.schema_audit` reports a `foundry` DDL fingerprint, revision, table count, table/column-name drift and shared-column nullability mismatches against current ORM metadata. It starts a read-only transaction and prints fixed error codes, never the URL or application rows. A current revision with missing or unexpected tables/columns or changed nullability is classified `migration_required`; this is **not** full ORM conformance (types, constraints, indexes, grants and RLS still require separate comparison) or a migration command. On this machine on 2026-10-09 its direct application connection returned `unreachable`; the live facts above came from the Supabase connector, not this command.
2. Review the historical migration problem: `0002` invokes current Engine 1 `Base.metadata.create_all`, so a fresh install may create 0005–0008 tables early. Engine 2 0009 uses separate metadata to avoid extending that behavior. Compare a fresh disposable install with a **sanitized** 0004→0009 upgrade, including constraints, indexes, grants, and data preservation. Do not edit a deployed historical migration casually.
3. Prove 0005→0009 on the disposable target first. Verify quality reports, verifier packets, scoped reviews, stable releases and the empty Engine 2 shell exist as intended. Legacy `publications` remain experimental; never backfill a real approval or release from them.
4. Rehearse backup/recovery and a forward-fix path. The rollback for archival tables is not `DROP` or destructive reset. Only after the team approves the exact diff should the operator schedule managed migration.

### Disposable migration comparison — 2026-10-09

`scripts/rehearse_migrations.py` created a new private PostgreSQL 17.11 loopback cluster using the previously retained portable runtime. It did not load the project `.env` or connect to Supabase. One empty database went directly to Alembic head `20261007_0008`; a second empty database stopped at `20261003_0004` before upgrading to the same head. Their reflected `foundry` catalogs matched, with 27 tables each including `alembic_version`. The one-time initialization password file was removed and `pg_ctl status` confirmed the owned cluster was stopped. This verifies that both **empty-cluster paths** converge at the current code revision. The stopped test data and log remain in the tool-reported temporary directory for diagnosis.

**Observed-boundary follow-up, 2026-10-09:** read-only Supabase SQL rechecked PostgreSQL 17.11, revision 0004, 21 application tables plus `alembic_version` (158 columns total). Against the current ORM, the only missing tables are `quality_reports`, `quality_observations`, `verifier_packets`, `scoped_reviews`, and `stable_releases`; all 21 shared application tables have the same column *names*. `validation_runs.duration_ms` is NOT NULL on Supabase. The rehearsal was rerun in a newly owned cluster after reconstructing precisely those five absences and that nullability at the disposable 0004 boundary (asserting each removed test table was empty, with no `CASCADE`). The reconstructed 0004 had 22 tables, and its upgrade again matched the fresh 0008 catalog at 27 tables. The temporary server was confirmed stopped and its initialization password file removed. This narrows the known 0002/current-metadata discrepancy; it does **not** prove constraints, indexes, grants, RLS, or populated rows match live 0004.

**Synthetic populated-row follow-up:** read-only counts on the live 0004 database found 13 validation runs, one legacy experimental publication, one rule version, one candidate, four sources, and eight audit events (no raw rows were read). In another newly owned cluster, the reconstructed 0004 database was seeded with five synthetic legacy records: candidate, rule version, validation run with non-null duration, unscoped review, and experimental publication. Their serialized database rows remained exactly equal after 0005–0008; `scoped_reviews` and `stable_releases` stayed empty, so no scoped approval or stable release was inferred. The fresh and upgraded 27-table catalogs still matched. The one-time password file was removed and `pg_ctl status` confirmed the cluster stopped. This is representative regression evidence, not proof that every live row survives or that application-level export is ready.

**Locally authored 0009 follow-up:** `20261009_0009` adds six empty private
Engine 2 shell tables: connections, runs, ordered tasks, snapshot seals,
complete layer-coverage declarations and coverage
gaps. It adds no policy body or AWS credential storage. A new disposable
PostgreSQL 17.11 rehearsal reached 0009 both fresh and from the reconstructed
0004 boundary with five seeded synthetic legacy rows; both catalogs matched at
33 tables including `alembic_version`. The five legacy rows were byte-for-byte
unchanged, no scoped review/stable release was inferred, and the six Engine 2
tables were empty with RLS enabled. New tables have explicit PUBLIC/anon/
authenticated revocations and no browser policies. The owned server was
confirmed stopped and its one-time password file removed. This does **not**
prove a live 0004 copy, production grants/locks, collector correctness, purge,
or that 0009 is approved for Supabase.

The same disposable rehearsal also exercised three boundary constraints in
rolled-back synthetic transactions: identical snapshot content may occur in
different collection runs, a real-account snapshot with an expiry beyond 90
days is rejected, a coverage gap cannot cite a task from another run,
coverage cannot claim authorization evaluation, and task sequence numbers
cannot be duplicated within a run.
These checks do not implement the scheduled purge or prove that a collector
reported complete coverage truthfully.
The proposed handoff-to-0009 compatibility bridge additionally rejects a
successful task without a response digest, unknown task principal, duplicate
task attempt and registered-account fingerprint mismatch. Its synthetic plan
inserted successfully on both disposable upgrade paths and was rolled back;
the inserted snapshot's whole-handoff digest and seven layer rows were read
back. The whole-handoff digest binds task order and the declared coverage,
while the inventory content digest remains separate.
This is metadata-only preparation, not a database importer or an AWS snapshot.

**Locally authored 0010 follow-up:** `20261009_0010` adds nine redacted,
snapshot-scoped IAM inventory tables for principals, policies, identity/trust
statements, attachments, memberships, group traversal and typed principal
references. It stores bounded action/condition arrays, not raw policy JSON,
credentials or ARNs. The pure importer plan maps all nine record types and
rechecks the 0009 handoff binding. Sequence numbers preserve the original
order of all hashed inventory lists, child references and coverage declarations.
A synthetic-only transaction writer commits one handoff on an opted-in
disposable loopback database. Its readback reconstructs the exact handoff,
recomputes both digests, covers all nine inventory row types (including group
traversal and trust references), and projects the same observed-only graph.
It rejects a modified statement digest or duplicate request. The graph still
reports incomplete source coverage and no authorization evaluation. The writer
refuses real-account input
and has no API route; no live AWS collector or managed importer exists.
Fresh and reconstructed-0004 disposable paths matched at 42 tables including
`alembic_version`; all 15 Engine 2 tables were empty with RLS enabled, and
the five synthetic legacy rows were unchanged. Rolled-back constraint probes
rejected cross-snapshot attachment/resource links. This is **not** a live
database copy, production grant/lock proof, or approval to apply 0010.

**Locally authored 0011 follow-up:** `20261009_0011` drafts four private
observed-graph tables: projection seal, nodes, direct edges, and exact policy/
statement evidence anchors. Principal and policy nodes have snapshot-scoped FKs
to the normalized inventory; edges have snapshot-scoped endpoint FKs; evidence
cannot cite a source from another snapshot. The DDL rejects `CAN_*` capability
edges and fixes `authorization_evaluated=false`. A fresh and a reconstructed-
0004 disposable PostgreSQL 17.11 path both reached 0011 with matching
46-table catalogs, 19 empty RLS-enabled Engine 2/graph tables, and five
unchanged synthetic legacy rows. Rolled-back probes rejected a phantom
principal node, a cross-snapshot edge, a capability edge, and cross-snapshot
policy evidence. A subsequent schema-first check added bounded
`incomplete_reason_codes` to the still-unapplied projection table; otherwise
its proposed digest could not be reproduced from stored rows. A pure
handoff-to-graph row mapper now checks exact inventory/handoff hashes and
produces only observed relationships with policy/trust anchors. A new owned
disposable fresh/reconstructed-0004 rehearsal matched at 46 tables and kept
five synthetic legacy rows intact after that draft change. A later disposable
rehearsal exercised an opt-in synthetic writer that inserts the exact handoff
and observed graph in one transaction. Its reader reprojects the stored
handoff and compares every graph row; an altered edge is rejected. **No
real-account graph writer, permission resolver, or managed migration exists.**
The projection-digest binding is application-validated, not a database-enforced
equality to the snapshot row; that remains a review gate before an importer
can seal a graph.

This comparison is **not** a sanitized copy of the live Supabase 0004 database. Both paths execute historical migration 0002's current-ORM `create_all`; the second path then repairs only the observed table/column-nullability boundary in its owned disposable copy. Populated-row preservation, live constraints/indexes/grants/RLS, backup/restore, and production-scale locks remain unverified. A managed migration still requires the Gate 1 decisions, a copy-based rehearsal, and explicit review; this script must never be pointed at a managed database.

The repo's PostgreSQL integration tests are guarded for an **opted-in disposable loopback** database; never point those tests at Supabase. See [product runbook](21_PRODUCT_FOUNDATION_RUNBOOK.md#database-setup-and-tests-are-separate-workflows) and [test guard](../src/fyp_iam/persistence/test_guard.py). No setup script implicitly migrates the managed project.

## Gate 3 — first additive schema tranche (Engine 2 boundary)

Keep `foundry` and existing IDs; choose exact DDL only after Gate 1. Split migrations so a failure is diagnosable and the portal can remain on fixtures while the collector is developed. The full table-by-table constraints, privacy classification and later engines are in [schema v0.1](24_WHOLE_PRODUCT_SCHEMA_PROPOSAL.md#table-specification); this is the **minimum build order**, not a second competing schema.

| Proposed tranche | Minimum invariant | Writer → reader |
|---|---|---|
| `account_connections`, `collection_runs`, `collection_tasks` | Opaque IDs; request-id uniqueness/idempotency; allowlisted account fingerprint/profile reference only; bounded state machine (`queued → running → succeeded/partial/failed`); per-principal HMAC scope key, pagination completion and sanitized response digest for group traversal; sanitized error codes; no secrets. | Backend collector → operations/API. |
| `account_snapshots`, `collection_layer_coverage`, `coverage_gaps` | Exactly one source run, `data_kind` (`synthetic` or `real_account_observed`), separate inventory and whole-handoff digests, collector/contract version, sealed time, immutable status and all seven declared policy layers plus scoped gaps. A partial run may seal a partial snapshot with gaps; failure cannot masquerade as complete. | Collector → normalizer/analyst. |
| `iam_principals`, `iam_policies`, `iam_identity_statements`, `iam_statement_resource_refs`, `iam_attachments`, `iam_memberships`, `iam_group_traversals`, `iam_trust_statements`, `iam_trust_principal_refs` | **0010 drafted locally:** every key and FK is snapshot-scoped; stable redacted/fingerprinted keys; policy version and statement/source digest; typed effect/action/resource/condition and bounded SQL arrays for parsed patterns/keys. Unsupported semantics remain explicit. `policy_layer_context` is later, not part of 0010. | Collector → graph resolver/analyst. |
| `graph_projections`, `graph_nodes`, `graph_edges`, `edge_policy_evidence` | **0011 drafted locally:** snapshot-scoped observed graph and source FKs, with direct configuration relationships only. Derived capability edges and effective-authorization claims require a later reviewed schema/contract. | Normalizer → future Engine 3/portal. |

**Indexes/constraints at minimum:** FKs on snapshot/run/release links; unique `(snapshot_id, stable_key)` for principals/policies/nodes and `(run_id, task_kind, attempt)` for collection tasks; indexes on `(connection_id, started_at DESC)`, `(snapshot_id, node_type)`, `(snapshot_id, source_node_id)`, and evidence lookup keys; checks for status vocabulary, non-negative counts, bounded payload size, terminal timestamp, and SHA-256 digest shape. Use a database transaction to seal a snapshot only after all required rows/coverage are written. No arbitrary JSONB GIN index until a real query justifies it.

**Migration order:** existing 0005–0008 on a disposable copy → **locally authored, unapplied** 0009 collection/run/snapshot shell → **locally authored, unapplied** 0010 normalized IAM inventory → **locally authored, unapplied** 0011 observed graph/evidence. Each migration is additive; application readers stay disabled/fixture-backed until the corresponding writer/contract tests pass. Derived capability edges, Engine 3 analysis and Engine 4 finding/export tables from schema v0.1 follow in later reviewed migrations. No managed migration has been approved or applied.

## Teammate contract — AWS snapshot producer → portal/graph consumer

The snapshot teammate can proceed **without waiting for portal redesign** by delivering a versioned, sanitized manifest and a redacted replay fixture in their own files. The proposed, tested metadata-only [CollectionManifest contract](../src/fyp_iam/contracts/collection.py) and separate [inventory handoff contract](27_AWS_INVENTORY_HANDOFF_CONTRACT.md) specify the boundary; neither is a collector or evidence-storage implementation. Validate raw AWS responses at ingress; never commit live payloads. The handoff should provide:

| Field / behavior | Required meaning |
|---|---|
| `contract_version`, `collector_version`, `run_id`, `snapshot_id` | Stable version/identity for reproducibility. IDs are opaque and not AWS account IDs. |
| `account_alias`, `account_fingerprint`, `data_kind` | Display alias and keyed fingerprint only; mark `real_account_observed` vs `synthetic`. No ARN/account ID exposed in logs or frontend payload by default. |
| `started_at`, `sealed_at`, `status`, `content_digest` | UTC, monotonic state, canonical digest after seal; no mutation after seal. |
| `tasks[]` | Operation name, optional pseudonymous subject principal and response digest, attempt, outcome (`succeeded`, `partial`, `denied`, `throttled`, `failed`), count, sanitized code, pagination completeness. A real-account `complete` per-user group traversal must match exactly one successful, fully paginated `iam:ListGroupsForUser` task for that user by count and digest. |
| `coverage[]` | Each relevant policy layer: `collected`, `absent`, `partial`, `not_collected`, or `unavailable`, plus a reason where incomplete. Absence means the layer was actually checked, not merely omitted. All layers carry `authorization_evaluated=false`; evaluation belongs to a later engine. |
| Separate `InventorySnapshot`: `principals[]`, `policies[]`, `statements[]`, `attachments[]`, `memberships[]`, `trust_statements[]` | These are **not fields of `CollectionManifest`**. The proposed typed envelope has snapshot-scoped opaque keys, version refs, bounded normalized evidence and source digests. The same snapshot must include both starting identities and required target objects. The collector must not label an identity “vulnerable” or “secure.” Missing policy versions, unparseable conditions and non-IAM layers become coverage gaps. |
| failure behavior | A failed/partial run cannot create a complete snapshot or an effective-allow verdict. Retry uses a new run/attempt linked to the old one; no in-place overwrite of a sealed snapshot. |

**Please hand back to this team:** the exact manifest schema/Pydantic type, redaction rules, read API allowlist and permissions, a smallest representative synthetic/replayed sample, tests for pagination/denial/throttling/partial coverage, and a list of IAM semantics the collector did *not* evaluate. Do not send credentials or actual account identifiers in chat. The existing [synthetic record model](../src/fyp_iam/engine2/records.py) is *not* a live AWS-response contract; integration should adapt into a new typed boundary rather than relabeling it.

## Gate 4 onward — backend and portal, slice by slice

1. **Contract first:** define request/response models for `collection run`, `snapshot summary`, `identity investigation`, `path`, `what-if`, and `handoff`. Additive fields only; stable machine-readable errors; paginated lists. Generated frontend types and provider-contract tests stay in sync. No API surface should imply `verified` where evidence is only inferred.
2. **Engine 3:** pin exact eligible rule release + immutable snapshot + analyzer version; bound search and persist candidate/denied/unknown outcomes with hop policy evidence. Real-account release remains blocked until authenticated review decision is made.
3. **Portal:** replace the foundry-first landing with an analyst-first journey, but preserve old deep links during transition. Signature UI element is a *branch ledger*: graph branch on one side, synchronized evidence/unknown/control table on the other. Monochrome with textual status; no animation on repeated navigation/keyboard actions. Use the existing React 19/Vite stack, not a parallel frontend.
4. **Operations:** write structured run/analysis events with correlation IDs, bounded status/error codes, source/task failure counts and duration histograms. Never log AWS policy bodies, ARNs, account IDs, credentials, raw request bodies or high-cardinality IDs in metric labels. Answer: “Which source/collection task failed?”, “Which layer is missing?”, “Which release and snapshot made this finding?”
5. **Finding review and IT export:** after the authenticated-actor decision, add `analyst_actors`, append-only `finding_review_decisions`, then `report_exports` in a reviewed migration. Bind each decision to the same finding's exact explanation plus finding/analysis/evidence/coverage hashes; recheck latest acceptance and the release/snapshot in the export transaction. A local alias or stale decision never authorizes real-account IT delivery. See [schema v0.1](24_WHOLE_PRODUCT_SCHEMA_PROPOSAL.md#engine-4--explanations-research-and-exports).
6. **Evaluation:** benchmark positives, hard negatives, explicit denies and missing context; real-account observations in a separate evidence class. Test one user journey end to end and export a reviewed IT report. No single security posture score until coverage and calibration justify it.

### Portal design brief for the later UI phase (not implemented here)

**Subject / user / job:** an IAM analyst deciding whether a specific identity's access-change path merits an IT ticket. The screen's first job is to answer *what was observed, what is inferred, and what remains unknown*. The visual signature is the synchronized **branch ledger**: selecting a graph edge highlights the exact evidence row, coverage gap and potential control; selecting the row returns to that edge. This is an analytic instrument, not a decorative multiverse animation.

**Proposed tokens for review:** Ink `#111214`, Paper `#FAFAF8`, Surface `#F0F0ED`, Hairline `#C7C8C4`, Secondary text `#55585B`, Inverse `#FFFFFF`. These are a near-monochrome proposal, not a CSS change. Keep semantic status readable with text and line/pattern treatments. Typography should retain the existing product's distinct roles—Bahnschrift for restrained headings, Segoe UI for readable body, Cascadia Mono for IDs/evidence—while testing fallback metrics and contrast. Layout is a narrow context rail, one dominant path canvas, and a resizable evidence ledger; on small screens the ledger follows the path in reading order. Motion is normally absent for keyboard and frequent graph selection; occasional drawers may use a short, reduced-motion-aware transition.

| Before (current code) | After (proposed) | Why |
|---|---|---|
| Seven foundry pages plus an `Investigation demo` route | Analyst journey is primary; foundry pages remain accessible under Curation | The current navigation describes Engine 1 operations more than an analyst's job. |
| Synthetic fixture loads automatically in `InvestigationPage` | Analyst explicitly selects a snapshot/identity; fixture and real-account states have unmistakable source labels | Prevent a test case from looking like a live account scan. |
| One horizontal permission step plus separate evidence/limitations cards | Bounded branch canvas synchronized with evidence, denial and unknown ledger; accessible text outline | Make *why this branch exists* inspectable without forcing users to infer from arrows. |
| Teal/blue/amber/red status accents in `styles.css` | Monochrome hierarchy with words/icons/patterns and contrast-tested emphasis | Matches the requested restraint and does not make color the sole carrier of security meaning. |
| “Suggested next step” in the fixture | Analyst decision and redacted, versioned IT handoff after authenticated review | Makes the outcome usable while separating recommendation from an applied AWS change. |

These are the phases for the active project goal. The first shippable slice is a **safe, reproducible read-only snapshot boundary**, not an immediate visual rewrite. Run scoped checks after each increment, then browser-check desktop/mobile, keyboard flow, and content claim labels. Source-driven implementation must confirm exact framework/library behavior against the versions in `pyproject.toml` and `frontend/package.json`; do not cargo-cult generic API or UI examples. No live AWS calls, RLS changes, migrations, or report publication were performed to produce this document.
