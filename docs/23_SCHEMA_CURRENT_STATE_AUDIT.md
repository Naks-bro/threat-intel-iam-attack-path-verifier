# Whole-product schema audit — observed state (2026-10-08)

**Historical checkpoint:** this document compares the managed 0004 database
with repository head 0008 as observed on 2026-10-08. The repository now has
locally authored, unapplied 0009; see [the later schema gate log](26_SCHEMA_FIRST_DELIVERY_GATES.md).

Status: **Verified where stated; no schema change authorized.** This audit is paired with [the proposed schema](24_WHOLE_PRODUCT_SCHEMA_PROPOSAL.md). The Supabase project named FYP was inspected read-only through the Supabase project connector. The repository's private `FYP_DATABASE_URL` is set; no URL or password was displayed. A direct connection using `application_database_url()` and `prepare_url()` with a read-only/timeout connection failed with `OperationalError`; therefore the connector, not a direct application session, is the basis for the live facts below. No migration, DML, RLS or privilege change was made.

## Evidence ledger and precedence

| Evidence | Observation | Limit |
|---|---|---|
| Supabase `list_projects`, `list_tables(verbose)`, `list_extensions`, and read-only `execute_sql` queries on FYP | Project healthy, PostgreSQL 17.11, `foundry.alembic_version = 20261003_0004`; exact `count(*)`, `pg_indexes`, `pg_constraint`, and `pg_class.relrowsecurity` inspected | Connector `list_migrations` returned `[]`; that is not the Alembic ledger. No row payloads were read. |
| `src/fyp_iam/persistence/{dotenv,urls,status}.py` | `.env` loader and TLS/URL selection; status requires current Alembic head | This machine's direct connection failed; exact cause was not verified without risking secret-bearing error text. |
| `alembic/versions/20261003_0001` through `20261007_0008`, `alembic/env.py` | Eight linear revisions; current head `20261007_0008` | Migration files describe intended upgrades, not live state. |
| `src/fyp_iam/engine1/foundry/models.py`; `src/fyp_iam/engine1/workbench/db.py` | Foundry ORM has 26 application tables; older workbench ORM targets public checkpoint tables | The old workbench API cannot be assumed usable with the post-0002 schema. |
| `src/fyp_iam/api/{app,review_api,schemas}.py`, `src/fyp_iam/contracts/{models,releases}.py`; Engine 1–4 source and targeted tests | API/contract assumptions and fixture-only analysis | Passing tests do not establish deployed Supabase features or live AWS collection. |

`docs/00_STATUS_AND_TRUTH_MODEL.md`, `docs/02_ARCHITECTURE.md`, `docs/03_ENGINE_CONTRACTS.md`, `docs/05_ENGINE_2_IAM_GRAPH.md`, `docs/06_ENGINE_3_VERIFICATION.md`, `docs/14_ENGINE_1_RESEARCH_GRADE_FOUNDRY_SPEC.md`, `docs/15_ENGINE_1_EXECUTION_PLAN.md`, and ADR-011–015 were treated as hypotheses and compared with source. In particular, the old architecture's Neo4j direction is superseded for this **proposed** PostgreSQL-first design; no Neo4j implementation exists in the inspected persistence model. `docs/06` and README still say the first foundry precondition is unsupported, while `engine3/discovery.py` and `tests/unit/test_stable_release_contract.py` now support and test `target_is_iam_user` on a synthetic edge. Those documentation statements are stale, not proof of a real-account release.

## Actual managed database

PostgreSQL `17.11`; application schemas `public` (0 base tables) and `foundry` (21 application tables plus `alembic_version`). Installed extensions reported: `plpgsql`, `pgcrypto`, `pg_stat_statements`, `uuid-ossp`, `supabase_vault`. These are platform installations, not a justification to use them in application design. All 22 listed `foundry` tables have `relrowsecurity=false` and `relforcerowsecurity=false`. `anon`, `authenticated`, and `service_role` reported **no USAGE** on the private `foundry` schema via `has_schema_privilege`; this is a schema privilege observation, not a complete security audit. Migration 0004 revokes `PUBLIC`, `anon`, and `authenticated`; do not infer RLS or user authentication from the absence of schema access.

The following are **exact counts at audit time**, obtained with `count(*)`, not catalog estimates. Columns came from connector `list_tables(verbose)`; PK, UQ, FK, checks and index definitions were cross-checked with read-only catalog queries. `PK` indexes exist for each table; only non-PK indexes/uniques are noted below. Foreign keys generally follow same-named `*_id` columns and are stated in the next paragraph.

| `foundry.` table | Rows | Columns (observed) | Notable UQ/index/check |
|---|---:|---|---|
| `alembic_version` | 1 | version_num | PK; value `20261003_0004` |
| `sources` | 4 | source_id, source_key, authority_tier, source_type, official_url, enabled, schedule_cron | UQ source_key; tier/type checks |
| `source_versions` | 3 | version_id, source_id, version_label, discovered_at, effective_at, content_hash | UQ(source_id,content_hash) |
| `pipeline_runs` | 8 | run_id, status, attempt, trigger, parent_run_id, started_at, finished_at, fetched_count, created_count, updated_count, unchanged_count, rejected_count, error_json, content_hash | status check |
| `ingestion_runs` | 32 | ingestion_id, pipeline_run_id, source_id, source_version_id, attempt, status, started_at, finished_at, fetched_count, created_count, updated_count, unchanged_count, rejected_count, error_json, retry_of, parser_version | status check |
| `raw_artifacts` | 3 | artifact_id, source_version_id, ingestion_id, source_native_id, mime_type, content_hash, byte_count, payload, storage_uri, retrieved_at, parser_version | UQ(source_version_id,source_native_id,content_hash); payload-or-URI check |
| `normalized_entities` | 18 | entity_id, entity_type, native_id, name, source_version_id, artifact_id, attributes_json | UQ(entity_type,native_id,source_version_id); type check |
| `evidence_claims` | 4 | claim_id, subject_entity_id, predicate, object_value, object_entity_id, artifact_id, source_location, extraction_method, confidence, valid_from, valid_to | UQ(artifact_id,subject_entity_id,predicate,object_value,source_location) |
| `evidence_relations` | 7 | relation_id, from_entity_id, to_entity_id, relation_type, mapping_method, mapping_confidence, review_state, rationale | UQ(from_entity_id,to_entity_id,relation_type,mapping_method); review check |
| `evidence_relation_claims` | 4 | relation_id, claim_id | composite PK |
| `attack_primitives` | 3 | primitive_id, primitive_key, outcome_category, required_actions_json, required_resources_json, preconditions_json, state_transition, resulting_capability, limitations, mapping_confidence, attack_mapping_state, generator_version | UQ(primitive_key,generator_version); mapped/unmapped check |
| `primitive_relations` | 7 | primitive_id, relation_id | composite PK |
| `rule_candidates` | 1 | candidate_id, lifecycle, generator_name, template_version | lifecycle check |
| `candidate_primitives` | 1 | candidate_id, primitive_id | composite PK |
| `candidate_entities` | 2 | candidate_id, entity_id | composite PK |
| `rule_versions` | 1 | version_id, candidate_id, rule_version, rule_json, semantic_hash, parent_version_id, generator_version | UQ(candidate_id,rule_version) |
| `validation_runs` | 13 | validation_id, rule_version_id, validator_name, validator_version, result, findings_json, corpus_version, executed_at, duration_ms | no non-PK index |
| `ai_verifications` | 1 | verification_id, rule_version_id, provider, model, prompt_version, schema_version, evidence_snapshot_hash, verdict, findings_json, citations_json, response_hash | verdict check; not independent authority |
| `ai_suggestions` | 0 | suggestion_id, verification_id, rule_version_id, suggestion_json, recorded_at | no non-PK index |
| `review_decisions` | 0 | decision_id, rule_version_id, reviewer_alias, decision, comment, decided_at | legacy alias, no exact-input scope |
| `publications` | 1 | publication_id, rule_version_id, evidence_snapshot_hash, channel, published_at | UQ(rule_version_id,channel); channel check; legacy experimental record is not stable approval |
| `audit_events` | 8 | event_id, actor, action, object_type, object_id, correlation_id, before_hash, after_hash, details_json, recorded_at | no non-PK index |

Observed FKs: `source_versions→sources`; `pipeline_runs.parent_run_id→pipeline_runs`; `ingestion_runs→pipeline_runs/sources/source_versions/ingestion_runs(retry_of)`; `raw_artifacts→source_versions/ingestion_runs`; `normalized_entities→source_versions/raw_artifacts`; `evidence_claims→normalized_entities` (subject and optional object) and `raw_artifacts`; `evidence_relations→normalized_entities` (both ends); `evidence_relation_claims→evidence_relations/evidence_claims`; `primitive_relations→attack_primitives/evidence_relations`; `candidate_primitives→rule_candidates/attack_primitives`; `candidate_entities→rule_candidates/normalized_entities`; `rule_versions→rule_candidates` and optional parent version; `validation_runs`, `ai_verifications`, `review_decisions`, `publications` → `rule_versions`; `ai_suggestions→ai_verifications/rule_versions`. `audit_events` deliberately has polymorphic object IDs without FKs. No dedicated lookup indexes exist on most FK columns; PostgreSQL does not create them automatically. Full catalog query evidence was inspected but not copied as raw connector payload because it can contain environment metadata.

## Drift: live DB ↔ migrations ↔ ORM ↔ API

| Boundary | Verified difference | Consequence / evidence |
|---|---|---|
| Live 0004 → repo 0005 | `quality_reports`, `quality_observations` absent; `validation_runs.duration_ms` remains non-null | `quality_store.py` and `models.py:318–354` assume 0005. Migration `20261003_0005_foundry_quality_reports.py` is unapplied. |
| Live 0004 → repo 0006 | `verifier_packets` absent | Exact request/result persistence in `verifier_store.py` is not available in managed DB. |
| Live 0004 → repo 0007 | `scoped_reviews` absent | Opt-in review API in `api/review_api.py` cannot durably review there. Legacy empty `review_decisions` is not a substitute. |
| Live 0004 → repo 0008 | `stable_releases` absent | No managed stable release/export; `engine1/foundry/release_store.py` assumes this table. |
| 0002 migration ↔ model evolution | 0002 calls current `Base.metadata.create_all`; later migrations use `IF NOT EXISTS` | A fresh install may create later tables earlier than their numbered revisions; deployed 0004 still lacks them. Freeze migration definitions before production schema work; compare fresh and upgrade paths. |
| Old workbench ORM ↔ live DB | `engine1/workbench/db.py` models public checkpoint tables replaced by 0002 | `/v1/workbench/imports/{pin_id}` in `api/app.py` can be database-gated yet structurally incompatible with the foundry schema; do not treat it as a supported managed write path. |
| API preview ↔ managed DB | `api/preview_app.py` forces no DB; `/health` says `offline_preview` | A browser demo proves neither managed schema nor durable release. |
| Engine 2/3/4 contracts ↔ ORM | `contracts/models.py` has portable graph/path/verification/finding types; ORM has no account inventory, graph, path or finding tables | Analyses are fixture/in-memory; `engine2/live.py` raises `LiveCollectionDisabled`. `engine3/releases.py` allows only explicitly synthetic benchmark snapshots. |
| Review identity ↔ security | `api/review_api.py` requires local operator alias and loopback; no authenticated actor table | Alias is not authenticated identity; publication for real-account scope remains disabled. |

Unknowns: direct database reachability from this process; table-level privilege grants for every role; whether a different private backend is using this database; row-level contents beyond counts; any out-of-band schema objects outside `public`/`foundry`; operating retention/backups; performance at scale. None was inferred from documentation. No read-only query in this audit changed state.
