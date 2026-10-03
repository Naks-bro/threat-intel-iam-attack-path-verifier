# Project Status and Truth Model

Last curated: 2026-10-03

## Why this file exists

The source material is a set of AI conversation exports. It mixes user decisions, assistant proposals, generated code that may never have been saved, copied document text, and claims about work completed elsewhere. This file defines what future collaborators may safely treat as fact.

## Evidence labels

| Label | Meaning | May drive implementation? |
|---|---|---|
| **Verified** | Confirmed by a primary source, an inspected project file, or observed command/test output | Yes |
| **Accepted decision** | Clearly selected by the team and recorded here or in an ADR | Yes, until superseded |
| **Proposed** | Sensible design needing team acceptance or implementation validation | For prototypes only |
| **Reported/unverified** | Claimed in chat but not supported by files in this folder | No; verify first |
| **Rejected/corrected** | Superseded, contradicted, unsafe, or misleading | No |

## Current verified inventory

The statements in this section describe this implementation repository after the local slice was added. The original curation folder still holds the raw conversation exports and the pre-implementation baseline. Those exports are not in this Git tree.

- Python package `fyp_iam` implements the local fixture pipeline: contract models, six synthetic cases, bounded path discovery, fixture verification, baseline findings that cite hop policy refs and gaps, server-rendered review pages, an RQ3 fixture manifest, and a FastAPI boundary.
- Engine 1 can load one pinned local technique file, reject a hash mismatch or unsafe text, propose a pending rule from a code allowlist, show that proposal on a review page, and export an `ApprovedRule` only after a separate human approval request. It also loads a pinned 50-row Enterprise ATT&CK 19.2 IaaS dataset and joins pinned OWASP short names, one keyless NVD page, and CISA KEV catalog metadata into source nodes. Strength counts distinct source families. The automated join stores a compact catalog whose rows are stated as technique, weakness, vulnerability, or catalog. A model checker has not run. Those rows stay `no_rule_yet`. `POST /v1/rules/intake` does not approve and does not fetch a URL. Request handling does not download the feeds. The reported HTML parser remains **Reported/unverified**.
- Engine 2 can normalize synthetic IAM records into an `IAMGraphSnapshot`, record an unevaluated permissions boundary, emit an exact `service:*.amazonaws.com` trust, reconcile node and edge counts, match the local verdict of the hand-built fixtures, and report capability-edge precision and recall. A twelve-action read-only IAM template is tested and not attached. Live AWS collection is disabled and makes no API call. Neo4j is not implemented.
- The reported Engine 1 parser from the chats remains **Reported/unverified**. It was not present in the curated folder and was not imported.
- ADRs 001–009 are **Proposed**. ADR-009 supersedes the product direction in ADR-008. The first foundry slice is in this checkout: a pinned Enterprise ATT&CK 19.2 extract, an AWS Service Reference v1.4 extract for selected IAM and STS actions, and a redacted Stratus metadata extract. It derives three attack primitives, compiles `rule_additional_cloud_credentials` as proposed, and marks an experimental publication when the deterministic checks and the fake verifier pass. T1548 is rejected as an IAM mapping. The AWS Threat Technique Catalog is registered as disabled; historical failed attempts remain in the database audit log. The other rule families, optional validators, scheduler, and stable publication are not implemented. Migration `20261003_0002` replaces the checkpoint tables. Migration `20261003_0003` widens entity and source checks and adds suggestion rows.
- Confirm the slice with `python -m pytest`, `python -m ruff check .`, and `python -m mypy src` from a Python 3.12 virtual environment.

**Verified** on 2026-10-03 with Python 3.12.10 in this checkout. The foundry PostgreSQL test is deselected locally because `FYP_DATABASE_URL` is not set. GitHub Actions run [37068170700](https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier/actions/runs/37068170700) passed the unit job, the frontend job, and the PostgreSQL job, including migration `20261003_0003`, stored-row compilation, and the portal flow from an empty registry. The earlier run [37061261254](https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier/actions/runs/37061261254) covers the pin-computed slice only. The earlier checkpoint run [37054187538](https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier/actions/runs/37054187538) does not cover migration `20261003_0002`.

- `python -m ruff check .` — all checks passed
- `python -m ruff format --check .` — files already formatted
- `python -m pytest -m "not postgres"` — 126 passed, 1 deselected, with one Starlette deprecation warning about the `httpx` test client
- `python -m mypy src` — no issues found in 53 source files
- `npm test` in `frontend` — 2 passed
- `npm run build` in `frontend` — type-check and Vite build completed

## Engine 1 foundry slice

**Verified local quality persistence, 2026-10-03:**
Migration 0005 and `quality_store.py` add immutable semantic reports and separate
run observations. Rule detail reads the latest stored report and rejects corrupt
content; missing reports remain null. Nineteen storage-boundary/route tests pass,
including additive PostgreSQL SQL generation and null/partial API contracts.
Five PostgreSQL integration tests passed on an isolated 17.11 cluster; fresh
migration, reconstructed older-schema upgrade, and actual restart durability
passed. The initial database skips were superseded by these observed checks.
New validation writes
use null rather than fabricated row-index timings; historical placeholders remain
excluded from experiments. P6.2's local checks are satisfied. No managed migration,
production-scale durability, or current remote CI result is claimed. ADR-010 is
Proposed; see `19_POSTGRES_VERIFICATION.md` for the exact environment and evidence.

**Verified version-bound quality artifact, 2026-10-03:** Task P6.1 now has a typed immutable deterministic report bound to the rule version, semantic hash, and evidence snapshot hash. Missing required checks become skipped/incomplete; optional disagreement and unavailable tools remain visible; empty or contradictory passing corpus results fail. The preview API and React dossier expose the report, and generated frontend types/fixtures are checked by pytest against the provider schema. The persisted response stays nullable when no stored report exists. Local verification passed 181 non-PostgreSQL tests, 16 frontend tests, the frontend build, three Edge browser flows, Ruff, mypy, and diff whitespace checks. That P6.1 checkpoint did not itself prove coverage, measured validator timings, PostgreSQL report storage, human approval, or stable publication. The later local persistence result is the paragraph above. See `docs/18_RULE_QUALITY_REPORT.md`.

**Verified multi-page control plane, 2026-10-03:** the React portal now renders seven separate hash-routed workspaces with deep links, active navigation, route-heading focus, and an architecture view that labels implemented, partial, and planned capabilities. Thirteen frontend tests, the production build, and three Edge browser flows passed, including all-page overflow checks at 320/768/1024/1440px. Pipeline assurance no longer appears complete when a required check fails; stage statuses have text labels. The overview no longer embeds the full candidate dossier. The backend regression suite passed 158 non-PostgreSQL tests, mypy, Ruff lint, and formatting. See `docs/17_ENGINE_1_ARCHITECTURE.md` for the page map and completion audit. This does not verify current PostgreSQL durability, real AI critique, the remaining rule families, exact-version review, stable publication, or production deployment.

**Verified local GUI preview, 2026-10-03:** `fyp_iam.api.preview_app:app` serves the pinned Engine 1 result without connecting to PostgreSQL. The portal at `http://127.0.0.1:5173/` labels this state “OFFLINE PREVIEW”; its button recomputes in memory. The one candidate has six scenario outcomes but no publication or Engine 3 export in preview. This is not evidence that the Supabase-backed registry, durable reviews, or a real AI critic work. The separate normal API remains database-backed for foundry runs. Local checks passed: non-Postgres Python tests, mypy, Ruff, frontend unit tests/build, and a live Edge browser test of the preview route and button. A full-page screenshot was inspected. Do not use the preview status as a persisted-run claim.

**Verified assurance view, 2026-10-03:** the rule API now exposes check scope and textual findings. The current pinned candidate has ten passing required checks and four unavailable optional external tools; the six scenario cases are shown separately. The portal distinguishes those unavailable tools from passing checks and labels the fake verifier as a schema-only harness. A local Edge test and desktop/mobile screenshots confirmed the rendered panel; this is still not a real model critique or live AWS validation.

**Current worktree, offline verified:** the additional-credentials compiler now checks a versioned closed vocabulary and retains its prior semantic hash. A pinned six-case corpus records positive, near-negative, missing-context, and adversarial outcomes; confusion counts are calculated from observed outcomes. Repeated runs can append validation versions for the same immutable rule. An opt-in verifier result must bind to the exact candidate/evidence version and cite known evidence IDs; the default verifier remains a deterministic fake with no external model call. The operator dossier renders case outcomes, evidence references, and limitations. A bounded CLI supports offline preview and persisted runs; PostgreSQL transaction locking is implemented but has not been verified through the application against a live database. The AWS Threat Technique Catalog is disabled in new runs, so it no longer creates a synthetic partial failure. Existing PostgreSQL rows are updated only when the new pipeline runs. A read-only Supabase query on 2026-10-03 confirmed the managed database still holds the prior catalog row as enabled with a failed last attempt. The direct PostgreSQL integration test could not connect because host resolution failed during the attempt; the new persisted behavior remains unverified here. The earlier three-case and failed-ingestion statements below describe prior checkpoints, not the current code.

**Verified** locally for the compiler, the empty-registry API response, and the React component tests. **Proposed** as the product direction in ADR-009. PostgreSQL persistence is verified in GitHub Actions run [37068170700](https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier/actions/runs/37068170700), including migration `20261003_0003`, one experimental publication compiled from stored rows, and the Playwright portal flow. A local PostgreSQL server has still not been run. Supabase is an optional PostgreSQL host described in ADR-009. This checkout has not been given `FYP_DATABASE_URL`, so the managed-host path is implemented and not exercised here. CI PostgreSQL remains the reproducible verification environment.

- Sources in the pin: MITRE ATT&CK Enterprise 19.2 parent collection `sha256:dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`, reduced to T1098, T1098.001, T1098.003, and T1548. AWS Service Reference `v1.4` for `iam` and `sts`, limited to the actions the three behaviors name. Stratus Red Team metadata for `aws.persistence.iam-backdoor-user`, `aws.persistence.iam-backdoor-role`, and `aws.persistence.iam-create-backdoor-role`, stored as a redacted field extract. The original markdown is not committed because an example account ARN was present.
- Primitives: `additional_cloud_credentials` mapped to T1098.001 and compiled; `backdoored_role_creation` mapped to T1098.003 and not compiled; `trust_policy_backdoor` left unmapped because a trust-policy edit is not additional role creation.
- The compiled rule stays `status=proposed`. Engine 3 does not receive it unless experimental consumption is explicitly requested. The AI path is a fake schema verifier. It does not call a model and it ignores source text.
- Corpus `iam-corpus-0.2` has one positive, three near-negative, one missing-context, and one adversarial scenario for `iam:CreateAccessKey`. Its counts and precision/recall describe only these project-curated cases. The source hash is checked before evaluation.
- The compiler reads stored entities and relations. It does not select the candidate by a pinned behavior id. `GET /v1/foundry/overview` reads the registry. Without `FYP_DATABASE_URL` the registry state is `unavailable` and the candidate list is empty. `POST /v1/foundry/runs` returns 503 and does not pretend to save. Rule detail is `GET /v1/foundry/rules/{version_id}` using the id returned by the registry.
- AWS Threat Technique Catalog is disabled in new runs because no stable versioned input is confirmed. The historical 2026-10-03 failed probe remains available as audit history. A disabled source is excluded from active source health and does not cause `partial` status.
- AWS Threat Technique Catalog HTML exists. On 2026-10-03 `https://github.com/aws-samples/threat-technique-catalog-for-aws` returned 404 and no versioned JSON export was confirmed. It is not an adapter.

## Engine 1 audit

**Verified** for the local prototype. **Proposed** for the checkpoint in ADR-008, which ADR-009 supersedes as product direction. The checkpoint routes remain. Migration `20261003_0002` drops those tables on the next upgrade. A local PostgreSQL server has not applied either migration.

- Reuse the pinned artifacts, the T1548 allowlist, fail-closed intake, and the in-memory approval export.
- `strength` in the current catalog is a distinct-source count. It is not an overall confidence score.
- Approval is not durable. The reviewer id is caller-supplied. The older review pages remain server-rendered HTML.
- AWS Threat Technique Catalog ingestion, scheduled source runs, and an AI checker are not in this checkout. The PostgreSQL mapping, Alembic migration, and first React screen are in this checkout.
- On 2026-10-03 this machine had no `psql` and no `docker`. That is a local execution limit. GitHub Actions run [37054187538](https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier/actions/runs/37054187538) applied the migration and passed the PostgreSQL import test. A local database has not been exercised here.

## Accepted project baseline

- Working title: **Human-Approved, Threat-Intelligence-Driven Rule Generation with Explainable Cloud IAM Attack-Path Verification**.
- First implementation is scoped to AWS.
- The academic narrative has two stages: rule curation, then detection/verification.
- Engineering work is divided into four engines to permit parallel ownership.
- Human approval gates rule activation and final remediation decisions.
- Live AWS collection is read-only.
- Machine-learning or graph-ranking output prioritizes investigation; it does not prove exploitability.
- Cross-engine communication uses versioned, validated contracts.

## Reported but unverified implementation status

The chats claim an Engine 1 parser prototype exists with MITRE STIX, AWS Threat Technique Catalog HTML, and OWASP HTML parsing; AWS filtering; provenance; hashing; bounded references; input/security controls; and automated tests. They also report a Python 3.14 `ensurepip` failure that prevented execution.

None of those implementation files or test outputs exist in this folder. Treat the whole claim as **Reported/unverified** until the repository is supplied and tests run successfully.

## Important corrections

1. **NVD + CISA KEV + MITRE is not the agreed primary source set.** It was an assistant proposal later corrected in the same chat. NVD and KEV are optional enrichment candidates.
2. **OWASP Cloud-Native Top 10 is guidance, not a live CTI feed.** It may supply curated patterns and controls, but requires a versioned extraction/curation process.
3. **AWS Threat Technique Catalog HTML is not an ingestion source.** The public HTML catalog exists. On 2026-10-03 the expected `aws-samples` GitHub repository returned 404, and no maintained machine-readable export was confirmed. Keyword scraping is not a substitute.
4. **IAM Policy Simulator is a pre-check, not ground truth.** It does not make a real service request and can differ from live behavior for advanced configurations.
5. **CloudGoat cannot generically validate every discovered path.** It provides curated intentionally vulnerable scenarios. A path can be sandbox-tested only if it maps to an available or deliberately implemented scenario.
6. **Betweenness centrality is not a vulnerability score.** It measures how often a node lies on shortest paths. Any use in security prioritization requires an empirical hypothesis and ablation against simpler baselines.
7. **A GNN is optional.** It should be included only if a labeled dataset, baseline, evaluation plan, and measurable gain exist.
8. **“No prior work combines these ideas” remains unverified.** Absence claims require a documented systematic search, not a handful of examples.

## Local slice still open

- Team acceptance of Proposed v0.1 and of ADR-004.
- The reported Engine 1 parser, if it exists outside this folder.
- Live read-only collection, Policy Simulator, and any mapped sandbox. None of those are part of the local slice.
