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
- ADRs 001–009 are **Proposed**. ADR-009 supersedes the product direction in ADR-008. The first foundry slice is in this checkout: a pinned Enterprise ATT&CK 19.2 extract, an AWS Service Reference v1.4 extract for selected IAM and STS actions, and a redacted Stratus metadata extract. It derives three attack primitives, compiles `rule_additional_cloud_credentials` as proposed, and marks an experimental publication when the deterministic checks and the fake verifier pass. T1548 is rejected as an IAM mapping. The AWS Threat Technique Catalog is not ingested. The other rule families, optional validators, scheduler, and stable publication are not implemented. Migration `20261003_0002` replaces the checkpoint tables. A local PostgreSQL server has not been run here.
- Confirm the slice with `python -m pytest`, `python -m ruff check .`, and `python -m mypy src` from a Python 3.12 virtual environment.

**Verified** on 2026-10-03 with Python 3.12.10 in this checkout. The foundry PostgreSQL test is deselected locally because `FYP_DATABASE_URL` is not set. The earlier checkpoint PostgreSQL run [37054187538](https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier/actions/runs/37054187538) does not cover migration `20261003_0002`.

- `python -m ruff check .` — all checks passed
- `python -m ruff format --check .` — files already formatted
- `python -m pytest -m "not postgres"` — 125 passed, 1 deselected, with one Starlette deprecation warning about the `httpx` test client
- `python -m mypy src` — no issues found in 50 source files
- `npm test` in `frontend` — 1 passed
- `npm run build` in `frontend` — type-check and Vite build completed

## Engine 1 foundry slice

**Verified** locally for the pinned computation and the React component test. **Proposed** as the product direction in ADR-009. PostgreSQL persistence for this slice is not verified on this machine.

- Sources in the pin: MITRE ATT&CK Enterprise 19.2 parent collection `sha256:dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`, reduced to T1098, T1098.001, T1098.003, and T1548. AWS Service Reference `v1.4` for `iam` and `sts`, limited to the actions the three behaviors name. Stratus Red Team metadata for `aws.persistence.iam-backdoor-user`, `aws.persistence.iam-backdoor-role`, and `aws.persistence.iam-create-backdoor-role`, stored as a redacted field extract. The original markdown is not committed because an example account ARN was present.
- Primitives: `additional_cloud_credentials` mapped to T1098.001 and compiled; `backdoored_role_creation` mapped to T1098.003 and not compiled; `trust_policy_backdoor` left unmapped because a trust-policy edit is not additional role creation.
- The compiled rule stays `status=proposed`. Engine 3 does not receive it unless experimental consumption is explicitly requested. The AI path is a fake schema verifier. It does not call a model and it ignores source text.
- Corpus `iam-corpus-0.1` has one positive and two near-negative scenarios for `iam:CreateAccessKey`. Its precision and recall describe that corpus only.
- `GET /v1/foundry/overview` computes that result from the pins. Without `FYP_DATABASE_URL` the response is labeled not stored. `POST /v1/foundry/runs` returns 503 and does not pretend to save.
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

