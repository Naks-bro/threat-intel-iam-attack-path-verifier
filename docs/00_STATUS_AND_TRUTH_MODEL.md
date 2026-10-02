# Project Status and Truth Model

Last curated: 2026-10-02

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

- Python package `fyp_iam` implements the local fixture pipeline: contract models, six synthetic cases, bounded path discovery, fixture verification, baseline findings, and a FastAPI boundary.
- Engines 1 and 2 are package boundaries only. No CTI parser, AWS collector, Neo4j schema, Redis worker, or LLM client is in this tree.
- The reported Engine 1 parser from the chats remains **Reported/unverified**. It was not present in the curated folder and was not imported.
- ADRs 001–004 are **Proposed**. ADR-004 records the local-slice behavior that the tests exercise.
- Confirm the slice with `python -m pytest`, `python -m ruff check .`, and `python -m mypy src` from a Python 3.12 virtual environment.

**Verified** on 2026-10-02 with Python 3.12.10 in this checkout:

- `python -m ruff check .` — all checks passed
- `python -m ruff format --check .` — 49 files already formatted
- `python -m pytest` — 39 passed, with one Starlette deprecation warning about the `httpx` test client
- `python -m mypy src` — no issues found in 22 source files

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
3. **AWS Threat Technique Catalog is real and relevant.** AWS CIRT launched it as an AWS-specific extension based on ATT&CK Cloud, with observed techniques, mitigations, and detections. The ingestion method still needs to be proven against the catalog's actual published format.
4. **IAM Policy Simulator is a pre-check, not ground truth.** It does not make a real service request and can differ from live behavior for advanced configurations.
5. **CloudGoat cannot generically validate every discovered path.** It provides curated intentionally vulnerable scenarios. A path can be sandbox-tested only if it maps to an available or deliberately implemented scenario.
6. **Betweenness centrality is not a vulnerability score.** It measures how often a node lies on shortest paths. Any use in security prioritization requires an empirical hypothesis and ablation against simpler baselines.
7. **A GNN is optional.** It should be included only if a labeled dataset, baseline, evaluation plan, and measurable gain exist.
8. **“No prior work combines these ideas” remains unverified.** Absence claims require a documented systematic search, not a handful of examples.

## Local slice still open

- Team acceptance of Proposed v0.1 and of ADR-004.
- The reported Engine 1 parser, if it exists outside this folder.
- Live read-only collection, Policy Simulator, and any mapped sandbox. None of those are part of the local slice.

