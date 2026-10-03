# Engine 1 Research-Grade Threat-to-Rule Foundry

## Document status

**Selected direction, proposed contract.** This document turns ADR-009 into a bounded FYP product and research specification. It selects a research-grade vertical foundry with a CI-style rule-quality gate. It does not make the Proposed cross-engine contracts Accepted; that still requires team review.

## One-sentence definition

Engine 1 is an automated, evidence-backed AWS IAM threat-to-rule foundry that converts pinned security knowledge into deterministic, versioned attack-path rules, uses AI only to challenge those rules, and requires a human decision on an exact immutable version before stable publication.

The React application is the foundry control plane. It is not the research contribution by itself.

## Research claim

The defensible claim is deliberately narrow:

> A bounded pipeline can transform selected AWS threat knowledge into traceable structural IAM rules, expose unsupported or ambiguous mappings, and improve rule-review quality through deterministic validation, an evidence-grounded AI critic, and exact-version human approval.

The project must not claim autonomous rule generation, complete AWS authorization semantics, universal CTI parsing, or proof of exploitability.

## Problem

Threat sources describe attacker behavior at different levels of abstraction. Engine 3 needs precise structural conditions over an IAM graph. A direct jump from prose or an ATT&CK identifier to a graph rule creates four problems:

1. the source may not support the AWS-specific interpretation;
2. the generated actions or preconditions may be invented;
3. later source or compiler changes may silently alter the rule;
4. a fluent AI explanation may hide uncertainty instead of resolving it.

Engine 1 exists to make that transformation inspectable, repeatable, testable, and reviewable.

## Users and jobs

### Primary user

A cloud-security researcher or engineer maintaining AWS IAM attack-path rules.

Their job is to decide whether a proposed rule is technically valid, supported by evidence, safe to publish, and useful to Engine 3.

### Project users

- FYP team members implementing and labeling the pipeline.
- Academic reviewers assessing traceability, reproducibility, and evaluation quality.
- Human rule reviewers accepting, rejecting, or requesting revision.
- Engine 3, which consumes only contract-valid publications allowed by its channel policy.

## Product outcome

For each selected behavior, a reviewer can move through this chain without trusting hidden state:

```text
versioned source artifact
  -> normalized entities and claims
  -> typed evidence relations
  -> AWS attack primitive
  -> immutable rule version
  -> deterministic quality report
  -> evidence-grounded AI critique
  -> human decision on that exact version
  -> experimental or stable publication
  -> Engine 3 contract export
```

Every arrow must be represented by stored identifiers, versions, hashes, or audit events.

## Scope

### Required FYP scope

- AWS IAM only.
- Three rule families completed end to end.
- Pinned and versioned source inputs with reproducible offline fixtures.
- Deterministic compiler templates over a closed rule ontology.
- Positive, near-negative, missing-context, and adversarial scenarios.
- A provider-neutral AI-verifier contract, a deterministic fake for CI, and one recorded real-model evaluation if privacy, cost, and supervisor approval permit it.
- Exact-version human review and stable-publication enforcement.
- A GUI for run health, evidence inspection, quality findings, version comparison, and review.
- Reproducible experiment manifests and metric exports.

### Selected rule families

The first three families should be:

1. **Additional credentials**: creation of access keys or equivalent additional cloud credentials for an existing principal.
2. **Role trust-policy backdoor**: a principal can change a role trust policy to enable a new assumption path.
3. **Service-mediated role escalation**: a principal can pass a more privileged role to a supported AWS service and reach a resulting capability.

The exact actions and service preconditions must be accepted in the rule ontology before implementation. `T1548 -> sts:AssumeRole` remains rejected unless new primary evidence supports a precise mapping.

### Stretch family

Privileged role or policy creation/attachment may be added only after all three required families pass the complete quality gate and evaluation pipeline.

### Explicit non-goals

- Generic multi-cloud support.
- A general-purpose CTI lake or SOC platform.
- Arbitrary webpage or PDF scraping.
- LLM-authored executable rules, Cypher, cloud commands, or remediation.
- Production AWS write access.
- Supabase Auth, Realtime, Storage, or Edge Functions.
- Celery, Redis, Kafka, or distributed scheduling for the FYP slice.
- A GNN unless a labeled dataset and transparent baseline justify it.
- Full AWS IAM, Organizations, and resource-policy semantics.
- Login roles in the current slice.

## Architectural decisions

### Deterministic authorship

Source-specific adapters normalize data. Explicit mapping functions produce attack primitives. Versioned compiler templates produce rule candidates. AI never creates or silently edits the canonical rule document.

### AI as an adversarial verifier

The AI verifier receives a closed evidence snapshot and immutable candidate. It returns schema-constrained findings with citations into that snapshot.

Allowed verdicts:

- `pass`
- `needs_review`
- `reject`
- `error`

The verifier may identify unsupported claims, contradictions, missing evidence, ambiguous preconditions, unsafe text, or explanation overconfidence. It cannot approve, publish, mutate, or execute anything.

### Human authority

Experimental publication may follow deterministic validation and the configured verifier policy. Stable publication requires an `approved` decision referencing the exact `rule_version_id` and evidence snapshot hash. A changed rule or changed evidence snapshot requires a new decision.

### Storage boundary

PostgreSQL is the persistence contract. Supabase may host PostgreSQL, but application code remains on SQLAlchemy, Psycopg, and Alembic. The React application talks only to FastAPI. Foundry tables remain outside anonymous and authenticated API roles.

### Failure semantics

- A failed source run does not delete successful evidence from other sources.
- Missing tools and unavailable AI providers are recorded, not disguised as passes.
- Unknown and inconclusive are first-class outcomes.
- Retry creates an auditable attempt.
- Reprocessing creates a new run and, when semantics change, a new rule version.

## Source strategy

| Source | Role | Rule-authoring authority |
|---|---|---|
| MITRE ATT&CK STIX | behavior taxonomy and relationships | Supporting; never sufficient alone for an AWS rule |
| AWS Service Authorization Reference | actions, resources, condition keys | Primary for action/resource vocabulary |
| Stratus Red Team metadata | reproducible AWS behavior examples | Supporting behavior evidence |
| AWS Threat Technique Catalog | potential AWS-specific evidence | Disabled until a stable, versioned machine-readable input is confirmed |
| OWASP cloud-native guidance | contextual risks and mitigations | Context only |
| NVD and CISA KEV | vulnerability/exploitation context | Context only; no keyword-to-rule generation |

Each enabled adapter must declare source key, authority tier, format, parser version, accepted domains or repositories, version-discovery method, license note, size limit, and failure behavior.

## Closed rule ontology

Before adding a rule family, define and test:

- permitted AWS actions;
- supported principal and resource types;
- resource-selector forms;
- supported precondition types;
- supported state transitions;
- resulting capability vocabulary;
- path predicates exposed to Engine 3;
- unsupported condition or policy layers;
- canonical ordering and semantic hashing rules.

Unknown vocabulary fails closed. The compiler must not pass arbitrary strings into graph queries or cloud APIs.

## Rule-quality gate

Every immutable rule version receives one quality report composed of these stages:

1. **Source integrity**: pinned version, hash, retrieval metadata, parser version, and allowed origin.
2. **Evidence coverage**: every material primitive and rule field links to accepted evidence or an explicit compiler decision.
3. **Schema validity**: the candidate satisfies the versioned cross-engine contract.
4. **Ontology validity**: actions, resources, predicates, and preconditions belong to the supported vocabulary.
5. **Semantic invariants**: no impossible transition, contradictory precondition, unsafe payload, or unsupported approval state.
6. **Scenario corpus**: positive, near-negative, missing-context, and adversarial cases run with recorded outcomes.
7. **Optional validators**: unavailable tools are reported; disagreement remains visible.
8. **AI critique**: the verifier evaluates only the frozen candidate and evidence snapshot.
9. **Human decision**: a reviewer sees all prior outputs and decides on the exact version.
10. **Publication policy**: the service computes channel eligibility; the UI cannot override it.

The report must expose stage status, version, duration, findings, evidence references, and whether the stage is required for the selected publication channel.

## Rule lifecycle

```text
draft -> proposed -> experimental
                  -> rejected
                  -> revision_requested -> superseded by new version
experimental -> approved -> stable
stable -> deprecated -> superseded
```

This diagram describes product intent. Existing Proposed contracts must be reconciled before changing persisted enums.

Rules are immutable. Lifecycle events and new versions replace in-place mutation.

## API capabilities

Exact paths are finalized through contract review, but the API must support these capabilities:

- list sources and latest source health;
- launch a bounded pipeline run;
- inspect pipeline and ingestion attempts;
- list candidate rules and publications;
- inspect one immutable rule version and its lineage;
- inspect evidence, validation, scenarios, and AI findings;
- compare two rule versions;
- create a review decision for one exact version;
- export rules eligible for Engine 3 under an explicit channel policy;
- export an experiment manifest and metrics artifact.

All write endpoints require idempotency or conflict behavior, typed error responses, correlation identifiers, and audit events. Secrets and connection strings never appear in responses or logs.

## Control-plane interface

### 1. Operations overview

- Registry and database state.
- Last pipeline run and partial failures.
- Source freshness and connector health.
- Candidate counts by lifecycle and publication channel.
- Quality-gate failures requiring attention.

### 2. Pipeline run detail

- Timeline of source attempts.
- Counts for fetched, created, updated, unchanged, and rejected records.
- Retry ancestry and sanitized failures.
- Semantic changes produced by the run.

### 3. Rule dossier

- Immutable rule JSON rendered as structured data.
- Primitive, evidence, and source lineage.
- Validation and scenario matrix.
- AI findings with evidence citations.
- Limitations, unsupported semantics, and publication eligibility.

### 4. Version comparison

- Field-level rule diff.
- Evidence additions/removals.
- Compiler, ontology, corpus, prompt, and model version changes.
- Prior review invalidation when applicable.

### 5. Review workspace

- Approve, reject, or request revision.
- Mandatory comment for rejection or revision.
- Confirmation of exact rule version, evidence hash, and approval scope.
- No editable reviewer identity supplied as an untrusted arbitrary request field in a production claim; the FYP demo may use a documented alias boundary.

Every screen must include loading, empty, partial, unavailable, and error states. Source prose is rendered as text, never unsanitized HTML.

## Evaluation design

### Primary research questions

- **E1:** How accurately does the pipeline extract and normalize the fields required by the selected rule families?
- **E2:** How accurately do deterministic mappings and compiler templates produce evidence-supported rule fields?
- **E3:** Does the AI verifier identify seeded unsupported claims or contradictions without being allowed to alter the rule?
- **E4:** Does the evidence dossier improve reviewer correctness or review time compared with a candidate-only view?
- **E5:** Are repeated runs over the same versions semantically reproducible?

### Datasets

1. A source gold set with labeled fields, relevance, evidence locations, and ambiguity notes.
2. Immutable rule versions with expected rule fields and reviewer outcomes.
3. A scenario corpus per required family containing at least one positive, two near-negative, one missing-context, and one adversarial case.
4. An AI defect set containing supported and deliberately unsupported candidate claims.
5. Reviewer-study tasks with answer keys and counterbalanced interface conditions where practical.

The pilot should establish labeling cost and class balance before the final sample size is frozen. At least 20% of the final gold set, and never fewer than 15 items, should receive independent second review if two reviewers are available.

### Metrics

- Field-level precision, recall, and F1 for extraction and normalization.
- Rule-field precision and evidence-entailment rate.
- Schema-valid and ontology-valid rates.
- Scenario verdicts and confusion matrix per rule family.
- AI defect-detection precision, recall, false-positive rate, and citation validity.
- Reviewer decision accuracy, time, and disagreement.
- Reproducibility rate across repeated identical runs.
- Runtime, failures, retries, and estimated external-model cost.

Counts and uncertainty must accompany percentages. A result on the local corpus is never described as global accuracy or exploitability.

### Baselines and ablations

- Manual rule curation versus deterministic foundry output.
- Deterministic checks alone versus deterministic checks plus AI critique.
- Candidate-only review versus evidence-dossier review.
- Full evidence set versus removal of each supporting source family.
- Fake verifier in CI versus recorded real-model evaluation, clearly labeled as different purposes.

## Acceptance criteria

The Engine 1 FYP slice is complete only when:

- all three required rule families pass an offline reproducible run;
- every published rule field has traceable provenance or a recorded deterministic derivation;
- unsupported action and predicate vocabulary fails closed;
- a source can fail without corrupting successful source results;
- each family has the required scenario classes;
- the AI verifier cannot author, mutate, approve, publish, or execute a rule;
- seeded prompt-injection text cannot escape the verifier schema or become instructions;
- stable publication is impossible without exact-version approval;
- Engine 3 excludes experimental rules by default;
- the GUI exposes evidence, limitations, disagreements, and partial failures;
- experiment manifests identify code, data, schema, compiler, corpus, model/prompt when used, and artifact hashes;
- Python checks, frontend tests/build, PostgreSQL integration tests, and browser flow all pass;
- documentation distinguishes Verified, Proposed, and unverified claims.

## Stop conditions requiring human decision

- Adding a paid or external model that receives non-public data.
- Changing accepted cross-engine contracts incompatibly.
- Broadening live AWS permissions or adding any write action.
- Provisioning an intentionally vulnerable environment.
- Changing datasets, labels, primary metrics, or frozen test sets after evaluation starts.
- Introducing login/authentication as a claimed security control.
- Treating a new external source as authoritative without format, version, and license review.

## Definition of success

The strongest final demonstration is not a large catalog. It is a replayable run in which a source change produces an evidence diff and a new rule version, the quality gate finds a deliberate defect, the AI critic cites the frozen evidence, a reviewer makes an exact-version decision, Engine 3 receives only an eligible stable rule, and the experiment manifest proves exactly what happened.
