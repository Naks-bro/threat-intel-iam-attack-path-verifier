# Research and Evaluation Plan

## Research framing

The defensible contribution is a traceable integration study: selected threat knowledge is transformed into human-approved structural IAM rules and evaluated against an AWS authorization graph with explicit evidence states. Do not claim global novelty until a systematic search demonstrates it.

## Research questions

- RQ1: How accurately can the pipeline normalize and classify selected AWS/IAM-relevant threat records?
- RQ2: How often are generated rule candidates structurally valid, evidence-supported, and approved by reviewers?
- RQ3: How accurately does graph/path analysis identify known positive and negative IAM escalation fixtures?
- RQ4: How much does policy simulation reduce unsupported candidates, and how often is it inconclusive?
- RQ5: For mapped scenarios, how often does sandbox evidence agree with static/simulator conclusions?
- RQ6: Do explanations improve reviewer correctness or speed compared with raw paths and policy documents?
- RQ7: Does any proposed ranking feature outperform transparent baselines without hiding high-impact paths?

## Datasets

Maintain separate versioned datasets:

1. **CTI gold set:** pinned source records with field labels, AWS relevance, evidence spans, and reviewer notes.
2. **Rule set:** proposed/approved/rejected rules with decision reasons and versions.
3. **IAM fixtures:** synthetic positive, negative, edge, and missing-context configurations.
4. **Sandbox scenarios:** scenario/version, expected steps, expected verdict, and teardown checks.

Do not train and test on variants of the same scenario across splits. Keep the final test set frozen before tuning prompts, rules, or thresholds.

## Metrics

| Layer | Primary metrics | Important failure analysis |
|---|---|---|
| CTI extraction | precision, recall, F1 per field/class | source type, ambiguity, missing evidence |
| Rule generation | schema-valid rate, evidence entailment, approval/revision/rejection rate | invented actions, unsupported conditions, unsafe output |
| Graph construction | node/edge precision and recall against expected fixture | missing policy layers, wrong direction, duplicates |
| Path discovery | path-level precision/recall, known-path coverage | cycles, duplicate paths, depth/time limits |
| Simulator | denied/supported/inconclusive distribution; agreement with mapped lab | missing context, unsupported controls |
| Sandbox | scenario success and cleanup success | provisioning drift, service changes, non-determinism |
| Explanation | factuality, evidence coverage, reviewer task accuracy/time | omission, overconfidence, misleading wording |
| Runtime | latency, memory, API calls, estimated cost | scale by nodes, edges, policies, paths |

Report counts and confidence intervals where possible; do not rely on accuracy alone for imbalanced datasets.

## Baselines and ablations

- Deterministic source extraction vs hybrid deterministic + LLM interpretation.
- Manual rule curation vs generated candidates with human approval.
- Direct policy/path rules vs graph centrality features.
- Transparent priority baseline vs any learned ranking model.
- Explanations with evidence links vs raw technical output.
- Policy simulation only vs mapped sandbox evidence.

## Experiment manifest

The local slice writes one RQ3 manifest for the six checked-in fixtures. It records verdict counts and capability-edge precision and recall for the cases the normalizer can represent. `CAN_ACCESS` is reported as not scored. Model, prompt, and random seed are `not_used`. A live-account or sandbox run is not included. A precision of 1 is agreement with the fixture, not exploitability.

Every reported run records:

```text
experiment_id
research_question
code_revision
dataset_ids_and_hashes
source_versions
schema_versions
rule_versions
graph_snapshot_ids
runtime/dependency versions
model/provider/prompt hash and decoding settings, if used
configuration and traversal bounds
random seeds
start/end timestamps
raw result artifact hashes
metric implementation version
known deviations
```

## Literature quality control

The raw project report lists 14 papers, some with placeholder authors or bibliographic fields. Before submission:

- verify title, authors, venue, year, pages, DOI/URL from the publisher or proceedings;
- read the actual methodology/limitations instead of relying on a search snippet;
- distinguish peer-reviewed publications from preprints and repositories;
- use a documented database/search strategy and inclusion/exclusion criteria;
- avoid “no work exists” unless the review supports that statement;
- maintain a claim-to-citation matrix.

## Reproducibility package

- anonymized fixtures and schemas;
- exact setup/run commands;
- locked dependencies and container definitions;
- experiment manifests and metric scripts;
- source/artifact hashes where redistribution is permitted;
- expected outputs for the demonstration slice;
- limitations and known nondeterminism.

