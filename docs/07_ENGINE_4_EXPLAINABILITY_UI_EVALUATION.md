# Engine 4 — Prioritization, Explanation, UI, and Evaluation

## Purpose

Engine 4 turns immutable detection and verification evidence into an understandable review workflow and reproducible research results. It does not rewrite Engine 3 verdicts.

## Responsibilities

- Baseline risk/priority scoring.
- Optional graph features and learned ranking experiments.
- Evidence-grounded natural-language explanations.
- MITRE/AWS technique references inherited from approved rules.
- Attack-path and graph visualization.
- Human review state and remediation proposals.
- Metrics, experiment manifests, tables, and exportable reports.

## Priority baseline

Start with a transparent baseline using recorded features such as:

- verification status;
- target privilege/sensitivity;
- path length and required preconditions;
- wildcard breadth and action criticality;
- evidence completeness and snapshot coverage;
- blast radius or number of affected principals.

Weights and thresholds must be documented and tested. Betweenness centrality may be an experimental feature, but it measures shortest-path brokerage—not vulnerability—and must be compared against the baseline.

## GNN decision gate

Do not add a GNN until all are true:

1. a sufficiently large, representative labeled graph/path dataset exists;
2. train/validation/test splits avoid account/scenario leakage;
3. simple heuristic and classical baselines are established;
4. metrics and error costs are defined;
5. an ablation demonstrates useful incremental value;
6. explanations do not misrepresent model confidence as verification.

If these conditions are not met, omitting the GNN is the academically stronger decision.

## Explanation template

Every finding should answer:

- What path was found?
- Which approved rule matched and why?
- What policies/relationships support each hop?
- What did the simulator actually evaluate?
- Was there a mapped sandbox run? What succeeded or failed?
- What is unknown or unsupported?
- What change could reduce the risk, and what could that change break?

Generated prose must cite immutable evidence IDs. If an LLM is used, factual slots are populated from structured records and the output is checked for unsupported claims.

## UI minimum

- Filterable finding list with verification status and evidence completeness.
- Path view showing principals/resources, hop actions, conditions, and policy references.
- Separate badges for discovered, simulator-supported/denied, sandbox-verified, and inconclusive.
- Rule provenance and approval history.
- Remediation proposal with explicit human-review state.
- Coverage/limitations panel that cannot be hidden by a high score.

## Evaluation ownership

Engine 4 owns experiment orchestration and reporting, but each engine owns correctness metrics for its output. Results must be reproducible from a manifest containing dataset versions/hashes, rule versions, graph snapshot IDs, code revision, configuration, model/prompt identifiers, and random seeds where applicable.

## Local explanation (implemented)

`build_finding` writes the explanation from the rule, the path, and the verification record. Each hop cites its edge id, effect, policy refs, and condition keys. Unknown context, unsupported conditions, denied edges, fixture notes, and incomplete collection are copied into the text. Simulator status is `not_run` and sandbox status is `not_mapped`. The baseline score is unchanged: `severity_weight * status_weight`. No LLM is called.

`GET /reviews` lists the six fixtures with status, priority, and score. `GET /reviews/fixtures/{case_id}` shows the rule, approval, hops, evidence, remediation, and a coverage panel that stays on the page. `GET /reviews/rules/attack-t1548-assume-chain` shows the pinned technique, the excerpt, and the pending rule. A separate approval request records the decision. `GET /reviews/datasets/cloud-techniques` lists the 50 normalized ATT&CK rows and their rule status. `GET /reviews/datasets/opportunities` lists the stored compact catalog: technique, weakness, vulnerability, or catalog, with sources and strength. `no_rule_yet` means the row is not sent to path search. Strength is not a verification result. The catalog is written by the automated join. A model checker has not run. Finding text is escaped. These pages are server-rendered HTML, not a separate frontend. React remains **Proposed**.

`GET /v1/experiments/local-fixtures` and `GET /reviews/experiment` record the RQ3 run: fixture-file hash, rule versions, snapshot ids, verdict counts, and a result hash. The model, prompt, and random seed are `not_used`. Simulator status is `not_run` and sandbox status is `not_mapped`. Timestamps are the fixture evaluation times.

## Acceptance criteria

- UI never labels simulator-only evidence as sandbox verification.
- Explanations are traceable to evidence and survive a blinded factuality review.
- Priority ordering is deterministic for the baseline.
- Research exports contain no credentials or sensitive account identifiers.
- A finding can be reproduced without relying on conversation history.

