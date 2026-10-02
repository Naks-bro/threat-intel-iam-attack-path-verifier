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

## Acceptance criteria

- UI never labels simulator-only evidence as sandbox verification.
- Explanations are traceable to evidence and survive a blinded factuality review.
- Priority ordering is deterministic for the baseline.
- Research exports contain no credentials or sensitive account identifiers.
- A finding can be reproduced without relying on conversation history.

