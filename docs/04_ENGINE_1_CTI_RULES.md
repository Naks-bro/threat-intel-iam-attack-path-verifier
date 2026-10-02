# Engine 1 — CTI to Human-Approved IAM Rules

## Purpose

Engine 1 converts selected, versioned security knowledge into reviewable structural IAM rule candidates. It preserves evidence and uncertainty, validates the candidate deterministically, explains why it was proposed, and activates it only after human approval.

## Source strategy

| Source | Role | Access approach | Caveat |
|---|---|---|---|
| MITRE ATT&CK Cloud | Machine-readable adversary techniques and relationships | Official STIX repository or ATT&CK TAXII | ATT&CK describes behavior; it is not an IAM rulebook |
| AWS Threat Technique Catalog | AWS-specific observed techniques, detections, and mitigations | Verify official catalog format; begin with a versioned snapshot/manual adapter if no stable API exists | Do not call HTML scraping a stable connector until tested |
| OWASP Cloud-Native Application Security Top 10 | Curated supporting risks and controls | Pin a release/document and curate records | Guidance source, not a continuously updated CTI feed |
| NVD/CISA KEV | Optional CVE/exploitation enrichment | Official APIs/feeds | Usually secondary to the IAM/path research question |

## Pipeline

```text
source manifest
 -> source-specific adapter
 -> raw artifact + hash
 -> normalized CTI record
 -> AWS/IAM relevance filter
 -> technique/capability interpretation
 -> proposed structural IAM rule
 -> deterministic schema and semantic validation
 -> explanation + evidence links
 -> human review
 -> ApprovedRule
```

## Design rules

- Store the raw artifact or stable official reference, retrieval time, source version, license/usage note, and SHA-256 hash.
- Keep adapters source-specific. Do not build a single parser full of source-condition branches.
- Perform deterministic extraction first. Use an LLM only for genuinely semantic fields.
- Require structured output against a closed schema and reject extra executable fields.
- Separate evidence excerpts from model interpretation.
- Never ask an LLM to produce executable Cypher or cloud commands for downstream execution.
- A human reviews the proposed rule, evidence, assumptions, and limitations—not only a fluent explanation.

## Minimum first slice

Use one ATT&CK/AWS technique with an independently known IAM escalation pattern. Produce one proposed rule, review it, and export an `ApprovedRule v0.1` fixture. Do not implement all sources before this slice passes contract tests.

## Validation layers

1. **Schema:** required fields, enums, lengths, identifier formats.
2. **Source integrity:** official domain/repository, pinned version, hash, retrieval metadata.
3. **Semantic allowlist:** AWS action names, principal/resource types, condition operators, supported path predicates.
4. **Evidence:** each material claim links to a source artifact and location.
5. **Safety:** no executable payloads, HTML/script injection, unbounded references, or remote fetches from arbitrary hosts.
6. **Approval:** reviewer identity/alias, timestamp, scope, comment, and immutable decision event.

## Evaluation

- Adapter field accuracy against manually labeled fixtures.
- AWS/IAM relevance precision, recall, and F1 on a gold set with written labeling guidance.
- Rule schema-valid rate.
- Unsupported/hallucinated action rate.
- Evidence-entailment rate from blinded human review.
- Approval, rejection, and revision rates plus reviewer time.
- Inter-rater agreement where two reviewers are available.

## Known unknowns

- Exact AWS TTC machine-access method and licensing/versioning behavior.
- Exact OWASP document/version to curate.
- LLM provider, privacy terms, model version, cost limits, and reproducibility settings.
- Rule ontology: complete operators, resource selectors, and supported IAM condition semantics.

## Acceptance criteria

- At least one source fixture parses reproducibly with no network access.
- Normalized output has provenance and a stable schema.
- Invalid or unsupported generated rules fail closed.
- Approval events are auditable and only approved rules are exported.
- A contract test proves Engine 3 can consume the exported fixture.

