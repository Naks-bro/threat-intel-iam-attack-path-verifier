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

## Local intake in this checkout

**Verified** for one pinned file, and **Proposed** as a process (ADR-005). This is not the multi-source parser reported in the chats.

- `src/fyp_iam/engine1/artifacts/attack-t1548-assume-chain.json` is a local pin. Its SHA-256 is checked in code. `https://attack.mitre.org/techniques/T1548/` is stored as a reference and is not fetched.
- The excerpt is evidence. A code allowlist maps that technique id to the two-hop `CAN_ASSUME` pattern already used by the fixture slice, including `role_trusts_service` for `lambda.amazonaws.com`.
- `POST /v1/rules/intake` returns a `proposed` rule with approval `pending`. It accepts an artifact id, not a URL.
- `GET /reviews/rules/attack-t1548-assume-chain` shows the pin, the excerpt, and why the allowlist proposed the rule. Opening the page does not approve it.
- `POST /v1/rules/approval` records one human decision. An `approved` decision exports the rule for the synthetic benchmark. A rejected decision exports nothing. That decision is not stored in PostgreSQL yet.
- `GET /v1/workbench/fixtures/attack-t1548-assume-chain` repeats the same pin as a pending candidate without writing. `POST /v1/workbench/imports/attack-t1548-assume-chain` writes it only when PostgreSQL is reachable.
- Engine 3 matches that exported rule on the positive fixture and returns `supported_by_fixture`. Simulator status stays `not_run`.
- An unmapped technique, a hash mismatch, markup, or a non-allowlisted reference fails closed.
- `src/fyp_iam/engine1/artifacts/cloud-techniques-50.json` is a separate dataset of 50 Enterprise ATT&CK 19.2 techniques that list the IaaS platform. Names and ids are stored. Descriptions are not. `GET /v1/datasets/cloud-techniques` reads that file and does not download ATT&CK. Every row is `no_rule_yet` until an allowlisted mapping exists. The review page at `GET /reviews/datasets/cloud-techniques` lists the same rows and does not send them to path search.
- A node may stand on one source or combine sources. Strength is the count of distinct families among `mitre-attack`, `owasp-cloud`, `nvd`, `cisa-kev`, and `aws-ttc`. One or two families is valid. `GET /v1/datasets/opportunities` builds that join from pinned files and does not download them. `GET /reviews/datasets/opportunities` lists the nodes. Strength is not a rule and is not sent to path search. AWS TTC is a family in the formula and is not ingested in this checkout.
- OWASP Cloud-Native Top 10 (2022) is pinned as ten short names, CNAS-1 through CNAS-10. Guidance prose is not stored. A local curated link joins CNAS-3 to the account techniques already in the 50-row set: T1078, T1078.001, T1078.004, T1098, T1098.001, T1098.003, and T1098.004. That link is not an official joint publication.
- NVD CVE API 2.0 was called once without an API key. The pin keeps the first five CVE ids for keyword `AWS IAM` (`totalResults` 43) and does not store descriptions. Only CVE-2018-9057, CVE-2020-16250, and CVE-2022-2385 are linked to CNAS-7. The other two keyword hits stay individual nodes.
- CISA KEV catalog `2026.10.02` (1733 records, feed retrieved 2026-10-02) is pinned as catalog metadata. A vendor/product filter for Amazon or AWS as a whole token matched no rows, so KEV does not raise any technique strength.
- `src/fyp_iam/engine1/artifacts/source-catalog.json` is the compact catalog stored for this system. Each row states a data kind: `technique`, `weakness`, `vulnerability`, or `catalog`. Technique rows also store platforms and tactics. `produced_by` is `automated-source-join-0.1` and `checker` is `not_used`. `GET /v1/datasets/source-catalog` and `GET /reviews/datasets/opportunities` read that file. They do not rebuild it and they do not call a model.

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

- Exact AWS TTC machine-access method and licensing/versioning behavior. The strength formula can count an `aws-ttc` support, and this checkout does not ingest that catalog.
- LLM provider, privacy terms, model version, cost limits, and reproducibility settings.
- Rule ontology: complete operators, resource selectors, and supported IAM condition semantics.

## Acceptance criteria

- At least one source fixture parses reproducibly with no network access.
- Normalized output has provenance and a stable schema.
- Invalid or unsupported generated rules fail closed.
- Approval events are auditable and only approved rules are exported.
- A contract test proves Engine 3 can consume the exported fixture.

