# ADR-007: Source strength from pinned families

## Status

Proposed. The pins, join, and tests below are implemented. This does not approve a rule, and strength is not exploitability.

## Date

2026-10-02

## Context

A node should be usable from one source or from a combination. The families in view are MITRE ATT&CK, the AWS Threat Technique Catalog, and OWASP Cloud-Native Top 10. NVD and CISA KEV are free public feeds that can add support when a record is explicitly linked. Combining families should raise strength automatically. One or two families is enough. The AWS catalog can be attached later.

## Decision

- Strength is the number of distinct source families on a node: `mitre-attack`, `owasp-cloud`, `aws-ttc`, `nvd`, and `cisa-kev`. Extra records from the same family do not raise strength again.
- `individual` means strength 1. `combined` means strength 2 or more.
- Runtime loading reads pinned JSON and checks SHA-256. It does not call NVD, CISA, MITRE, or OWASP.
- OWASP is the 2022 Cloud-Native Top 10 short names only (CNAS-1 through CNAS-10). Guidance prose is not stored.
- NVD is one keyless API 2.0 page, keyword `AWS IAM`, five CVE ids, no descriptions. Retrieved 2026-10-02. `totalResults` was 43.
- CISA KEV catalog `2026.10.02` is stored as catalog metadata for 1733 records. The vendor/product filter for Amazon or AWS as a whole token matched none, so no KEV row is attached.
- Local curated links, not an official joint publication: CNAS-3 joins T1078, T1078.001, T1078.004, T1098, T1098.001, T1098.003, and T1098.004. CNAS-7 joins CVE-2018-9057, CVE-2020-16250, and CVE-2022-2385. CVE-2019-10200 and CVE-2021-22969 stay keyword hits with strength 1.
- An unknown id, a hash mismatch, or a KEV id while the match list is empty fails closed.
- `aws-ttc` remains in the formula. The shipped dataset status is `not_ingested`.
- Every opportunity stays `no_rule_yet`. Engine 3 still receives a rule only after human approval.
- The compact catalog file stores those nodes in system terms: technique, weakness, vulnerability, or catalog. The automated join writes it. A model is not used as the builder. A later model may only check a finished catalog.

## Consequences

- Most of the 50 ATT&CK rows stay strength 1. Twelve nodes are combined in this pin.
- A later AWS TTC adapter can add that family and raise strength without changing the count rule.
- A later KEV catalog that actually names an AWS product can be linked only after the pin's match list contains that CVE id.
