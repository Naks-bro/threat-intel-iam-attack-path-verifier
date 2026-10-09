# ADR-006: Fifty-row cloud technique dataset

## Status

Proposed. The file and loader below are implemented and covered by tests. This does not approve 50 rules.

## Date

2026-10-02

## Context

The charter asks for a small versioned set of AWS-relevant threat records before a wider catalog. ATT&CK Enterprise publishes STIX JSON. The AWS Threat Technique Catalog and OWASP document do not have a confirmed stable API, so they are not in this dataset.

## Decision

- Build 50 rows from local processing of Enterprise ATT&CK 19.2, collection modified `2026-08-05T21:33:58.496Z`.
- Keep attack-pattern objects that are not revoked and list platform `IaaS`. Sort by technique id and keep the first 50. That release had 104 such rows.
- Store technique id, name, platforms, tactics, STIX id, and the official technique URL. Do not store technique descriptions.
- Pin the dataset file by SHA-256. `load_cloud_technique_dataset` does not download the bundle.
- Mark every row `no_rule_yet` unless its technique id is already on the rule allowlist. None of these 50 ids is on that allowlist. The existing T1548 pin stays a separate artifact.
- `GET /reviews/datasets/cloud-techniques` lists the rows. The page does not approve them and does not start path search.

## Consequences

- Engine 3 still receives a rule only after human approval of an allowlisted pattern.
- A later page of this dataset can take the remaining IaaS rows. OWASP short names, a small NVD page, and the CISA KEV catalog metadata are pinned separately in ADR-007. AWS TTC still needs its own adapter.
