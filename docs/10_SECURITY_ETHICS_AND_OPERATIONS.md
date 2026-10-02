# Security, Ethics, and Safe Operations

## Authorization

Analyze only AWS accounts, data, and lab scenarios the team owns or has explicit written permission to assess. Educational intent does not authorize access to someone else's environment.

## Live-account policy

- Collector credentials are read-only and least-privilege.
- No automatic remediation, policy attachment, role assumption for exploitation, resource creation, or destructive action.
- Account IDs, ARNs, policy documents, and findings are sensitive; minimize, encrypt, redact, and control access.
- Log credential metadata only when essential; never log secrets, session tokens, or access keys.

## Sandbox policy

- Dedicated disposable account, never production or an account with sensitive resources.
- Explicit account allowlist and environment flag.
- Region allowlist, spending budget/alarm, quotas, and run deadline.
- Record resources created by run ID.
- Automated teardown plus independent post-teardown inventory.
- Manual incident procedure when cleanup fails.
- CloudGoat's own warning applies: it creates intentionally vulnerable resources and only manages resources it created.

## LLM and external-service policy

- Do not send live account policies, sensitive ARNs, credentials, logs, or customer data to an external model without documented approval.
- Prefer sanitized fixtures for development and evaluation.
- Treat generated content as untrusted input.
- Enforce schemas, size limits, allowlists, and human review.
- Record model/provider/version and prompt hash for research reproducibility.

## Web ingestion controls

- Allowlist official source hosts.
- Block private, loopback, link-local, metadata-service, and redirected-to-private addresses.
- Limit downloads, decompression ratio, references, redirects, and processing time.
- Store raw artifacts as data; never execute embedded scripts/macros/instructions.
- Escape untrusted text in the UI.

## Threat model summary

| Threat | Control |
|---|---|
| Prompt/content injection in CTI | Treat content as data; constrained extraction; no tool instructions from source text |
| SSRF through reference fetcher | URL allowlist, DNS/IP validation, redirect revalidation, network egress controls |
| LLM-generated executable content | Closed rule DSL; reject Cypher/commands; deterministic compiler |
| Over-permissioned AWS collector | Dedicated role, least privilege, short-lived credentials, CloudTrail review |
| False-positive remediation harm | No auto-remediation; evidence and human approval |
| Vulnerable sandbox exposure | Dedicated account, IP allowlisting, deadlines, teardown verification |
| Evidence tampering | hashes, immutable run records, stable IDs, restricted write access |
| Sensitive data in research artifacts | aliases/hashes, minimization, access control, pre-release review |

## Responsible reporting

Clearly separate discovered weaknesses in team-owned fixtures from claims about real organizations or products. If a previously unknown vulnerability is found, stop public disclosure and follow coordinated disclosure with the affected vendor and guide.

