# Project Charter

## Problem

AWS authorization can become difficult to reason about when identity policies, trust policies, resource policies, permission boundaries, organization controls, and multi-step principal pivots interact. Existing threat knowledge describes attacker behavior, while IAM analysis tools model permissions and escalation paths. This project explores whether selected threat knowledge can be transformed into human-approved, structural IAM rules and used to produce explainable, evidence-backed findings against an AWS IAM graph.

## Research question

Can a contract-driven, human-approved pipeline translate selected AWS-relevant threat techniques into structural IAM rules that improve the traceability and usefulness of AWS IAM attack-path analysis without allowing generated content to act directly on production systems?

This is narrower and more testable than claiming a fully autonomous or continuously self-updating security platform.

## Objectives

1. Ingest and normalize a small, versioned set of AWS/IAM-relevant threat records with provenance.
2. Generate or curate candidate structural IAM rules and explain the supporting evidence.
3. Require a human to approve, reject, or request changes before activation.
4. Collect a controlled AWS IAM environment read-only and create a reproducible graph snapshot.
5. Match approved rules and discover bounded candidate privilege-escalation paths.
6. evaluate authorization using deterministic evidence, with sandbox execution only where a mapped lab scenario exists.
7. Present findings, uncertainty, limitations, and remediation guidance to a human reviewer.
8. Evaluate extraction quality, contract validity, detection quality, verification coverage, runtime, and reviewer usefulness.

## In scope for the minimum viable research prototype

- One AWS account or explicitly controlled multi-account fixture.
- IAM users, roles, groups where needed, managed/inline policies, role trust policies, permission boundaries, and a deliberately limited set of relevant resource policies and organization controls.
- MITRE ATT&CK cloud data and AWS Threat Technique Catalog as primary machine/semistructured inputs.
- One explicitly selected OWASP cloud-native document as curated supporting guidance.
- One end-to-end privilege-escalation pattern first, followed by a small benchmark set.
- Human approval, immutable audit events, and evidence references.
- Synthetic fixtures plus a dedicated sandbox account.

## Out of scope for the first version

- Autonomous remediation or production write access.
- Generic multi-cloud support.
- Universal parsing of arbitrary PDFs/web pages.
- Real-time SIEM, endpoint, malware, or IOC detection.
- Proving every graph path through CloudGoat.
- Treating ATT&CK technique IDs as executable detection rules.
- Training a GNN without an adequate labeled dataset and baseline comparison.
- Claiming complete coverage of AWS authorization semantics.

## Stakeholders

- Four student engine owners.
- Project guide and academic reviewers.
- Security analyst/reviewer using the dashboard.
- AWS account owner authorizing collection and sandbox use.

## Success criteria

The project succeeds when a reproducible demonstration can show:

```text
versioned source record
 -> normalized CTI with provenance
 -> reviewable rule candidate
 -> human-approved rule
 -> deterministic AWS fixture/graph snapshot
 -> bounded candidate path
 -> simulator and/or mapped sandbox evidence
 -> clear finding with uncertainty and remediation
```

Each arrow must have a versioned contract and test evidence. A polished UI without this traceability is not sufficient.

