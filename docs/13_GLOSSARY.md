# Glossary

## ApprovedRule

A versioned structural IAM rule that passed deterministic validation and a recorded human approval decision. It is not an executable query.

## Attack path

An ordered sequence of authorization-relevant relationships/capabilities by which one principal may reach a higher privilege or sensitive goal. A discovered path is a hypothesis until supported by further evidence.

## AWS TTC

AWS Threat Technique Catalog. AWS CIRT's AWS-specific threat-technique catalog based on MITRE ATT&CK Cloud.

## CTI

Cyber threat intelligence: evidence and knowledge about adversaries, behavior, vulnerabilities, indicators, and defensive context.

## Evidence

An immutable or content-addressed record supporting a claim: source excerpt, policy document reference, simulator request/result, graph derivation, or sandbox observation.

## Graph snapshot

An immutable, versioned representation of collected AWS authorization state and derived relationships at a point in time.

## GDS

Neo4j Graph Data Science library. Optional algorithms for graph analysis; results need domain validation.

## GNN

Graph neural network. An optional machine-learning approach for graph tasks, not a default project requirement and not a verification mechanism.

## Human in the loop

A workflow in which a qualified person reviews evidence and decides whether to approve a rule or recommendation. A button click without sufficient context is not meaningful human oversight.

## IAM

Identity and Access Management: identities, credentials, roles, policies, permissions, trust, and authorization controls.

## IAM Policy Simulator

An AWS service/tool that evaluates specified actions/resources against policies and context without making the actual service request. It has documented coverage limits.

## MITRE ATT&CK

A knowledge base of adversary tactics and techniques. ATT&CK IDs organize behavior; they are not executable detections or IAM rules by themselves.

## Normalization

Transforming source-specific records into a common internal schema while preserving the original data and provenance.

## Provenance

Where data came from, which version was used, when and how it was acquired, and how a derived artifact links back to it.

## Rule DSL

A constrained domain-specific representation of supported IAM capabilities, preconditions, and path patterns. Trusted code compiles it into queries/checks.

## STIX / TAXII

STIX is a structured language/serialization for CTI. TAXII is an HTTPS application protocol for exchanging CTI.

## Verification

The process of gathering evidence about a candidate path. This project uses graded statuses; graph discovery, simulation support, and sandbox success are distinct.

## XAI

Explainable AI. In this project, explanations must be evidence-grounded and must expose limitations rather than only provide fluent prose.

