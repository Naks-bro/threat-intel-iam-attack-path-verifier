"""Closed vocabulary for the first foundry rule family.

The cross-engine contract accepts broader strings. This module narrows what
Engine 1 may compile; new families must be added deliberately and tested.
"""

from __future__ import annotations

from fyp_iam.contracts.models import ApprovedRule

ONTOLOGY_VERSION = "foundry-ontology-0.1"

_CAPABILITIES = {("iam:CreateAccessKey", "user", "iam_user")}
_PRECONDITIONS = {("target_is_iam_user", "target_user", "iam_user")}
_PATTERN_STEPS = {("principal", "CAN_CREATE_AS", "target_user")}


def ontology_findings(rule: ApprovedRule) -> list[str]:
    """Return unsupported semantics; an empty list permits compilation."""

    findings: list[str] = []
    for capability in rule.required_capabilities:
        key = (
            capability.action,
            capability.resource_selector.kind,
            capability.resource_selector.constraint,
        )
        if key not in _CAPABILITIES:
            findings.append(f"unsupported capability: {capability.action}")
    for precondition in rule.preconditions:
        key = (precondition.type, precondition.subject, precondition.value)
        if key not in _PRECONDITIONS:
            findings.append(f"unsupported precondition: {precondition.type}")
    for step in rule.path_pattern:
        key = (step.from_role, step.relationship.value, step.to_role)
        if key not in _PATTERN_STEPS:
            findings.append(f"unsupported path relationship: {step.relationship.value}")
    if (
        len(rule.required_capabilities) != 1
        or len(rule.preconditions) != 1
        or len(rule.path_pattern) != 1
    ):
        findings.append("unsupported rule shape for additional credentials")
    if len(rule.technique_refs) != 1 or (
        rule.technique_refs[0].framework,
        rule.technique_refs[0].external_id,
    ) != ("mitre-attack", "T1098.001"):
        findings.append("unsupported technique mapping for additional credentials")
    return findings
