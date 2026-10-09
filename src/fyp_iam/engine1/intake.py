"""Pinned local CTI intake. This module does not fetch a network resource or call a model."""

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from fyp_iam.contracts.models import (
    Approval,
    ApprovalDecision,
    ApprovedRule,
    CreatedBy,
    CreatorKind,
    EdgeType,
    PatternStep,
    Precondition,
    RequiredCapability,
    ResourceSelector,
    RuleStatus,
    Severity,
    TechniqueRef,
)
from fyp_iam.core.ids import stable_id
from fyp_iam.engine1.errors import IntakeError
from fyp_iam.engine1.models import (
    ApprovalEvent,
    NormalizedTechnique,
    SourceArtifact,
    SourceProvenance,
)

_METHOD = "allowlisted-technique-map-0.1"
_ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
_PINNED_SHA256 = {
    "attack-t1548-assume-chain": (
        "sha256:bd5d58ba5bdb5c354b498df9bf09b1d3183955d76f44b237d05604a3b627ce32"
    ),
    "attack-t9999-unmapped": (
        "sha256:444c1b085e1646f99e4e8960f5eb003a7d869abc0c13b255530768e32b7a4a66"
    ),
}


@dataclass(frozen=True)
class _Mapping:
    rule_id: str
    title: str
    description: str
    limitation: str


_MAPPINGS = {
    ("mitre-attack", "T1548"): _Mapping(
        rule_id="rule_t1548_assume_chain",
        title="Two-hop role assumption to an administrative role",
        description=(
            "A principal may reach another role through two derived CAN_ASSUME edges. "
            "The description is data and is never executed."
        ),
        limitation=(
            "This local pin maps one curated assume-chain pattern onto T1548. "
            "It is not the full technique, and it does not evaluate IAM policy JSON."
        ),
    )
}


def mapped_rule_id(framework: str, external_id: str) -> str | None:
    """Return the allowlisted rule id. Other technique ids stay unmapped."""

    mapping = _MAPPINGS.get((framework, external_id))
    if mapping is None:
        return None
    return mapping.rule_id


def fetch_remote_source(reference: str) -> None:
    """Refuse every remote fetch. The reference is not requested."""

    if not reference:
        raise IntakeError("network_disabled", "CTI intake does not fetch remote sources")
    raise IntakeError("network_disabled", "CTI intake does not fetch remote sources")


def load_artifact(artifact_id: str) -> tuple[SourceArtifact, str]:
    if artifact_id not in _PINNED_SHA256 or not re.fullmatch(r"[a-z0-9-]{1,64}", artifact_id):
        raise IntakeError("unknown_artifact", "artifact is not available")
    root = _ARTIFACTS.resolve()
    path = (root / f"{artifact_id}.json").resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise IntakeError("unknown_artifact", "artifact is not available")
    raw = path.read_bytes()
    digest = _sha256(raw)
    if digest != _PINNED_SHA256[artifact_id]:
        raise IntakeError("hash_mismatch", "artifact hash does not match the pin")
    return parse_artifact(raw, artifact_id), digest


def parse_artifact(raw: bytes, artifact_id: str) -> SourceArtifact:
    try:
        artifact = SourceArtifact.model_validate_json(raw)
    except ValidationError as exc:
        _raise_from_validation(exc)
    if artifact.artifact_id != artifact_id:
        raise IntakeError("invalid_artifact", "artifact id does not match the requested pin")
    return artifact


def normalize_technique(artifact: SourceArtifact, artifact_sha256: str) -> NormalizedTechnique:
    relevant = (artifact.framework, artifact.external_id) in _MAPPINGS
    return NormalizedTechnique(
        schema_version="0.1",
        record_id=stable_id("cti", artifact.artifact_id, artifact_sha256),
        provenance=SourceProvenance(
            source_name=artifact.source_name,
            source_version=artifact.source_version,
            retrieved_at=artifact.retrieved_at,
            official_reference=artifact.official_reference,
            license_note=artifact.license_note,
            artifact_sha256=artifact_sha256,
        ),
        framework=artifact.framework,
        external_id=artifact.external_id,
        technique_name=artifact.technique_name,
        aws_iam_relevant=relevant,
        evidence_excerpt=artifact.excerpt,
        evidence_location=artifact.excerpt_location,
    )


def propose_rule(record: NormalizedTechnique) -> ApprovedRule:
    mapping = _MAPPINGS.get((record.framework, record.external_id))
    if mapping is None or not record.aws_iam_relevant:
        raise IntakeError("unsupported_technique", "no curated IAM mapping is available")
    evidence_id = f"evidence_{record.provenance.artifact_sha256[7:23]}"
    return ApprovedRule(
        schema_version="0.1",
        rule_id=mapping.rule_id,
        rule_version=1,
        title=mapping.title,
        description=mapping.description,
        status=RuleStatus.proposed,
        severity=Severity.high,
        technique_refs=[
            TechniqueRef(
                framework=record.framework,
                external_id=record.external_id,
                version=record.provenance.source_version,
            )
        ],
        required_capabilities=[
            RequiredCapability(
                action="sts:AssumeRole",
                resource_selector=ResourceSelector(kind="role", constraint="derived_edge"),
            )
        ],
        preconditions=[
            Precondition(
                type="role_trusts_service",
                subject="admin_role",
                value="lambda.amazonaws.com",
            )
        ],
        path_pattern=[
            PatternStep(from_role="principal", relationship=EdgeType.CAN_ASSUME, to_role="mid"),
            PatternStep(from_role="mid", relationship=EdgeType.CAN_ASSUME, to_role="admin_role"),
        ],
        evidence_refs=[evidence_id],
        limitations=[mapping.limitation],
        approval=Approval(
            decision=ApprovalDecision.pending,
            reviewer_id="pending_review",
            decided_at=record.provenance.retrieved_at,
            comment="Awaiting human approval of the curated mapping.",
        ),
        created_by=CreatedBy(kind=CreatorKind.deterministic, model_or_method=_METHOD),
        created_at=record.provenance.retrieved_at,
    )


def explain_proposal(record: NormalizedTechnique, rule: ApprovedRule) -> str:
    """Say why the allowlist proposed the rule. The excerpt is not copied in."""

    steps = ", ".join(
        f"{step.from_role} {step.relationship.value} {step.to_role}" for step in rule.path_pattern
    )
    return (
        "The technique id is on the local allowlist. "
        f"Candidate {rule.rule_id} uses this path: {steps}. "
        "The source excerpt was not copied into the title or description. "
        "No model wrote this rule."
    )


def decide_candidate(
    artifact_id: str,
    *,
    decision: ApprovalDecision,
    reviewer_id: str,
    decided_at: datetime,
    comment: str,
) -> tuple[ApprovalEvent, ApprovedRule | None]:
    """Record one human decision. A rejection returns no exported rule."""

    artifact, digest = load_artifact(artifact_id)
    record = normalize_technique(artifact, digest)
    rule = propose_rule(record)
    validate_candidate(rule, record)
    try:
        event = record_approval(
            rule,
            record,
            decision=decision,
            reviewer_id=reviewer_id,
            decided_at=decided_at,
            comment=comment,
        )
    except ValidationError as exc:
        raise IntakeError("invalid_approval", "approval text was rejected") from exc
    if decision == ApprovalDecision.rejected:
        return event, None
    return event, export_approved_rule(rule, record, event)


def validate_candidate(rule: ApprovedRule, record: NormalizedTechnique) -> None:
    mapping = _MAPPINGS.get((record.framework, record.external_id))
    evidence_id = f"evidence_{record.provenance.artifact_sha256[7:23]}"
    checks = (
        mapping is not None,
        rule.status == RuleStatus.proposed,
        rule.approval.decision == ApprovalDecision.pending,
        rule.created_by.kind == CreatorKind.deterministic,
        rule.created_by.model_or_method == _METHOD,
        mapping is not None and rule.rule_id == mapping.rule_id,
        mapping is not None and rule.title == mapping.title,
        mapping is not None and rule.description == mapping.description,
        record.evidence_excerpt not in rule.title,
        record.evidence_excerpt not in rule.description,
        rule.technique_refs[0].external_id == record.external_id,
        all(step.relationship == EdgeType.CAN_ASSUME for step in rule.path_pattern),
        all(item.action == "sts:AssumeRole" for item in rule.required_capabilities),
        all(item.type == "role_trusts_service" for item in rule.preconditions),
        rule.evidence_refs == [evidence_id],
    )
    if not all(checks):
        raise IntakeError("invalid_candidate", "candidate failed the closed validation")


def record_approval(
    rule: ApprovedRule,
    record: NormalizedTechnique,
    *,
    decision: ApprovalDecision,
    reviewer_id: str,
    decided_at: datetime,
    comment: str,
) -> ApprovalEvent:
    if decision not in {ApprovalDecision.approved, ApprovalDecision.rejected}:
        raise IntakeError("approval_mismatch", "approval must be approved or rejected")
    if reviewer_id == "pending_review":
        raise IntakeError("approval_mismatch", "a human reviewer alias is required")
    return ApprovalEvent(
        schema_version="0.1",
        event_id=stable_id(
            "approval",
            rule.rule_id,
            str(rule.rule_version),
            record.provenance.artifact_sha256,
            decision.value,
            reviewer_id,
            decided_at.isoformat(),
            "synthetic-benchmark",
        ),
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        artifact_sha256=record.provenance.artifact_sha256,
        decision=decision.value,
        reviewer_id=reviewer_id,
        decided_at=decided_at,
        comment=comment,
        scope="synthetic-benchmark",
    )


def export_approved_rule(
    rule: ApprovedRule,
    record: NormalizedTechnique,
    event: ApprovalEvent,
) -> ApprovedRule:
    validate_candidate(rule, record)
    if event.decision != ApprovalDecision.approved.value:
        raise IntakeError("not_approved", "only an approved decision can be exported")
    if (
        event.rule_id != rule.rule_id
        or event.rule_version != rule.rule_version
        or event.artifact_sha256 != record.provenance.artifact_sha256
        or event.scope != "synthetic-benchmark"
    ):
        raise IntakeError("approval_mismatch", "approval event does not match the candidate")
    return rule.model_copy(
        update={
            "status": RuleStatus.approved,
            "approval": Approval(
                decision=ApprovalDecision.approved,
                reviewer_id=event.reviewer_id,
                decided_at=event.decided_at,
                comment=event.comment,
            ),
        }
    )


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _raise_from_validation(exc: ValidationError) -> None:
    text = str(exc)
    if "executable" in text or "disallowed credential" in text:
        raise IntakeError("unsafe_content", "artifact text was rejected") from exc
    if "official reference" in text:
        raise IntakeError("bad_reference", "artifact reference was rejected") from exc
    raise IntakeError("invalid_artifact", "artifact did not match the local schema") from exc
