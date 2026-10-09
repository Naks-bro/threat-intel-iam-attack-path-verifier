"""Computed pre-publication assessment; never a publication or AWS capability."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fyp_iam.engine1.foundry.quality import QualityReport
from fyp_iam.engine1.foundry.review import Digest, Identifier, ReviewRecord, ReviewScope
from fyp_iam.engine1.foundry.verifier_models import VerifierRecordSummary

Channel = Literal["experimental", "stable"]
Blocker = Literal[
    "quality_missing",
    "quality_not_passing",
    "assurance_binding_mismatch",
    "verifier_missing",
    "verifier_not_passing",
    "verifier_policy_unconfigured",
    "review_missing",
    "review_not_approved",
    "review_binding_mismatch",
    "experimental_not_opted_in",
]


class PublicationAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    policy_version: Literal["local-benchmark-gate-0.1"] = "local-benchmark-gate-0.1"
    rule_version_id: Identifier
    rule_semantic_hash: Digest
    scope: ReviewScope
    channel: Channel
    eligible_for_publication: bool = Field(strict=True)
    blockers: tuple[Blocker, ...]
    export_available: Literal[False] = False
    published: Literal[False] = False

    @model_validator(mode="after")
    def consistent(self) -> "PublicationAssessment":
        if self.eligible_for_publication != (not self.blockers):
            raise ValueError("publication assessment contradicts blockers")
        if len(set(self.blockers)) != len(self.blockers):
            raise ValueError("duplicate publication blocker")
        return self


def assess_publication(
    *,
    version_id: str,
    semantic_hash: str,
    scope: ReviewScope,
    channel: Channel,
    quality: QualityReport | None,
    verifier: VerifierRecordSummary | None,
    review: ReviewRecord | None,
    allow_experimental: bool = False,
) -> PublicationAssessment:
    """Assess rechecked current inputs; the caller must supply the latest scoped review.

    Only the explicit local fake benchmark policy exists today. Provider names
    are not proof of independently verified AI; every other policy fails closed.
    No candidate mutation, release creation, export, or cloud call occurs here.
    """
    blockers: list[Blocker] = []
    if quality is None:
        blockers.append("quality_missing")
    elif quality.status != "pass":
        blockers.append("quality_not_passing")
    if verifier is None:
        blockers.append("verifier_missing")
    elif verifier.verdict != "pass":
        blockers.append("verifier_not_passing")
    if scope != "synthetic_benchmark" or (
        verifier is not None and (verifier.provider, verifier.model) != ("fake", "schema-only")
    ):
        blockers.append("verifier_policy_unconfigured")
    if (
        quality is not None
        and (quality.rule_version_id != version_id or quality.rule_semantic_hash != semantic_hash)
    ) or (
        verifier is not None
        and (
            verifier.rule_version_id != version_id
            or verifier.rule_semantic_hash != semantic_hash
            or (
                quality is not None
                and verifier.evidence_snapshot_hash != quality.evidence_snapshot_hash
            )
        )
    ):
        blockers.append("assurance_binding_mismatch")
    if channel == "experimental" and not allow_experimental:
        blockers.append("experimental_not_opted_in")
    # A negative decision blocks both channels; experimental never bypasses it.
    if review is None:
        if channel == "stable":
            blockers.append("review_missing")
    else:
        command = review.command
        if command.decision != "approved":
            blockers.append("review_not_approved")
        if (
            command.rule_version_id != version_id
            or command.rule_semantic_hash != semantic_hash
            or command.scope != scope
            or quality is None
            or verifier is None
            or command.evidence_snapshot_hash != quality.evidence_snapshot_hash
            or command.evidence_snapshot_hash != verifier.evidence_snapshot_hash
            or command.quality_report_hash != quality.report_hash
            or command.verifier_request_hash != verifier.request_hash
            or command.verifier_response_hash != verifier.response_hash
        ):
            blockers.append("review_binding_mismatch")
    return PublicationAssessment(
        rule_version_id=version_id,
        rule_semantic_hash=semantic_hash,
        scope=scope,
        channel=channel,
        eligible_for_publication=not blockers,
        blockers=tuple(blockers),
    )
