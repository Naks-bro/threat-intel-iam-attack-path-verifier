"""Compare two selected IAM identity questions without assigning risk labels.

This is a proposed, read-only integration contract. It compares recorded
policy text, not effective AWS permissions or account security posture.
"""

from dataclasses import dataclass
from typing import Literal

from pydantic import ConfigDict, Field

from fyp_iam.contracts.inventory import CollectionHandoff
from fyp_iam.contracts.models import ContractModel
from fyp_iam.engine2.credential_policy_text import (
    CredentialPolicyTextResult,
    inspect_create_access_key_policy_text,
)


@dataclass(frozen=True)
class CredentialPolicyQuestion:
    handoff: CollectionHandoff
    source_principal_key: str
    target_user_key: str


class PairedCredentialPolicyText(ContractModel):
    """A fixed pair of observations; never a vulnerable/secure verdict."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    comparison_version: Literal["paired-credential-policy-text-0.1"] = (
        "paired-credential-policy-text-0.1"
    )
    data_kind: Literal["synthetic", "real_account_observed"]
    first: CredentialPolicyTextResult
    second: CredentialPolicyTextResult
    snapshot_basis: Literal["shared_snapshot", "different_snapshots"]
    contrast: Literal[
        "candidate_only_first",
        "candidate_only_second",
        "no_policy_text_contrast",
        "requires_review",
        "different_snapshot_context",
    ]
    authorization_evaluated: Literal[False] = False
    account_security_assessment: Literal["not_assessed"] = "not_assessed"
    caution_codes: tuple[str, ...] = Field(default_factory=tuple)


def compare_credential_policy_text(
    first: CredentialPolicyQuestion, second: CredentialPolicyQuestion
) -> PairedCredentialPolicyText:
    """Run the same bounded policy-text question for two distinct identities.

    Different snapshots are permitted for review, but cannot produce a matched
    contrast claim; missing coverage is never converted into a clean label.
    """

    first_sealed = CollectionHandoff.model_validate_json(first.handoff.model_dump_json())
    second_sealed = CollectionHandoff.model_validate_json(second.handoff.model_dump_json())
    if first_sealed.manifest.data_kind != second_sealed.manifest.data_kind:
        raise ValueError("mixed_data_kinds_not_comparable")

    same_id = first_sealed.inventory.snapshot_id == second_sealed.inventory.snapshot_id
    same_digest = first_sealed.manifest.snapshot_digest == second_sealed.manifest.snapshot_digest
    if same_id != same_digest:
        raise ValueError("snapshot_identity_conflict")
    shared_snapshot = same_id and same_digest
    if shared_snapshot:
        if first_sealed.manifest != second_sealed.manifest:
            raise ValueError("shared_snapshot_manifest_conflict")
        if first.source_principal_key == second.source_principal_key:
            raise ValueError("starting_identities_must_differ")
        if first.target_user_key != second.target_user_key:
            raise ValueError("shared_snapshot_target_must_match")

    first_result = inspect_create_access_key_policy_text(
        first_sealed, first.source_principal_key, first.target_user_key
    )
    second_result = inspect_create_access_key_policy_text(
        second_sealed, second.source_principal_key, second.target_user_key
    )
    caution: set[str] = set()
    if not shared_snapshot:
        contrast = "different_snapshot_context"
        caution.add("environmental_differences_not_controlled")
    elif first_result.uncertainty_codes or second_result.uncertainty_codes:
        contrast = "requires_review"
        caution.add("policy_text_uncertainty")
    elif first_result.status == "policy_text_candidate" and (
        second_result.status == "no_observed_identity_allow"
    ):
        contrast = "candidate_only_first"
    elif second_result.status == "policy_text_candidate" and (
        first_result.status == "no_observed_identity_allow"
    ):
        contrast = "candidate_only_second"
    elif first_result.status == second_result.status:
        contrast = "no_policy_text_contrast"
    else:
        contrast = "requires_review"
        caution.add("different_nonbinary_policy_text_states")

    if first_result.coverage_gap_codes or second_result.coverage_gap_codes:
        caution.add("source_coverage_gaps_present")
    return PairedCredentialPolicyText(
        data_kind=first_result.data_kind,
        first=first_result,
        second=second_result,
        snapshot_basis="shared_snapshot" if shared_snapshot else "different_snapshots",
        contrast=contrast,
        caution_codes=tuple(sorted(caution)),
    )
