"""Apply the additional-credentials rule to two identities on one sealed handoff.

This is an in-memory policy-text observation. An Allow stays policy text.
A missing real-account group traversal is unknown. The function does not call
Engine 3 ``analyze``, emit ``supported_by_fixture``, or assign exposed/control
labels. ``authorization_evaluated`` stays false.
"""

import hashlib
import json
from typing import Literal

from pydantic import ConfigDict, Field, field_validator

from fyp_iam.contracts.inventory import CollectionHandoff
from fyp_iam.contracts.models import ApprovedRule, ContractModel, reject_sensitive_text
from fyp_iam.core.ids import sha256_key
from fyp_iam.engine2.credential_policy_text import (
    CredentialPolicyTextResult,
    inspect_create_access_key_policy_text,
)

_RULE_ID: Literal["rule_additional_cloud_credentials"] = "rule_additional_cloud_credentials"
_ACTION = "iam:CreateAccessKey"
ObservationLabel = Literal["candidate_from_policy_text", "no_matching_statement", "unknown"]


class IdentityPolicyTextObservation(ContractModel):
    """One starting identity. No exposed, control, or authorization label."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal_key: str = Field(min_length=1, max_length=128)
    display_alias: str = Field(min_length=1, max_length=128)
    label: ObservationLabel
    observed_facts: tuple[str, ...] = Field(max_length=8)
    inferences: tuple[str, ...] = Field(max_length=8)
    unknowns: tuple[str, ...] = Field(max_length=32)

    @field_validator("principal_key", "display_alias")
    @classmethod
    def clean_identity(cls, value: str) -> str:
        return reject_sensitive_text(value)

    @field_validator("observed_facts", "inferences", "unknowns")
    @classmethod
    def clean_lines(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        for item in value:
            if not item or len(item) > 240:
                raise ValueError("observation line rejected")
            cleaned.append(reject_sensitive_text(item))
        return tuple(cleaned)


class PairedObservationReport(ContractModel):
    """Two results bound to one snapshot digest and one rule digest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    report_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    snapshot_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    rule_id: Literal["rule_additional_cloud_credentials"] = _RULE_ID
    rule_version: int = Field(ge=1, le=1000)
    rule_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    data_kind: Literal["synthetic", "real_account_observed"]
    first: IdentityPolicyTextObservation
    second: IdentityPolicyTextObservation
    authorization_evaluated: Literal[False] = False


def paired_report_digest(report: PairedObservationReport) -> str:
    """Hash the report without its own digest field."""

    payload = report.model_dump(mode="json", exclude={"report_digest"})
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def observe_additional_credentials_pair(
    handoff: CollectionHandoff,
    rule: ApprovedRule,
    first_principal_key: str,
    second_principal_key: str,
) -> PairedObservationReport:
    """Observe both starting identities against one sealed handoff and one rule.

    When the snapshot has exactly those two IAM users, each is screened against
    the other. Otherwise the single remaining IAM user is the shared target.
    Results are candidate-from-policy-text, no matching statement, or unknown.
    Neither identity is labelled exposed or control.
    """

    _require_rule(rule)
    if first_principal_key == second_principal_key:
        raise ValueError("starting_identities_must_differ")
    sealed = CollectionHandoff.model_validate_json(handoff.model_dump_json())
    starts = (first_principal_key, second_principal_key)
    first_target, second_target = _targets(sealed, starts)
    rule_digest = sha256_key(rule.model_dump_json())
    first = _observe_one(sealed, starts[0], first_target)
    second = _observe_one(sealed, starts[1], second_target)
    draft = PairedObservationReport(
        report_digest="sha256:" + ("0" * 64),
        snapshot_digest=sealed.manifest.snapshot_digest,
        rule_version=rule.rule_version,
        rule_digest=rule_digest,
        data_kind=sealed.manifest.data_kind,
        first=first,
        second=second,
    )
    return draft.model_copy(update={"report_digest": paired_report_digest(draft)})


def _require_rule(rule: ApprovedRule) -> None:
    capabilities = rule.required_capabilities
    selector = capabilities[0].resource_selector if len(capabilities) == 1 else None
    if (
        rule.rule_id != _RULE_ID
        or selector is None
        or capabilities[0].action != _ACTION
        or selector.kind != "user"
        or selector.constraint != "iam_user"
    ):
        raise ValueError("rule_family_rejected")


def _targets(handoff: CollectionHandoff, starts: tuple[str, str]) -> tuple[str, str]:
    """Choose the IAM user each starting identity is screened against."""

    users = [item.principal_key for item in handoff.inventory.principals if item.kind == "iam_user"]
    if len(users) == 2 and set(users) == set(starts):
        return starts[1], starts[0]
    others = [key for key in users if key not in set(starts)]
    if len(others) != 1:
        raise ValueError("target_user_not_unique")
    return others[0], others[0]


def _observe_one(
    handoff: CollectionHandoff, principal_key: str, target_user_key: str
) -> IdentityPolicyTextObservation:
    result = inspect_create_access_key_policy_text(handoff, principal_key, target_user_key)
    principal = next(
        item for item in handoff.inventory.principals if item.principal_key == principal_key
    )
    label = _label(result)
    facts, inferences, unknowns = _narrative(result, label)
    return IdentityPolicyTextObservation(
        principal_key=principal.principal_key,
        display_alias=principal.display_alias,
        label=label,
        observed_facts=facts,
        inferences=inferences,
        unknowns=unknowns,
    )


def _label(result: CredentialPolicyTextResult) -> ObservationLabel:
    gaps = set(result.uncertainty_codes) | set(result.coverage_gap_codes)
    if "group_traversal_incomplete" in gaps:
        return "unknown"
    if result.status == "policy_text_candidate":
        return "candidate_from_policy_text"
    if result.status == "no_observed_identity_allow":
        return "no_matching_statement"
    return "unknown"


def _narrative(
    result: CredentialPolicyTextResult, label: ObservationLabel
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    unknowns = tuple(sorted(set(result.uncertainty_codes) | set(result.coverage_gap_codes)))
    if label == "candidate_from_policy_text":
        return (
            ("An Allow statement matching iam:CreateAccessKey is policy text.",),
            ("The additional-credentials rule records a policy-text candidate.",),
            unknowns,
        )
    if label == "no_matching_statement":
        return (
            ("No identity-policy statement matched iam:CreateAccessKey.",),
            ("The additional-credentials rule has no matching statement for this identity.",),
            unknowns,
        )
    if "group_traversal_incomplete" in unknowns:
        facts = ("Group membership traversal is missing for this identity.",)
    else:
        facts = ("The additional-credentials rule cannot be resolved to policy text or no match.",)
    return facts, (), unknowns
