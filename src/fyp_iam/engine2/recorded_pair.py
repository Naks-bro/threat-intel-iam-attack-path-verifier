"""Select two observed IAM users and apply the additional-credentials rule.

The collector does not assign exposed or control labels. This module does not
call Engine 3 ``analyze`` or ``branch_walk``, and it does not emit
``supported_by_fixture``. ``authorization_evaluated`` stays false.
"""

from datetime import UTC, datetime

from fyp_iam.contracts.inventory import CollectionHandoff
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
from fyp_iam.engine2.paired_observation import (
    PairedObservationReport,
    observe_additional_credentials_pair,
)

_WHEN = datetime(2026, 10, 9, tzinfo=UTC)


def observation_rule() -> ApprovedRule:
    """The one rule family this real-account observation is allowed to apply."""

    return ApprovedRule(
        schema_version="0.1",
        rule_id="rule_additional_cloud_credentials",
        rule_version=1,
        title="Creation of an additional access key",
        description="Policy text is data and is never executed.",
        status=RuleStatus.proposed,
        severity=Severity.high,
        technique_refs=[
            TechniqueRef(framework="mitre-attack", external_id="T1098.001", version="19.2")
        ],
        required_capabilities=[
            RequiredCapability(
                action="iam:CreateAccessKey",
                resource_selector=ResourceSelector(kind="user", constraint="iam_user"),
            )
        ],
        preconditions=[
            Precondition(type="target_is_iam_user", subject="target_user", value="iam_user")
        ],
        path_pattern=[
            PatternStep(
                from_role="principal",
                relationship=EdgeType.CAN_CREATE_AS,
                to_role="target_user",
            )
        ],
        evidence_refs=["evidence_additional_credentials"],
        limitations=["This observation does not evaluate effective AWS permission."],
        approval=Approval(
            decision=ApprovalDecision.pending,
            reviewer_id="experimental_channel",
            decided_at=_WHEN,
            comment="Experimental publication is not a stable human approval.",
        ),
        created_by=CreatedBy(kind=CreatorKind.deterministic, model_or_method="recorded-pair"),
        created_at=_WHEN,
    )


def observe_recorded_user_pair(handoff: CollectionHandoff) -> PairedObservationReport:
    """Observe the two IAM users in one real-account handoff.

    Any other user count is refused. The two users are ordered by principal key
    and are not named exposed or control.
    """

    sealed = CollectionHandoff.model_validate_json(handoff.model_dump_json())
    if sealed.manifest.data_kind != "real_account_observed":
        raise ValueError("real_account_data_kind_required")
    users = [item for item in sealed.inventory.principals if item.kind == "iam_user"]
    if len(users) != 2:
        raise ValueError("starting_user_count_unsupported")
    ordered = tuple(sorted(users, key=lambda item: item.principal_key))
    report = observe_additional_credentials_pair(
        sealed,
        observation_rule(),
        ordered[0].principal_key,
        ordered[1].principal_key,
    )
    if report.authorization_evaluated is not False:
        raise ValueError("authorization_evaluated_rejected")
    if report.data_kind != "real_account_observed":
        raise ValueError("real_account_data_kind_required")
    return report
