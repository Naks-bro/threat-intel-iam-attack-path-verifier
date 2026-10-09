"""In-memory additional-credentials observation for two starting identities."""

import ast
from datetime import UTC, datetime
from pathlib import Path

from tests.unit.test_inventory_handoff import USER, _paired_credential_handoff

from fyp_iam.contracts.inventory import CollectionHandoff, InventorySnapshot
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
from fyp_iam.core.ids import sha256_key
from fyp_iam.engine2 import paired_observation
from fyp_iam.engine2.paired_observation import (
    observe_additional_credentials_pair,
    paired_report_digest,
)

_WHEN = datetime(2026, 10, 9, tzinfo=UTC)
_CONTROL = "p_" + "6" * 32
_TARGET = "p_" + "9" * 32


def additional_credentials_rule(**overrides: object) -> ApprovedRule:
    payload: dict[str, object] = {
        "schema_version": "0.1",
        "rule_id": "rule_additional_cloud_credentials",
        "rule_version": 1,
        "title": "Creation of an additional access key",
        "description": "Policy text is data and is never executed.",
        "status": RuleStatus.proposed,
        "severity": Severity.high,
        "technique_refs": [
            TechniqueRef(framework="mitre-attack", external_id="T1098.001", version="19.2")
        ],
        "required_capabilities": [
            RequiredCapability(
                action="iam:CreateAccessKey",
                resource_selector=ResourceSelector(kind="user", constraint="iam_user"),
            )
        ],
        "preconditions": [
            Precondition(type="target_is_iam_user", subject="target_user", value="iam_user")
        ],
        "path_pattern": [
            PatternStep(
                from_role="principal",
                relationship=EdgeType.CAN_CREATE_AS,
                to_role="target_user",
            )
        ],
        "evidence_refs": ["evidence_additional_credentials"],
        "limitations": ["This observation does not evaluate effective AWS permission."],
        "approval": Approval(
            decision=ApprovalDecision.pending,
            reviewer_id="experimental_channel",
            decided_at=_WHEN,
            comment="Experimental publication is not a stable human approval.",
        ),
        "created_by": CreatedBy(kind=CreatorKind.deterministic, model_or_method="unit-test"),
        "created_at": _WHEN,
    }
    payload.update(overrides)
    return ApprovedRule.model_validate(payload)


def _observe(handoff: CollectionHandoff | None = None, **rule_overrides: object):
    sealed = handoff or _paired_credential_handoff()
    return observe_additional_credentials_pair(
        sealed, additional_credentials_rule(**rule_overrides), USER, _CONTROL
    )


def test_pair_shares_one_snapshot_digest_and_one_rule_digest() -> None:
    handoff = _paired_credential_handoff()
    rule = additional_credentials_rule()
    report = observe_additional_credentials_pair(handoff, rule, USER, _CONTROL)
    dumped = report.model_dump()
    assert report.first.label == "candidate_from_policy_text"
    assert report.second.label == "no_matching_statement"
    assert dumped["snapshot_digest"] == handoff.manifest.snapshot_digest
    assert dumped["rule_digest"] == sha256_key(rule.model_dump_json())
    assert "snapshot_digest" not in dumped["first"]
    assert "rule_digest" not in dumped["second"]
    assert report.report_digest == paired_report_digest(report)
    assert report.authorization_evaluated is False
    assert report.first.observed_facts == (
        "An Allow statement matching iam:CreateAccessKey is policy text.",
    )
    assert "supported_by_fixture" not in dumped
    assert "exposed" not in report.model_dump_json()
    assert "secure" not in report.model_dump_json()


def test_missing_group_traversal_forces_unknown_even_when_allow_text_exists() -> None:
    payload = _paired_credential_handoff().model_dump(mode="json")
    payload["manifest"]["data_kind"] = "real_account_observed"
    handoff = CollectionHandoff.model_validate(payload)
    report = _observe(handoff)
    assert report.data_kind == "real_account_observed"
    assert report.first.label == "unknown"
    assert report.second.label == "unknown"
    assert report.snapshot_digest == handoff.manifest.snapshot_digest
    assert "rule_digest" not in report.first.model_dump()
    assert "snapshot_digest" not in report.second.model_dump()
    assert "group_traversal_incomplete" in report.first.unknowns
    assert "group_traversal_incomplete" in report.second.unknowns
    assert report.first.inferences == ()
    assert report.authorization_evaluated is False


def test_complete_group_traversal_keeps_allow_as_policy_text() -> None:
    payload = _paired_credential_handoff().model_dump(mode="json")
    payload["manifest"]["data_kind"] = "real_account_observed"
    digest = "sha256:" + "2" * 64
    payload["inventory"]["group_traversals"] = [
        {
            "user_key": key,
            "state": "complete",
            "membership_count": count,
            "evidence_digest": digest,
        }
        for key, count in ((USER, 1), (_CONTROL, 0), (_TARGET, 0))
    ]
    payload["manifest"]["tasks"].extend(
        {
            "operation": "iam:ListGroupsForUser",
            "subject_principal_key": key,
            "attempt": 1,
            "outcome": "succeeded",
            "page_count": 1,
            "item_count": count,
            "pagination_complete": True,
            "response_digest": digest,
        }
        for key, count in ((USER, 1), (_CONTROL, 0), (_TARGET, 0))
    )
    payload["manifest"]["snapshot_digest"] = InventorySnapshot.model_validate(
        payload["inventory"]
    ).content_digest()
    report = _observe(CollectionHandoff.model_validate(payload))
    assert report.first.label == "candidate_from_policy_text"
    assert report.second.label == "no_matching_statement"
    assert report.first.unknowns
    assert "group_traversal_incomplete" not in report.first.unknowns
    assert report.authorization_evaluated is False
    assert report.snapshot_digest == payload["manifest"]["snapshot_digest"]


def test_explicit_deny_is_unknown_rather_than_a_grant_or_a_clean_miss() -> None:
    payload = _paired_credential_handoff().model_dump(mode="json")
    payload["inventory"]["statements"].append(
        {
            "statement_key": "st_" + "7" * 32,
            "policy_key": payload["inventory"]["statements"][0]["policy_key"],
            "effect": "deny",
            "action_mode": "action",
            "action_patterns": ["iam:CreateAccessKey"],
            "resource_mode": "all",
            "condition_state": "absent",
            "source_digest": "sha256:" + "2" * 64,
        }
    )
    payload["manifest"]["snapshot_digest"] = InventorySnapshot.model_validate(
        payload["inventory"]
    ).content_digest()
    report = _observe(CollectionHandoff.model_validate(payload))
    assert report.first.label == "unknown"
    assert report.second.label == "no_matching_statement"
    assert report.authorization_evaluated is False


def test_other_rule_families_and_duplicate_starts_are_rejected() -> None:
    handoff = _paired_credential_handoff()
    try:
        observe_additional_credentials_pair(
            handoff, additional_credentials_rule(rule_id="rule_other_family"), USER, _CONTROL
        )
    except ValueError as exc:
        assert str(exc) == "rule_family_rejected"
    else:
        raise AssertionError("wrong rule family was accepted")
    try:
        observe_additional_credentials_pair(handoff, additional_credentials_rule(), USER, USER)
    except ValueError as exc:
        assert str(exc) == "starting_identities_must_differ"
    else:
        raise AssertionError("duplicate starting identity was accepted")


def test_module_does_not_import_fixture_analysis_or_branch_walk() -> None:
    source = Path(paired_observation.__file__).read_text(encoding="utf-8")
    imported: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.append(node.module)
    assert imported
    assert all("engine3" not in name and "branch_walk" not in name for name in imported)
