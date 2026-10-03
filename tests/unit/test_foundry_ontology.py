"""The compiler must reject unknown Engine 1 rule semantics."""

from fyp_iam.contracts.models import ApprovedRule
from fyp_iam.engine1.foundry.ontology import ontology_findings
from fyp_iam.engine1.foundry.pipeline import build_foundry


def _rule() -> ApprovedRule:
    overview = build_foundry(persisted=False, storage="not_written")
    candidate = overview["candidate"]
    assert isinstance(candidate, dict)
    return ApprovedRule.model_validate(candidate["rule"])


def test_compiled_credential_rule_uses_only_supported_vocabulary() -> None:
    rule = _rule()
    assert ontology_findings(rule) == []
    overview = build_foundry(persisted=False, storage="not_written")
    assert overview["candidate"]["semantic_hash"] == (
        "sha256:322da0c250b1b6c0f8fd1bfb9d38efbf6602314509eb5382fc3d906259e47fa7"
    )


def test_unknown_action_and_selector_fail_closed() -> None:
    rule = _rule()
    body = rule.model_dump(by_alias=True)
    body["required_capabilities"][0]["action"] = "iam:PassRole"
    assert ontology_findings(ApprovedRule.model_validate(body))
    body["required_capabilities"][0]["action"] = "iam:CreateAccessKey"
    body["required_capabilities"][0]["resource_selector"]["kind"] = "role"
    assert ontology_findings(ApprovedRule.model_validate(body))


def test_unknown_precondition_and_path_fail_closed() -> None:
    rule = _rule()
    body = rule.model_dump(by_alias=True)
    body["preconditions"][0]["type"] = "role_trusts_service"
    assert ontology_findings(ApprovedRule.model_validate(body))
    body["preconditions"][0]["type"] = "target_is_iam_user"
    body["path_pattern"][0]["relationship"] = "CAN_ASSUME"
    assert ontology_findings(ApprovedRule.model_validate(body))


def test_unrelated_technique_fails_closed() -> None:
    body = _rule().model_dump(by_alias=True)
    body["technique_refs"][0]["external_id"] = "T1548"
    assert "unsupported technique mapping for additional credentials" in ontology_findings(
        ApprovedRule.model_validate(body)
    )
