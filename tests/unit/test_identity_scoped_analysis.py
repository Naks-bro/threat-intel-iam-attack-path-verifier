"""A paired IAM pilot must analyze starting identities independently."""

import pytest

from fyp_iam.contracts.models import NodeType
from fyp_iam.engine3.pipeline import analyze
from fyp_iam.fixtures.builders import EVALUATED_AT, make_node, make_snapshot
from fyp_iam.fixtures.cases import credential_creation_case


def test_exposed_and_control_identities_share_snapshot_but_not_paths() -> None:
    case = credential_creation_case()
    snapshot = make_snapshot(
        "snapshot_pair_test",
        list(case.snapshot.nodes),
        list(case.snapshot.edges),
    )
    exposed = analyze(
        case.rules,
        snapshot,
        evaluated_at=EVALUATED_AT,
        start_node_id="principal:user/developer",
    )
    control = analyze(
        case.rules,
        snapshot,
        evaluated_at=EVALUATED_AT,
        start_node_id="principal:user/control",
    )
    assert len(exposed.attack_paths) == 1
    assert exposed.attack_paths[0].start_node_id == "principal:user/developer"
    assert control.attack_paths == []
    assert control.findings == []
    assert exposed.snapshot_id == control.snapshot_id
    assert exposed.graph_input_digest == control.graph_input_digest
    assert exposed.graph_input_digest == snapshot.content_digest()
    assert exposed.start_node_id == "principal:user/developer"
    assert control.start_node_id == "principal:user/control"
    assert exposed.input_rule_refs == control.input_rule_refs
    assert exposed.input_rule_digest == control.input_rule_digest
    assert exposed.input_rule_refs[0].rule_id == "rule_additional_cloud_credentials"


def test_same_snapshot_id_with_different_graph_bytes_cannot_share_digest() -> None:
    case = credential_creation_case()
    changed = make_snapshot(
        case.snapshot.snapshot_id,
        list(case.snapshot.nodes),
        list(case.snapshot.edges),
        complete=False,
        warnings=["a policy layer was not collected"],
    )
    original_report = analyze(case.rules, case.snapshot, evaluated_at=EVALUATED_AT)
    changed_report = analyze(case.rules, changed, evaluated_at=EVALUATED_AT)
    assert original_report.snapshot_id == changed_report.snapshot_id
    assert original_report.graph_input_digest != changed_report.graph_input_digest
    assert original_report.input_rule_digest == changed_report.input_rule_digest


def test_unknown_start_identity_is_not_mistaken_for_a_clean_result() -> None:
    case = credential_creation_case()
    with pytest.raises(ValueError, match="not in the snapshot"):
        analyze(case.rules, case.snapshot, start_node_id="principal:user/absent")


def test_non_principal_start_is_rejected() -> None:
    case = credential_creation_case()
    snapshot = make_snapshot(
        "snapshot_with_policy_node",
        [*case.snapshot.nodes, make_node("policy:example", NodeType.policy, "example")],
        list(case.snapshot.edges),
    )
    with pytest.raises(ValueError, match="must be a principal"):
        analyze(case.rules, snapshot, start_node_id="policy:example")


def test_local_fixture_verifier_rejects_real_account_snapshot_marker() -> None:
    case = credential_creation_case()
    snapshot = case.snapshot.model_copy(deep=True)
    snapshot.collection.permissions_profile = "real-read-only-account"
    with pytest.raises(ValueError, match="explicitly synthetic"):
        analyze(case.rules, snapshot, start_node_id="principal:user/developer")


def test_incomplete_collection_cannot_be_interpreted_as_no_path() -> None:
    case = credential_creation_case()
    snapshot = make_snapshot(
        "snapshot_pair_incomplete",
        list(case.snapshot.nodes),
        list(case.snapshot.edges),
        complete=False,
        warnings=["one policy layer was not collected"],
    )
    report = analyze(
        case.rules,
        snapshot,
        evaluated_at=EVALUATED_AT,
        start_node_id="principal:user/control",
    )
    assert report.attack_paths == []
    assert report.start_node_id == "principal:user/control"
    assert report.input_rule_refs
    assert any(issue.code == "collection_incomplete" for issue in report.issues)
