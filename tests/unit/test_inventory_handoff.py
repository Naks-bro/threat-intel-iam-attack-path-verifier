"""The proposed AWS handoff has sealed, redacted, local references only."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from fyp_iam.contracts.collection import PolicyLayer
from fyp_iam.contracts.handoff_preview import main as preview_main
from fyp_iam.contracts.handoff_preview import preview_file
from fyp_iam.contracts.inventory import CollectionHandoff, InventorySnapshot
from fyp_iam.engine2.credential_policy_text import inspect_create_access_key_policy_text
from fyp_iam.engine2.graph_import import GraphImportRejected, prepare_graph_import
from fyp_iam.engine2.graph_schema import metadata as graph_metadata
from fyp_iam.engine2.identity_observation import observe_identity
from fyp_iam.engine2.observed_graph import project_observed_inventory
from fyp_iam.engine2.paired_policy_text import (
    CredentialPolicyQuestion,
    compare_credential_policy_text,
)

USER = "p_" + "a" * 32
ROLE = "p_" + "b" * 32
GROUP = "p_" + "c" * 32
POLICY = "pol_" + "d" * 32
TRUST = "pol_" + "e" * 32
STATEMENT = "st_" + "f" * 32
TRUST_STATEMENT = "st_" + "1" * 32
DIGEST = "sha256:" + "2" * 64
HMAC = "hmac-sha256:" + "3" * 64
ROLE_HMAC = "hmac-sha256:" + "4" * 64
GROUP_HMAC = "hmac-sha256:" + "5" * 64


def _inventory() -> dict[str, object]:
    return {
        "snapshot_id": "snapshot_handoff_test",
        "principals": [
            {
                "principal_key": USER,
                "principal_fingerprint": HMAC,
                "kind": "iam_user",
                "display_alias": "user-00000001",
                "source_digest": DIGEST,
            },
            {
                "principal_key": ROLE,
                "principal_fingerprint": ROLE_HMAC,
                "kind": "iam_role",
                "display_alias": "role-00000002",
                "source_digest": DIGEST,
            },
            {
                "principal_key": GROUP,
                "principal_fingerprint": GROUP_HMAC,
                "kind": "iam_group",
                "display_alias": "group-00000003",
                "source_digest": DIGEST,
            },
        ],
        "policies": [
            {
                "policy_key": POLICY,
                "kind": "managed",
                "version_label": "v1",
                "is_default": True,
                "parse_state": "parsed",
                "source_digest": DIGEST,
            },
            {
                "policy_key": TRUST,
                "kind": "trust",
                "parse_state": "parsed",
                "source_digest": DIGEST,
            },
        ],
        "statements": [
            {
                "statement_key": STATEMENT,
                "policy_key": POLICY,
                "effect": "allow",
                "action_mode": "action",
                "action_patterns": ["iam:CreateAccessKey"],
                "resource_mode": "linked_principals",
                "resource_principal_keys": [ROLE],
                "condition_state": "absent",
                "source_digest": DIGEST,
            }
        ],
        "attachments": [
            {
                "principal_key": USER,
                "policy_key": POLICY,
                "kind": "managed",
                "source_digest": DIGEST,
            }
        ],
        "memberships": [{"user_key": USER, "group_key": GROUP, "source_digest": DIGEST}],
        "trust_statements": [
            {
                "statement_key": TRUST_STATEMENT,
                "policy_key": TRUST,
                "role_key": ROLE,
                "effect": "allow",
                "action_mode": "action",
                "action_patterns": ["sts:AssumeRole"],
                "trusted_principal_keys": [USER],
                "selector_state": "linked",
                "condition_state": "absent",
                "source_digest": DIGEST,
            }
        ],
    }


def _handoff(inventory: dict[str, object] | None = None) -> dict[str, object]:
    data = InventorySnapshot.model_validate(inventory or _inventory())
    return {
        "manifest": {
            "data_kind": "synthetic",
            "run_id": "run_handoff_test",
            "snapshot_id": data.snapshot_id,
            "account_alias": "lab-account",
            "account_fingerprint": HMAC,
            "collector_version": "contract-test-1",
            "started_at": datetime(2026, 10, 9, tzinfo=UTC),
            "sealed_at": datetime(2026, 10, 9, tzinfo=UTC) + timedelta(seconds=1),
            "outcome": "succeeded",
            "snapshot_digest": data.content_digest(),
            "tasks": [
                {
                    "operation": "iam:ListUsers",
                    "attempt": 1,
                    "outcome": "succeeded",
                    "page_count": 1,
                    "item_count": 1,
                    "pagination_complete": True,
                }
            ],
            "coverage": [
                {"layer": layer, "state": "not_collected", "reason_code": "outside_scope"}
                for layer in PolicyLayer
            ],
        },
        "inventory": data.model_dump(mode="json"),
    }


def test_sealed_handoff_preserves_statement_and_trust_lineage() -> None:
    handoff = CollectionHandoff.model_validate(_handoff())
    assert handoff.inventory.statements[0].policy_key == POLICY
    assert handoff.inventory.trust_statements[0].role_key == ROLE
    assert handoff.manifest.snapshot_digest == handoff.inventory.content_digest()
    assert handoff.manifest.coverage[0].authorization_evaluated is False


def test_observed_graph_row_plan_pins_exact_handoff_and_evidence() -> None:
    handoff = CollectionHandoff.model_validate(_handoff())
    plan = prepare_graph_import(
        handoff, resolver_version="observed_0.1", generated_at=datetime(2026, 10, 9, tzinfo=UTC)
    )
    assert plan.projection["handoff_digest"] == handoff.content_digest()
    assert plan.projection["projection_digest"] == plan.graph.content_digest()
    assert plan.projection["authorization_evaluated"] is False
    assert plan.projection["incomplete_reason_codes"] == list(plan.graph.incomplete_reason_codes)
    assert {edge["kind"] for edge in plan.edges} == {
        "policy_attachment",
        "group_membership",
        "role_trust_policy",
        "trust_selector_reference",
    }
    assert all(edge["derivation"] == "observed_configuration" for edge in plan.edges)
    assert any(row["trust_statement_key"] == TRUST_STATEMENT for row in plan.evidence)
    assert any(row["policy_key"] == POLICY for row in plan.evidence)
    for name, row in (
        ("graph_projections", plan.projection),
        ("graph_nodes", plan.nodes[0]),
        ("graph_edges", plan.edges[0]),
        ("edge_policy_evidence", plan.evidence[0]),
    ):
        assert set(row) == set(graph_metadata.tables[f"foundry.{name}"].columns.keys())


def test_graph_row_plan_rejects_changed_handoff_and_invalid_version() -> None:
    handoff = CollectionHandoff.model_validate(_handoff())
    with pytest.raises(GraphImportRejected, match="^resolver_version_invalid$"):
        prepare_graph_import(
            handoff, resolver_version="bad version", generated_at=datetime.now(UTC)
        )
    handoff.manifest.snapshot_digest = DIGEST
    with pytest.raises(GraphImportRejected, match="^graph_input_invalid$"):
        prepare_graph_import(
            handoff, resolver_version="observed_0.1", generated_at=datetime.now(UTC)
        )


def test_additive_group_records_preserve_old_empty_digest_but_pin_new_evidence() -> None:
    old_payload = _inventory()
    old_data = InventorySnapshot.model_validate(old_payload).model_dump(mode="json")
    old_data.pop("group_traversals")
    old_canonical = json.dumps(old_data, sort_keys=True, separators=(",", ":"))
    old_digest = "sha256:" + hashlib.sha256(old_canonical.encode("utf-8")).hexdigest()
    assert InventorySnapshot.model_validate(old_payload).content_digest() == old_digest
    old_handoff = CollectionHandoff.model_validate(_handoff(old_payload))
    old_handoff_data = old_handoff.model_dump(mode="json")
    old_handoff_data["inventory"].pop("group_traversals")
    for task in old_handoff_data["manifest"]["tasks"]:
        task.pop("subject_principal_key")
        task.pop("subject_policy_fingerprint")
        task.pop("response_digest")
    old_handoff_canonical = json.dumps(old_handoff_data, sort_keys=True, separators=(",", ":"))
    assert (
        old_handoff.content_digest()
        == "sha256:" + hashlib.sha256(old_handoff_canonical.encode("utf-8")).hexdigest()
    )

    with_traversal = dict(old_payload)
    with_traversal["group_traversals"] = [
        {
            "user_key": USER,
            "state": "complete",
            "membership_count": 1,
            "evidence_digest": DIGEST,
        }
    ]
    assert InventorySnapshot.model_validate(with_traversal).content_digest() != old_digest
    assert CollectionHandoff.model_validate(_handoff(with_traversal)).content_digest() != (
        old_handoff.content_digest()
    )


def test_no_user_policy_or_group_does_not_hide_direct_role_trust() -> None:
    inventory = _inventory()
    inventory["attachments"] = []
    inventory["memberships"] = []
    handoff = CollectionHandoff.model_validate(_handoff(inventory))

    observed = observe_identity(handoff, USER)
    graph = project_observed_inventory(handoff)

    assert observed.attachments == ()
    assert observed.assessment == "not_evaluated"
    assert observed.authorization_evaluated is False
    assert len(observed.trust_statements) == 1
    assert observed.trust_statements[0].selected_is_linked_trustee is True
    assert observed.trust_statements[0].action_patterns == ("sts:AssumeRole",)
    assert not any(relation.kind == "group_membership" for relation in graph.relations)
    assert any(relation.kind == "trust_selector_reference" for relation in graph.relations)


def test_real_account_group_traversal_is_explicit_per_user() -> None:
    inventory = _inventory()
    payload = _handoff(inventory)
    payload["manifest"]["data_kind"] = "real_account_observed"
    missing = project_observed_inventory(CollectionHandoff.model_validate(payload))
    assert "user_group_traversal_incomplete" in missing.incomplete_reason_codes
    assert missing.source_coverage_complete is False
    selected_role = observe_identity(CollectionHandoff.model_validate(payload), ROLE)
    assert "user_group_traversal_incomplete" not in selected_role.incomplete_reason_codes

    inventory["group_traversals"] = [
        {
            "user_key": USER,
            "state": "complete",
            "membership_count": 1,
            "evidence_digest": DIGEST,
        }
    ]
    payload = _handoff(inventory)
    payload["manifest"]["data_kind"] = "real_account_observed"
    payload["manifest"]["tasks"].append(
        {
            "operation": "iam:ListGroupsForUser",
            "subject_principal_key": USER,
            "attempt": 1,
            "outcome": "succeeded",
            "page_count": 1,
            "item_count": 1,
            "pagination_complete": True,
            "response_digest": DIGEST,
        }
    )
    complete = project_observed_inventory(CollectionHandoff.model_validate(payload))
    assert "user_group_traversal_incomplete" not in complete.incomplete_reason_codes
    assert complete.authorization_evaluated is False

    inventory["group_traversals"][0]["membership_count"] = 0
    with pytest.raises(ValidationError, match="count disagrees"):
        InventorySnapshot.model_validate(inventory)


def test_zero_groups_requires_a_complete_read_not_an_empty_list() -> None:
    inventory = _inventory()
    inventory["memberships"] = []
    payload = _handoff(inventory)
    payload["manifest"]["data_kind"] = "real_account_observed"
    assert (
        "user_group_traversal_incomplete"
        in project_observed_inventory(
            CollectionHandoff.model_validate(payload)
        ).incomplete_reason_codes
    )

    inventory["group_traversals"] = [
        {
            "user_key": USER,
            "state": "complete",
            "membership_count": 0,
            "evidence_digest": DIGEST,
        }
    ]
    payload = _handoff(inventory)
    payload["manifest"]["data_kind"] = "real_account_observed"
    payload["manifest"]["tasks"].append(
        {
            "operation": "iam:ListGroupsForUser",
            "subject_principal_key": USER,
            "attempt": 1,
            "outcome": "succeeded",
            "page_count": 1,
            "item_count": 0,
            "pagination_complete": True,
            "response_digest": DIGEST,
        }
    )
    graph = project_observed_inventory(CollectionHandoff.model_validate(payload))
    assert "user_group_traversal_incomplete" not in graph.incomplete_reason_codes
    assert not any(relation.kind == "group_membership" for relation in graph.relations)


def test_unread_group_traversal_cannot_claim_zero_memberships() -> None:
    inventory = _inventory()
    inventory["group_traversals"] = [
        {
            "user_key": USER,
            "state": "unavailable",
            "reason_code": "access_denied",
            "membership_count": 0,
        }
    ]
    with pytest.raises(ValidationError, match="cannot claim observations"):
        InventorySnapshot.model_validate(inventory)


def test_handoff_digest_pins_coverage_not_only_inventory_rows() -> None:
    first = CollectionHandoff.model_validate(_handoff())
    payload = first.model_dump(mode="json")
    payload["manifest"]["coverage"][0].update(state="absent", object_count=0)
    payload["manifest"]["coverage"][0].pop("reason_code")
    second = CollectionHandoff.model_validate(payload)
    assert first.inventory.content_digest() == second.inventory.content_digest()
    assert first.content_digest() != second.content_digest()


def test_observed_graph_preserves_relationships_without_claiming_capabilities() -> None:
    handoff = CollectionHandoff.model_validate(_handoff())
    graph = project_observed_inventory(handoff)
    assert graph.snapshot_id == handoff.inventory.snapshot_id
    assert graph.inventory_digest == handoff.manifest.snapshot_digest
    assert graph.handoff_digest == handoff.content_digest()
    assert graph.authorization_evaluated is False
    assert graph.source_coverage_complete is False
    assert "layer_identity_policy_incomplete" in graph.incomplete_reason_codes
    assert {relation.kind for relation in graph.relations} == {
        "policy_attachment",
        "group_membership",
        "role_trust_policy",
        "trust_selector_reference",
    }
    selector = next(
        relation for relation in graph.relations if relation.kind == "trust_selector_reference"
    )
    assert selector.source_key == ROLE
    assert selector.target_key == USER
    assert selector.statement_key == TRUST_STATEMENT
    assert selector.effect == "allow"  # This is the *trust statement*, not effective access.
    assert project_observed_inventory(handoff) == graph


def test_observed_graph_keeps_deny_boundary_and_unresolved_trust_distinct() -> None:
    inventory = _inventory()
    inventory["attachments"] = [
        {
            "principal_key": USER,
            "policy_key": POLICY,
            "kind": "permissions_boundary",
            "source_digest": DIGEST,
        }
    ]
    trust = inventory["trust_statements"][0]
    trust["effect"] = "deny"
    trust["selector_state"] = "unresolved"
    trust["trusted_principal_keys"] = []
    trust["condition_state"] = "unsupported"
    graph = project_observed_inventory(CollectionHandoff.model_validate(_handoff(inventory)))
    assert {relation.kind for relation in graph.relations} == {
        "permissions_boundary_attachment",
        "group_membership",
        "role_trust_policy",
    }
    role_policy = next(
        relation for relation in graph.relations if relation.kind == "role_trust_policy"
    )
    assert role_policy.effect == "deny"
    assert "trust_statement_unresolved" in graph.incomplete_reason_codes


def test_observed_graph_revalidates_mutated_handoff_and_distinguishes_real_data() -> None:
    payload = _handoff()
    payload["manifest"]["data_kind"] = "real_account_observed"
    handoff = CollectionHandoff.model_validate(payload)
    assert project_observed_inventory(handoff).data_kind == "real_account_observed"
    handoff.inventory.principals[0].display_alias = "user-aaaaaaaa"
    with pytest.raises(ValidationError):
        project_observed_inventory(handoff)


def test_identity_observation_is_one_principal_and_not_an_access_verdict() -> None:
    handoff = CollectionHandoff.model_validate(_handoff())
    user = observe_identity(handoff, USER)
    role = observe_identity(handoff, ROLE)
    assert user.principal_key == USER
    assert user.handoff_digest == handoff.content_digest()
    assert user.assessment == "not_evaluated"
    assert user.authorization_evaluated is False
    assert user.attachments[0].policy_key == POLICY
    assert user.statements[0].statement_key == STATEMENT
    assert user.statements[0].effect == "allow"  # Statement text, not final permission.
    assert user.trust_statements[0].selected_is_linked_trustee is True
    assert role.trust_statements[0].selected_is_role is True
    assert role.attachments == ()
    with pytest.raises(ValueError, match="principal_not_investigable"):
        observe_identity(handoff, GROUP)
    assert observe_identity(handoff, USER) == user
    with pytest.raises(ValueError, match="principal_not_in_snapshot"):
        observe_identity(handoff, "p_" + "9" * 32)


def test_identity_observation_preserves_group_lineage_and_control_absence() -> None:
    inventory = _inventory()
    control = "p_" + "6" * 32
    group_policy = "pol_" + "7" * 32
    group_statement = "st_" + "8" * 32
    inventory["principals"].append(
        {
            "principal_key": control,
            "principal_fingerprint": "hmac-sha256:" + "6" * 64,
            "kind": "iam_user",
            "display_alias": "user-00000004",
            "source_digest": DIGEST,
        }
    )
    inventory["policies"].append(
        {
            "policy_key": group_policy,
            "kind": "inline",
            "parse_state": "parsed",
            "source_digest": DIGEST,
        }
    )
    inventory["statements"].append(
        {
            "statement_key": group_statement,
            "policy_key": group_policy,
            "effect": "deny",
            "action_mode": "action",
            "action_patterns": ["iam:CreateAccessKey"],
            "resource_mode": "all",
            "condition_state": "absent",
            "source_digest": DIGEST,
        }
    )
    inventory["attachments"].append(
        {
            "principal_key": GROUP,
            "policy_key": group_policy,
            "kind": "inline",
            "source_digest": DIGEST,
        }
    )
    handoff = CollectionHandoff.model_validate(_handoff(inventory))
    exposed = observe_identity(handoff, USER)
    control_view = observe_identity(handoff, control)
    inherited = next(row for row in exposed.attachments if row.via_group_key == GROUP)
    assert inherited.membership_relation_id is not None
    assert inherited.statement_keys == (group_statement,)
    assert {row.statement_key for row in exposed.statements} == {STATEMENT, group_statement}
    assert control_view.attachments == ()
    assert control_view.statements == ()
    assert control_view.trust_statements == ()
    assert control_view.assessment == "not_evaluated"  # Empty evidence is not secure.


def _credential_handoff() -> dict[str, object]:
    inventory = _inventory()
    target = "p_" + "9" * 32
    inventory["principals"].append(
        {
            "principal_key": target,
            "principal_fingerprint": "hmac-sha256:" + "9" * 64,
            "kind": "iam_user",
            "display_alias": "user-00000009",
            "source_digest": DIGEST,
        }
    )
    inventory["statements"][0]["resource_principal_keys"] = [target]
    payload = _handoff(inventory)
    for coverage in payload["manifest"]["coverage"]:
        if coverage["layer"] == PolicyLayer.identity_policy:
            coverage.update(state="collected", object_count=1)
            coverage.pop("reason_code")
    return payload


def test_credential_text_candidate_is_pinned_but_never_authorized() -> None:
    handoff = CollectionHandoff.model_validate(_credential_handoff())
    target = "p_" + "9" * 32
    result = inspect_create_access_key_policy_text(handoff, USER, target)
    assert result.status == "policy_text_candidate"
    assert result.action == "iam:CreateAccessKey"
    assert result.inventory_digest == handoff.manifest.snapshot_digest
    assert result.handoff_digest == handoff.content_digest()
    assert result.analyzer_version == "credential-policy-text-0.1"
    assert result.allow_evidence[0].statement_key == STATEMENT
    assert result.allow_evidence[0].attachment_relation_id.startswith("rel_")
    assert result.authorization_evaluated is False
    assert "layer_service_control_policy_incomplete" in result.coverage_gap_codes


def test_credential_text_control_is_no_observed_allow_not_secure() -> None:
    payload = _credential_handoff()
    control = "p_" + "6" * 32
    payload["inventory"]["principals"].append(
        {
            "principal_key": control,
            "principal_fingerprint": "hmac-sha256:" + "6" * 64,
            "kind": "iam_user",
            "display_alias": "user-00000006",
            "source_digest": DIGEST,
        }
    )
    payload = _handoff(payload["inventory"])
    for coverage in payload["manifest"]["coverage"]:
        if coverage["layer"] == PolicyLayer.identity_policy:
            coverage.update(state="collected", object_count=1)
            coverage.pop("reason_code")
    result = inspect_create_access_key_policy_text(
        CollectionHandoff.model_validate(payload), control, "p_" + "9" * 32
    )
    assert result.status == "no_observed_identity_allow"
    assert result.allow_evidence == ()
    assert result.authorization_evaluated is False


def test_credential_text_deny_overrides_and_unknown_forms_do_not_become_allow() -> None:
    payload = _credential_handoff()
    inventory = payload["inventory"]
    inventory["statements"].append(
        {
            "statement_key": "st_" + "7" * 32,
            "policy_key": POLICY,
            "effect": "deny",
            "action_mode": "action",
            "action_patterns": ["IAM:createaccesskey"],
            "resource_mode": "linked_principals",
            "resource_principal_keys": ["p_" + "9" * 32],
            "condition_state": "absent",
            "source_digest": DIGEST,
        }
    )
    handoff = CollectionHandoff.model_validate(_handoff(inventory))
    result = inspect_create_access_key_policy_text(handoff, USER, "p_" + "9" * 32)
    assert result.status == "recorded_explicit_deny"
    assert len(result.allow_evidence) == 1
    assert len(result.deny_evidence) == 1

    inventory["statements"][0].update(
        condition_state="unevaluated", condition_keys=["aws:MultiFactorAuthPresent"]
    )
    inventory["statements"].pop()
    result = inspect_create_access_key_policy_text(
        CollectionHandoff.model_validate(_handoff(inventory)), USER, "p_" + "9" * 32
    )
    assert result.status == "uncertain_policy_text"
    assert "condition_not_evaluated" in result.uncertainty_codes
    assert result.allow_evidence == ()

    inventory["statements"][0].update(
        condition_state="absent",
        condition_keys=[],
        action_mode="not_action",
        action_patterns=["iam:DeleteAccessKey"],
    )
    result = inspect_create_access_key_policy_text(
        CollectionHandoff.model_validate(_handoff(inventory)), USER, "p_" + "9" * 32
    )
    assert result.status == "uncertain_policy_text"
    assert "unsupported_action_or_resource_selector" in result.uncertainty_codes


def test_credential_text_rejects_self_and_non_user_target() -> None:
    handoff = CollectionHandoff.model_validate(_credential_handoff())
    with pytest.raises(ValueError, match="self_key_creation_outside_first_pattern"):
        inspect_create_access_key_policy_text(handoff, USER, USER)
    with pytest.raises(ValueError, match="target_not_iam_user"):
        inspect_create_access_key_policy_text(handoff, USER, ROLE)


def test_credential_text_follows_group_policy_but_boundary_allow_never_grants() -> None:
    payload = _credential_handoff()
    inventory = payload["inventory"]
    inventory["attachments"][0]["principal_key"] = GROUP
    inherited = inspect_create_access_key_policy_text(
        CollectionHandoff.model_validate(_handoff(inventory)), USER, "p_" + "9" * 32
    )
    assert inherited.allow_evidence[0].via_group_key == GROUP
    assert inherited.allow_evidence[0].attachment_relation_id.startswith("rel_")

    inventory["attachments"][0].update(principal_key=USER, kind="permissions_boundary")
    boundary_only = inspect_create_access_key_policy_text(
        CollectionHandoff.model_validate(_handoff(inventory)), USER, "p_" + "9" * 32
    )
    assert boundary_only.status == "uncertain_policy_text"
    assert boundary_only.allow_evidence == ()
    assert "permissions_boundary_not_evaluated" in boundary_only.uncertainty_codes


def test_credential_text_wildcard_and_notresource_remain_distinct() -> None:
    payload = _credential_handoff()
    inventory = payload["inventory"]
    inventory["statements"][0]["action_patterns"] = ["IAM:*AccessKey*"]
    wildcard = inspect_create_access_key_policy_text(
        CollectionHandoff.model_validate(_handoff(inventory)), USER, "p_" + "9" * 32
    )
    assert wildcard.allow_evidence[0].statement_key == STATEMENT

    inventory["statements"][0].update(resource_mode="not_resource", resource_principal_keys=[])
    unresolved = inspect_create_access_key_policy_text(
        CollectionHandoff.model_validate(_handoff(inventory)), USER, "p_" + "9" * 32
    )
    assert unresolved.status == "uncertain_policy_text"
    assert unresolved.allow_evidence == ()
    assert "unsupported_action_or_resource_selector" in unresolved.uncertainty_codes


def test_credential_text_fails_closed_on_partial_run_and_inconsistent_absence() -> None:
    payload = _credential_handoff()
    payload["manifest"]["outcome"] = "partial"
    payload["manifest"]["tasks"][0].update(
        outcome="partial", pagination_complete=False, error_code="page_incomplete"
    )
    partial = inspect_create_access_key_policy_text(
        CollectionHandoff.model_validate(payload), USER, "p_" + "9" * 32
    )
    assert partial.status == "uncertain_policy_text"
    assert "collection_run_incomplete" in partial.uncertainty_codes

    payload = _credential_handoff()
    identity_layer = next(
        row
        for row in payload["manifest"]["coverage"]
        if row["layer"] == PolicyLayer.identity_policy
    )
    identity_layer["state"] = "absent"
    identity_layer["object_count"] = 0
    mismatch = inspect_create_access_key_policy_text(
        CollectionHandoff.model_validate(payload), USER, "p_" + "9" * 32
    )
    assert mismatch.status == "uncertain_policy_text"
    assert "coverage_inventory_mismatch" in mismatch.uncertainty_codes


def _paired_credential_handoff() -> CollectionHandoff:
    payload = _credential_handoff()
    payload["inventory"]["principals"].append(
        {
            "principal_key": "p_" + "6" * 32,
            "principal_fingerprint": "hmac-sha256:" + "6" * 64,
            "kind": "iam_user",
            "display_alias": "user-00000006",
            "source_digest": DIGEST,
        }
    )
    payload["manifest"]["snapshot_digest"] = InventorySnapshot.model_validate(
        payload["inventory"]
    ).content_digest()
    return CollectionHandoff.model_validate(payload)


def test_paired_policy_text_compares_two_starts_on_one_sealed_snapshot() -> None:
    handoff = _paired_credential_handoff()
    target = "p_" + "9" * 32
    comparison = compare_credential_policy_text(
        CredentialPolicyQuestion(handoff, USER, target),
        CredentialPolicyQuestion(handoff, "p_" + "6" * 32, target),
    )
    assert comparison.snapshot_basis == "shared_snapshot"
    assert comparison.contrast == "candidate_only_first"
    assert comparison.first.inventory_digest == comparison.second.inventory_digest
    assert comparison.first.handoff_digest == comparison.second.handoff_digest
    assert comparison.comparison_version == "paired-credential-policy-text-0.1"
    assert comparison.first.status == "policy_text_candidate"
    assert comparison.second.status == "no_observed_identity_allow"
    assert comparison.account_security_assessment == "not_assessed"
    assert comparison.authorization_evaluated is False
    assert "source_coverage_gaps_present" in comparison.caution_codes


def test_offline_pair_preview_emits_only_policy_text_metadata(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    handoff = _paired_credential_handoff()
    path = tmp_path / "private-account-secret.json"
    path.write_text(handoff.model_dump_json(), encoding="utf-8")
    first, second, target = USER, "p_" + "6" * 32, "p_" + "9" * 32
    assert (
        preview_main(
            ["--file", str(path), "--first", first, "--second", second, "--target", target]
        )
        == 0
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["code"] == "policy_text_only"
    assert payload["contrast"] == "candidate_only_first"
    assert payload["first_status"] == "policy_text_candidate"
    assert payload["second_status"] == "no_observed_identity_allow"
    assert payload["authorization_evaluated"] is False
    assert payload["account_security_assessment"] == "not_assessed"
    assert captured.err == ""
    assert all(value not in captured.out for value in (str(path), first, second, target, DIGEST))


def test_offline_pair_preview_rejects_bad_selection_and_private_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "private-AKIAABCDEFGHIJKLMNOP.json"
    path.write_text(_paired_credential_handoff().model_dump_json(), encoding="utf-8")
    assert (
        preview_main(
            ["--file", str(path), "--first", USER, "--second", USER, "--target", "p_" + "9" * 32]
        )
        == 1
    )
    output = capsys.readouterr()
    assert json.loads(output.out)["code"] == "invalid_selection"
    assert str(path) not in output.out
    assert output.err == ""

    path.write_text('{"private":"AKIAABCDEFGHIJKLMNOP"}', encoding="utf-8")
    invalid = preview_file(path, USER, "p_" + "6" * 32, "p_" + "9" * 32)
    assert invalid.status == "invalid"
    assert invalid.code == "invalid_contract"
    assert invalid.authorization_evaluated is False


def test_offline_real_pair_with_missing_group_read_is_uncertain(tmp_path: Path) -> None:
    payload = _paired_credential_handoff().model_dump(mode="json")
    payload["manifest"]["data_kind"] = "real_account_observed"
    path = tmp_path / "redacted.json"
    path.write_text(CollectionHandoff.model_validate(payload).model_dump_json(), encoding="utf-8")
    result = preview_file(path, USER, "p_" + "6" * 32, "p_" + "9" * 32)
    assert result.status == "observation"
    assert result.data_kind == "real_account_observed"
    assert result.contrast == "requires_review"
    assert result.second_status == "uncertain_policy_text"
    assert result.second_uncertainty_count is not None
    assert result.second_uncertainty_count > 0


def test_real_pair_with_unread_user_groups_cannot_claim_clean_policy_text_control() -> None:
    payload = _paired_credential_handoff().model_dump(mode="json")
    payload["manifest"]["data_kind"] = "real_account_observed"
    handoff = CollectionHandoff.model_validate(payload)
    target = "p_" + "9" * 32
    control = "p_" + "6" * 32
    comparison = compare_credential_policy_text(
        CredentialPolicyQuestion(handoff, USER, target),
        CredentialPolicyQuestion(handoff, control, target),
    )
    assert comparison.contrast == "requires_review"
    assert comparison.second.status == "uncertain_policy_text"
    assert "group_traversal_incomplete" in comparison.second.uncertainty_codes
    assert comparison.authorization_evaluated is False

    payload["inventory"]["group_traversals"] = [
        {
            "user_key": key,
            "state": "complete",
            "membership_count": count,
            "evidence_digest": DIGEST,
        }
        for key, count in ((USER, 1), (control, 0), (target, 0))
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
            "response_digest": DIGEST,
        }
        for key, count in ((USER, 1), (control, 0), (target, 0))
    )
    payload["manifest"]["snapshot_digest"] = InventorySnapshot.model_validate(
        payload["inventory"]
    ).content_digest()
    complete_handoff = CollectionHandoff.model_validate(payload)
    complete_comparison = compare_credential_policy_text(
        CredentialPolicyQuestion(complete_handoff, USER, target),
        CredentialPolicyQuestion(complete_handoff, control, target),
    )
    assert complete_comparison.contrast == "candidate_only_first"
    assert complete_comparison.second.status == "no_observed_identity_allow"
    assert complete_comparison.account_security_assessment == "not_assessed"


@pytest.mark.parametrize("task_change", ["missing", "wrong_count", "wrong_digest", "duplicate"])
def test_real_complete_group_traversal_requires_exact_successful_read_task(
    task_change: str,
) -> None:
    payload = _paired_credential_handoff().model_dump(mode="json")
    payload["manifest"]["data_kind"] = "real_account_observed"
    payload["inventory"]["group_traversals"] = [
        {
            "user_key": "p_" + "6" * 32,
            "state": "complete",
            "membership_count": 0,
            "evidence_digest": DIGEST,
        }
    ]
    payload["manifest"]["snapshot_digest"] = InventorySnapshot.model_validate(
        payload["inventory"]
    ).content_digest()
    task = {
        "operation": "iam:ListGroupsForUser",
        "subject_principal_key": "p_" + "6" * 32,
        "attempt": 1,
        "outcome": "succeeded",
        "page_count": 1,
        "item_count": 0,
        "pagination_complete": True,
        "response_digest": DIGEST,
    }
    if task_change == "wrong_count":
        task["item_count"] = 1
    elif task_change == "wrong_digest":
        task["response_digest"] = "sha256:" + "3" * 64
    elif task_change == "duplicate":
        payload["manifest"]["tasks"].append(task.copy())
    if task_change != "missing":
        payload["manifest"]["tasks"].append(task)
    with pytest.raises(ValidationError, match="complete group traversal"):
        CollectionHandoff.model_validate(payload)


def test_paired_policy_text_discloses_different_snapshot_context() -> None:
    first = _paired_credential_handoff()
    other_payload = first.model_dump(mode="json")
    other_payload["inventory"]["snapshot_id"] = "snapshot_other_synthetic"
    other_payload["manifest"]["snapshot_id"] = "snapshot_other_synthetic"
    other_payload["manifest"]["snapshot_digest"] = InventorySnapshot.model_validate(
        other_payload["inventory"]
    ).content_digest()
    other = CollectionHandoff.model_validate(other_payload)
    target = "p_" + "9" * 32
    comparison = compare_credential_policy_text(
        CredentialPolicyQuestion(first, USER, target),
        CredentialPolicyQuestion(other, "p_" + "6" * 32, target),
    )
    assert comparison.snapshot_basis == "different_snapshots"
    assert comparison.contrast == "different_snapshot_context"
    assert "environmental_differences_not_controlled" in comparison.caution_codes


def test_paired_policy_text_rejects_mixed_kinds_and_inconsistent_shared_metadata() -> None:
    first = _paired_credential_handoff()
    target = "p_" + "9" * 32
    mixed_payload = first.model_dump(mode="json")
    mixed_payload["manifest"]["data_kind"] = "real_account_observed"
    mixed = CollectionHandoff.model_validate(mixed_payload)
    with pytest.raises(ValueError, match="mixed_data_kinds_not_comparable"):
        compare_credential_policy_text(
            CredentialPolicyQuestion(first, USER, target),
            CredentialPolicyQuestion(mixed, "p_" + "6" * 32, target),
        )

    changed_payload = first.model_dump(mode="json")
    changed_payload["manifest"]["run_id"] = "run_different_metadata"
    changed = CollectionHandoff.model_validate(changed_payload)
    with pytest.raises(ValueError, match="shared_snapshot_manifest_conflict"):
        compare_credential_policy_text(
            CredentialPolicyQuestion(first, USER, target),
            CredentialPolicyQuestion(changed, "p_" + "6" * 32, target),
        )


def test_tampered_inventory_or_wrong_snapshot_cannot_match_manifest() -> None:
    data = _handoff()
    data["inventory"]["principals"][0]["display_alias"] = "user-00000009"
    with pytest.raises(ValidationError, match="digest"):
        CollectionHandoff.model_validate(data)

    data = _handoff()
    data["inventory"]["snapshot_id"] = "snapshot_other"
    with pytest.raises(ValidationError, match="snapshot IDs differ"):
        CollectionHandoff.model_validate(data)

    accepted = CollectionHandoff.model_validate(_handoff())
    accepted.inventory.principals[0].display_alias = "user-00000009"
    with pytest.raises(ValidationError, match="digest"):
        CollectionHandoff.model_validate_json(accepted.model_dump_json())


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data["statements"][0].update({"resource_principal_keys": ["p_" + "9" * 32]}),
        lambda data: data["attachments"][0].update({"policy_key": TRUST}),
        lambda data: data["memberships"][0].update({"group_key": ROLE}),
        lambda data: data["trust_statements"][0].update({"role_key": USER}),
        lambda data: data["principals"][1].update({"principal_key": USER}),
        lambda data: data["principals"][1].update({"principal_fingerprint": HMAC}),
        lambda data: data["policies"][0].update({"is_default": False}),
        lambda data: data["policies"][0].update({"parse_state": "unsupported"}),
    ],
)
def test_cross_record_or_duplicate_references_fail(mutation) -> None:
    data = _inventory()
    mutation(data)
    with pytest.raises(ValidationError):
        InventorySnapshot.model_validate(data)


def test_advanced_policy_forms_are_preserved_as_modes_not_claimed_as_allows() -> None:
    data = _inventory()
    statement = data["statements"][0]
    statement.update(
        {
            "action_mode": "not_action",
            "action_patterns": ["iam:DeleteUser"],
            "resource_mode": "not_resource",
            "resource_principal_keys": [],
            "condition_state": "unevaluated",
            "condition_keys": ["aws:MultiFactorAuthPresent"],
        }
    )
    inventory = InventorySnapshot.model_validate(data)
    assert inventory.statements[0].action_mode == "not_action"
    assert inventory.statements[0].resource_mode == "not_resource"
    assert inventory.statements[0].condition_state == "unevaluated"


def test_unparsed_statement_is_retained_as_unknown_without_invented_edges() -> None:
    data = _inventory()
    data["statements"][0].update(
        {
            "action_mode": "unsupported",
            "action_patterns": [],
            "resource_mode": "unresolved",
            "resource_principal_keys": [],
            "condition_state": "unsupported",
        }
    )
    inventory = InventorySnapshot.model_validate(data)
    assert inventory.statements[0].action_patterns == []
    assert inventory.statements[0].resource_principal_keys == []


def test_raw_policy_json_is_not_an_inventory_field() -> None:
    data = _inventory()
    data["policies"][0]["raw_document"] = '{"Statement":[]}'
    with pytest.raises(ValidationError):
        InventorySnapshot.model_validate(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("display_alias", "arn:aws:iam::123456789012:user/alice"),
        ("display_alias", "alice@example.com"),
        ("principal_key", "123456789012"),
        ("principal_fingerprint", "sha256:" + "1" * 64),
    ],
)
def test_raw_identifiers_are_not_accepted(field: str, value: str) -> None:
    data = _inventory()
    data["principals"][0][field] = value
    with pytest.raises(ValidationError):
        InventorySnapshot.model_validate(data)


def test_unknown_trust_selector_cannot_claim_linked_principals() -> None:
    data = _inventory()
    data["trust_statements"][0]["selector_state"] = "unresolved"
    with pytest.raises(ValidationError):
        InventorySnapshot.model_validate(data)


def test_condition_key_cannot_carry_an_account_identifier() -> None:
    data = _inventory()
    data["statements"][0]["condition_state"] = "unevaluated"
    data["statements"][0]["condition_keys"] = ["aws:PrincipalTag/123456789012"]
    with pytest.raises(ValidationError):
        InventorySnapshot.model_validate(data)
