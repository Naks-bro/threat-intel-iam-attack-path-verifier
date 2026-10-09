"""Real-account handoff storage on an opted-in disposable loopback database.

Refusal checks never open a connection. The PostgreSQL roundtrip is marked
``postgres`` and runs only after ``fyp_iam.persistence.test_guard`` allows the
configured URL. Do not point it at a managed host.
"""

import os
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url

from fyp_iam.contracts.collection import PolicyLayer
from fyp_iam.contracts.inventory import CollectionHandoff, InventorySnapshot
from fyp_iam.engine2.real_account_store import (
    RealAccountImportRejected,
    load_real_account_handoff,
    persist_real_account_handoff,
)
from fyp_iam.engine2.schema import metadata

USER = "p_" + "a" * 32
ROLE = "p_" + "1" * 32
GROUP = "p_" + "2" * 32
POLICY = "pol_" + "b" * 32
TRUST = "pol_" + "3" * 32
DIGEST = "sha256:" + "d" * 64
ACCOUNT = "hmac-sha256:" + "e" * 64
LOOPBACK = "postgresql+psycopg://user@127.0.0.1/fyp_iam"


class NoConnectEngine:
    def __init__(self, url: str) -> None:
        self.url = make_url(url)
        self.began = False

    def begin(self) -> None:
        self.began = True
        raise AssertionError("database connection must not open")

    def connect(self) -> None:
        self.began = True
        raise AssertionError("database connection must not open")


def _redacted_handoff() -> CollectionHandoff:
    inventory = InventorySnapshot.model_validate(
        {
            "snapshot_id": "realstore_snapshot_1",
            "principals": [
                {
                    "principal_key": USER,
                    "principal_fingerprint": "hmac-sha256:" + "c" * 64,
                    "kind": "iam_user",
                    "display_alias": "user-00000001",
                    "source_digest": DIGEST,
                },
                {
                    "principal_key": ROLE,
                    "principal_fingerprint": "hmac-sha256:" + "1" * 64,
                    "kind": "iam_role",
                    "display_alias": "role-00000002",
                    "source_digest": DIGEST,
                },
                {
                    "principal_key": GROUP,
                    "principal_fingerprint": "hmac-sha256:" + "2" * 64,
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
                    "statement_key": "st_" + "e" * 32,
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
            "group_traversals": [
                {
                    "user_key": USER,
                    "state": "complete",
                    "membership_count": 1,
                    "evidence_digest": DIGEST,
                }
            ],
            "trust_statements": [
                {
                    "statement_key": "st_" + "4" * 32,
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
    )
    started = datetime(2026, 10, 9, tzinfo=UTC)
    return CollectionHandoff.model_validate(
        {
            "manifest": {
                "data_kind": "real_account_observed",
                "run_id": "realstore_run_1",
                "snapshot_id": inventory.snapshot_id,
                "account_alias": "lab-account",
                "account_fingerprint": ACCOUNT,
                "collector_version": "realstore-test-1",
                "started_at": started,
                "sealed_at": started + timedelta(seconds=1),
                "outcome": "succeeded",
                "snapshot_digest": inventory.content_digest(),
                "tasks": [
                    {
                        "operation": "iam:ListUsers",
                        "attempt": 1,
                        "outcome": "succeeded",
                        "page_count": 1,
                        "item_count": 1,
                        "pagination_complete": True,
                        "response_digest": DIGEST,
                    },
                    {
                        "operation": "iam:ListGroupsForUser",
                        "subject_principal_key": USER,
                        "attempt": 1,
                        "outcome": "succeeded",
                        "page_count": 1,
                        "item_count": 1,
                        "pagination_complete": True,
                        "response_digest": DIGEST,
                    },
                ],
                "coverage": [
                    {"layer": layer, "state": "not_collected", "reason_code": "outside_scope"}
                    for layer in PolicyLayer
                ],
            },
            "inventory": inventory.model_dump(mode="json"),
        }
    )


def _persist(engine: Engine, handoff: object, **overrides: object) -> object:
    kwargs: dict[str, object] = {
        "connection_id": "realstore_connection",
        "request_id": "realstore_request",
        "allow_disposable": True,
        "allow_real_account": True,
    }
    kwargs.update(overrides)
    return persist_real_account_handoff(
        engine,
        cast(CollectionHandoff, handoff),
        connection_id=cast(str, kwargs["connection_id"]),
        request_id=cast(str, kwargs["request_id"]),
        allow_disposable=cast(bool, kwargs["allow_disposable"]),
        allow_real_account=cast(bool, kwargs["allow_real_account"]),
    )


@pytest.mark.parametrize(
    ("url", "allow_disposable"),
    [
        ("postgresql+psycopg://user@db.example.test/postgres", True),
        ("postgresql+psycopg://user@localhost/fyp_iam", False),
        ("postgresql+psycopg://user@localhost/postgres", True),
        ("postgresql+psycopg://user@127.0.0.1/fyp_iam?sslmode=require", True),
        ("sqlite:///local.db", True),
    ],
)
def test_non_loopback_target_is_refused_before_connect(url: str, allow_disposable: bool) -> None:
    engine = NoConnectEngine(url)
    with pytest.raises(RealAccountImportRejected, match="^disposable_target_required$"):
        _persist(cast(Engine, engine), None, allow_disposable=allow_disposable)
    assert engine.began is False


def test_real_account_opt_in_is_required_before_connect() -> None:
    engine = NoConnectEngine(LOOPBACK)
    with pytest.raises(RealAccountImportRejected, match="^real_account_opt_in_required$"):
        _persist(cast(Engine, engine), _redacted_handoff(), allow_real_account=False)
    assert engine.began is False


def test_credential_is_refused_before_connect() -> None:
    engine = NoConnectEngine(LOOPBACK)
    payload = _redacted_handoff().model_dump(mode="json")
    payload["manifest"]["account_alias"] = "akia" + "A" * 16
    with pytest.raises(RealAccountImportRejected, match="^credential_rejected$"):
        _persist(cast(Engine, engine), payload)
    assert engine.began is False


def test_raw_policy_body_is_refused_before_connect() -> None:
    engine = NoConnectEngine(LOOPBACK)
    payload = _redacted_handoff().model_dump(mode="json")
    payload["PolicyDocument"] = {"Statement": []}
    with pytest.raises(RealAccountImportRejected, match="^raw_policy_body_rejected$"):
        _persist(cast(Engine, engine), payload)
    assert engine.began is False


def test_authorization_evaluated_true_is_refused_before_connect() -> None:
    engine = NoConnectEngine(LOOPBACK)
    payload = _redacted_handoff().model_dump(mode="json")
    payload["manifest"]["coverage"][0]["authorization_evaluated"] = True
    with pytest.raises(RealAccountImportRejected, match="^authorization_evaluated_rejected$"):
        _persist(cast(Engine, engine), payload)
    assert engine.began is False


def test_synthetic_handoff_is_refused_before_connect() -> None:
    engine = NoConnectEngine(LOOPBACK)
    payload = _redacted_handoff().model_dump(mode="json")
    payload["manifest"]["data_kind"] = "synthetic"
    with pytest.raises(RealAccountImportRejected, match="^real_account_data_kind_required$"):
        _persist(cast(Engine, engine), payload)
    assert engine.began is False


def test_redacted_handoff_passes_safety_scan_before_connect() -> None:
    engine = NoConnectEngine(LOOPBACK)
    with pytest.raises(AssertionError, match="database connection must not open"):
        _persist(cast(Engine, engine), _redacted_handoff())
    assert engine.began is True


def test_reader_refuses_managed_target_before_connect() -> None:
    engine = NoConnectEngine("postgresql+psycopg://user@db.example.test/postgres")
    with pytest.raises(RealAccountImportRejected, match="^disposable_target_required$"):
        load_real_account_handoff(
            cast(Engine, engine),
            "realstore_snapshot_1",
            allow_disposable=True,
            allow_real_account=True,
        )
    assert engine.began is False


@pytest.mark.postgres
def test_opted_in_writer_roundtrips_snapshot_digest() -> None:
    url = os.environ["FYP_DATABASE_URL"]
    handoff = _redacted_handoff()
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    tables = {table.name: table for table in metadata.tables.values()}
    try:
        with engine.begin() as connection:
            connection.execute(
                tables["account_connections"].insert(),
                {
                    "connection_id": "realstore_connection",
                    "project_key": "fyp",
                    "account_alias": handoff.manifest.account_alias,
                    "account_fingerprint": handoff.manifest.account_fingerprint,
                    "provider": "aws",
                    "credential_mode": "external_profile",
                    "profile_alias": "lab-profile",
                    "selected_region": "ap-southeast-2",
                    "enabled": True,
                    "created_at": handoff.manifest.started_at,
                },
            )
        result = persist_real_account_handoff(
            engine,
            handoff,
            connection_id="realstore_connection",
            request_id="realstore_request",
            allow_disposable=True,
            allow_real_account=True,
        )
        assert result.snapshot_digest == handoff.manifest.snapshot_digest
        assert result.handoff_hash == handoff.content_digest()
        rebuilt = load_real_account_handoff(
            engine,
            handoff.inventory.snapshot_id,
            allow_disposable=True,
            allow_real_account=True,
        )
        assert rebuilt.inventory.content_digest() == handoff.inventory.content_digest()
        assert rebuilt.manifest.snapshot_digest == handoff.manifest.snapshot_digest
        assert rebuilt.manifest.data_kind == "real_account_observed"
        assert all(item.authorization_evaluated is False for item in rebuilt.manifest.coverage)
        with engine.connect() as connection:
            connection.exec_driver_sql("SET TRANSACTION READ ONLY")
            stored_kind = connection.execute(
                text(
                    "SELECT data_kind FROM foundry.account_snapshots WHERE snapshot_id = :snapshot"
                ),
                {"snapshot": handoff.inventory.snapshot_id},
            ).scalar_one()
            projection_count = connection.execute(
                text(
                    "SELECT count(*) FROM foundry.graph_projections WHERE snapshot_id = :snapshot"
                ),
                {"snapshot": handoff.inventory.snapshot_id},
            ).scalar_one()
        assert stored_kind == "real_account_observed"
        assert projection_count == 1
    finally:
        _delete_fixture(engine)
        engine.dispose()


def _delete_fixture(engine: Engine) -> None:
    names = (
        "edge_policy_evidence",
        "graph_edges",
        "graph_nodes",
        "graph_projections",
        "iam_trust_principal_refs",
        "iam_statement_resource_refs",
        "iam_trust_statements",
        "iam_identity_statements",
        "iam_attachments",
        "iam_memberships",
        "iam_group_traversals",
        "iam_policies",
        "iam_principals",
        "coverage_gaps",
        "collection_layer_coverage",
        "snapshot_purge_tombstones",
        "account_snapshots",
        "collection_tasks",
        "collection_runs",
        "account_connections",
    )
    with engine.begin() as connection:
        for name in names:
            if name == "collection_tasks":
                connection.execute(
                    text(
                        "DELETE FROM foundry.collection_tasks "
                        "WHERE collection_run_id = 'realstore_run_1'"
                    )
                )
            elif name == "collection_runs":
                connection.execute(
                    text(
                        "DELETE FROM foundry.collection_runs "
                        "WHERE collection_run_id = 'realstore_run_1'"
                    )
                )
            elif name == "account_connections":
                connection.execute(
                    text(
                        "DELETE FROM foundry.account_connections "
                        "WHERE connection_id = 'realstore_connection'"
                    )
                )
            else:
                connection.execute(
                    text(f"DELETE FROM foundry.{name} WHERE snapshot_id = 'realstore_snapshot_1'")
                )
