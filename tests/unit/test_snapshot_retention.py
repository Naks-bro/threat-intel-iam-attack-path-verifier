"""Expiry, private-key replay, and purge tombstones. No database or AWS calls."""

from datetime import UTC, datetime, timedelta

import pytest

from fyp_iam.engine2.snapshot_retention import (
    SnapshotRetentionRejected,
    assert_replay,
    assert_snapshot_usable,
    plan_purge,
    seal_snapshot,
)

_SEALED = datetime(2026, 10, 9, tzinfo=UTC)
_HASH = "sha256:" + "ab" * 32
_KEY = bytes(range(32))


def test_real_account_seal_expires_at_ninety_days_and_replays_with_the_same_key() -> None:
    seal = seal_snapshot(
        handoff_hash=_HASH,
        data_kind="real_account_observed",
        sealed_at=_SEALED,
        hmac_secret=_KEY,
    )
    assert seal.retention_expires_at - seal.sealed_at == timedelta(days=90)
    assert_replay(
        seal,
        handoff_hash=_HASH,
        hmac_secret=_KEY,
        as_of=_SEALED + timedelta(days=1),
    )
    assert "hmac" not in seal.seal
    assert _KEY.hex() not in seal.seal


def test_wrong_key_or_tampered_hash_cannot_replay() -> None:
    seal = seal_snapshot(
        handoff_hash=_HASH,
        data_kind="real_account_observed",
        sealed_at=_SEALED,
        hmac_secret=_KEY,
    )
    other = bytes(range(1, 33))
    with pytest.raises(SnapshotRetentionRejected, match="snapshot_seal_mismatch"):
        assert_replay(seal, handoff_hash=_HASH, hmac_secret=other, as_of=_SEALED)
    tampered = "sha256:" + "cd" * 32
    with pytest.raises(SnapshotRetentionRejected, match="snapshot_seal_mismatch"):
        assert_replay(seal, handoff_hash=tampered, hmac_secret=_KEY, as_of=_SEALED)


def test_expired_or_purged_snapshot_cannot_be_used() -> None:
    seal = seal_snapshot(
        handoff_hash=_HASH,
        data_kind="real_account_observed",
        sealed_at=_SEALED,
        hmac_secret=_KEY,
    )
    with pytest.raises(SnapshotRetentionRejected, match="snapshot_expired"):
        assert_snapshot_usable(
            sealed_at=seal.sealed_at,
            retention_expires_at=seal.retention_expires_at,
            data_kind=seal.data_kind,
            as_of=seal.retention_expires_at,
        )
    with pytest.raises(SnapshotRetentionRejected, match="snapshot_purged"):
        assert_replay(
            seal,
            handoff_hash=_HASH,
            hmac_secret=_KEY,
            as_of=_SEALED,
            purged_at=_SEALED + timedelta(days=1),
        )


def test_retention_beyond_ninety_days_is_rejected_for_real_accounts() -> None:
    with pytest.raises(SnapshotRetentionRejected, match="retention_exceeds_ceiling"):
        seal_snapshot(
            handoff_hash=_HASH,
            data_kind="real_account_observed",
            sealed_at=_SEALED,
            hmac_secret=_KEY,
            retention_expires_at=_SEALED + timedelta(days=91),
        )


def test_degenerate_key_is_rejected() -> None:
    with pytest.raises(SnapshotRetentionRejected, match="private_hmac_key_invalid"):
        seal_snapshot(
            handoff_hash=_HASH,
            data_kind="synthetic",
            sealed_at=_SEALED,
            hmac_secret=b"\x00" * 32,
        )


def test_purge_tombstone_keeps_hashes_only_and_names_body_tables() -> None:
    seal = seal_snapshot(
        handoff_hash=_HASH,
        data_kind="real_account_observed",
        sealed_at=_SEALED,
        hmac_secret=_KEY,
    )
    plan = plan_purge(
        snapshot_id="snapshot_redacted_1",
        content_hash=_HASH,
        handoff_hash=seal.handoff_hash,
        data_kind=seal.data_kind,
        sealed_at=seal.sealed_at,
        retention_expires_at=seal.retention_expires_at,
        purged_at=seal.retention_expires_at,
        reason="retention_elapsed",
    )
    assert set(plan.tombstone) == {
        "snapshot_id",
        "content_hash",
        "handoff_hash",
        "data_kind",
        "sealed_at",
        "retention_expires_at",
        "purged_at",
        "purge_reason",
    }
    assert "iam_identity_statements" in plan.delete_tables
    assert "iam_principals" in plan.delete_tables
    assert "graph_edges" in plan.delete_tables
    joined = " ".join(str(value) for value in plan.tombstone.values())
    assert "arn:aws" not in joined and "AKIA" not in joined


def test_early_retention_purge_is_rejected() -> None:
    with pytest.raises(SnapshotRetentionRejected, match="retention_not_elapsed"):
        plan_purge(
            snapshot_id="snapshot_redacted_1",
            content_hash=_HASH,
            handoff_hash=_HASH,
            data_kind="synthetic",
            sealed_at=_SEALED,
            retention_expires_at=_SEALED + timedelta(days=365),
            purged_at=_SEALED + timedelta(days=1),
            reason="retention_elapsed",
        )


def test_operator_purge_may_happen_before_expiry() -> None:
    plan = plan_purge(
        snapshot_id="snapshot_redacted_1",
        content_hash=_HASH,
        handoff_hash=_HASH,
        data_kind="synthetic",
        sealed_at=_SEALED,
        retention_expires_at=_SEALED + timedelta(days=365),
        purged_at=_SEALED + timedelta(days=1),
        reason="operator_purge",
    )
    assert plan.tombstone["purge_reason"] == "operator_purge"
