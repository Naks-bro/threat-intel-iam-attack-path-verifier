"""Expiry and purge rules for a sealed redacted snapshot.

The private HMAC key is an argument, never a stored field. A purge tombstone
keeps hashes and timestamps only. It is not a finding, an IT export, or proof
that the collected configuration was complete or effective.
"""

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from fyp_iam.contracts.models import reject_sensitive_text

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,79}$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

REAL_ACCOUNT_MAX = timedelta(days=90)
SYNTHETIC_DEFAULT = timedelta(days=365)
SYNTHETIC_MAX = timedelta(days=731)

# Child rows that hold redacted topology or policy text. The snapshot seal,
# collection tasks, coverage, and gaps stay so an expired read cannot look empty.
PURGE_BODY_TABLES: tuple[str, ...] = (
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
)


class SnapshotRetentionRejected(ValueError):
    """Fixed failure code. The message must not include key or identifier material."""


@dataclass(frozen=True)
class SnapshotSeal:
    handoff_hash: str
    data_kind: str
    sealed_at: datetime
    retention_expires_at: datetime
    seal: str


@dataclass(frozen=True)
class PurgePlan:
    tombstone: dict[str, object]
    delete_tables: tuple[str, ...]


def default_retention_expires_at(sealed_at: datetime, data_kind: str) -> datetime:
    _aware(sealed_at)
    if data_kind == "real_account_observed":
        return sealed_at + REAL_ACCOUNT_MAX
    if data_kind == "synthetic":
        return sealed_at + SYNTHETIC_DEFAULT
    raise SnapshotRetentionRejected("data_kind_rejected")


def key_commitment(secret: bytes) -> str:
    if len(secret) != 32 or len(set(secret)) < 16:
        raise SnapshotRetentionRejected("private_hmac_key_invalid")
    return "sha256:" + hashlib.sha256(secret).hexdigest()


def seal_snapshot(
    *,
    handoff_hash: str,
    data_kind: str,
    sealed_at: datetime,
    hmac_secret: bytes,
    retention_expires_at: datetime | None = None,
) -> SnapshotSeal:
    expires = retention_expires_at or default_retention_expires_at(sealed_at, data_kind)
    _assert_window(sealed_at, expires, data_kind)
    if not _HASH.fullmatch(handoff_hash):
        raise SnapshotRetentionRejected("handoff_hash_rejected")
    commitment = key_commitment(hmac_secret)
    material = "|".join(
        (
            commitment,
            handoff_hash,
            data_kind,
            sealed_at.isoformat(),
            expires.isoformat(),
        )
    )
    return SnapshotSeal(
        handoff_hash=handoff_hash,
        data_kind=data_kind,
        sealed_at=sealed_at,
        retention_expires_at=expires,
        seal="sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest(),
    )


def assert_replay(
    expected: SnapshotSeal,
    *,
    handoff_hash: str,
    hmac_secret: bytes,
    as_of: datetime,
    purged_at: datetime | None = None,
) -> None:
    actual = seal_snapshot(
        handoff_hash=handoff_hash,
        data_kind=expected.data_kind,
        sealed_at=expected.sealed_at,
        hmac_secret=hmac_secret,
        retention_expires_at=expected.retention_expires_at,
    )
    if actual.seal != expected.seal or actual.handoff_hash != expected.handoff_hash:
        raise SnapshotRetentionRejected("snapshot_seal_mismatch")
    assert_snapshot_usable(
        sealed_at=expected.sealed_at,
        retention_expires_at=expected.retention_expires_at,
        data_kind=expected.data_kind,
        as_of=as_of,
        purged_at=purged_at,
    )


def assert_snapshot_usable(
    *,
    sealed_at: datetime,
    retention_expires_at: datetime,
    data_kind: str,
    as_of: datetime,
    purged_at: datetime | None = None,
) -> None:
    _assert_window(sealed_at, retention_expires_at, data_kind)
    _aware(as_of)
    if purged_at is not None:
        _aware(purged_at)
        raise SnapshotRetentionRejected("snapshot_purged")
    if as_of >= retention_expires_at:
        raise SnapshotRetentionRejected("snapshot_expired")


def plan_purge(
    *,
    snapshot_id: str,
    content_hash: str,
    handoff_hash: str,
    data_kind: str,
    sealed_at: datetime,
    retention_expires_at: datetime,
    purged_at: datetime,
    reason: str,
) -> PurgePlan:
    if reason not in {"retention_elapsed", "operator_purge"} or not _REASON.fullmatch(reason):
        raise SnapshotRetentionRejected("purge_reason_rejected")
    if not _ID.fullmatch(snapshot_id) or not _HASH.fullmatch(content_hash):
        raise SnapshotRetentionRejected("purge_identity_rejected")
    if not _HASH.fullmatch(handoff_hash):
        raise SnapshotRetentionRejected("purge_identity_rejected")
    _assert_window(sealed_at, retention_expires_at, data_kind)
    _aware(purged_at)
    if purged_at < sealed_at:
        raise SnapshotRetentionRejected("purge_before_seal")
    if reason == "retention_elapsed" and purged_at < retention_expires_at:
        raise SnapshotRetentionRejected("retention_not_elapsed")
    tombstone = {
        "snapshot_id": snapshot_id,
        "content_hash": content_hash,
        "handoff_hash": handoff_hash,
        "data_kind": data_kind,
        "sealed_at": sealed_at,
        "retention_expires_at": retention_expires_at,
        "purged_at": purged_at,
        "purge_reason": reason,
    }
    for key, value in tombstone.items():
        if isinstance(value, str):
            reject_sensitive_text(value)
            if key.endswith("_hash") or key == "snapshot_id":
                continue
        if key in {"hmac_secret", "account_id", "arn", "policy_document"}:
            raise SnapshotRetentionRejected("purge_identity_rejected")
    return PurgePlan(tombstone=tombstone, delete_tables=PURGE_BODY_TABLES)


def _assert_window(sealed_at: datetime, expires_at: datetime, data_kind: str) -> None:
    _aware(sealed_at)
    _aware(expires_at)
    if data_kind not in {"synthetic", "real_account_observed"}:
        raise SnapshotRetentionRejected("data_kind_rejected")
    if expires_at <= sealed_at:
        raise SnapshotRetentionRejected("retention_not_after_seal")
    ceiling = REAL_ACCOUNT_MAX if data_kind == "real_account_observed" else SYNTHETIC_MAX
    if expires_at - sealed_at > ceiling:
        raise SnapshotRetentionRejected("retention_exceeds_ceiling")


def _aware(value: datetime) -> None:
    if value.tzinfo is None:
        raise SnapshotRetentionRejected("timestamp_not_aware")
