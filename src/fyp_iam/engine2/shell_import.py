"""Prepare a sealed AWS handoff for the proposed 0009 metadata shell.

This is deliberately a pure compatibility gate, not a database writer or an
AWS collector. It does not turn collected policy text into effective access.
"""

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from fyp_iam.contracts.collection import CoverageState, PolicyLayer
from fyp_iam.contracts.inventory import CollectionHandoff
from fyp_iam.contracts.models import reject_sensitive_text
from fyp_iam.engine2.snapshot_retention import default_retention_expires_at

_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,79}$")
_ALIAS = re.compile(r"^[a-z][a-z0-9-]{0,79}$")


class ShellImportRejected(ValueError):
    """A fixed, non-sensitive reason the handoff cannot fit the shell."""


@dataclass(frozen=True)
class ShellImportPlan:
    run: dict[str, Any]
    tasks: tuple[dict[str, Any], ...]
    snapshot: dict[str, Any]
    coverage: tuple[dict[str, Any], ...]
    gaps: tuple[dict[str, Any], ...]


def _opaque_id(value: str) -> bool:
    return (
        _OPAQUE_ID.fullmatch(value) is not None
        and re.search(r"\b\d{12}\b", value) is None
        and not _contains_sensitive_text(value)
    )


def _contains_sensitive_text(value: str) -> bool:
    try:
        reject_sensitive_text(value)
    except ValueError:
        return True
    return False


def _derived_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:32]
    return prefix + digest


def prepare_shell_import(
    handoff: CollectionHandoff,
    *,
    connection_id: str,
    expected_account_fingerprint: str,
    request_id: str,
    attempt: int = 1,
    retry_of: str | None = None,
) -> ShellImportPlan:
    """Map validated, redacted metadata to 0009 shapes without writing it.

    The caller must resolve ``connection_id`` from a private authorized
    registry and verify its fingerprint there. This function checks the value
    supplied by the caller but cannot attest to that registry or to AWS.
    """

    # Pydantic objects are mutable. Revalidate their current bytes and binding
    # before deriving any rows; never trust an earlier validation event.
    try:
        sealed = CollectionHandoff.model_validate(handoff.model_dump(mode="json"))
    except (ValueError, TypeError) as exc:
        raise ShellImportRejected("handoff_invalid") from exc

    manifest = sealed.manifest
    identifiers = (connection_id, request_id, manifest.run_id, manifest.snapshot_id)
    if not all(_opaque_id(value) for value in identifiers):
        raise ShellImportRejected("identifier_not_storable")
    if retry_of is not None and not _opaque_id(retry_of):
        raise ShellImportRejected("retry_identifier_not_storable")
    if not 1 <= attempt <= 10:
        raise ShellImportRejected("attempt_out_of_range")
    if not _ALIAS.fullmatch(manifest.account_alias):
        raise ShellImportRejected("account_alias_not_storable")
    if manifest.account_fingerprint != expected_account_fingerprint:
        raise ShellImportRejected("account_fingerprint_mismatch")

    principals = {principal.principal_key: principal for principal in sealed.inventory.principals}
    tasks: list[dict[str, Any]] = []
    task_keys: set[tuple[str, str, int]] = set()
    for index, task in enumerate(manifest.tasks):
        subject = task.subject_principal_key
        if subject is not None and subject not in principals:
            raise ShellImportRejected("task_subject_unknown")
        if task.outcome == "succeeded" and task.response_digest is None:
            raise ShellImportRejected("successful_task_digest_missing")
        scope = (
            principals[subject].principal_fingerprint
            if subject is not None
            else task.subject_policy_fingerprint or "account"
        )
        key = (task.operation, scope, task.attempt)
        if key in task_keys:
            raise ShellImportRejected("duplicate_task_attempt")
        task_keys.add(key)
        tasks.append(
            {
                "task_id": _derived_id("task_", manifest.run_id, str(index)),
                "collection_run_id": manifest.run_id,
                "api_name": task.operation,
                "scope_key": scope,
                "sequence_no": index,
                "attempt": task.attempt,
                "status": task.outcome.value,
                "page_count": task.page_count,
                "item_count": task.item_count,
                "pagination_complete": task.pagination_complete,
                "response_digest": task.response_digest,
                "error_code": task.error_code,
            }
        )

    gaps: list[dict[str, Any]] = []
    gap_keys: set[tuple[str, str, str]] = set()

    def gap(layer: PolicyLayer, scope: str, state: str, reason: str) -> None:
        key = (layer.value, scope, reason)
        if key in gap_keys:
            return
        gap_keys.add(key)
        gaps.append(
            {
                "gap_id": _derived_id("gap_", manifest.snapshot_id, *key),
                "snapshot_id": manifest.snapshot_id,
                "collection_run_id": manifest.run_id,
                "task_id": None,
                "layer": layer.value,
                "scope_key": scope,
                "coverage_state": state,
                "reason_code": reason,
            }
        )

    for coverage in manifest.coverage:
        if coverage.state not in {CoverageState.collected, CoverageState.absent}:
            gap(coverage.layer, "account", coverage.state.value, coverage.reason_code or "unknown")

    coverage_rows = tuple(
        {
            "sequence_no": index,
            "snapshot_id": manifest.snapshot_id,
            "collection_run_id": manifest.run_id,
            "layer": item.layer.value,
            "state": item.state.value,
            "object_count": item.object_count,
            "reason_code": item.reason_code,
            "authorization_evaluated": False,
        }
        for index, item in enumerate(manifest.coverage)
    )

    if manifest.data_kind == "real_account_observed":
        traversals = {item.user_key: item for item in sealed.inventory.group_traversals}
        for principal in sealed.inventory.principals:
            if principal.kind != "iam_user":
                continue
            traversal = traversals.get(principal.principal_key)
            if traversal is None:
                gap(
                    PolicyLayer.identity_policy,
                    principal.principal_fingerprint,
                    "not_collected",
                    "group_traversal_missing",
                )
            elif traversal.state != "complete":
                gap(
                    PolicyLayer.identity_policy,
                    principal.principal_fingerprint,
                    "partial" if traversal.state == "partial" else "unavailable",
                    traversal.reason_code or "group_traversal_incomplete",
                )

    if manifest.outcome == "partial" and not gaps:
        raise ShellImportRejected("partial_run_without_coverage_gap")

    seal_status = "partial" if gaps else "complete"
    expiry = default_retention_expires_at(manifest.sealed_at, manifest.data_kind)
    return ShellImportPlan(
        run={
            "collection_run_id": manifest.run_id,
            "connection_id": connection_id,
            "retry_of": retry_of,
            "request_id": request_id,
            "status": manifest.outcome.value,
            "attempt": attempt,
            "collector_version": manifest.collector_version,
            "started_at": manifest.started_at,
            "finished_at": manifest.sealed_at,
            "error_code": "incomplete_collection" if manifest.outcome == "partial" else None,
        },
        tasks=tuple(tasks),
        snapshot={
            "snapshot_id": manifest.snapshot_id,
            "connection_id": connection_id,
            "collection_run_id": manifest.run_id,
            "data_kind": manifest.data_kind,
            "seal_status": seal_status,
            "content_hash": manifest.snapshot_digest,
            "handoff_hash": sealed.content_digest(),
            "contract_version": manifest.schema_version,
            "sealed_at": manifest.sealed_at,
            "retention_expires_at": expiry,
        },
        coverage=coverage_rows,
        gaps=tuple(gaps),
    )
