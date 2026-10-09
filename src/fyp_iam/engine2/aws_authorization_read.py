"""Bounded, opt-in read transport for AWS IAM authorization details.

Returns private raw pages in memory to the redacting normalizer. Never prints
or persists those pages. A stable private key can seal the redacted handoff
hash in memory. ``--write-redacted-seal`` may store only that redacted handoff
in the gitignored local seal file. The seal is not a database snapshot or an
access verdict.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from typing import Any

from fyp_iam.engine2.aws_guard import GuardBlocked, record_failure, reserve_call
from fyp_iam.engine2.aws_preflight import PreflightConfig, _child_environment, check_connection

RunCommand = Callable[..., subprocess.CompletedProcess[str]]
_COLLECTIONS = ("UserDetailList", "RoleDetailList", "GroupDetailList", "Policies")
_FILTER = ("User", "Role", "Group", "LocalManagedPolicy")
_MAX_PAGES = 20
_MAX_PAGE_BYTES = 1_000_000
_MAX_TOTAL_BYTES = 2_000_000
_MAX_GROUP_USERS = 6
_MAX_GROUP_PAGES = 5
_MAX_REFERENCED_POLICIES = 3
_VERSION = re.compile(r"^v[1-9][0-9]{0,4}$")


class AuthorizationReadRejected(ValueError):
    """Fixed status code; never attach raw AWS response or CLI stderr."""


@dataclass(frozen=True)
class GroupTraversalRead:
    """Private per-user read; failure never means an empty membership list."""

    user_arn: str = field(repr=False)
    user_name: str = field(repr=False)
    groups: tuple[dict[str, Any], ...] = field(repr=False)
    status: str
    page_count: int
    response_digest: str | None
    error_code: str | None


@dataclass(frozen=True)
class ManagedPolicyRead:
    """Private exact-default-version read of a referenced AWS-managed policy."""

    policy_arn: str = field(repr=False)
    document: Any = field(repr=False)
    default_version: str | None
    status: str
    response_digests: tuple[str, ...]
    error_code: str | None


@dataclass(frozen=True)
class AuthorizationRead:
    """Private raw pages; callers must redact before display or persistence."""

    pages: tuple[dict[str, Any], ...] = field(repr=False)
    page_digests: tuple[str, ...]
    page_count: int
    raw_bytes: int
    group_traversals: tuple[GroupTraversalRead, ...] = field(default=(), repr=False)
    managed_policy_reads: tuple[ManagedPolicyRead, ...] = field(default=(), repr=False)


def read_authorization_details(
    config: PreflightConfig,
    *,
    include_group_traversal: bool = False,
    include_managed_policies: bool = False,
    run: RunCommand = subprocess.run,
) -> AuthorizationRead:
    """Read every page or fail closed; require owner-supplied expected account."""

    preflight = check_connection(config, run=run)
    if preflight.status != "ready":
        raise AuthorizationReadRejected("preflight_not_ready")
    pages: list[dict[str, Any]] = []
    digests: list[str] = []
    markers: set[str] = set()
    marker: str | None = None
    total = 0
    for _ in range(_MAX_PAGES):
        payload: dict[str, Any] = {"Filter": list(_FILTER), "MaxItems": 100}
        if marker is not None:
            payload["Marker"] = marker
        argv = [
            "aws",
            "iam",
            "get-account-authorization-details",
            "--profile",
            config.profile,
            "--region",
            "us-east-1",
            "--endpoint-url",
            "https://iam.amazonaws.com",
            "--no-paginate",
            "--cli-input-json",
            json.dumps(payload, separators=(",", ":")),
            "--output",
            "json",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "15",
        ]
        try:
            reserve_call()
        except GuardBlocked:
            raise AuthorizationReadRejected("aws_guard_blocked") from None
        try:
            response = run(
                argv,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                timeout=25,
                env=_child_environment(),
            )
        except (OSError, subprocess.TimeoutExpired):
            _cooldown()
            raise AuthorizationReadRejected("aws_read_failed") from None
        if response.returncode != 0:
            _cooldown()
            raise AuthorizationReadRejected("aws_read_failed")
        try:
            raw = response.stdout.encode("utf-8")
        except (UnicodeError, AttributeError):
            raise AuthorizationReadRejected("aws_response_invalid") from None
        total += len(raw)
        if len(raw) > _MAX_PAGE_BYTES or total > _MAX_TOTAL_BYTES:
            raise AuthorizationReadRejected("aws_response_too_large")
        try:
            decoded = json.loads(raw)
        except (UnicodeError, ValueError, TypeError):
            raise AuthorizationReadRejected("aws_response_invalid") from None
        if not isinstance(decoded, dict) or type(decoded.get("IsTruncated")) is not bool:
            raise AuthorizationReadRejected("aws_response_invalid")
        if any(name in decoded and not isinstance(decoded[name], list) for name in _COLLECTIONS):
            raise AuthorizationReadRejected("aws_response_invalid")
        pages.append(decoded)
        digests.append("sha256:" + hashlib.sha256(raw).hexdigest())
        if not decoded["IsTruncated"]:
            group_reads = (
                _read_group_traversals(config, pages, run=run) if include_group_traversal else ()
            )
            policy_reads = (
                _read_managed_policies(config, pages, run=run) if include_managed_policies else ()
            )
            return AuthorizationRead(
                tuple(pages), tuple(digests), len(pages), total, group_reads, policy_reads
            )
        next_marker = decoded.get("Marker")
        if not isinstance(next_marker, str) or not next_marker or next_marker in markers:
            raise AuthorizationReadRejected("aws_pagination_invalid")
        markers.add(next_marker)
        marker = next_marker
    raise AuthorizationReadRejected("aws_page_limit_exceeded")


def _read_group_traversals(
    config: PreflightConfig,
    pages: list[dict[str, Any]],
    *,
    run: RunCommand,
) -> tuple[GroupTraversalRead, ...]:
    users = [
        item for page in pages for item in page.get("UserDetailList", []) if isinstance(item, dict)
    ]
    result: list[GroupTraversalRead] = []
    for index, user in enumerate(users):
        user_arn, user_name = user.get("Arn"), user.get("UserName")
        if not isinstance(user_arn, str) or not isinstance(user_name, str):
            raise AuthorizationReadRejected("aws_user_identity_invalid")
        if index >= _MAX_GROUP_USERS:
            result.append(
                GroupTraversalRead(
                    user_arn, user_name, (), "not_collected", 0, None, "group_read_budget"
                )
            )
            continue
        groups: list[dict[str, Any]] = []
        raw_pages: list[dict[str, Any]] = []
        seen: set[str] = set()
        marker: str | None = None
        failure: str | None = None
        for _ in range(_MAX_GROUP_PAGES):
            payload: dict[str, Any] = {"UserName": user_name, "MaxItems": 100}
            if marker is not None:
                payload["Marker"] = marker
            argv = [
                "aws",
                "iam",
                "list-groups-for-user",
                "--profile",
                config.profile,
                "--region",
                "us-east-1",
                "--endpoint-url",
                "https://iam.amazonaws.com",
                "--no-paginate",
                "--cli-input-json",
                json.dumps(payload, separators=(",", ":")),
                "--output",
                "json",
                "--no-cli-pager",
                "--cli-connect-timeout",
                "5",
                "--cli-read-timeout",
                "15",
            ]
            try:
                reserve_call()
            except GuardBlocked:
                failure = "aws_guard_blocked"
                break
            try:
                response = run(
                    argv,
                    shell=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    timeout=25,
                    env=_child_environment(),
                )
            except (OSError, subprocess.TimeoutExpired):
                _cooldown()
                failure = "group_read_failed"
                break
            if response.returncode != 0:
                _cooldown()
                failure = "group_read_failed"
                break
            try:
                output = response.stdout.encode("utf-8")
                if len(output) > 200_000:
                    failure = "group_response_too_large"
                    break
                decoded = json.loads(output)
            except (UnicodeError, ValueError, TypeError, AttributeError):
                failure = "group_response_invalid"
                break
            if (
                not isinstance(decoded, dict)
                or type(decoded.get("IsTruncated")) is not bool
                or not isinstance(decoded.get("Groups"), list)
                or any(not isinstance(group, dict) for group in decoded["Groups"])
            ):
                failure = "group_response_invalid"
                break
            raw_pages.append(decoded)
            groups.extend(decoded["Groups"])
            if not decoded["IsTruncated"]:
                digest = (
                    "sha256:"
                    + hashlib.sha256(
                        json.dumps(raw_pages, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    ).hexdigest()
                )
                result.append(
                    GroupTraversalRead(
                        user_arn,
                        user_name,
                        tuple(groups),
                        "succeeded",
                        len(raw_pages),
                        digest,
                        None,
                    )
                )
                break
            next_marker = decoded.get("Marker")
            if not isinstance(next_marker, str) or not next_marker or next_marker in seen:
                failure = "group_pagination_invalid"
                break
            seen.add(next_marker)
            marker = next_marker
        else:
            failure = "group_page_limit_exceeded"
        if failure is not None:
            result.append(
                GroupTraversalRead(
                    user_arn, user_name, (), "partial", len(raw_pages), None, failure
                )
            )
    return tuple(result)


def _cooldown() -> None:
    try:
        record_failure()
    except GuardBlocked:
        pass


def _read_managed_policies(
    config: PreflightConfig,
    pages: list[dict[str, Any]],
    *,
    run: RunCommand,
) -> tuple[ManagedPolicyRead, ...]:
    """Read only referenced AWS-managed policies, never enumerate the AWS catalog."""

    referenced: set[str] = set()
    for page in pages:
        for name in ("UserDetailList", "RoleDetailList", "GroupDetailList"):
            for owner in page.get(name, []):
                if not isinstance(owner, dict):
                    continue
                for attachment in owner.get("AttachedManagedPolicies", []):
                    if isinstance(attachment, dict):
                        arn = attachment.get("PolicyArn")
                        if isinstance(arn, str) and arn.startswith("arn:aws:iam::aws:policy/"):
                            referenced.add(arn)
                boundary = owner.get("PermissionsBoundary")
                if isinstance(boundary, dict):
                    arn = boundary.get("PermissionsBoundaryArn")
                    if isinstance(arn, str) and arn.startswith("arn:aws:iam::aws:policy/"):
                        referenced.add(arn)

    def request(operation: str, payload: dict[str, str]) -> tuple[dict[str, Any] | None, str]:
        argv = [
            "aws",
            "iam",
            operation,
            "--profile",
            config.profile,
            "--region",
            "us-east-1",
            "--endpoint-url",
            "https://iam.amazonaws.com",
            "--no-paginate",
            "--cli-input-json",
            json.dumps(payload, separators=(",", ":")),
            "--output",
            "json",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "15",
        ]
        try:
            reserve_call()
        except GuardBlocked:
            return None, "aws_guard_blocked"
        try:
            response = run(
                argv,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                timeout=25,
                env=_child_environment(),
            )
        except (OSError, subprocess.TimeoutExpired):
            _cooldown()
            return None, "managed_policy_read_failed"
        if response.returncode != 0:
            _cooldown()
            return None, "managed_policy_read_failed"
        try:
            raw = response.stdout.encode("utf-8")
            if len(raw) > 200_000:
                return None, "managed_policy_response_too_large"
            parsed = json.loads(raw)
        except (UnicodeError, ValueError, TypeError, AttributeError):
            return None, "managed_policy_response_invalid"
        if not isinstance(parsed, dict):
            return None, "managed_policy_response_invalid"
        return parsed, "sha256:" + hashlib.sha256(raw).hexdigest()

    result: list[ManagedPolicyRead] = []
    for index, arn in enumerate(sorted(referenced)):
        if index >= _MAX_REFERENCED_POLICIES:
            result.append(
                ManagedPolicyRead(arn, None, None, "not_collected", (), "policy_read_budget")
            )
            continue
        metadata, metadata_digest = request("get-policy", {"PolicyArn": arn})
        if metadata is None:
            result.append(ManagedPolicyRead(arn, None, None, "partial", (), metadata_digest))
            continue
        policy = metadata.get("Policy")
        if not isinstance(policy, dict) or policy.get("Arn") != arn:
            result.append(
                ManagedPolicyRead(arn, None, None, "partial", (), "policy_binding_invalid")
            )
            continue
        version = policy.get("DefaultVersionId")
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            result.append(
                ManagedPolicyRead(arn, None, None, "partial", (), "policy_version_invalid")
            )
            continue
        version_data, version_digest = request(
            "get-policy-version", {"PolicyArn": arn, "VersionId": version}
        )
        if version_data is None:
            result.append(
                ManagedPolicyRead(arn, None, version, "partial", (metadata_digest,), version_digest)
            )
            continue
        actual = version_data.get("PolicyVersion")
        if (
            not isinstance(actual, dict)
            or actual.get("VersionId") != version
            or actual.get("IsDefaultVersion") is not True
            or "Document" not in actual
        ):
            result.append(
                ManagedPolicyRead(
                    arn, None, version, "partial", (metadata_digest,), "policy_version_changed"
                )
            )
            continue
        result.append(
            ManagedPolicyRead(
                arn,
                actual["Document"],
                version,
                "succeeded",
                (metadata_digest, version_digest),
                None,
            )
        )
    return tuple(result)


def main(argv: Sequence[str] | None = None) -> int:
    """Opt-in aggregate probe; never emit raw IAM values or retain pages."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--normalize-preview",
        action="store_true",
        help="Use an ephemeral HMAC key to check a redacted in-memory handoff only",
    )
    parser.add_argument(
        "--stable-key-preview",
        action="store_true",
        help="Use private FYP_AWS_HMAC_KEY_HEX to seal a repeatable in-memory handoff",
    )
    parser.add_argument(
        "--read-groups",
        action="store_true",
        help="Also make bounded per-user ListGroupsForUser calls (requires normalize preview)",
    )
    parser.add_argument(
        "--read-managed-policies",
        action="store_true",
        help="Read bounded referenced AWS-managed policy defaults (requires preview)",
    )
    parser.add_argument(
        "--write-redacted-seal",
        action="store_true",
        help="Write only the redacted handoff to the gitignored local seal file",
    )
    args = parser.parse_args(argv)
    if args.write_redacted_seal and not args.normalize_preview:
        print(json.dumps({"status": "not_configured", "code": "preview_required"}))
        return 2
    if (args.read_groups or args.read_managed_policies) and not args.normalize_preview:
        print(json.dumps({"status": "not_configured", "code": "preview_required"}))
        return 2
    if args.stable_key_preview and not args.normalize_preview:
        print(json.dumps({"status": "not_configured", "code": "preview_required"}))
        return 2
    stable_key: bytes | None = None
    if args.stable_key_preview:
        supplied = os.environ.get("FYP_AWS_HMAC_KEY_HEX", "")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", supplied):
            print(json.dumps({"status": "not_configured", "code": "private_hmac_key_invalid"}))
            return 2
        stable_key = bytes.fromhex(supplied)
        if len(set(stable_key)) < 16:
            print(json.dumps({"status": "not_configured", "code": "private_hmac_key_invalid"}))
            return 2
    profile = os.environ.get("FYP_AWS_PROFILE")
    expected = os.environ.get("FYP_AWS_EXPECTED_ACCOUNT_ID")
    if not profile or not expected:
        print(json.dumps({"status": "not_configured", "code": "configuration_required"}))
        return 2
    try:
        config = PreflightConfig(profile=profile, expected_account=expected)
    except ValueError:
        print(json.dumps({"status": "not_configured", "code": "invalid_configuration"}))
        return 2
    try:
        started = datetime.now(UTC)
        if args.read_groups or args.read_managed_policies:
            result = read_authorization_details(
                config,
                include_group_traversal=args.read_groups,
                include_managed_policies=args.read_managed_policies,
            )
        else:
            result = read_authorization_details(config)
    except AuthorizationReadRejected as exc:
        print(json.dumps({"status": "incomplete", "code": str(exc)}))
        return 2
    counts = {name: sum(len(page.get(name, [])) for page in result.pages) for name in _COLLECTIONS}
    preview: dict[str, Any] = {}
    if args.normalize_preview:
        # Import locally to avoid a module cycle. Neither key variant is emitted.
        import secrets

        from fyp_iam.engine2.aws_authorization_normalize import normalize_authorization_details
        from fyp_iam.engine2.inventory_import import prepare_inventory_import
        from fyp_iam.engine2.observed_graph import project_observed_inventory
        from fyp_iam.engine2.shell_import import prepare_shell_import
        from fyp_iam.engine2.snapshot_retention import seal_snapshot

        stage = "normalization"
        try:
            normalized = normalize_authorization_details(
                result,
                account_id=expected,
                hmac_secret=stable_key if stable_key is not None else secrets.token_bytes(32),
                started_at=started,
                sealed_at=datetime.now(UTC),
            )
            stage = "graph_projection"
            observed = project_observed_inventory(normalized.handoff)
            stage = "shell_mapping"
            shell = prepare_shell_import(
                normalized.handoff,
                connection_id="preview_connection",
                expected_account_fingerprint=normalized.handoff.manifest.account_fingerprint,
                request_id="preview_request",
            )
            stage = "inventory_mapping"
            inventory_rows = prepare_inventory_import(normalized.handoff, shell)
        except Exception:
            # Raw AWS input can appear in parser exceptions; never echo it.
            print(json.dumps({"status": "incomplete", "code": f"{stage}_preview_failed"}))
            return 2
        preview = {
            "redacted_handoff_valid": True,
            "draft_rows_compatible": True,
            "principal_count": len(normalized.handoff.inventory.principals),
            "identity_statement_count": len(normalized.handoff.inventory.statements),
            "trust_statement_count": len(normalized.handoff.inventory.trust_statements),
            "uncertainty_codes": normalized.uncertainty_codes,
            "observed_relation_count": len(observed.relations),
            "draft_inventory_row_count": sum(
                len(getattr(inventory_rows, item.name)) for item in fields(inventory_rows)
            ),
            "source_coverage_complete": observed.source_coverage_complete,
            "ephemeral_key_discarded": stable_key is None,
            "stable_key_preview": stable_key is not None,
            "snapshot_sealed": False,
            "group_traversal_completed": sum(
                item.status == "succeeded" for item in result.group_traversals
            ),
            "managed_policy_reads_completed": sum(
                item.status == "succeeded" for item in result.managed_policy_reads
            ),
        }
        if stable_key is not None:
            sealed = seal_snapshot(
                handoff_hash=normalized.handoff.content_digest(),
                data_kind=normalized.handoff.manifest.data_kind,
                sealed_at=normalized.handoff.manifest.sealed_at,
                hmac_secret=stable_key,
                retention_expires_at=shell.snapshot["retention_expires_at"],
            )
            preview["snapshot_sealed"] = True
            preview["snapshot_seal"] = sealed.seal
            preview["retention_expires_at"] = sealed.retention_expires_at.isoformat()
        if args.write_redacted_seal:
            from fyp_iam.engine2.redacted_seal import write_redacted_seal

            try:
                write_redacted_seal(normalized.handoff)
            except Exception:
                print(json.dumps({"status": "incomplete", "code": "redacted_seal_rejected"}))
                return 2
            preview["redacted_seal_written"] = True
    print(
        json.dumps(
            {
                "status": "observed",
                "code": "raw_iam_read_only",
                "page_count": result.page_count,
                "aggregate_counts": counts,
                "snapshot_sealed": False,
                "authorization_evaluated": False,
                **preview,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
