"""AWS IAM response normalization must redact and fail toward unknown."""

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from fyp_iam.engine2 import aws_authorization_read
from fyp_iam.engine2.aws_authorization_normalize import (
    NormalizationRejected,
    normalize_authorization_details,
)
from fyp_iam.engine2.aws_authorization_read import (
    AuthorizationRead,
    GroupTraversalRead,
    ManagedPolicyRead,
)
from fyp_iam.engine2.observed_graph import project_observed_inventory

ACCOUNT = "111122223333"  # Synthetic only.
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/private-developer"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/private-target"
POLICY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/private-readonly"
SECRET = b"synthetic-test-hmac-key-not-for-any-real-account"


def sample_read(*, include_missing_aws_policy: bool = False) -> AuthorizationRead:
    attached = [{"PolicyArn": POLICY_ARN, "PolicyName": "private-readonly"}]
    if include_missing_aws_policy:
        attached.append({"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
    page = {
        "IsTruncated": False,
        "UserDetailList": [
            {
                "Arn": USER_ARN,
                "UserName": "private-developer",
                "UserId": "AIDAEXAMPLEPRIVATE",
                "GroupList": [],
                "AttachedManagedPolicies": [],
            }
        ],
        "RoleDetailList": [
            {
                "Arn": ROLE_ARN,
                "RoleName": "private-target",
                "RoleId": "AROAEXAMPLEPRIVATE",
                "AttachedManagedPolicies": attached,
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Principal": {"AWS": USER_ARN},
                        }
                    ]
                },
            }
        ],
        "GroupDetailList": [],
        "Policies": [
            {
                "Arn": POLICY_ARN,
                "DefaultVersionId": "v1",
                "PolicyVersionList": [
                    {
                        "VersionId": "v1",
                        "Document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "iam:CreateAccessKey",
                                    "Resource": USER_ARN,
                                }
                            ]
                        },
                    }
                ],
            }
        ],
    }
    return AuthorizationRead(
        pages=(page,),
        page_digests=("sha256:" + "f" * 64,),
        page_count=1,
        raw_bytes=1234,
    )


def normalize(read: AuthorizationRead):  # type: ignore[no-untyped-def]
    start = datetime(2026, 10, 9, tzinfo=UTC)
    return normalize_authorization_details(
        read,
        account_id=ACCOUNT,
        hmac_secret=SECRET,
        started_at=start,
        sealed_at=start + timedelta(seconds=1),
    )


def test_redacted_handoff_keeps_observed_relationships_without_permission_claim() -> None:
    result = normalize(sample_read())
    handoff = result.handoff
    serialized = handoff.model_dump_json()
    for private in (ACCOUNT, USER_ARN, ROLE_ARN, POLICY_ARN, "private-developer", "private-target"):
        assert private not in serialized
    assert handoff.manifest.data_kind == "real_account_observed"
    assert handoff.manifest.snapshot_digest == handoff.inventory.content_digest()
    assert len(handoff.inventory.principals) == 2
    assert len(handoff.inventory.statements) == 1
    assert len(handoff.inventory.trust_statements) == 1
    assert handoff.inventory.group_traversals[0].state == "not_collected"
    graph = project_observed_inventory(handoff)
    assert graph.authorization_evaluated is False
    assert graph.source_coverage_complete is False
    assert all("CAN_" not in relation.kind for relation in graph.relations)


def test_unfetched_aws_managed_policy_marks_partial_and_does_not_invent_attachment() -> None:
    result = normalize(sample_read(include_missing_aws_policy=True))
    coverage = {item.layer: item for item in result.handoff.manifest.coverage}
    assert coverage["identity_policy"].state == "partial"
    assert "managed_policy_unfetched" in result.uncertainty_codes
    assert len(result.handoff.inventory.attachments) == 1


def test_fetched_aws_managed_policy_is_attached_as_observed_not_effective() -> None:
    original = sample_read(include_missing_aws_policy=True)
    aws_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    read = AuthorizationRead(
        pages=original.pages,
        page_digests=original.page_digests,
        page_count=original.page_count,
        raw_bytes=original.raw_bytes,
        managed_policy_reads=(
            ManagedPolicyRead(
                aws_arn,
                {"Statement": [{"Effect": "Allow", "Action": "s3:List*", "Resource": "*"}]},
                "v7",
                "succeeded",
                ("sha256:" + "a" * 64, "sha256:" + "b" * 64),
                None,
            ),
        ),
    )
    result = normalize(read)
    assert len(result.handoff.inventory.attachments) == 2
    assert len(result.handoff.inventory.statements) == 2
    assert len(result.handoff.manifest.tasks) == 3
    assert "managed_policy_unfetched" not in result.uncertainty_codes
    assert project_observed_inventory(result.handoff).authorization_evaluated is False
    assert aws_arn not in result.handoff.model_dump_json()


def test_denied_managed_policy_read_preserves_gap_and_partial_task() -> None:
    original = sample_read(include_missing_aws_policy=True)
    read = AuthorizationRead(
        pages=original.pages,
        page_digests=original.page_digests,
        page_count=original.page_count,
        raw_bytes=original.raw_bytes,
        managed_policy_reads=(
            ManagedPolicyRead(
                "arn:aws:iam::aws:policy/ReadOnlyAccess",
                None,
                None,
                "partial",
                (),
                "managed_policy_read_failed",
            ),
        ),
    )
    result = normalize(read)
    assert result.handoff.manifest.outcome == "partial"
    assert "managed_policy_read_failed" in result.uncertainty_codes
    assert "managed_policy_unfetched" in result.uncertainty_codes
    assert len(result.handoff.inventory.attachments) == 1


def test_json_without_statements_is_partial_not_parsed() -> None:
    original = sample_read()
    page = deepcopy(original.pages[0])
    page["Policies"][0]["PolicyVersionList"][0]["Document"] = {"Version": "2012-10-17"}
    read = AuthorizationRead(
        pages=(page,),
        page_digests=original.page_digests,
        page_count=1,
        raw_bytes=original.raw_bytes,
    )
    result = normalize(read)
    managed = [policy for policy in result.handoff.inventory.policies if policy.kind == "managed"]
    assert managed[0].parse_state == "partial"
    assert result.handoff.inventory.statements == []
    coverage = {item.layer: item for item in result.handoff.manifest.coverage}
    assert coverage["identity_policy"].state == "partial"


def test_independent_empty_group_read_seals_zero_memberships_without_safe_verdict() -> None:
    original = sample_read()
    with_group = AuthorizationRead(
        pages=original.pages,
        page_digests=original.page_digests,
        page_count=1,
        raw_bytes=original.raw_bytes,
        group_traversals=(
            GroupTraversalRead(
                USER_ARN,
                "private-developer",
                (),
                "succeeded",
                1,
                "sha256:" + "b" * 64,
                None,
            ),
        ),
    )
    result = normalize(with_group)
    assert result.handoff.inventory.group_traversals[0].state == "complete"
    assert result.handoff.inventory.group_traversals[0].membership_count == 0
    assert len(result.handoff.manifest.tasks) == 2
    assert "group_traversal_not_independently_read" not in result.uncertainty_codes
    assert project_observed_inventory(result.handoff).authorization_evaluated is False


def test_failed_group_read_remains_partial_with_task_error() -> None:
    original = sample_read()
    with_failure = AuthorizationRead(
        pages=original.pages,
        page_digests=original.page_digests,
        page_count=1,
        raw_bytes=original.raw_bytes,
        group_traversals=(
            GroupTraversalRead(
                USER_ARN, "private-developer", (), "partial", 1, None, "group_pagination_invalid"
            ),
        ),
    )
    result = normalize(with_failure)
    assert result.handoff.manifest.outcome == "partial"
    assert result.handoff.inventory.group_traversals[0].state == "partial"
    assert result.handoff.manifest.tasks[1].pagination_complete is False
    assert "group_pagination_invalid" in result.uncertainty_codes


def test_account_mismatch_and_short_hmac_key_fail_without_raw_values() -> None:
    read = sample_read()
    start = datetime(2026, 10, 9, tzinfo=UTC)
    with pytest.raises(NormalizationRejected, match="^principal_identity_invalid$") as mismatch:
        normalize_authorization_details(
            read,
            account_id="444455556666",
            hmac_secret=SECRET,
            started_at=start,
            sealed_at=start + timedelta(seconds=1),
        )
    assert USER_ARN not in str(mismatch.value)
    with pytest.raises(NormalizationRejected, match="^private_configuration_invalid$"):
        normalize_authorization_details(
            read,
            account_id=ACCOUNT,
            hmac_secret=b"too-short",
            started_at=start,
            sealed_at=start + timedelta(seconds=1),
        )


def test_operator_normalize_preview_emits_only_aggregate_redacted_status(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FYP_AWS_PROFILE", "fyp-readonly")
    monkeypatch.setenv("FYP_AWS_EXPECTED_ACCOUNT_ID", ACCOUNT)
    monkeypatch.setattr(
        aws_authorization_read, "read_authorization_details", lambda _config: sample_read()
    )
    assert aws_authorization_read.main(["--normalize-preview"]) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["redacted_handoff_valid"] is True
    assert json.loads(output)["authorization_evaluated"] is False
    assert json.loads(output)["snapshot_sealed"] is False
    assert "snapshot_seal" not in json.loads(output)
    for private in (ACCOUNT, USER_ARN, ROLE_ARN, "private-developer", "private-target"):
        assert private not in output


def test_stable_key_preview_requires_private_config_before_aws_read(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FYP_AWS_PROFILE", "fyp-readonly")
    monkeypatch.setenv("FYP_AWS_EXPECTED_ACCOUNT_ID", ACCOUNT)
    monkeypatch.delenv("FYP_AWS_HMAC_KEY_HEX", raising=False)
    monkeypatch.setattr(
        aws_authorization_read,
        "read_authorization_details",
        lambda _config: pytest.fail("AWS read must not start without a stable key"),
    )
    assert aws_authorization_read.main(["--normalize-preview", "--stable-key-preview"]) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "private_hmac_key_invalid"
    monkeypatch.setenv("FYP_AWS_HMAC_KEY_HEX", "00" * 32)
    assert aws_authorization_read.main(["--normalize-preview", "--stable-key-preview"]) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "private_hmac_key_invalid"


def test_stable_key_preview_is_repeatable_and_never_prints_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from datetime import UTC, datetime

    from fyp_iam.engine2 import aws_authorization_normalize

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz: object = None) -> datetime:
            return datetime(2026, 10, 9, tzinfo=UTC)

    secret_hex = bytes(range(32)).hex()
    monkeypatch.setenv("FYP_AWS_PROFILE", "fyp-readonly")
    monkeypatch.setenv("FYP_AWS_EXPECTED_ACCOUNT_ID", ACCOUNT)
    monkeypatch.setenv("FYP_AWS_HMAC_KEY_HEX", secret_hex)
    monkeypatch.setattr(aws_authorization_read, "datetime", FrozenDateTime)
    monkeypatch.setattr(
        aws_authorization_read, "read_authorization_details", lambda _config: sample_read()
    )
    real_normalize = aws_authorization_normalize.normalize_authorization_details
    fingerprints: list[str] = []
    seals: list[str] = []

    def capture_normalize(*args: object, **kwargs: object) -> object:
        result = real_normalize(*args, **kwargs)
        fingerprints.append(result.handoff.inventory.principals[0].principal_fingerprint)
        return result

    monkeypatch.setattr(
        aws_authorization_normalize, "normalize_authorization_details", capture_normalize
    )
    for _ in range(2):
        assert aws_authorization_read.main(["--normalize-preview", "--stable-key-preview"]) == 0
        output = capsys.readouterr().out
        assert json.loads(output)["stable_key_preview"] is True
        assert json.loads(output)["snapshot_sealed"] is True
        assert json.loads(output)["snapshot_seal"].startswith("sha256:")
        assert json.loads(output)["authorization_evaluated"] is False
        assert secret_hex not in output
        assert ACCOUNT not in output
        seals.append(json.loads(output)["snapshot_seal"])
    assert fingerprints[0] == fingerprints[1]
    assert seals[0] != seals[1]


def test_redacted_seal_flag_writes_only_after_preview_and_keeps_private_values_out(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    destination = Path(tmp_path) / ".aws-safety" / "redacted-handoff.json"
    monkeypatch.setattr("fyp_iam.engine2.redacted_seal.seal_path", lambda: destination)
    monkeypatch.setenv("FYP_AWS_PROFILE", "fyp-readonly")
    monkeypatch.setenv("FYP_AWS_EXPECTED_ACCOUNT_ID", ACCOUNT)
    monkeypatch.setattr(
        aws_authorization_read,
        "read_authorization_details",
        lambda _config: pytest.fail("AWS read must not start without preview"),
    )
    assert aws_authorization_read.main(["--write-redacted-seal"]) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "preview_required"
    assert not destination.exists()

    monkeypatch.setattr(
        aws_authorization_read, "read_authorization_details", lambda _config: sample_read()
    )
    assert aws_authorization_read.main(["--normalize-preview", "--write-redacted-seal"]) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["redacted_seal_written"] is True
    assert json.loads(output)["authorization_evaluated"] is False
    stored = destination.read_text(encoding="utf-8")
    for private in (ACCOUNT, USER_ARN, ROLE_ARN, "private-developer", "private-target"):
        assert private not in output
        assert private not in stored
