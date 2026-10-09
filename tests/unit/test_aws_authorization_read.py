"""Only allow bounded, complete, preflighted read-only IAM pages."""

import json
import subprocess
from collections.abc import Callable

import pytest

from fyp_iam.engine2 import aws_authorization_read, aws_guard
from fyp_iam.engine2.aws_authorization_read import (
    AuthorizationRead,
    AuthorizationReadRejected,
    read_authorization_details,
)
from fyp_iam.engine2.aws_preflight import PreflightConfig

ACCOUNT = "111122223333"  # Synthetic fixture only.


@pytest.fixture(autouse=True)
def isolated_guard(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(aws_guard, "STATE_DIR", tmp_path / "guard")
    monkeypatch.delenv("FYP_AWS_STOP", raising=False)


def config() -> PreflightConfig:
    return PreflightConfig(profile="fyp-readonly", expected_account=ACCOUNT)


def runner(
    responses: list[dict[str, object] | BaseException], calls: list[list[str]]
) -> Callable[..., subprocess.CompletedProcess[str]]:
    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        assert kwargs["shell"] is False
        assert kwargs["stderr"] == subprocess.DEVNULL
        response = responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return subprocess.CompletedProcess(argv, 0, json.dumps(response))

    return run


def preflight() -> list[dict[str, object]]:
    return [
        {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/readonly/test-session",
        },
        {"item_count": 1, "truncated": False},
        {"item_count": 1, "truncated": False},
    ]


def test_complete_two_page_read_is_private_and_pinned() -> None:
    calls: list[list[str]] = []
    responses = preflight() + [
        {"IsTruncated": True, "Marker": "page-two", "UserDetailList": [{"UserName": "Private"}]},
        {"IsTruncated": False, "RoleDetailList": [{"RoleName": "Private"}]},
    ]
    result = read_authorization_details(config(), run=runner(responses, calls))
    assert result.page_count == 2
    assert len(result.page_digests) == 2
    assert all(item.startswith("sha256:") for item in result.page_digests)
    assert [call[1:3] for call in calls[3:]] == [
        ["iam", "get-account-authorization-details"],
        ["iam", "get-account-authorization-details"],
    ]
    assert json.loads(calls[3][calls[3].index("--cli-input-json") + 1]) == {
        "Filter": ["User", "Role", "Group", "LocalManagedPolicy"],
        "MaxItems": 100,
    }
    assert json.loads(calls[4][calls[4].index("--cli-input-json") + 1])["Marker"] == "page-two"
    assert "Private" not in repr(result)


def test_completed_group_read_is_separate_and_paginates() -> None:
    calls: list[list[str]] = []
    user_arn = f"arn:aws:iam::{ACCOUNT}:user/private-user"
    responses = preflight() + [
        {"IsTruncated": False, "UserDetailList": [{"Arn": user_arn, "UserName": "private-user"}]},
        {"IsTruncated": True, "Marker": "next", "Groups": []},
        {"IsTruncated": False, "Groups": []},
    ]
    result = read_authorization_details(
        config(), include_group_traversal=True, run=runner(responses, calls)
    )
    assert len(calls) == 6
    assert result.group_traversals[0].status == "succeeded"
    assert result.group_traversals[0].page_count == 2
    assert result.group_traversals[0].groups == ()
    assert result.group_traversals[0].response_digest is not None
    assert "private-user" not in repr(result)
    assert json.loads(calls[-1][calls[-1].index("--cli-input-json") + 1])["Marker"] == "next"


def test_incomplete_group_read_does_not_become_empty_success() -> None:
    calls: list[list[str]] = []
    user_arn = f"arn:aws:iam::{ACCOUNT}:user/private-user"
    responses = preflight() + [
        {"IsTruncated": False, "UserDetailList": [{"Arn": user_arn, "UserName": "private-user"}]},
        {"IsTruncated": True, "Groups": []},
    ]
    result = read_authorization_details(
        config(), include_group_traversal=True, run=runner(responses, calls)
    )
    assert result.group_traversals[0].status == "partial"
    assert result.group_traversals[0].response_digest is None
    assert result.group_traversals[0].error_code == "group_pagination_invalid"


def test_referenced_managed_policy_reads_exact_default_version() -> None:
    calls: list[list[str]] = []
    arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    responses = preflight() + [
        {
            "IsTruncated": False,
            "RoleDetailList": [{"AttachedManagedPolicies": [{"PolicyArn": arn}]}],
        },
        {"Policy": {"Arn": arn, "DefaultVersionId": "v7"}},
        {
            "PolicyVersion": {
                "VersionId": "v7",
                "IsDefaultVersion": True,
                "Document": {"Statement": []},
            }
        },
    ]
    result = read_authorization_details(
        config(), include_managed_policies=True, run=runner(responses, calls)
    )
    assert len(result.managed_policy_reads) == 1
    assert result.managed_policy_reads[0].status == "succeeded"
    assert len(result.managed_policy_reads[0].response_digests) == 2
    assert [call[1:3] for call in calls[-2:]] == [
        ["iam", "get-policy"],
        ["iam", "get-policy-version"],
    ]
    assert json.loads(calls[-1][calls[-1].index("--cli-input-json") + 1]) == {
        "PolicyArn": arn,
        "VersionId": "v7",
    }
    assert arn not in repr(result)


def test_changed_managed_policy_default_stays_partial() -> None:
    calls: list[list[str]] = []
    arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    responses = preflight() + [
        {
            "IsTruncated": False,
            "UserDetailList": [{"AttachedManagedPolicies": [{"PolicyArn": arn}]}],
        },
        {"Policy": {"Arn": arn, "DefaultVersionId": "v7"}},
        {
            "PolicyVersion": {
                "VersionId": "v7",
                "IsDefaultVersion": False,
                "Document": {"Statement": []},
            }
        },
    ]
    result = read_authorization_details(
        config(), include_managed_policies=True, run=runner(responses, calls)
    )
    assert result.managed_policy_reads[0].status == "partial"
    assert result.managed_policy_reads[0].document is None
    assert result.managed_policy_reads[0].error_code == "policy_version_changed"


def test_referenced_policy_budget_does_not_expand_into_catalog_read() -> None:
    calls: list[list[str]] = []
    arns = [f"arn:aws:iam::aws:policy/Example{i}" for i in range(4)]
    responses = preflight() + [
        {
            "IsTruncated": False,
            "UserDetailList": [{"AttachedManagedPolicies": [{"PolicyArn": arn} for arn in arns]}],
        }
    ]
    for arn in arns[:3]:
        responses.extend(
            [
                {"Policy": {"Arn": arn, "DefaultVersionId": "v1"}},
                {
                    "PolicyVersion": {
                        "VersionId": "v1",
                        "IsDefaultVersion": True,
                        "Document": {"Statement": []},
                    }
                },
            ]
        )
    result = read_authorization_details(
        config(), include_managed_policies=True, run=runner(responses, calls)
    )
    assert len(calls) == 10  # three preflight, one account, three exact policy pairs
    assert [item.status for item in result.managed_policy_reads] == [
        "succeeded",
        "succeeded",
        "succeeded",
        "not_collected",
    ]
    assert result.managed_policy_reads[-1].error_code == "policy_read_budget"


def test_mismatched_account_blocks_before_authorization_read() -> None:
    calls: list[list[str]] = []
    wrong = {"Account": "444455556666", "Arn": "arn:aws:iam::444455556666:user/test"}
    with pytest.raises(AuthorizationReadRejected, match="^preflight_not_ready$"):
        read_authorization_details(config(), run=runner([wrong], calls))
    assert len(calls) == 1


@pytest.mark.parametrize(
    "page,code",
    [
        ({"IsTruncated": True, "UserDetailList": []}, "aws_pagination_invalid"),
        ({"IsTruncated": True, "Marker": "repeat"}, "aws_pagination_invalid"),
        ({"IsTruncated": "false"}, "aws_response_invalid"),
        ({"IsTruncated": False, "UserDetailList": {}}, "aws_response_invalid"),
    ],
)
def test_bad_page_fails_closed(page: dict[str, object], code: str) -> None:
    calls: list[list[str]] = []
    pages = preflight() + [page]
    if page.get("Marker") == "repeat":
        pages.append({"IsTruncated": True, "Marker": "repeat"})
    with pytest.raises(AuthorizationReadRejected, match=f"^{code}$"):
        read_authorization_details(config(), run=runner(pages, calls))


def test_timeout_emits_fixed_code_and_no_raw_identity() -> None:
    calls: list[list[str]] = []
    responses = preflight() + [subprocess.TimeoutExpired("private", 25)]
    with pytest.raises(AuthorizationReadRejected, match="^aws_read_failed$") as failure:
        read_authorization_details(config(), run=runner(responses, calls))
    assert "private" not in str(failure.value)
    assert len(calls) == 4


def test_stop_switch_blocks_before_any_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FYP_AWS_STOP", "1")
    calls: list[list[str]] = []
    with pytest.raises(AuthorizationReadRejected, match="^preflight_not_ready$"):
        read_authorization_details(config(), run=runner([], calls))
    assert calls == []


def test_operator_probe_emits_only_aggregates(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FYP_AWS_PROFILE", "fyp-readonly")
    monkeypatch.setenv("FYP_AWS_EXPECTED_ACCOUNT_ID", ACCOUNT)

    def fake_read(config: PreflightConfig) -> AuthorizationRead:
        assert config.profile == "fyp-readonly"
        return AuthorizationRead(
            pages=({"UserDetailList": [{"UserName": "PrivateName"}]},),
            page_digests=("sha256:" + "a" * 64,),
            page_count=1,
            raw_bytes=99,
        )

    monkeypatch.setattr(aws_authorization_read, "read_authorization_details", fake_read)
    assert aws_authorization_read.main([]) == 0
    output = capsys.readouterr().out
    assert "PrivateName" not in output
    assert ACCOUNT not in output
    assert json.loads(output)["aggregate_counts"]["UserDetailList"] == 1
    assert json.loads(output)["snapshot_sealed"] is False
