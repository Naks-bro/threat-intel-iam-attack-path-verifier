import inspect
import json
from pathlib import Path

import pytest

from fyp_iam.engine2.collector_policy import (
    READ_ONLY_ACTIONS,
    assert_collector_policy_text,
    validate_collector_policy,
)

_POLICY = Path(__file__).resolve().parents[2] / "docs" / "policies" / "iam-readonly-collector.json"


def _document() -> dict[str, object]:
    raw = _POLICY.read_text(encoding="utf-8-sig")
    assert_collector_policy_text(raw)
    loaded: object = json.loads(raw)
    assert isinstance(loaded, dict)
    return loaded


def test_checked_in_policy_matches_the_read_only_allowlist() -> None:
    document = _document()
    assert validate_collector_policy(document) == []
    statement = document["Statement"]
    assert isinstance(statement, list)
    body = statement[0]
    assert isinstance(body, dict)
    assert body["Action"] == sorted(READ_ONLY_ACTIONS)
    assert "iam:PutRolePolicy" not in READ_ONLY_ACTIONS
    assert "iam:SimulatePrincipalPolicy" not in READ_ONLY_ACTIONS


def test_policy_module_does_not_call_aws() -> None:
    import fyp_iam.engine2.collector_policy as policy

    source = inspect.getsource(policy)
    assert "boto3" not in source
    assert "subprocess" not in source


def test_write_action_is_rejected() -> None:
    document = _document()
    statement = document["Statement"]
    assert isinstance(statement, list)
    body = statement[0]
    assert isinstance(body, dict)
    body["Action"] = ["iam:GetRole", "iam:PutRolePolicy"]
    errors = validate_collector_policy(document)
    assert any("allowlist" in item or "mutating" in item for item in errors)


def test_account_id_is_rejected() -> None:
    raw = _POLICY.read_text(encoding="utf-8-sig") + "\n"
    with pytest.raises(ValueError, match="account id"):
        assert_collector_policy_text(raw + "111122223333")
