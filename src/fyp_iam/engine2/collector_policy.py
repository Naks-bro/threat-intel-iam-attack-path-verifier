"""Least-privilege IAM read policy for a future lab collector.

This module checks a policy document. It does not attach the policy and it
does not call AWS.
"""

import re
from collections.abc import Mapping

_ACCOUNT_ID = re.compile(r"\b\d{12}\b")
_WRITE_MARKERS = (
    "Add",
    "Attach",
    "Create",
    "Delete",
    "Detach",
    "Pass",
    "Put",
    "Remove",
    "Set",
    "Simulate",
    "Tag",
    "Untag",
    "Update",
)

# Each action is a read that a later collector may use. GetRole and GetUser
# include the trust policy and a permissions-boundary attachment. They do not
# include SCPs, RCPs, session policies, or resource policies.
READ_ONLY_ACTIONS: dict[str, str] = {
    "iam:GetPolicy": "managed policy metadata",
    "iam:GetPolicyVersion": "managed or boundary policy document",
    "iam:GetRole": "role record, trust policy, and boundary attachment",
    "iam:GetRolePolicy": "inline role policy document",
    "iam:GetUser": "user record and boundary attachment",
    "iam:GetUserPolicy": "inline user policy document",
    "iam:ListAttachedRolePolicies": "managed policies attached to a role",
    "iam:ListAttachedUserPolicies": "managed policies attached to a user",
    "iam:ListRolePolicies": "inline role policy names",
    "iam:ListRoles": "role index",
    "iam:ListUserPolicies": "inline user policy names",
    "iam:ListUsers": "user index",
}


def validate_collector_policy(document: object) -> list[str]:
    """Return problems that would make this template unsafe to attach later."""
    if not isinstance(document, dict):
        return ["policy must be a JSON object"]
    errors: list[str] = []
    unexpected = set(document) - {"comment", "Version", "Statement"}
    if unexpected:
        errors.append("policy contains an unexpected top-level key")
    if document.get("Version") != "2012-10-17":
        errors.append("policy Version must be 2012-10-17")
    comment = document.get("comment")
    if not isinstance(comment, str) or "not attached" not in comment.casefold():
        errors.append("policy comment must say the template is not attached")
    statement = document.get("Statement")
    if not isinstance(statement, list) or len(statement) != 1 or not isinstance(statement[0], dict):
        errors.append("policy must contain one statement object")
        return errors
    body: Mapping[str, object] = statement[0]
    extra = set(body) - {"Sid", "Effect", "Action", "Resource"}
    if extra:
        errors.append("statement contains an unexpected key")
    if body.get("Sid") != "ReadIamConfiguration":
        errors.append("statement Sid must be ReadIamConfiguration")
    if body.get("Effect") != "Allow":
        errors.append("statement Effect must be Allow")
    if body.get("Resource") != "*":
        errors.append("statement Resource must be * for these IAM read APIs")
    actions = body.get("Action")
    if not isinstance(actions, list) or not all(isinstance(item, str) for item in actions):
        errors.append("statement Action must be a list of strings")
        return errors
    names = [item for item in actions if isinstance(item, str)]
    if len(names) != len(set(names)):
        errors.append("statement Action contains a duplicate")
    if set(names) != set(READ_ONLY_ACTIONS):
        errors.append("statement Action does not match the read-only allowlist")
    for name in names:
        if not name.startswith("iam:"):
            errors.append(f"{name} is outside IAM")
        verb = name.split(":", 1)[-1]
        if not verb.startswith(("Get", "List")):
            errors.append(f"{name} is not a Get or List action")
        if verb.startswith(_WRITE_MARKERS):
            errors.append(f"{name} is a mutating or simulation action")
    return errors


def assert_collector_policy_text(raw: str) -> None:
    """Reject account identifiers and credential-shaped text before parsing."""
    if _ACCOUNT_ID.search(raw):
        raise ValueError("collector policy contains an account id")
    lowered = raw.casefold()
    if "arn:aws:" in lowered or "akia" in lowered or "asia" in lowered:
        raise ValueError("collector policy contains a credential or ARN marker")
