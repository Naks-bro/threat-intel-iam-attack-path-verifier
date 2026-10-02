"""Synthetic IAM records. These are not live AWS API responses."""

import re

from pydantic import Field, field_validator, model_validator

from fyp_iam.contracts.models import (
    AuthorizationEffect,
    ContractModel,
    IdStr,
    reject_sensitive_text,
)

_ACTION = r"^(\*|[a-z0-9*]+:[A-Za-z0-9*]+)$"
_TOKEN = r"^(\*|[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127})$"
_SERVICE_ID = re.compile(r"^service:([a-z0-9][a-z0-9.-]{0,62})$")


class IdentityStatement(ContractModel):
    statement_id: IdStr
    effect: AuthorizationEffect
    actions: list[str] = Field(min_length=1, max_length=20)
    resource_ids: list[str] = Field(min_length=1, max_length=20)
    condition_keys: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("actions")
    @classmethod
    def action_shape(cls, value: list[str]) -> list[str]:
        return [_one(item, _ACTION, "invalid action") for item in value]

    @field_validator("resource_ids", "condition_keys")
    @classmethod
    def token_shape(cls, value: list[str]) -> list[str]:
        return [_one(item, _TOKEN, "invalid token") for item in value]


class TrustStatement(ContractModel):
    statement_id: IdStr
    effect: AuthorizationEffect
    actions: list[str] = Field(min_length=1, max_length=20)
    principal_ids: list[str] = Field(min_length=1, max_length=20)
    condition_keys: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("actions")
    @classmethod
    def action_shape(cls, value: list[str]) -> list[str]:
        return [_one(item, _ACTION, "invalid action") for item in value]

    @field_validator("principal_ids", "condition_keys")
    @classmethod
    def token_shape(cls, value: list[str]) -> list[str]:
        return [_one(item, _TOKEN, "invalid token") for item in value]


class IdentityRecord(ContractModel):
    node_id: IdStr
    display_name: str = Field(min_length=1, max_length=128)
    subtype: str = Field(pattern=r"^iam_(user|role)$")
    identity_statements: list[IdentityStatement] = Field(default_factory=list, max_length=50)
    trust_statements: list[TrustStatement] = Field(default_factory=list, max_length=50)
    boundary_id: str | None = Field(
        default=None,
        pattern=r"^boundary:[A-Za-z0-9][A-Za-z0-9_.:/-]{0,118}$",
    )

    @field_validator("display_name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        return reject_sensitive_text(value)

    @field_validator("boundary_id")
    @classmethod
    def clean_boundary(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return reject_sensitive_text(value)

    @model_validator(mode="after")
    def users_have_no_trust_policy(self) -> "IdentityRecord":
        if self.subtype == "iam_user" and self.trust_statements:
            raise ValueError("iam_user records cannot include trust statements")
        return self


class SyntheticAccount(ContractModel):
    snapshot_id: IdStr
    identities: list[IdentityRecord] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def unique_identity_ids(self) -> "SyntheticAccount":
        seen: set[str] = set()
        for item in self.identities:
            if item.node_id in seen:
                raise ValueError("duplicate identity node_id")
            seen.add(item.node_id)
        return self


def service_principal_name(principal_id: str) -> str | None:
    """Return the service name for an exact ``service:*.amazonaws.com`` id."""
    match = _SERVICE_ID.fullmatch(principal_id)
    if match is None:
        return None
    name = match.group(1)
    if not name.endswith(".amazonaws.com"):
        return None
    return name


def _one(value: str, pattern: str, message: str) -> str:
    cleaned = reject_sensitive_text(value)
    if re.fullmatch(pattern, cleaned) is None:
        raise ValueError(message)
    return cleaned
