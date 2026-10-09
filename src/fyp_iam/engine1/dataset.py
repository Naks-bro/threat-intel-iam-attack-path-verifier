"""Pinned 50-row cloud technique dataset. Loading it does not download ATT&CK."""

import hashlib
import re
from datetime import datetime
from pathlib import Path

from pydantic import Field, field_validator, model_validator

from fyp_iam.contracts.models import ContractModel, ensure_utc, reject_sensitive_text
from fyp_iam.engine1.errors import IntakeError
from fyp_iam.engine1.intake import mapped_rule_id

_DATASET = Path(__file__).resolve().parent / "artifacts" / "cloud-techniques-50.json"
_PINNED_SHA256 = "sha256:c5e5b06c1e46beb747d39c32f92712e584ce3d9a6fe3fa85936423608f94cb54"
_REFERENCE = re.compile(r"^https://attack\.mitre\.org/techniques/T[0-9]{4}(?:/[0-9]{3})?/$")
_TECHNIQUE_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")


class CloudTechniqueRecord(ContractModel):
    external_id: str = Field(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")
    name: str = Field(min_length=1, max_length=200)
    platforms: list[str] = Field(min_length=1, max_length=12)
    stix_id: str = Field(pattern=r"^attack-pattern--[0-9a-f-]{36}$")
    tactics: list[str] = Field(min_length=1, max_length=8)
    official_reference: str
    rule_id: str | None = None
    rule_status: str = Field(default="no_rule_yet", pattern=r"^(mapped|no_rule_yet)$")

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        return reject_sensitive_text(value)

    @field_validator("official_reference")
    @classmethod
    def official_host(cls, value: str) -> str:
        if _REFERENCE.fullmatch(value) is None:
            raise ValueError("official reference is not on the local allowlist")
        return value

    @field_validator("platforms", "tactics")
    @classmethod
    def clean_labels(cls, value: list[str]) -> list[str]:
        for item in value:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.:-]{0,63}", item):
                raise ValueError("label is not a short technique field")
        return value


class CloudTechniqueDataset(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    dataset_id: str = Field(pattern=r"^mitre-enterprise-cloud-50$")
    source_name: str = Field(pattern=r"^mitre-attack$")
    source_version: str = Field(pattern=r"^19\.2$")
    retrieved_at: datetime
    collection_modified: datetime
    collection_url: str
    collection_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    selection: str = Field(min_length=1, max_length=500)
    license_note: str = Field(min_length=1, max_length=500)
    records: list[CloudTechniqueRecord] = Field(min_length=50, max_length=50)

    @field_validator("retrieved_at", "collection_modified")
    @classmethod
    def utc_times(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator("collection_url")
    @classmethod
    def pinned_collection(cls, value: str) -> str:
        expected = (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
            "enterprise-attack/enterprise-attack-19.2.json"
        )
        if value != expected:
            raise ValueError("collection url is not the pinned ATT&CK release")
        return value

    @model_validator(mode="after")
    def records_are_sorted_and_unique(self) -> "CloudTechniqueDataset":
        ids = [item.external_id for item in self.records]
        if ids != sorted(ids) or len(set(ids)) != len(ids):
            raise ValueError("technique ids must be unique and sorted")
        for item in self.records:
            if not _TECHNIQUE_ID.fullmatch(item.external_id):
                raise ValueError("technique id is not usable")
        return self


def load_cloud_technique_dataset() -> CloudTechniqueDataset:
    if not _DATASET.is_file():
        raise IntakeError("unknown_artifact", "cloud technique dataset is not available")
    raw = _DATASET.read_bytes()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if digest != _PINNED_SHA256:
        raise IntakeError("hash_mismatch", "cloud technique dataset hash does not match the pin")
    dataset = CloudTechniqueDataset.model_validate_json(raw)
    annotated: list[CloudTechniqueRecord] = []
    for record in dataset.records:
        rule_id = mapped_rule_id("mitre-attack", record.external_id)
        status = "mapped" if rule_id else "no_rule_yet"
        annotated.append(record.model_copy(update={"rule_id": rule_id, "rule_status": status}))
    return dataset.model_copy(update={"records": annotated})
