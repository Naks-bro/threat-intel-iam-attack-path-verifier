"""Compact source catalog stored for this system. Loading it does not download feeds."""

import hashlib
import json
import re
from pathlib import Path

from pydantic import Field, ValidationError, field_validator, model_validator

from fyp_iam.contracts.models import ContractModel, reject_sensitive_text
from fyp_iam.engine1.dataset import CloudTechniqueRecord, load_cloud_technique_dataset
from fyp_iam.engine1.errors import IntakeError
from fyp_iam.engine1.models import reject_executable_text
from fyp_iam.engine1.opportunities import OpportunityDataset, build_opportunities

_CATALOG = Path(__file__).resolve().parent / "artifacts" / "source-catalog.json"
_CATALOG_SHA256 = "sha256:de79943c0f4d9835cf65406e8169ccd118e1db5eae69dfe9ded9d66a203123d4"
_PRODUCED_BY = "automated-source-join-0.1"
_STATEMENT = (
    "Compact catalog for this system. A technique is an ATT&CK entry, "
    "a weakness is an OWASP cloud item, a vulnerability is an NVD record, "
    "and a catalog row is the CISA KEV header. Strength counts source families. "
    "The automated join wrote this file. A model checker has not run."
)
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.:-]{0,63}")
_KINDS = "mitre-attack|owasp-cloud|aws-ttc|nvd|cisa-kev"


class CatalogRecord(ContractModel):
    """One stored row. The fields are the compact view a teammate reads."""

    node_id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=200)
    data_kind: str = Field(pattern=r"^(technique|weakness|vulnerability|catalog)$")
    platforms: list[str] = Field(max_length=12)
    tactics: list[str] = Field(max_length=8)
    sources: list[str] = Field(min_length=1, max_length=5)
    source_ids: list[str] = Field(min_length=1, max_length=20)
    strength: int = Field(ge=1, le=5)
    attachment: str = Field(pattern=r"^(individual|combined)$")
    rule_status: str = Field(pattern=r"^no_rule_yet$")

    @field_validator("node_id", "name")
    @classmethod
    def clean_text(cls, value: str) -> str:
        return reject_executable_text(value)

    @field_validator("platforms", "tactics", "sources", "source_ids")
    @classmethod
    def clean_labels(cls, value: list[str]) -> list[str]:
        for item in value:
            if _LABEL.fullmatch(item) is None:
                raise ValueError("label is not a short catalog field")
        return value

    @model_validator(mode="after")
    def row_states_its_kind(self) -> "CatalogRecord":
        if self.data_kind != _kind_for(self.node_id):
            raise ValueError("data kind does not match the node id")
        if self.data_kind == "technique":
            if not self.platforms or not self.tactics:
                raise ValueError("a technique row stores platforms and tactics")
        elif self.platforms or self.tactics:
            raise ValueError("only a technique row stores platforms and tactics")
        if self.sources != sorted(set(self.sources)):
            raise ValueError("sources must be unique and sorted")
        if self.source_ids != sorted(set(self.source_ids)):
            raise ValueError("source ids must be unique and sorted")
        if self.strength != len(self.sources):
            raise ValueError("strength must count distinct source families")
        expected = "combined" if self.strength >= 2 else "individual"
        if self.attachment != expected:
            raise ValueError("attachment does not match strength")
        if any(re.fullmatch(rf"^({_KINDS})$", item) is None for item in self.sources):
            raise ValueError("source family is not in the system list")
        return self


class SystemCatalog(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    catalog_id: str = Field(pattern=r"^system-source-catalog-0\.1$")
    produced_by: str = Field(pattern=r"^automated-source-join-0\.1$")
    checker: str = Field(pattern=r"^not_used$")
    statement: str = Field(min_length=1, max_length=500)
    aws_ttc_status: str = Field(pattern=r"^not_ingested$")
    kev_catalog_version: str = Field(pattern=r"^[0-9]{4}\.[0-9]{2}\.[0-9]{2}$")
    kev_matched_count: int = Field(ge=0)
    combined_count: int = Field(ge=0)
    individual_count: int = Field(ge=0)
    record_count: int = Field(ge=1)
    records: list[CatalogRecord] = Field(min_length=1)

    @field_validator("statement")
    @classmethod
    def clean_statement(cls, value: str) -> str:
        return reject_sensitive_text(value)

    @model_validator(mode="after")
    def records_match_header(self) -> "SystemCatalog":
        if len(self.records) != self.record_count:
            raise ValueError("record count does not match the stored rows")
        ids = [item.node_id for item in self.records]
        if ids != sorted(ids) or len(set(ids)) != len(ids):
            raise ValueError("catalog ids must be unique and sorted")
        combined = sum(1 for item in self.records if item.attachment == "combined")
        if combined != self.combined_count:
            raise ValueError("combined count does not match the stored rows")
        if self.record_count - combined != self.individual_count:
            raise ValueError("individual count does not match the stored rows")
        return self


def build_system_catalog() -> SystemCatalog:
    """Fold the automated join into the compact rows this system stores."""

    techniques = {item.external_id: item for item in load_cloud_technique_dataset().records}
    return _catalog_from(build_opportunities(), techniques)


def load_system_catalog() -> SystemCatalog:
    """Read the stored catalog. This does not rebuild it and does not download."""

    if not _CATALOG.is_file():
        raise IntakeError("unknown_artifact", "source catalog is not available")
    raw = _CATALOG.read_bytes()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if digest != _CATALOG_SHA256:
        raise IntakeError("hash_mismatch", "source catalog hash does not match the pin")
    try:
        return SystemCatalog.model_validate(json.loads(raw))
    except (ValidationError, json.JSONDecodeError) as exc:
        raise IntakeError("invalid_artifact", "source catalog did not match the schema") from exc


def _catalog_from(
    dataset: OpportunityDataset,
    techniques: dict[str, CloudTechniqueRecord],
) -> SystemCatalog:
    records: list[CatalogRecord] = []
    for item in dataset.opportunities:
        technique = techniques.get(item.node_id)
        platforms = list(technique.platforms) if technique is not None else []
        tactics = list(technique.tactics) if technique is not None else []
        records.append(
            CatalogRecord(
                node_id=item.node_id,
                name=item.title,
                data_kind=_kind_for(item.node_id),
                platforms=platforms,
                tactics=tactics,
                sources=sorted({support.source_kind for support in item.supports}),
                source_ids=sorted(support.source_id for support in item.supports),
                strength=item.strength,
                attachment=item.attachment,
                rule_status=item.rule_status,
            )
        )
    return SystemCatalog(
        schema_version="0.1",
        catalog_id="system-source-catalog-0.1",
        produced_by=_PRODUCED_BY,
        checker="not_used",
        statement=_STATEMENT,
        aws_ttc_status=dataset.aws_ttc_status,
        kev_catalog_version=dataset.kev_catalog_version,
        kev_matched_count=dataset.kev_matched_count,
        combined_count=dataset.combined_count,
        individual_count=dataset.individual_count,
        record_count=len(records),
        records=records,
    )


def _kind_for(node_id: str) -> str:
    if re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", node_id):
        return "technique"
    if re.fullmatch(r"CNAS-(?:[1-9]|10)", node_id):
        return "weakness"
    if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", node_id):
        return "vulnerability"
    if re.fullmatch(r"cisa-kev-[0-9]{4}\.[0-9]{2}\.[0-9]{2}", node_id):
        return "catalog"
    raise IntakeError("unknown_link", "node id has no system data kind")
