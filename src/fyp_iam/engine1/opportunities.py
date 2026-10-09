"""Combine pinned sources into nodes. Loading this module does not download feeds."""

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import NoReturn

from pydantic import Field, ValidationError, field_validator, model_validator

from fyp_iam.contracts.models import ContractModel, ensure_utc, reject_sensitive_text
from fyp_iam.engine1.dataset import CloudTechniqueRecord, load_cloud_technique_dataset
from fyp_iam.engine1.errors import IntakeError
from fyp_iam.engine1.models import reject_executable_text

_ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
_OWASP = _ARTIFACTS / "owasp-cnas-10.json"
_NVD = _ARTIFACTS / "nvd-aws-iam-page.json"
_KEV = _ARTIFACTS / "cisa-kev-catalog.json"
_LINKS = _ARTIFACTS / "source-links.json"
_OWASP_SHA256 = "sha256:3fa7d0f7dacd0fc386472a41e32146552137ea11128c8fdf4eb69c47d9474512"
_NVD_SHA256 = "sha256:30d4966efd648561cf968629c192931314750a94188646e9d3865fe88a2a415b"
_KEV_SHA256 = "sha256:ece103582bd533ce9849e8d37cc8c90ffe423b59b64ff4fb0d4cd0f1439341a6"
_LINKS_SHA256 = "sha256:91d0f62279b8ab8d85a1286cc9cb10537d13e30bfeb7bdc42236c661aaa8e3f6"
_PROJECT_URL = "https://owasp.org/www-project-cloud-native-application-security-top-10/"
_NVD_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=AWS%20IAM&resultsPerPage=5"
)
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_AWS_URL = "https://aws-samples.github.io/threat-technique-catalog-for-aws/"
_KINDS = ("mitre-attack", "owasp-cloud", "aws-ttc", "nvd", "cisa-kev")
_KIND = "|".join(_KINDS)
_PAIRS = {
    frozenset({"mitre-attack", "owasp-cloud"}),
    frozenset({"owasp-cloud", "nvd"}),
    frozenset({"owasp-cloud", "cisa-kev"}),
    frozenset({"mitre-attack", "nvd"}),
    frozenset({"mitre-attack", "cisa-kev"}),
    frozenset({"mitre-attack", "aws-ttc"}),
    frozenset({"owasp-cloud", "aws-ttc"}),
    frozenset({"nvd", "cisa-kev"}),
}
_NOTE = (
    "Local curated associations. Not an official joint publication. "
    "Strength counts distinct source families and is not exploitability."
)


class SourceSupport(ContractModel):
    source_kind: str = Field(pattern=rf"^({_KIND})$")
    source_id: str = Field(min_length=1, max_length=64)
    official_reference: str

    @field_validator("source_id", "official_reference")
    @classmethod
    def clean_support(cls, value: str) -> str:
        return reject_executable_text(value)

    @model_validator(mode="after")
    def id_and_reference_match_kind(self) -> "SourceSupport":
        if _id_pattern(self.source_kind).fullmatch(self.source_id) is None:
            raise ValueError("source id does not match its family")
        if _reference_pattern(self.source_kind).fullmatch(self.official_reference) is None:
            raise ValueError("official reference is not on the local allowlist")
        if self.source_kind == "mitre-attack":
            path = self.source_id.replace(".", "/")
            if not self.official_reference.endswith(f"/{path}/"):
                raise ValueError("official reference is not on the local allowlist")
        if self.source_kind == "nvd" and not self.official_reference.endswith("/" + self.source_id):
            raise ValueError("official reference is not on the local allowlist")
        return self


class Opportunity(ContractModel):
    node_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    supports: list[SourceSupport] = Field(min_length=1, max_length=20)
    strength: int = Field(ge=1, le=5)
    attachment: str = Field(pattern=r"^(individual|combined)$")
    rule_status: str = Field(pattern=r"^no_rule_yet$")

    @field_validator("node_id", "title")
    @classmethod
    def clean_node(cls, value: str) -> str:
        return reject_executable_text(value)

    @model_validator(mode="after")
    def strength_counts_families(self) -> "Opportunity":
        pairs = [(item.source_kind, item.source_id) for item in self.supports]
        if len(pairs) != len(set(pairs)):
            raise ValueError("duplicate support")
        families = {item.source_kind for item in self.supports}
        if self.strength != len(families):
            raise ValueError("strength must count distinct source families")
        expected = "combined" if self.strength >= 2 else "individual"
        if self.attachment != expected:
            raise ValueError("attachment does not match strength")
        ordered = sorted(pairs)
        if pairs != ordered:
            raise ValueError("supports must be sorted")
        return self


class OpportunityDataset(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    dataset_id: str = Field(pattern=r"^source-opportunities-0\.1$")
    association: str = Field(pattern=r"^local-curated$")
    association_note: str = Field(min_length=1, max_length=500)
    aws_ttc_status: str = Field(pattern=r"^not_ingested$")
    kev_catalog_version: str = Field(pattern=r"^[0-9]{4}\.[0-9]{2}\.[0-9]{2}$")
    kev_vulnerability_count: int = Field(ge=0)
    kev_matched_count: int = Field(ge=0)
    nvd_page_size: int = Field(ge=1, le=20)
    nvd_total_results: int = Field(ge=0)
    combined_count: int = Field(ge=0)
    individual_count: int = Field(ge=0)
    opportunities: list[Opportunity] = Field(min_length=1)

    @field_validator("association_note")
    @classmethod
    def clean_note(cls, value: str) -> str:
        return reject_sensitive_text(value)

    @model_validator(mode="after")
    def counts_match_nodes(self) -> "OpportunityDataset":
        combined = sum(1 for item in self.opportunities if item.attachment == "combined")
        individual = len(self.opportunities) - combined
        if combined != self.combined_count or individual != self.individual_count:
            raise ValueError("attachment counts do not match")
        ids = [item.node_id for item in self.opportunities]
        if ids != sorted(ids) or len(set(ids)) != len(ids):
            raise ValueError("opportunity ids must be unique and sorted")
        aws = [
            item
            for item in self.opportunities
            for support in item.supports
            if support.source_kind == "aws-ttc"
        ]
        if self.aws_ttc_status == "not_ingested" and aws:
            raise ValueError("aws ttc is not ingested")
        cve_supports = [
            support.source_id
            for item in self.opportunities
            for support in item.supports
            if support.source_kind == "cisa-kev" and support.source_id.startswith("CVE-")
        ]
        if len(cve_supports) != self.kev_matched_count:
            raise ValueError("kev match count does not match attached records")
        return self


class _OwaspRecord(ContractModel):
    external_id: str = Field(pattern=r"^CNAS-(?:[1-9]|10)$")
    name: str = Field(min_length=1, max_length=200)
    source_file: str = Field(pattern=r"^2022/en/src/0x[0-9A-F]{2}_[a-z0-9_]+\.md$")

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        return reject_executable_text(value)


class _OwaspCatalog(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    source_name: str = Field(pattern=r"^owasp-cloud$")
    source_version: str = Field(pattern=r"^2022$")
    project_url: str
    license_note: str = Field(min_length=1, max_length=500)
    records: list[_OwaspRecord] = Field(min_length=10, max_length=10)

    @field_validator("project_url")
    @classmethod
    def pinned_project(cls, value: str) -> str:
        if value != _PROJECT_URL:
            raise ValueError("official reference is not on the local allowlist")
        return value

    @model_validator(mode="after")
    def ten_sorted_items(self) -> "_OwaspCatalog":
        ids = [int(item.external_id.split("-")[1]) for item in self.records]
        if ids != list(range(1, 11)):
            raise ValueError("owasp ids must be CNAS-1 through CNAS-10")
        return self


class _NvdRecord(ContractModel):
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    official_reference: str
    published: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+$")

    @field_validator("official_reference")
    @classmethod
    def nvd_host(cls, value: str) -> str:
        if _reference_pattern("nvd").fullmatch(value) is None:
            raise ValueError("official reference is not on the local allowlist")
        return value


class _NvdPage(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    source_name: str = Field(pattern=r"^nvd$")
    api_key_used: bool
    keyword_search: str
    request_url: str
    results_per_page: int = Field(ge=1, le=5)
    total_results: int = Field(ge=0)
    retrieved_at: datetime
    license_note: str = Field(min_length=1, max_length=500)
    records: list[_NvdRecord] = Field(min_length=1, max_length=5)

    @field_validator("retrieved_at")
    @classmethod
    def utc_retrieved(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator("keyword_search")
    @classmethod
    def pinned_keyword(cls, value: str) -> str:
        if value != "AWS IAM":
            raise ValueError("keyword is not the pinned NVD query")
        return value

    @field_validator("request_url")
    @classmethod
    def pinned_request(cls, value: str) -> str:
        if value != _NVD_URL:
            raise ValueError("official reference is not on the local allowlist")
        return value

    @model_validator(mode="after")
    def page_is_small_and_keyless(self) -> "_NvdPage":
        if self.api_key_used:
            raise ValueError("nvd pin must not use an api key")
        ids = [item.cve_id for item in self.records]
        if ids != sorted(ids) or len(ids) != self.results_per_page:
            raise ValueError("nvd page records must be sorted and complete")
        return self


class _KevCatalog(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    source_name: str = Field(pattern=r"^cisa-kev$")
    catalog_version: str = Field(pattern=r"^[0-9]{4}\.[0-9]{2}\.[0-9]{2}$")
    date_released: datetime
    vulnerability_count: int = Field(ge=0)
    feed_url: str
    feed_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    retrieved_at: datetime
    product_filter: str = Field(min_length=1, max_length=200)
    matched_cve_ids: list[str] = Field(max_length=20)
    license_note: str = Field(min_length=1, max_length=500)

    @field_validator("date_released", "retrieved_at")
    @classmethod
    def utc_times(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator("feed_url")
    @classmethod
    def pinned_feed(cls, value: str) -> str:
        if value != _KEV_URL:
            raise ValueError("official reference is not on the local allowlist")
        return value

    @field_validator("matched_cve_ids")
    @classmethod
    def cve_ids(cls, value: list[str]) -> list[str]:
        for item in value:
            if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", item) is None:
                raise ValueError("kev match is not a cve id")
        if value != sorted(value):
            raise ValueError("kev matches must be sorted")
        return value


class _SourceLink(ContractModel):
    left_kind: str = Field(pattern=rf"^({_KIND})$")
    left_id: str = Field(min_length=1, max_length=64)
    right_kind: str = Field(pattern=rf"^({_KIND})$")
    right_id: str = Field(min_length=1, max_length=64)


class _LinkSet(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    association: str = Field(pattern=r"^local-curated$")
    license_note: str = Field(min_length=1, max_length=500)
    links: list[_SourceLink] = Field(min_length=1, max_length=40)


def opportunity_from_supports(
    node_id: str,
    title: str,
    supports: list[SourceSupport],
) -> Opportunity:
    """Build one node. Strength is the number of distinct source families."""

    return Opportunity(
        node_id=node_id,
        title=title,
        supports=sorted(supports, key=lambda item: (item.source_kind, item.source_id)),
        strength=len({item.source_kind for item in supports}),
        attachment="combined"
        if len({item.source_kind for item in supports}) >= 2
        else "individual",
        rule_status="no_rule_yet",
    )


def assert_known_endpoint(kind: str, source_id: str, known: dict[str, set[str]]) -> None:
    """Reject a link whose endpoint is not in the pinned source."""

    if kind not in known or source_id not in known[kind]:
        raise IntakeError("unknown_link", "link endpoint is not in a pinned source")


def build_opportunities() -> OpportunityDataset:
    """Join the pinned sources. Unlisted ids do not attach, and AWS TTC is absent."""

    techniques = load_cloud_technique_dataset()
    owasp = _load_model(_OWASP, _OWASP_SHA256, _OwaspCatalog)
    nvd = _load_model(_NVD, _NVD_SHA256, _NvdPage)
    kev = _load_model(_KEV, _KEV_SHA256, _KevCatalog)
    links = _load_model(_LINKS, _LINKS_SHA256, _LinkSet)
    references = _reference_index(techniques.records, owasp, nvd, kev)
    _validate_links(links.links, references)
    nodes = [
        *_technique_nodes(techniques.records, links.links, references),
        *_owasp_nodes(owasp, links.links, references),
        *_nvd_nodes(nvd, links.links, references),
        _kev_node(kev),
    ]
    nodes.sort(key=lambda item: item.node_id)
    combined = sum(1 for item in nodes if item.attachment == "combined")
    return OpportunityDataset(
        schema_version="0.1",
        dataset_id="source-opportunities-0.1",
        association="local-curated",
        association_note=_NOTE,
        aws_ttc_status="not_ingested",
        kev_catalog_version=kev.catalog_version,
        kev_vulnerability_count=kev.vulnerability_count,
        kev_matched_count=len(kev.matched_cve_ids),
        nvd_page_size=nvd.results_per_page,
        nvd_total_results=nvd.total_results,
        combined_count=combined,
        individual_count=len(nodes) - combined,
        opportunities=nodes,
    )


def _reference_index(
    techniques: list[CloudTechniqueRecord],
    owasp: _OwaspCatalog,
    nvd: _NvdPage,
    kev: _KevCatalog,
) -> dict[str, dict[str, str]]:
    mitre = {record.external_id: record.official_reference for record in techniques}
    return {
        "mitre-attack": mitre,
        "owasp-cloud": {item.external_id: owasp.project_url for item in owasp.records},
        "nvd": {item.cve_id: item.official_reference for item in nvd.records},
        "cisa-kev": {item: kev.feed_url for item in kev.matched_cve_ids},
        "aws-ttc": {},
    }


def _validate_links(links: list[_SourceLink], references: dict[str, dict[str, str]]) -> None:
    known = {kind: set(items) for kind, items in references.items()}
    for link in links:
        pair = frozenset({link.left_kind, link.right_kind})
        if link.left_kind == link.right_kind or pair not in _PAIRS:
            raise IntakeError("unsupported_link", "link pair is not a supported source combination")
        assert_known_endpoint(link.left_kind, link.left_id, known)
        assert_known_endpoint(link.right_kind, link.right_id, known)


def _technique_nodes(
    techniques: list[CloudTechniqueRecord],
    links: list[_SourceLink],
    references: dict[str, dict[str, str]],
) -> list[Opportunity]:
    nodes: list[Opportunity] = []
    for record in techniques:
        supports = [
            SourceSupport(
                source_kind="mitre-attack",
                source_id=record.external_id,
                official_reference=record.official_reference,
            )
        ]
        supports.extend(_partners("mitre-attack", record.external_id, links, references))
        nodes.append(opportunity_from_supports(record.external_id, record.name, supports))
    return nodes


def _owasp_nodes(
    owasp: _OwaspCatalog,
    links: list[_SourceLink],
    references: dict[str, dict[str, str]],
) -> list[Opportunity]:
    nodes: list[Opportunity] = []
    for record in owasp.records:
        supports = [
            SourceSupport(
                source_kind="owasp-cloud",
                source_id=record.external_id,
                official_reference=owasp.project_url,
            )
        ]
        supports.extend(_partners("owasp-cloud", record.external_id, links, references))
        nodes.append(opportunity_from_supports(record.external_id, record.name, supports))
    return nodes


def _nvd_nodes(
    nvd: _NvdPage,
    links: list[_SourceLink],
    references: dict[str, dict[str, str]],
) -> list[Opportunity]:
    nodes: list[Opportunity] = []
    for record in nvd.records:
        supports = [
            SourceSupport(
                source_kind="nvd",
                source_id=record.cve_id,
                official_reference=record.official_reference,
            )
        ]
        supports.extend(_partners("nvd", record.cve_id, links, references))
        nodes.append(opportunity_from_supports(record.cve_id, "NVD keyword-page record", supports))
    return nodes


def _kev_node(kev: _KevCatalog) -> Opportunity:
    return opportunity_from_supports(
        f"cisa-kev-{kev.catalog_version}",
        "CISA KEV catalog",
        [
            SourceSupport(
                source_kind="cisa-kev",
                source_id=kev.catalog_version,
                official_reference=kev.feed_url,
            )
        ],
    )


def _partners(
    kind: str,
    source_id: str,
    links: list[_SourceLink],
    references: dict[str, dict[str, str]],
) -> list[SourceSupport]:
    supports: list[SourceSupport] = []
    for link in links:
        if link.left_kind == kind and link.left_id == source_id:
            other_kind, other_id = link.right_kind, link.right_id
        elif link.right_kind == kind and link.right_id == source_id:
            other_kind, other_id = link.left_kind, link.left_id
        else:
            continue
        supports.append(
            SourceSupport(
                source_kind=other_kind,
                source_id=other_id,
                official_reference=references[other_kind][other_id],
            )
        )
    return supports


def _load_model[ModelT: ContractModel](path: Path, expected: str, model: type[ModelT]) -> ModelT:
    if not path.is_file():
        raise IntakeError("unknown_artifact", "pinned source is not available")
    raw = path.read_bytes()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if digest != expected:
        raise IntakeError("hash_mismatch", "pinned source hash does not match the pin")
    try:
        loaded = json.loads(raw)
        return model.model_validate(loaded)
    except (ValidationError, json.JSONDecodeError) as exc:
        _raise_from_validation(exc)


def _raise_from_validation(exc: Exception) -> NoReturn:
    text = str(exc)
    if "executable" in text or "disallowed credential" in text:
        raise IntakeError("unsafe_content", "artifact text was rejected") from exc
    if "official reference" in text or "allowlist" in text:
        raise IntakeError("bad_reference", "artifact reference was rejected") from exc
    raise IntakeError("invalid_artifact", "artifact did not match the local schema") from exc


def _id_pattern(kind: str) -> re.Pattern[str]:
    patterns = {
        "mitre-attack": r"^T[0-9]{4}(?:\.[0-9]{3})?$",
        "owasp-cloud": r"^CNAS-(?:[1-9]|10)$",
        "nvd": r"^CVE-[0-9]{4}-[0-9]{4,}$",
        "cisa-kev": r"^(?:[0-9]{4}\.[0-9]{2}\.[0-9]{2}|CVE-[0-9]{4}-[0-9]{4,})$",
        "aws-ttc": r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$",
    }
    return re.compile(patterns[kind])


def _reference_pattern(kind: str) -> re.Pattern[str]:
    patterns = {
        "mitre-attack": r"^https://attack\.mitre\.org/techniques/T[0-9]{4}(?:/[0-9]{3})?/$",
        "owasp-cloud": re.escape(_PROJECT_URL),
        "nvd": r"^https://nvd\.nist\.gov/vuln/detail/CVE-[0-9]{4}-[0-9]{4,}$",
        "cisa-kev": re.escape(_KEV_URL),
        "aws-ttc": re.escape(_AWS_URL),
    }
    return re.compile(patterns[kind])
