"""Source nodes combine pinned families. Strength is a count, not a verdict."""

import inspect

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from fyp_iam.api.app import create_app
from fyp_iam.engine1 import catalog as catalog_module
from fyp_iam.engine1 import opportunities as opportunities_module
from fyp_iam.engine1.catalog import build_system_catalog, load_system_catalog
from fyp_iam.engine1.errors import IntakeError
from fyp_iam.engine1.opportunities import (
    SourceSupport,
    assert_known_endpoint,
    build_opportunities,
    opportunity_from_supports,
)

_MITRE = "https://attack.mitre.org/techniques/T1078/"
_OWASP = "https://owasp.org/www-project-cloud-native-application-security-top-10/"
_NVD = "https://nvd.nist.gov/vuln/detail/CVE-2022-2385"
_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_AWS = "https://aws-samples.github.io/threat-technique-catalog-for-aws/"


def _support(kind: str, source_id: str, reference: str) -> SourceSupport:
    return SourceSupport(source_kind=kind, source_id=source_id, official_reference=reference)


def test_strength_rises_only_when_a_new_family_is_attached() -> None:
    one = opportunity_from_supports(
        "T1078",
        "Valid Accounts",
        [_support("mitre-attack", "T1078", _MITRE)],
    )
    two = opportunity_from_supports(
        "T1078",
        "Valid Accounts",
        [
            _support("mitre-attack", "T1078", _MITRE),
            _support("owasp-cloud", "CNAS-3", _OWASP),
        ],
    )
    same_family = opportunity_from_supports(
        "CNAS-7",
        "Using components with known vulnerabilities",
        [
            _support("owasp-cloud", "CNAS-7", _OWASP),
            _support("nvd", "CVE-2018-9057", "https://nvd.nist.gov/vuln/detail/CVE-2018-9057"),
            _support("nvd", "CVE-2022-2385", _NVD),
        ],
    )
    five = opportunity_from_supports(
        "T1078",
        "Valid Accounts",
        [
            _support("mitre-attack", "T1078", _MITRE),
            _support("owasp-cloud", "CNAS-3", _OWASP),
            _support("nvd", "CVE-2022-2385", _NVD),
            _support("cisa-kev", "CVE-2022-2385", _KEV),
            _support("aws-ttc", "TTC-EXAMPLE", _AWS),
        ],
    )
    assert one.strength == 1 and one.attachment == "individual"
    assert two.strength == 2 and two.attachment == "combined"
    assert same_family.strength == 2
    assert five.strength == 5
    assert one.rule_status == "no_rule_yet"


def test_unknown_endpoint_and_bad_reference_fail_closed() -> None:
    with pytest.raises(IntakeError) as missing:
        assert_known_endpoint("mitre-attack", "T9999", {"mitre-attack": {"T1078"}})
    assert missing.value.code == "unknown_link"
    with pytest.raises(IntakeError) as kev:
        assert_known_endpoint("cisa-kev", "CVE-2022-2385", {"cisa-kev": set()})
    assert kev.value.code == "unknown_link"
    with pytest.raises(ValidationError):
        _support("mitre-attack", "T1078", "https://example.invalid/T1078/")
    with pytest.raises(ValidationError):
        opportunity_from_supports("empty", "Empty", [])


def test_pinned_nodes_combine_mitre_owasp_and_selected_nvd_rows() -> None:
    dataset = build_opportunities()
    by_id = {item.node_id: item for item in dataset.opportunities}
    assert len(dataset.opportunities) == 66
    assert dataset.aws_ttc_status == "not_ingested"
    assert dataset.kev_matched_count == 0
    assert dataset.kev_vulnerability_count == 1733
    assert dataset.nvd_page_size == 5
    assert dataset.combined_count == 12
    assert dataset.individual_count == 54
    alone = by_id["T1020.001"]
    assert [item.source_kind for item in alone.supports] == ["mitre-attack"]
    assert alone.strength == 1
    combined = by_id["T1078"]
    assert {item.source_kind for item in combined.supports} == {"mitre-attack", "owasp-cloud"}
    assert combined.strength == 2
    assert "nvd" not in {item.source_kind for item in combined.supports}
    cnas7 = by_id["CNAS-7"]
    nvd_ids = sorted(item.source_id for item in cnas7.supports if item.source_kind == "nvd")
    assert nvd_ids == ["CVE-2018-9057", "CVE-2020-16250", "CVE-2022-2385"]
    assert cnas7.strength == 2
    assert by_id["CVE-2022-2385"].strength == 2
    assert by_id["CVE-2019-10200"].strength == 1
    assert by_id["CVE-2021-22969"].strength == 1
    kev = by_id["cisa-kev-2026.10.02"]
    assert kev.strength == 1
    assert all(item.rule_status == "no_rule_yet" for item in dataset.opportunities)
    assert not any(
        support.source_kind == "aws-ttc"
        for item in dataset.opportunities
        for support in item.supports
    )
    assert not any(
        support.source_kind == "cisa-kev" and support.source_id.startswith("CVE-")
        for item in dataset.opportunities
        for support in item.supports
    )


def test_pins_keep_short_names_and_do_not_download() -> None:
    source = inspect.getsource(opportunities_module)
    for banned in ("urllib", "requests", "httpx", "boto3", "subprocess"):
        assert banned not in source
    owasp = opportunities_module._OWASP.read_text(encoding="utf-8")
    nvd = opportunities_module._NVD.read_text(encoding="utf-8")
    kev = opportunities_module._KEV.read_text(encoding="utf-8")
    assert "How To Prevent" not in owasp
    assert '"description"' not in nvd
    assert "shortDescription" not in kev
    assert '"api_key_used": false' in nvd


def test_pin_mismatch_rejects_the_join(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(opportunities_module, "_LINKS_SHA256", "sha256:" + ("ab" * 32))
    with pytest.raises(IntakeError) as exc:
        build_opportunities()
    assert exc.value.code == "hash_mismatch"


def test_opportunities_endpoint_returns_source_counts() -> None:
    response = TestClient(create_app()).get("/v1/datasets/opportunities")
    assert response.status_code == 200
    body = response.json()
    assert body["aws_ttc_status"] == "not_ingested"
    assert body["combined_count"] == 12
    assert body["kev_matched_count"] == 0
    assert len(body["opportunities"]) == 66
    t1078 = next(item for item in body["opportunities"] if item["node_id"] == "T1078")
    assert t1078["strength"] == 2
    assert t1078["rule_status"] == "no_rule_yet"


def test_stored_catalog_matches_the_automated_join() -> None:
    stored = load_system_catalog()
    built = build_system_catalog()
    assert stored.model_dump() == built.model_dump()
    assert stored.produced_by == "automated-source-join-0.1"
    assert stored.checker == "not_used"
    by_id = {item.node_id: item for item in stored.records}
    technique = by_id["T1078"]
    assert technique.data_kind == "technique"
    assert technique.sources == ["mitre-attack", "owasp-cloud"]
    assert "IaaS" in technique.platforms
    assert "initial-access" in technique.tactics
    assert by_id["CNAS-1"].data_kind == "weakness"
    assert by_id["CNAS-1"].platforms == []
    assert by_id["CVE-2019-10200"].data_kind == "vulnerability"
    assert by_id["cisa-kev-2026.10.02"].data_kind == "catalog"
    source = inspect.getsource(catalog_module)
    for banned in ("urllib", "requests", "httpx", "boto3", "subprocess"):
        assert banned not in source


def test_catalog_pin_rejects_a_changed_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(catalog_module, "_CATALOG_SHA256", "sha256:" + ("ab" * 32))
    with pytest.raises(IntakeError) as exc:
        load_system_catalog()
    assert exc.value.code == "hash_mismatch"


def test_catalog_endpoint_returns_the_stored_rows() -> None:
    response = TestClient(create_app()).get("/v1/datasets/source-catalog")
    assert response.status_code == 200
    body = response.json()
    assert body["checker"] == "not_used"
    assert body["produced_by"] == "automated-source-join-0.1"
    assert body["record_count"] == 66
    t1078 = next(item for item in body["records"] if item["node_id"] == "T1078")
    assert t1078["data_kind"] == "technique"
    assert t1078["strength"] == 2
