"""The pinned 50-row cloud technique dataset."""

import inspect

import pytest
from fastapi.testclient import TestClient

from fyp_iam.api.app import create_app
from fyp_iam.engine1 import dataset as dataset_module
from fyp_iam.engine1.dataset import load_cloud_technique_dataset
from fyp_iam.engine1.errors import IntakeError


def test_dataset_has_fifty_sorted_cloud_techniques() -> None:
    dataset = load_cloud_technique_dataset()
    assert dataset.source_version == "19.2"
    assert dataset.dataset_id == "mitre-enterprise-cloud-50"
    assert len(dataset.records) == 50
    ids = [item.external_id for item in dataset.records]
    assert ids == sorted(ids)
    assert len(set(ids)) == 50
    assert dataset.records[0].external_id == "T1020.001"
    assert all(item.rule_status == "no_rule_yet" for item in dataset.records)
    assert all(item.rule_id is None for item in dataset.records)
    assert "description" not in dataset.model_dump()
    assert "IaaS" in dataset.records[0].platforms
    raw = dataset_module._DATASET.read_text(encoding="utf-8")
    assert '"description"' not in raw


def test_dataset_loader_does_not_download() -> None:
    source = inspect.getsource(dataset_module)
    for banned in ("urllib", "requests", "httpx", "boto3", "subprocess"):
        assert banned not in source


def test_dataset_pin_rejects_a_changed_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dataset_module, "_PINNED_SHA256", "sha256:" + ("ab" * 32))
    with pytest.raises(IntakeError) as exc:
        load_cloud_technique_dataset()
    assert exc.value.code == "hash_mismatch"


def test_dataset_endpoint_returns_the_fifty_rows() -> None:
    response = TestClient(create_app()).get("/v1/datasets/cloud-techniques")
    assert response.status_code == 200
    body = response.json()
    assert len(body["records"]) == 50
    assert body["source_version"] == "19.2"
    assert body["records"][0]["rule_status"] == "no_rule_yet"
