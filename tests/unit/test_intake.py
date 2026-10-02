"""Local CTI intake: pinned artifact, closed proposal, human export."""

import inspect
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fyp_iam.api.app import create_app
from fyp_iam.contracts.models import (
    ApprovalDecision,
    EdgeType,
    RuleStatus,
    VerificationStatus,
)
from fyp_iam.engine1 import intake as intake_module
from fyp_iam.engine1.errors import IntakeError
from fyp_iam.engine1.intake import (
    decide_candidate,
    explain_proposal,
    export_approved_rule,
    fetch_remote_source,
    load_artifact,
    normalize_technique,
    parse_artifact,
    propose_rule,
    record_approval,
    validate_candidate,
)
from fyp_iam.engine3.pipeline import analyze
from fyp_iam.fixtures.builders import EVALUATED_AT
from fyp_iam.fixtures.cases import positive_case

_PINNED = Path(__file__).resolve().parents[2] / "src" / "fyp_iam" / "engine1" / "artifacts"
_MAPPED = "attack-t1548-assume-chain"


def _mapped():
    artifact, digest = load_artifact(_MAPPED)
    record = normalize_technique(artifact, digest)
    candidate = propose_rule(record)
    validate_candidate(candidate, record)
    return record, candidate


def test_pinned_artifact_normalizes_without_a_network_fetch() -> None:
    artifact, digest = load_artifact(_MAPPED)
    record = normalize_technique(artifact, digest)
    assert digest.startswith("sha256:")
    assert record.provenance.artifact_sha256 == digest
    assert record.provenance.official_reference == "https://attack.mitre.org/techniques/T1548/"
    assert record.provenance.source_version == "local-pin-2026-10-02"
    assert record.aws_iam_relevant is True
    assert record.external_id == "T1548"


def test_proposal_stays_pending_and_ignores_excerpt_wording() -> None:
    record, candidate = _mapped()
    assert candidate.status == RuleStatus.proposed
    assert candidate.approval.decision == ApprovalDecision.pending
    assert candidate.created_by.model_or_method == "allowlisted-technique-map-0.1"
    assert record.evidence_excerpt not in candidate.title
    assert record.evidence_excerpt not in candidate.description


def test_unmapped_technique_fails_closed() -> None:
    artifact, digest = load_artifact("attack-t9999-unmapped")
    record = normalize_technique(artifact, digest)
    assert record.aws_iam_relevant is False
    with pytest.raises(IntakeError) as exc:
        propose_rule(record)
    assert exc.value.code == "unsupported_technique"


def test_markup_in_the_artifact_is_rejected() -> None:
    raw = (_PINNED / f"{_MAPPED}.json").read_bytes()
    tainted = raw.replace(b"evidence text", b"<script>alert(1)</script>")
    with pytest.raises(IntakeError) as exc:
        parse_artifact(tainted, _MAPPED)
    assert exc.value.code == "unsafe_content"


def test_reference_host_outside_the_allowlist_is_rejected() -> None:
    raw = (_PINNED / f"{_MAPPED}.json").read_bytes()
    tainted = raw.replace(b"https://attack.mitre.org/", b"https://example.invalid/")
    with pytest.raises(IntakeError) as exc:
        parse_artifact(tainted, _MAPPED)
    assert exc.value.code == "bad_reference"


def test_changed_pin_rejects_the_checked_in_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        intake_module._PINNED_SHA256,
        _MAPPED,
        "sha256:" + ("ab" * 32),
    )
    with pytest.raises(IntakeError) as exc:
        load_artifact(_MAPPED)
    assert exc.value.code == "hash_mismatch"


def test_remote_fetch_is_refused_and_the_module_does_not_import_a_client() -> None:
    with pytest.raises(IntakeError) as exc:
        fetch_remote_source("https://attack.mitre.org/techniques/T1548/")
    assert exc.value.code == "network_disabled"
    source = inspect.getsource(intake_module)
    for banned in ("urllib", "requests", "httpx", "boto3", "subprocess", "socket"):
        assert banned not in source


def test_rejected_decision_is_not_exported() -> None:
    record, candidate = _mapped()
    event = record_approval(
        candidate,
        record,
        decision=ApprovalDecision.rejected,
        reviewer_id="reviewer_alias",
        decided_at=EVALUATED_AT,
        comment="Mapping is too broad for this benchmark.",
    )
    with pytest.raises(IntakeError) as exc:
        export_approved_rule(candidate, record, event)
    assert exc.value.code == "not_approved"


def test_same_approval_inputs_produce_the_same_event_id() -> None:
    record, candidate = _mapped()
    kwargs = {
        "decision": ApprovalDecision.approved,
        "reviewer_id": "reviewer_alias",
        "decided_at": EVALUATED_AT,
        "comment": "Approved for the synthetic benchmark only.",
    }
    first = record_approval(candidate, record, **kwargs)
    second = record_approval(candidate, record, **kwargs)
    assert first.event_id == second.event_id
    assert first.scope == "synthetic-benchmark"


def test_unsupported_edge_fails_validation() -> None:
    record, candidate = _mapped()
    broken = candidate.model_copy(
        update={
            "path_pattern": [
                candidate.path_pattern[0].model_copy(update={"relationship": EdgeType.CAN_ACCESS}),
                candidate.path_pattern[1],
            ]
        }
    )
    with pytest.raises(IntakeError) as exc:
        validate_candidate(broken, record)
    assert exc.value.code == "invalid_candidate"


def test_exported_rule_is_the_only_form_engine3_will_match() -> None:
    record, candidate = _mapped()
    case = positive_case()
    pending = analyze([candidate], case.snapshot, evaluated_at=case.evaluated_at)
    assert pending.findings == []
    assert pending.issues[0].code == "rule_not_approved"
    event = record_approval(
        candidate,
        record,
        decision=ApprovalDecision.approved,
        reviewer_id="reviewer_alias",
        decided_at=EVALUATED_AT,
        comment="Approved for the synthetic benchmark only.",
    )
    exported = export_approved_rule(candidate, record, event)
    assert exported.status == RuleStatus.approved
    report = analyze([exported], case.snapshot, evaluated_at=case.evaluated_at)
    assert report.verifications[0].status == VerificationStatus.supported_by_fixture
    assert report.attack_paths[0].rule_refs[0].rule_id == "rule_t1548_assume_chain"
    assert report.verifications[0].policy_simulation.status == "not_run"


def test_explanation_does_not_copy_the_excerpt() -> None:
    record, candidate = _mapped()
    text = explain_proposal(record, candidate)
    assert record.evidence_excerpt not in text
    assert "No model wrote this rule." in text


def test_approval_endpoint_exports_only_an_approved_decision() -> None:
    client = TestClient(create_app())
    body = {
        "artifact_id": _MAPPED,
        "reviewer_id": "reviewer_alias",
        "comment": "Approved for the synthetic benchmark only.",
        "decided_at": "2026-10-02T12:00:00Z",
    }
    rejected = client.post("/v1/rules/approval", json={**body, "decision": "rejected"})
    assert rejected.status_code == 200
    assert rejected.json()["exported_rule"] is None
    assert rejected.json()["event"]["decision"] == "rejected"
    approved = client.post("/v1/rules/approval", json={**body, "decision": "approved"})
    assert approved.status_code == 200
    payload = approved.json()
    assert payload["exported_rule"]["status"] == "approved"
    assert payload["event"]["scope"] == "synthetic-benchmark"
    event, exported = decide_candidate(
        _MAPPED,
        decision=ApprovalDecision.approved,
        reviewer_id="reviewer_alias",
        decided_at=EVALUATED_AT,
        comment="Approved for the synthetic benchmark only.",
    )
    assert exported is not None
    assert exported.rule_id == payload["exported_rule"]["rule_id"]
    assert event.event_id == payload["event"]["event_id"]
    markup = client.post(
        "/v1/rules/approval",
        json={**body, "decision": "approved", "comment": "<script>alert(1)</script>"},
    )
    assert markup.status_code == 422


def test_intake_endpoint_proposes_and_does_not_approve() -> None:
    client = TestClient(create_app())
    response = client.post("/v1/rules/intake", json={"artifact_id": _MAPPED})
    assert response.status_code == 200
    body = response.json()
    assert body["candidate"]["status"] == "proposed"
    assert body["candidate"]["approval"]["decision"] == "pending"
    assert body["record"]["provenance"]["artifact_sha256"].startswith("sha256:")
    missing = client.post("/v1/rules/intake", json={"artifact_id": "not-a-pin"})
    assert missing.status_code == 404
    escaped = client.post("/v1/rules/intake", json={"artifact_id": "../secrets"})
    assert escaped.status_code == 422
