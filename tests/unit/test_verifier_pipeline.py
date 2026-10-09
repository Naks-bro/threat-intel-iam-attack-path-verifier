"""The pipeline selects actual pinned evidence before invoking the critic."""

import asyncio
import json
from dataclasses import replace

import pytest

from fyp_iam.engine1.foundry.adapters import assemble_snapshot
from fyp_iam.engine1.foundry.compiler import ToolResult, compile_snapshot
from fyp_iam.engine1.foundry.verifier import FakeVerifier
from fyp_iam.engine1.foundry.verifier_models import VerifierRequest
from fyp_iam.engine1.foundry.verifier_pipeline import (
    build_verifier_request,
    compile_verified_snapshot,
)


def test_selected_bytes_are_actual_pinned_inputs_and_reproducible() -> None:
    snapshot = assemble_snapshot()
    compiled = compile_snapshot(snapshot)
    request = build_verifier_request(snapshot, compiled)
    assert {item.source_key for item in request.evidence} == {
        "mitre-attack",
        "aws-service-reference",
        "stratus-red-team",
    }
    assert all(item.text.encode() in snapshot.payloads.values() for item in request.evidence)
    assert request.request_hash == build_verifier_request(snapshot, compiled).request_hash
    assert "CreateAccessKey" in "".join(item.text for item in request.evidence)


@pytest.mark.parametrize("corruption", ["missing", "changed", "metadata", "duplicate"])
def test_missing_or_tampered_inputs_fail_before_provider(corruption: str) -> None:
    snapshot = assemble_snapshot()
    compiled = compile_snapshot(snapshot)
    if corruption == "missing":
        snapshot = replace(snapshot, payloads={})
    elif corruption == "changed":
        snapshot = replace(snapshot, payloads={name: b"{}" for name in snapshot.payloads})
    elif corruption == "metadata":
        snapshot = replace(
            snapshot,
            sources=tuple(replace(source, version_label="other") for source in snapshot.sources),
        )
    else:
        snapshot = replace(snapshot, sources=(*snapshot.sources, snapshot.sources[0]))
    with pytest.raises(ValueError, match="verifier evidence unavailable"):
        build_verifier_request(snapshot, compiled)


def test_verified_path_runs_validators_once_and_never_mutates_candidate() -> None:
    snapshot = assemble_snapshot()
    baseline = compile_snapshot(snapshot)
    result = asyncio.run(compile_verified_snapshot(snapshot))
    assert result["candidate"] == baseline["candidate"]
    assert result["validations"] == baseline["validations"]
    assert (
        result["ai_verification"]["request_hash"]
        == build_verifier_request(snapshot, baseline).request_hash
    )
    assert result["publication"]["channel"] == "experimental"
    assert result["candidate"]["rule"]["approval"]["decision"] == "pending"


def test_provider_error_removes_experimental_publication() -> None:
    class Broken(FakeVerifier):
        async def verify(self, request: VerifierRequest) -> dict[str, object]:
            raise RuntimeError("private token")

    result = asyncio.run(
        compile_verified_snapshot(assemble_snapshot(), adapter=Broken(validations_passed=True))
    )
    assert result["publication"] is None
    assert result["ai_verification"]["failure_code"] == "provider_error"
    assert "private token" not in json.dumps(result)


def test_incomplete_stored_snapshot_cannot_fall_back_to_default_fake() -> None:
    class Never(FakeVerifier):
        async def verify(self, request: VerifierRequest) -> dict[str, object]:
            pytest.fail("Missing evidence must not invoke a provider")

    snapshot = replace(assemble_snapshot(), payloads={})
    result = asyncio.run(
        compile_verified_snapshot(snapshot, adapter=Never(validations_passed=True))
    )
    assert result["publication"] is None
    assert result["ai_verification"]["failure_code"] == "evidence_unavailable"


def test_optional_validators_are_not_reexecuted_and_disagreement_blocks_publication() -> None:
    class Counting:
        name = "parliament"
        calls = 0

        def evaluate(self, rule: dict[str, object]) -> ToolResult:
            self.calls += 1
            return ToolResult(self.name, "test", "fail", ("Recorded disagreement",))

    tool = Counting()
    result = asyncio.run(
        compile_verified_snapshot(
            assemble_snapshot(), tools=(tool,), adapter=FakeVerifier(validations_passed=True)
        )
    )
    assert tool.calls == 1
    assert result["ai_verification"]["verdict"] == "pass"
    assert result["publication"] is None
