"""An untrusted verifier response cannot publish without exact evidence binding."""

from fyp_iam.engine1.foundry.adapters import assemble_snapshot
from fyp_iam.engine1.foundry.compiler import compile_snapshot


def _base_response() -> dict[str, object]:
    compiled = compile_snapshot(assemble_snapshot())
    candidate = compiled["candidate"]
    assert isinstance(candidate, dict)
    return {
        "provider": "test-provider",
        "model": "test-model",
        "prompt_version": "verifier-prompt-0.1",
        "schema_version": "0.1",
        "candidate_version_id": candidate["version_id"],
        "evidence_snapshot_hash": candidate["evidence_snapshot_hash"],
        "verdict": "pass",
        "findings": ["No contradiction in the bounded evidence snapshot"],
        "citations": candidate["evidence_ids"],
        "suggestions": [],
    }


def test_valid_cited_verifier_result_can_publish_experimentally() -> None:
    compiled = compile_snapshot(assemble_snapshot(), verification=_base_response())
    assert compiled["ai_verification"]["verdict"] == "pass"
    assert compiled["publication"]["channel"] == "experimental"


def test_missing_binding_unknown_citation_and_extra_tool_call_fail_closed() -> None:
    for mutation in (
        {"candidate_version_id": "different_version"},
        {"citations": ["invented_evidence"]},
        {"tool_call": "execute shell"},
    ):
        response = {**_base_response(), **mutation}
        compiled = compile_snapshot(assemble_snapshot(), verification=response)
        assert compiled["publication"] is None
        assert compiled["ai_verification"]["verdict"] == "needs_review"


def test_bare_pass_verdict_cannot_publish() -> None:
    compiled = compile_snapshot(assemble_snapshot(), verification={"verdict": "pass"})
    assert compiled["publication"] is None
