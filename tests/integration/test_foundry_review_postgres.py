"""Real scoped decision history, isolated by the disposable database gate."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from fyp_iam.engine1.foundry.models import PublicationRow, ScopedReviewRow
from fyp_iam.engine1.foundry.review import ReviewCommand
from fyp_iam.engine1.foundry.review_store import ReviewConflict, append_review, read_latest_review
from fyp_iam.engine1.foundry.store import persist_foundry, read_rule

pytestmark = pytest.mark.postgres


def test_publication_assessment_rechecks_current_scoped_history_over_http() -> None:
    from fastapi.testclient import TestClient

    from fyp_iam.api.app import create_app

    url = os.environ["FYP_DATABASE_URL"]
    command = current_command(url).model_copy(update={"scope": "synthetic_benchmark"})
    app = create_app(database_url=url, local_reviewer_alias="assessment_test_operator")
    with TestClient(app, base_url="http://localhost:8765", client=("127.0.0.1", 1234)) as client:
        route = f"/v1/foundry/rules/{command.rule_version_id}/publication-assessment"
        assert client.post("/v1/foundry/reviews", json=command.model_dump()).status_code == 200
        allowed = client.get(route, params={"scope": "synthetic_benchmark"})
        assert allowed.status_code == 200 and allowed.json()["eligible_for_publication"]
        assert not allowed.json()["published"] and not allowed.json()["export_available"]
        real = client.get(route, params={"scope": "read_only_account_analysis"})
        assert real.status_code == 200 and not real.json()["eligible_for_publication"]
        assert "verifier_policy_unconfigured" in real.json()["blockers"]
        default = client.get(
            route, params={"scope": "synthetic_benchmark", "channel": "experimental"}
        )
        assert "experimental_not_opted_in" in default.json()["blockers"]
        revised = command.model_copy(
            update={
                "request_id": "review_" + uuid4().hex,
                "decision": "revision_requested",
                "comment": "Automated test only; more evidence required.",
            }
        )
        assert client.post("/v1/foundry/reviews", json=revised.model_dump()).status_code == 200
        for channel in ("stable", "experimental"):
            blocked = client.get(
                route,
                params={
                    "scope": "synthetic_benchmark",
                    "channel": channel,
                    "allow_experimental": True,
                },
            )
            assert not blocked.json()["eligible_for_publication"]
            assert "review_not_approved" in blocked.json()["blockers"]


def current_command(url: str) -> ReviewCommand:
    overview = persist_foundry(url)
    dossier = read_rule(url, overview["candidate"]["version_id"])
    assert dossier is not None
    quality, verifier = dossier["quality_report"], dossier["verifier_record"]
    return ReviewCommand(
        request_id="review_" + uuid4().hex,
        rule_version_id=dossier["version_id"],
        rule_semantic_hash=dossier["semantic_hash"],
        evidence_snapshot_hash=quality["evidence_snapshot_hash"],
        quality_report_hash=quality["report_hash"],
        verifier_request_hash=verifier["request_hash"],
        verifier_response_hash=verifier["response_hash"],
        scope="read_only_account_analysis",
        decision="approved",
        comment="Local operator review; no cloud write authority.",
    )


def test_stable_release_http_export_revocation_and_engine3_boundary() -> None:
    from fastapi.testclient import TestClient

    from fyp_iam.api.app import create_app
    from fyp_iam.contracts.models import ApprovedRule
    from fyp_iam.contracts.releases import StableReleaseCommand, StableRuleRelease
    from fyp_iam.engine1.foundry.models import RuleVersionRow, StableReleaseRow
    from fyp_iam.engine1.foundry.release_store import ReleaseConflict, export_release
    from fyp_iam.engine3.releases import analyze_published_release
    from fyp_iam.fixtures.cases import positive_case

    url = os.environ["FYP_DATABASE_URL"]
    review = current_command(url).model_copy(update={"scope": "synthetic_benchmark"})
    app = create_app(database_url=url, local_reviewer_alias="stable_release_test")
    engine = create_engine(url)
    try:
        with Session(engine) as session:
            original_candidate_json = session.get(RuleVersionRow, review.rule_version_id).rule_json
        with TestClient(
            app, base_url="http://localhost:8765", client=("127.0.0.1", 1234)
        ) as client:
            saved = client.post("/v1/foundry/reviews", json=review.model_dump()).json()
            command = StableReleaseCommand(
                request_id="release_" + uuid4().hex,
                rule_version_id=review.rule_version_id,
                scope=review.scope,
                review_decision_id=saved["decision_id"],
                review_record_hash=saved["record_hash"],
            )
            created = client.post("/v1/foundry/releases", json=command.model_dump())
            assert created.status_code == 200
            release = StableRuleRelease.model_validate(created.json())
            assert (
                client.post("/v1/foundry/releases", json=command.model_dump()).json()
                == created.json()
            )
            route = f"/v1/foundry/releases/{release.release_id}/export"
            assert client.get(route, params={"scope": review.scope}).json() == created.json()
            assert (
                client.get(route, params={"scope": "read_only_account_analysis"}).status_code == 409
            )
            report = analyze_published_release(
                release.release_id,
                positive_case().snapshot,
                scope=review.scope,
                export_loader=lambda release_id, scope: export_release(url, release_id, scope),
            )
            # The existing Engine 3 adapter does not implement this family yet.
            assert [issue.code for issue in report.issues] == ["unsupported_precondition"]
            with Session(engine) as session:
                assert (
                    session.get(RuleVersionRow, review.rule_version_id).rule_json
                    == original_candidate_json
                )
                assert (
                    ApprovedRule.model_validate_json(original_candidate_json).model_dump_json()
                    == release.candidate_json
                )
                assert session.get(StableReleaseRow, release.release_id) is not None
            with Session(engine) as session, session.begin():
                session.get(StableReleaseRow, release.release_id).record_hash = "sha256:" + "0" * 64
            try:
                corrupted = client.get(route, params={"scope": review.scope})
                assert corrupted.status_code == 503 and corrupted.json() == {
                    "detail": "database_unavailable"
                }
            finally:
                with Session(engine) as session, session.begin():
                    session.get(
                        StableReleaseRow, release.release_id
                    ).record_hash = release.record_hash
            rejected = review.model_copy(
                update={
                    "request_id": "review_" + uuid4().hex,
                    "decision": "rejected",
                    "comment": "Automated negative test; not an actual human decision.",
                }
            )
            assert client.post("/v1/foundry/reviews", json=rejected.model_dump()).status_code == 200
            denied = client.get(route, params={"scope": review.scope})
            assert denied.status_code == 409 and denied.json() == {"detail": "release_conflict"}
            with pytest.raises(ReleaseConflict):
                analyze_published_release(
                    release.release_id,
                    positive_case().snapshot,
                    scope=review.scope,
                    export_loader=lambda release_id, scope: export_release(url, release_id, scope),
                )
            # Archival retry preserves history, but cannot make the revoked export work.
            assert (
                client.post("/v1/foundry/releases", json=command.model_dump()).json()
                == created.json()
            )
            new = command.model_copy(update={"request_id": "release_" + uuid4().hex})
            assert client.post("/v1/foundry/releases", json=new.model_dump()).status_code == 409
            real_review = review.model_copy(
                update={
                    "request_id": "review_" + uuid4().hex,
                    "scope": "read_only_account_analysis",
                }
            )
            real_saved = client.post("/v1/foundry/reviews", json=real_review.model_dump()).json()
            real_release = command.model_copy(
                update={
                    "request_id": "release_" + uuid4().hex,
                    "scope": real_review.scope,
                    "review_decision_id": real_saved["decision_id"],
                    "review_record_hash": real_saved["record_hash"],
                }
            )
            assert (
                client.post("/v1/foundry/releases", json=real_release.model_dump()).status_code
                == 409
            )
    finally:
        engine.dispose()


def test_review_retry_scope_and_opposing_history_survive_new_sessions() -> None:
    url = os.environ["FYP_DATABASE_URL"]
    command = current_command(url)
    engine = create_engine(url)
    try:
        with Session(engine) as session, session.begin():
            first = append_review(session, command, "operator_test")
        with Session(engine) as session, session.begin():
            before = session.scalar(select(func.count()).select_from(ScopedReviewRow))
            assert append_review(session, command, "operator_test") == first
            assert session.scalar(select(func.count()).select_from(ScopedReviewRow)) == before
            assert read_latest_review(session, command.rule_version_id, command.scope) == first
            lab = read_latest_review(session, command.rule_version_id, "isolated_lab_validation")
            # A read-only approval must never become a lab approval.
            assert lab is None
        rejected = command.model_copy(
            update={
                "request_id": "review_" + uuid4().hex,
                "decision": "revision_requested",
                "comment": "More evidence needed before release.",
            }
        )
        with Session(engine) as session, session.begin():
            later = append_review(session, rejected, "operator_test")
        with Session(engine) as session:
            assert read_latest_review(session, command.rule_version_id, command.scope) == later
            assert session.get(ScopedReviewRow, first.decision_id) is not None
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(PublicationRow)
                    .where(PublicationRow.channel == "stable")
                )
                == 0
            )
    finally:
        engine.dispose()


def test_stale_review_and_reused_request_id_do_not_append() -> None:
    url = os.environ["FYP_DATABASE_URL"]
    command = current_command(url)
    engine = create_engine(url)
    try:
        with Session(engine) as session, session.begin():
            append_review(session, command, "operator_test")
        for changed in (
            command.model_copy(update={"decision": "rejected", "comment": "Opposing decision"}),
            command.model_copy(
                update={
                    "request_id": "review_" + uuid4().hex,
                    "evidence_snapshot_hash": "sha256:" + "0" * 64,
                }
            ),
        ):
            with Session(engine) as session:
                before = session.scalar(select(func.count()).select_from(ScopedReviewRow))
            with pytest.raises(ReviewConflict), Session(engine) as session, session.begin():
                append_review(session, changed, "operator_test")
            with Session(engine) as session:
                assert session.scalar(select(func.count()).select_from(ScopedReviewRow)) == before
    finally:
        engine.dispose()


def test_review_http_persists_retries_and_sanitizes_corrupt_history() -> None:
    from fastapi.testclient import TestClient

    from fyp_iam.api.app import create_app

    url = os.environ["FYP_DATABASE_URL"]
    command = current_command(url)
    engine = create_engine(url)
    decision_id = None
    original_hash = None
    try:
        app = create_app(database_url=url, local_reviewer_alias="operator_http")
        with TestClient(
            app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 1234)
        ) as client:
            response = client.post(
                "/v1/foundry/reviews",
                json=command.model_dump(),
                headers={"Origin": "http://127.0.0.1:5173"},
            )
            assert response.status_code == 200
            stored = response.json()
            assert stored["reviewer_alias"] == "operator_http"
            assert client.post("/v1/foundry/reviews", json=command.model_dump()).json() == stored
            route = f"/v1/foundry/rules/{command.rule_version_id}/review"
            latest = client.get(route, params={"scope": command.scope})
            assert latest.status_code == 200 and latest.json()["latest"] == stored
            assert latest.json()["release_eligibility"] == "not_evaluated"
            assert (
                client.get(route, params={"scope": "isolated_lab_validation"}).json()["latest"]
                is None
            )
            stale = command.model_copy(
                update={
                    "request_id": "review_" + uuid4().hex,
                    "quality_report_hash": "sha256:" + "0" * 64,
                }
            )
            failed = client.post("/v1/foundry/reviews", json=stale.model_dump())
            assert failed.status_code == 409 and failed.json()["detail"] == "review_conflict"
            decision_id, original_hash = stored["decision_id"], stored["record_hash"]
            with Session(engine) as session, session.begin():
                row = session.get(ScopedReviewRow, decision_id)
                assert row is not None
                row.record_hash = "sha256:" + "0" * 64
            corrupted = client.get(route, params={"scope": command.scope})
            assert corrupted.status_code == 503
            assert corrupted.json() == {"detail": "database_unavailable"}
    finally:
        if decision_id is not None:
            with Session(engine) as session, session.begin():
                row = session.get(ScopedReviewRow, decision_id)
                assert row is not None
                row.record_hash = original_hash
        engine.dispose()
