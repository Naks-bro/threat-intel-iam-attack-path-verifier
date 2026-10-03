"""The command emits bounded operational output without connection strings."""

import json

import pytest

import fyp_iam.engine1.foundry.runner as runner
from fyp_iam.engine1.foundry.store import FoundryRunInProgress


def test_preview_is_reproducible_and_does_not_claim_persistence(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert runner.main(["preview"]) == 0
    first = capsys.readouterr().out
    assert runner.main(["preview"]) == 0
    assert capsys.readouterr().out == first
    summary = json.loads(first)
    assert summary["status"] == "succeeded"
    assert summary["persisted"] is False
    assert summary["active_sources"] == 3
    assert summary["disabled_sources"] == 1


def test_run_without_database_fails_with_safe_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(runner, "database_url_from_env", lambda: None)
    assert runner.main(["run"]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "database_not_configured"}


def test_concurrent_run_returns_conflict_without_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        runner,
        "database_url_from_env",
        lambda: "postgresql+psycopg://user:private@127.0.0.1:5432/postgres",
    )
    monkeypatch.setattr(runner, "prepare_url", lambda url: (url, None))

    def busy(_url: str) -> None:
        raise FoundryRunInProgress

    monkeypatch.setattr(runner, "persist_foundry", busy)
    assert runner.main(["run"]) == 3
    assert json.loads(capsys.readouterr().out) == {"error": "foundry_run_in_progress"}
