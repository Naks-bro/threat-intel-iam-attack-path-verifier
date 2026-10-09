import os

import pytest

import fyp_iam.persistence.dotenv as dotenv


@pytest.mark.parametrize("operator", [None, "process_operator"])
def test_database_dotenv_cannot_enable_or_replace_review_operator(tmp_path, monkeypatch, operator):
    config = tmp_path / ".env"
    config.write_text(
        "FYP_DATABASE_URL=fixture-database-url\nFYP_LOCAL_REVIEWER_ALIAS=file_operator\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(dotenv, "_candidates", lambda: (config,))
    monkeypatch.delenv("FYP_DATABASE_URL", raising=False)
    if operator is None:
        monkeypatch.delenv("FYP_LOCAL_REVIEWER_ALIAS", raising=False)
    else:
        monkeypatch.setenv("FYP_LOCAL_REVIEWER_ALIAS", operator)
    dotenv.load_local_env()
    assert os.environ["FYP_DATABASE_URL"] == "fixture-database-url"
    assert os.environ.get("FYP_LOCAL_REVIEWER_ALIAS") == operator
