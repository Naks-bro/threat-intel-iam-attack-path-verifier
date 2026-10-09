import os
from pathlib import Path

import pytest

from fyp_iam.persistence.test_guard import database_test_gate


@pytest.fixture(autouse=True)
def protect_database_tests(request: pytest.FixtureRequest) -> None:
    if request.node.get_closest_marker("postgres") is None:
        return
    error = database_test_gate(os.environ)
    if error == "database_test_not_configured":
        pytest.skip(error)
    if error:
        pytest.fail(error, pytrace=False)


@pytest.fixture(scope="session")
def fixture_dir() -> Path:
    return Path(__file__).resolve().parent / "fixtures"
