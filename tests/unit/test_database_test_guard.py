from pathlib import Path

import pytest

from fyp_iam.persistence.test_guard import database_test_gate

pytest_plugins = ["pytester"]

_LOCAL = "postgresql+psycopg://test:synthetic-password@127.0.0.1:55432/fyp_iam"


def _env(url: str = _LOCAL) -> dict[str, str]:
    return {"FYP_DATABASE_URL": url, "FYP_ALLOW_DISPOSABLE_DATABASE_TESTS": "1"}


def test_absent_configuration_is_not_database_verification() -> None:
    assert database_test_gate({}) == "database_test_not_configured"


def test_local_database_needs_explicit_disposable_opt_in() -> None:
    assert database_test_gate({"FYP_DATABASE_URL": _LOCAL}) == "database_test_opt_in_required"


def test_explicit_loopback_disposable_target_is_accepted() -> None:
    assert database_test_gate(_env()) is None


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://test:synthetic-password@db.example.com:5432/fyp_iam",
        "postgresql+psycopg://test:synthetic-password@127.0.0.1:5432/postgres",
        "postgresql+psycopg://test:synthetic-password@127.0.0.1:5432/fyp_iam?host=db.example.com",
        "postgresql+psycopg://test:synthetic-password@127.0.0.1:5432/fyp_iam?service=managed",
        "postgresql+psycopg://test:synthetic-password@127.0.0.1:0/fyp_iam",
        "postgresql+psycopg:///fyp_iam",
        "sqlite:///fyp_iam",
        "bad-url-with-synthetic-password",
    ],
)
def test_unsafe_targets_are_rejected_without_returning_secrets(url: str) -> None:
    assert database_test_gate(_env(url)) == "database_test_unsafe_target"


@pytest.mark.parametrize(
    "key",
    [
        "FYP_TEST_DATABASE_URL",
        "FYP_DATABASE_DIRECT_URL",
        "FYP_DATABASE_SESSION_URL",
        "FYP_MIGRATION_DATABASE_URL",
    ],
)
def test_secondary_target_cannot_redirect_test_or_migration(key: str) -> None:
    env = _env()
    env[key] = "postgresql+psycopg://test:synthetic-password@db.example.com:5432/postgres"
    assert database_test_gate(env) == "database_test_url_mismatch"


@pytest.mark.parametrize("key", ["PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "PGHOST"])
def test_libpq_environment_cannot_override_target(key: str) -> None:
    env = _env()
    env[key] = "untrusted-connection-selector"
    assert database_test_gate(env) == "database_test_environment_override"


def test_ipv6_loopback_is_supported() -> None:
    assert database_test_gate(_env(_LOCAL.replace("127.0.0.1", "[::1]"))) is None


def test_pytest_gate_prevents_database_test_body_for_managed_target(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conftest = Path(__file__).resolve().parents[1] / "conftest.py"
    pytester.makeconftest(conftest.read_text(encoding="utf-8"))
    pytester.makeini("[pytest]\nmarkers = postgres: disposable database required")
    pytester.makepyfile("""
        from pathlib import Path
        import pytest
        @pytest.mark.postgres
        def test_must_not_run():
            Path("body_was_executed").write_text("unsafe", encoding="utf-8")
    """)
    monkeypatch.setenv(
        "FYP_DATABASE_URL",
        "postgresql+psycopg://test:synthetic-password@db.example.com:5432/postgres",
    )
    monkeypatch.setenv("FYP_ALLOW_DISPOSABLE_DATABASE_TESTS", "1")
    for key in ("PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGSERVICE", "PGSERVICEFILE"):
        monkeypatch.delenv(key, raising=False)
    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(errors=1)
    assert "database_test_unsafe_target" in result.stdout.str()
    assert not (pytester.path / "body_was_executed").exists()
    assert "synthetic-password" not in result.stdout.str()
