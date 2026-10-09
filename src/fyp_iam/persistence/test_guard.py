"""Fail closed before integration-test writes. Does not load .env or connect."""

import os
from collections.abc import Mapping

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


def database_test_gate(environment: Mapping[str, str]) -> str | None:
    """Return only a fixed error code; never an environment value or parsed URL."""
    raw = environment.get("FYP_DATABASE_URL", "").strip()
    if not raw:
        return "database_test_not_configured"
    if environment.get("FYP_ALLOW_DISPOSABLE_DATABASE_TESTS") != "1":
        return "database_test_opt_in_required"
    for key in ("PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGSERVICE", "PGSERVICEFILE"):
        if environment.get(key, "").strip():
            return "database_test_environment_override"
    try:
        url = make_url(raw)
        if (
            url.drivername != "postgresql+psycopg"
            or url.host not in {"127.0.0.1", "localhost", "::1"}
            or url.database != "fyp_iam"
            or url.query
            or (url.port is not None and not 1 <= url.port <= 65535)
        ):
            return "database_test_unsafe_target"
        for key in (
            "FYP_TEST_DATABASE_URL",
            "FYP_DATABASE_DIRECT_URL",
            "FYP_DATABASE_SESSION_URL",
            "FYP_MIGRATION_DATABASE_URL",
        ):
            alternate = environment.get(key, "").strip()
            if alternate and make_url(alternate) != url:
                return "database_test_url_mismatch"
    except (ArgumentError, ValueError):
        return "database_test_unsafe_target"
    return None


def main() -> int:
    error = database_test_gate(os.environ)
    print(error or "disposable_database_target_allowed")
    return 2 if error else 0


if __name__ == "__main__":
    raise SystemExit(main())
