"""Environment configuration. An empty URL means the database is not configured."""

import os


def database_url_from_env() -> str | None:
    value = os.environ.get("FYP_DATABASE_URL", "").strip()
    return value or None
