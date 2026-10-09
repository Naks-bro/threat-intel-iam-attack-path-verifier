"""Persistence failures. A failed write must not look like a saved review."""


class DatabaseUnavailable(Exception):
    """PostgreSQL cannot be used. Callers receive no stored id."""

    code = "database_unavailable"

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)
