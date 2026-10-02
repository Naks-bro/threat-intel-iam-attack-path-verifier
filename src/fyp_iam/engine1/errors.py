"""Closed failures for local CTI intake. Callers do not receive a partial rule."""


class IntakeError(Exception):
    """The artifact, candidate, or approval cannot proceed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)
