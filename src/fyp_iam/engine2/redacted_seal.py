"""Gitignored local file for one redacted handoff.

The file is not a database row, a managed import, or an authorization result.
Raw pages, account identifiers, ARNs, and credentials are refused before write.
"""

import re
from pathlib import Path

from fyp_iam.contracts.inventory import CollectionHandoff

_FORBIDDEN = re.compile(
    r"arn:aws:|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|aws_secret_access_key|\b\d{12}\b",
    re.IGNORECASE,
)


class RedactedSealRejected(ValueError):
    """Fixed refusal. The message never includes handoff contents."""

    def __init__(self) -> None:
        super().__init__("redacted_seal_rejected")


def seal_path() -> Path:
    """Return the only location this process may store the redacted handoff."""

    return Path(__file__).resolve().parents[3] / ".aws-safety" / "redacted-handoff.json"


def assert_redacted_text(payload: str) -> None:
    """Reject text that still carries an account identifier, ARN, or credential."""

    if _FORBIDDEN.search(payload):
        raise RedactedSealRejected


def write_redacted_seal(handoff: CollectionHandoff) -> None:
    """Revalidate one redacted handoff and write it to the gitignored seal path."""

    try:
        sealed = CollectionHandoff.model_validate_json(handoff.model_dump_json())
        payload = sealed.model_dump_json()
    except ValueError:
        raise RedactedSealRejected from None
    assert_redacted_text(payload)
    path = seal_path()
    if path.name != "redacted-handoff.json" or path.parent.name != ".aws-safety":
        raise RedactedSealRejected
    path.parent.mkdir(exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def read_redacted_seal(path: Path | None = None) -> CollectionHandoff:
    """Load the gitignored seal. Missing file and unsafe text stay distinct."""

    location = path or seal_path()
    if not location.is_file():
        raise FileNotFoundError
    try:
        raw = location.read_bytes()
    except OSError:
        raise RedactedSealRejected from None
    if len(raw) > 2_000_000:
        raise RedactedSealRejected
    try:
        payload = raw.decode("utf-8")
    except UnicodeError:
        raise RedactedSealRejected from None
    assert_redacted_text(payload)
    try:
        return CollectionHandoff.model_validate_json(payload)
    except ValueError:
        raise RedactedSealRejected from None
