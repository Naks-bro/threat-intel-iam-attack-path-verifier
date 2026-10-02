"""Load checked-in fixture JSON without leaving the fixture directory."""

import json
import re
from pathlib import Path

from fyp_iam.fixtures.cases import FixtureCase


class FixtureLoadError(Exception):
    """The requested fixture name or file is not usable."""


def default_fixture_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "tests" / "fixtures"


def list_fixture_ids(directory: Path) -> list[str]:
    root = directory.resolve()
    if not root.is_dir():
        return []
    return sorted(
        path.stem for path in root.glob("*.json") if re.fullmatch(r"[a-z0-9_]+", path.stem)
    )


def load_fixture(directory: Path, case_id: str) -> FixtureCase:
    if not re.fullmatch(r"[a-z0-9_]+", case_id):
        raise FixtureLoadError("fixture name is not allowed")
    root = directory.resolve()
    path = (root / f"{case_id}.json").resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise FixtureLoadError("fixture was not found")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return FixtureCase.model_validate(payload)
