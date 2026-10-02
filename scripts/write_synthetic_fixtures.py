"""Write the synthetic fixture JSON files from the in-repo case builders."""

import json
from pathlib import Path

from fyp_iam.fixtures.cases import all_cases
from fyp_iam.fixtures.loader import default_fixture_dir


def write_fixtures(directory: Path | None = None) -> None:
    target = directory or default_fixture_dir()
    target.mkdir(parents=True, exist_ok=True)
    for case in all_cases():
        payload = case.model_dump(mode="json", by_alias=True)
        path = target / f"{case.case_id}.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    write_fixtures()


if __name__ == "__main__":
    main()
