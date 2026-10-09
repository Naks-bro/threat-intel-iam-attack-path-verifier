"""Write the compact source catalog from the automated join.

Request handling does not run this script. Run it after a pin changes, then
update the SHA-256 constant in catalog.py. No model call is involved.
"""

import hashlib
import json
from pathlib import Path

from fyp_iam.engine1.catalog import build_system_catalog

_PATH = Path(__file__).resolve().parents[1] / "src" / "fyp_iam" / "engine1" / "artifacts"
_PATH = _PATH / "source-catalog.json"


def main() -> None:
    payload = build_system_catalog().model_dump(mode="json")
    _PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    digest = hashlib.sha256(_PATH.read_bytes()).hexdigest()
    print(f"source-catalog.json sha256:{digest}")


if __name__ == "__main__":
    main()
