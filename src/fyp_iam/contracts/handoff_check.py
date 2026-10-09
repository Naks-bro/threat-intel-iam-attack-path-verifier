"""Validate a teammate's redacted handoff file without importing or logging it.

Usage: python -m fyp_iam.contracts.handoff_check --file <private-json-path>
This command never contacts AWS or PostgreSQL and never prints input values.
"""

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from fyp_iam.contracts.collection import CoverageState
from fyp_iam.contracts.inventory import CollectionHandoff
from fyp_iam.engine2.inventory_import import prepare_inventory_import
from fyp_iam.engine2.shell_import import prepare_shell_import

_MAX_BYTES = 2_000_000
CheckCode = Literal[
    "schema_valid_only",
    "file_unavailable",
    "file_too_large",
    "invalid_json",
    "invalid_contract",
    "draft_0010_rows_valid",
    "draft_0010_rows_invalid",
]


@dataclass(frozen=True)
class HandoffCheck:
    status: Literal["valid", "invalid"]
    code: CheckCode
    authorization_evaluated: Literal[False] = False
    principal_count: int | None = None
    policy_count: int | None = None
    unresolved_layer_count: int | None = None


def check_file(path: Path, *, draft_store_check: bool = False) -> HandoffCheck:
    """Return fixed codes only; draft check is pure and never writes data."""

    handoff, error = load_handoff_file(path)
    if error is not None:
        return HandoffCheck(status="invalid", code=error)
    assert handoff is not None
    unresolved = sum(
        layer.state not in {CoverageState.collected, CoverageState.absent}
        for layer in handoff.manifest.coverage
    )
    code: CheckCode = "schema_valid_only"
    if draft_store_check:
        try:
            shell = prepare_shell_import(
                handoff,
                connection_id="handoff_check_connection",
                expected_account_fingerprint=handoff.manifest.account_fingerprint,
                request_id="handoff_check_request",
            )
            prepare_inventory_import(handoff, shell)
        except Exception:
            # The exception can contain private input; report only a fixed code.
            code = "draft_0010_rows_invalid"
        else:
            code = "draft_0010_rows_valid"
    return HandoffCheck(
        status="invalid" if code == "draft_0010_rows_invalid" else "valid",
        code=code,
        principal_count=len(handoff.inventory.principals),
        policy_count=len(handoff.inventory.policies),
        unresolved_layer_count=unresolved,
    )


def load_handoff_file(path: Path) -> tuple[CollectionHandoff | None, CheckCode | None]:
    """Read a bounded private file and discard all sensitive parse errors."""

    try:
        with path.open("rb") as source:
            payload = source.read(_MAX_BYTES + 1)
    except OSError:
        return None, "file_unavailable"
    if len(payload) > _MAX_BYTES:
        return None, "file_too_large"
    try:
        parsed = json.loads(payload)
    except (UnicodeError, ValueError, RecursionError):
        return None, "invalid_json"
    try:
        handoff = CollectionHandoff.model_validate(parsed)
    except Exception:
        # Third-party bytes and custom validators can produce sensitive exception text.
        # The operator command reports only a fixed code, never a traceback or input.
        return None, "invalid_contract"
    return handoff, None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a private, redacted inventory handoff")
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument(
        "--draft-store-check",
        action="store_true",
        help="Check pure row compatibility with proposed unapplied 0009–0010; never writes",
    )
    args = parser.parse_args(argv)
    result = check_file(args.file, draft_store_check=args.draft_store_check)
    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.status == "valid" else 1


if __name__ == "__main__":
    raise SystemExit(main())
