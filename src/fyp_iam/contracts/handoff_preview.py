"""Offline two-identity policy-text preview for a private redacted handoff.

Never contacts AWS or PostgreSQL, stores data, or reports effective permission.
"""

import argparse
import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from fyp_iam.contracts.handoff_check import CheckCode, load_handoff_file
from fyp_iam.engine2.paired_policy_text import (
    CredentialPolicyQuestion,
    compare_credential_policy_text,
)

_KEY = re.compile(r"^p_[0-9a-f]{32}$")
PreviewCode = CheckCode | Literal["invalid_selection", "policy_text_only"]


@dataclass(frozen=True)
class HandoffPreview:
    status: Literal["observation", "invalid"]
    code: PreviewCode
    authorization_evaluated: Literal[False] = False
    account_security_assessment: Literal["not_assessed"] = "not_assessed"
    data_kind: Literal["synthetic", "real_account_observed"] | None = None
    snapshot_basis: Literal["shared_snapshot"] | None = None
    contrast: str | None = None
    first_status: str | None = None
    second_status: str | None = None
    first_uncertainty_count: int | None = None
    second_uncertainty_count: int | None = None
    first_coverage_gap_count: int | None = None
    second_coverage_gap_count: int | None = None


def preview_file(path: Path, first: str, second: str, target: str) -> HandoffPreview:
    """Return fixed codes and bounded metadata, never private identifiers or evidence."""

    handoff, error = load_handoff_file(path)
    if error is not None:
        return HandoffPreview(status="invalid", code=error)
    assert handoff is not None
    if not all(_KEY.fullmatch(key) for key in (first, second, target)):
        return HandoffPreview(status="invalid", code="invalid_selection")
    try:
        result = compare_credential_policy_text(
            CredentialPolicyQuestion(handoff, first, target),
            CredentialPolicyQuestion(handoff, second, target),
        )
    except Exception:
        # Untrusted selections and handoffs can raise with private values in
        # their exception text; no exception detail crosses the CLI boundary.
        return HandoffPreview(status="invalid", code="invalid_selection")
    return HandoffPreview(
        status="observation",
        code="policy_text_only",
        data_kind=result.data_kind,
        snapshot_basis="shared_snapshot",
        contrast=result.contrast,
        first_status=result.first.status,
        second_status=result.second.status,
        first_uncertainty_count=len(result.first.uncertainty_codes),
        second_uncertainty_count=len(result.second.uncertainty_codes),
        first_coverage_gap_count=len(result.first.coverage_gap_codes),
        second_coverage_gap_count=len(result.second.coverage_gap_codes),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preview redacted IAM policy-text contrast")
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--first", required=True)
    parser.add_argument("--second", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args(argv)
    result = preview_file(args.file, args.first, args.second, args.target)
    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.status == "observation" else 1


if __name__ == "__main__":
    raise SystemExit(main())
