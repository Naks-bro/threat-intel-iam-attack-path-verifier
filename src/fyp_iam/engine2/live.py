"""Live collection boundary. This module does not call AWS."""


class LiveCollectionDisabled(RuntimeError):
    """Raised instead of contacting AWS."""


def collect_live_account() -> None:
    """Refuse live collection until a lab account is explicitly authorized."""
    raise LiveCollectionDisabled(
        "Live AWS collection is disabled. No API call was made. "
        "The read-only template in docs/policies/iam-readonly-collector.json is not attached. "
        "Use normalize_synthetic_account for fixtures."
    )
