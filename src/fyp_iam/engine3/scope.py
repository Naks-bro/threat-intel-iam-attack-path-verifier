"""Fail-closed marker for the local fixture verifier.

This marker prevents accidental real-account use; it is not authentication or
proof of data provenance when a caller controls the snapshot payload.
"""

from fyp_iam.contracts.models import IAMGraphSnapshot

SYNTHETIC_PROFILES = frozenset({"none-synthetic-fixture", "synthetic-records-no-aws-api"})


def require_synthetic_snapshot(snapshot: IAMGraphSnapshot) -> None:
    if snapshot.collection.permissions_profile not in SYNTHETIC_PROFILES:
        raise ValueError("Local fixture analysis requires an explicitly synthetic snapshot")
