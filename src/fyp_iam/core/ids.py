"""Opaque identifiers derived from canonical inputs."""

import hashlib


def digest(*parts: str) -> str:
    payload = "\n".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def stable_id(prefix: str, *parts: str) -> str:
    return f"{prefix}_{digest(*parts)[:32]}"


def sha256_key(*parts: str) -> str:
    return f"sha256:{digest(*parts)}"
