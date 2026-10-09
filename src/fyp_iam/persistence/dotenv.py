"""Load a local .env file without printing its values."""

import os
from pathlib import Path


def load_local_env() -> None:
    """Set missing environment variables from the first .env file found."""

    for path in _candidates():
        if path.is_file():
            _apply(path)
            return


def _candidates() -> tuple[Path, ...]:
    cwd = Path.cwd() / ".env"
    repo = Path(__file__).resolve().parents[3] / ".env"
    if cwd == repo:
        return (cwd,)
    return (cwd, repo)


def _apply(path: Path) -> None:
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        # Local review enablement must come from the operator process, not DB config.
        if key == "FYP_LOCAL_REVIEWER_ALIAS":
            continue
        if not key or key in os.environ:
            continue
        os.environ[key] = value.strip().strip('"').strip("'")
