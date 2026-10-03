"""Bounded command entry point for offline preview and a persisted foundry run.

An external scheduler can invoke ``run``. This process never holds a secret in
its output and does not perform live AWS writes or external model calls.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from fyp_iam.engine1.foundry.pipeline import build_foundry
from fyp_iam.engine1.foundry.store import FoundryRunInProgress, persist_foundry
from fyp_iam.engine1.workbench.config import database_url_from_env
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable
from fyp_iam.persistence.urls import prepare_url


def _summary(overview: dict[str, object]) -> dict[str, object]:
    run = overview.get("run")
    sources = overview.get("sources")
    candidate = overview.get("candidate")
    if not isinstance(run, dict) or not isinstance(sources, list):
        raise RuntimeError("foundry result is incomplete")
    return {
        "status": run.get("status"),
        "persisted": overview.get("persisted", False),
        "active_sources": sum(
            isinstance(source, dict) and source.get("enabled") is True for source in sources
        ),
        "disabled_sources": sum(
            isinstance(source, dict) and source.get("enabled") is False for source in sources
        ),
        "candidate_id": candidate.get("rule_id") if isinstance(candidate, dict) else None,
        "semantic_hash": candidate.get("semantic_hash") if isinstance(candidate, dict) else None,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fyp_iam.engine1.foundry.runner")
    parser.add_argument("mode", choices=("preview", "run"))
    args = parser.parse_args(argv)

    if args.mode == "preview":
        overview = build_foundry(persisted=False, storage="not_written")
        print(json.dumps(_summary(overview), sort_keys=True))
        return 0

    raw_url = database_url_from_env()
    if raw_url is None:
        print(json.dumps({"error": "database_not_configured"}))
        return 2
    url, error = prepare_url(raw_url)
    if error is not None:
        print(json.dumps({"error": error}))
        return 2
    try:
        overview = persist_foundry(url)
    except FoundryRunInProgress:
        print(json.dumps({"error": "foundry_run_in_progress"}))
        return 3
    except DatabaseUnavailable:
        print(json.dumps({"error": "database_unavailable"}))
        return 4
    print(json.dumps(_summary(overview), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
