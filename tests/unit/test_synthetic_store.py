"""The synthetic writer must refuse managed and real-account targets early."""

from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy import Engine
from sqlalchemy.engine import make_url

from fyp_iam.contracts.inventory import CollectionHandoff
from fyp_iam.engine2.synthetic_store import (
    SyntheticImportRejected,
    load_synthetic_observed_graph,
    persist_synthetic_handoff,
)


class NoConnectEngine:
    def __init__(self, url: str) -> None:
        self.url = make_url(url)

    def begin(self) -> None:
        raise AssertionError("database connection must not open")


@pytest.mark.parametrize(
    ("url", "allow_disposable"),
    [
        ("postgresql+psycopg://user@db.example.test/postgres", True),
        ("postgresql+psycopg://user@localhost/fyp_iam", False),
        ("postgresql+psycopg://user@localhost/postgres", True),
        ("sqlite:///local.db", True),
    ],
)
def test_unsafe_target_is_refused_before_connect(url: str, allow_disposable: bool) -> None:
    engine = cast(Engine, NoConnectEngine(url))
    with pytest.raises(SyntheticImportRejected, match="^disposable_target_required$"):
        persist_synthetic_handoff(
            engine,
            cast(CollectionHandoff, None),
            connection_id="fixture",
            request_id="request",
            allow_disposable=allow_disposable,
        )


def test_real_account_handoff_is_refused_before_connect() -> None:
    engine = cast(Engine, NoConnectEngine("postgresql+psycopg://user@localhost/fyp_iam"))
    handoff = cast(
        CollectionHandoff,
        SimpleNamespace(manifest=SimpleNamespace(data_kind="real_account_observed")),
    )
    with pytest.raises(SyntheticImportRejected, match="^real_account_import_disabled$"):
        persist_synthetic_handoff(
            engine,
            handoff,
            connection_id="fixture",
            request_id="request",
            allow_disposable=True,
            include_observed_graph=True,
        )


def test_graph_reader_refuses_managed_target_before_connect() -> None:
    engine = cast(Engine, NoConnectEngine("postgresql+psycopg://user@db.example.test/postgres"))
    with pytest.raises(SyntheticImportRejected, match="^disposable_target_required$"):
        load_synthetic_observed_graph(engine, "snapshot_1", allow_disposable=True)
