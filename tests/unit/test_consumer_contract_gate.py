"""The routine drift gate rejects stale/missing artifacts without rewriting them."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest


def load_generator() -> ModuleType:
    path = Path(__file__).resolve().parents[2] / "scripts" / "quality_contract_types.py"
    spec = importlib.util.spec_from_file_location("consumer_contract_gate", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("mode", ["quality", "fixture", "verifier", "review"])
@pytest.mark.parametrize("state", ["matching", "stale", "missing"])
def test_consumer_gate_is_fail_closed_and_read_only(
    mode: str, state: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    generator = load_generator()
    quality = tmp_path / "quality-types.ts"
    fixture = tmp_path / "quality-fixture.ts"
    verifier = tmp_path / "verifier-types.ts"
    review = tmp_path / "review-types.ts"
    monkeypatch.setattr(generator, "TARGET", quality)
    monkeypatch.setattr(generator, "FIXTURE_TARGET", fixture)
    targets = {"quality": quality, "fixture": fixture, "verifier": verifier, "review": review}
    target = targets[mode]
    expected = (
        generator.generated_fixture()
        if mode == "fixture"
        else generator.generated_types(verifier=mode == "verifier", review=mode == "review")
    )
    if state != "missing":
        target.write_text(expected if state == "matching" else "stale\n", encoding="utf-8")
    before = target.read_bytes() if target.exists() else None
    arguments = ["generator", "--check"]
    if mode != "quality":
        arguments.append(f"--{mode}")
    monkeypatch.setattr(sys, "argv", arguments)

    assert generator.main() == (0 if state == "matching" else 1)
    assert (target.read_bytes() if target.exists() else None) == before
    assert all(not path.exists() for name, path in targets.items() if name != mode)


def test_verifier_fixture_request_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    generator = load_generator()
    monkeypatch.setattr(sys, "argv", ["generator", "--verifier", "--fixture", "--check"])
    with pytest.raises(SystemExit) as failure:
        generator.main()
    assert failure.value.code == 2
