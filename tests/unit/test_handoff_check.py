"""The local handoff check emits only fixed codes and safe aggregate counts."""

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fyp_iam.contracts.collection import PolicyLayer
from fyp_iam.contracts.handoff_check import check_file
from fyp_iam.contracts.inventory import InventorySnapshot


def _valid_payload() -> dict[str, object]:
    inventory = InventorySnapshot(snapshot_id="snapshot_empty_test")
    started = datetime(2026, 10, 9, tzinfo=UTC)
    return {
        "manifest": {
            "data_kind": "synthetic",
            "run_id": "run_empty_test",
            "snapshot_id": inventory.snapshot_id,
            "account_alias": "lab-account",
            "account_fingerprint": "hmac-sha256:" + "a" * 64,
            "collector_version": "test-1",
            "started_at": started.isoformat(),
            "sealed_at": (started + timedelta(seconds=1)).isoformat(),
            "outcome": "succeeded",
            "snapshot_digest": inventory.content_digest(),
            "tasks": [
                {
                    "operation": "iam:ListUsers",
                    "attempt": 1,
                    "outcome": "succeeded",
                    "page_count": 1,
                    "item_count": 0,
                    "pagination_complete": True,
                }
            ],
            "coverage": [
                {"layer": layer.value, "state": "not_collected", "reason_code": "outside_scope"}
                for layer in PolicyLayer
            ],
        },
        "inventory": inventory.model_dump(mode="json"),
    }


def test_valid_file_is_only_schema_valid_and_keeps_unknown_coverage(tmp_path: Path) -> None:
    path = tmp_path / "private-handoff.json"
    path.write_text(json.dumps(_valid_payload()), encoding="utf-8")
    result = check_file(path)
    assert result.status == "valid"
    assert result.code == "schema_valid_only"
    assert result.principal_count == 0
    assert result.unresolved_layer_count == len(PolicyLayer)
    assert result.authorization_evaluated is False
    process = subprocess.run(
        [sys.executable, "-m", "fyp_iam.contracts.handoff_check", "--file", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0
    assert json.loads(process.stdout)["code"] == "schema_valid_only"
    assert str(path) not in process.stdout


def test_draft_store_check_distinguishes_schema_from_storable_rows(tmp_path: Path) -> None:
    path = tmp_path / "private-handoff.json"
    payload = _valid_payload()
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert check_file(path).code == "schema_valid_only"
    assert check_file(path, draft_store_check=True).code == "draft_0010_rows_invalid"

    payload["manifest"]["tasks"][0]["response_digest"] = "sha256:" + "c" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "fyp_iam.contracts.handoff_check",
            "--file",
            str(path),
            "--draft-store-check",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0
    assert json.loads(process.stdout)["code"] == "draft_0010_rows_valid"
    assert str(path) not in process.stdout
    assert process.stderr == ""


def test_invalid_file_prints_no_path_or_sensitive_input(tmp_path: Path) -> None:
    path = tmp_path / "aws_secret_access_key-private.json"
    path.write_text('{"private":"AKIAABCDEFGHIJKLMNOP"}', encoding="utf-8")
    process = subprocess.run(
        [sys.executable, "-m", "fyp_iam.contracts.handoff_check", "--file", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 1
    assert json.loads(process.stdout) == {
        "status": "invalid",
        "code": "invalid_contract",
        "authorization_evaluated": False,
        "principal_count": None,
        "policy_count": None,
        "unresolved_layer_count": None,
    }
    assert process.stderr == ""
    assert str(path) not in process.stdout
    assert "AKIAABCDEFGHIJKLMNOP" not in process.stdout


def test_fixed_failure_codes_for_missing_malformed_and_oversized(tmp_path: Path) -> None:
    assert check_file(tmp_path / "missing.json").code == "file_unavailable"
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    assert check_file(malformed).code == "invalid_json"
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * 2_000_001)
    assert check_file(oversized).code == "file_too_large"


def test_changed_inventory_digest_is_rejected_without_echo(tmp_path: Path) -> None:
    payload = _valid_payload()
    payload["manifest"]["snapshot_digest"] = "sha256:" + "b" * 64
    path = tmp_path / "digest-mismatch.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert check_file(path).code == "invalid_contract"


def test_unpaired_unicode_is_rejected_without_traceback(tmp_path: Path) -> None:
    payload = _valid_payload()
    payload["manifest"]["account_alias"] = "\ud800"
    path = tmp_path / "private-unicode.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    process = subprocess.run(
        [sys.executable, "-m", "fyp_iam.contracts.handoff_check", "--file", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 1
    assert json.loads(process.stdout)["status"] == "invalid"
    assert process.stderr == ""
