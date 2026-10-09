import subprocess
import sys
from pathlib import Path


def test_review_consumer_matches_provider_schema():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "scripts/quality_contract_types.py", "--review", "--check"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout
