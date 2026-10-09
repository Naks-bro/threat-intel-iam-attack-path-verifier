import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell setup entrypoint")
def test_setup_check_only_validates_backend_dependencies_without_installing() -> None:
    root = Path(__file__).resolve().parents[2]
    script = root / "scripts" / "setup.ps1"
    assert script.is_file()
    result = subprocess.run(
        [
            shutil.which("pwsh.exe") or "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            "-CheckOnly",
            "-BackendOnly",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, "Setup dependency check failed; inspect tools, not secrets."
    assert "Dependency checks passed" in result.stdout
    assert "Installing" not in result.stdout
