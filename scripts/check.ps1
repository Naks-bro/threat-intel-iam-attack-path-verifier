$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "Missing .venv. Create it with: py -3.12 -m venv .venv"
}

function Invoke-Check([string[]]$CheckArgs) {
    & $Python @CheckArgs
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

Invoke-Check @("-m", "ruff", "check", ".")
Invoke-Check @("-m", "ruff", "format", "--check", ".")
Invoke-Check @("-m", "mypy", "src")
Invoke-Check @("-m", "pytest")
