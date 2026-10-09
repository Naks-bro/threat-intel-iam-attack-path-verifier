[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$BackendOnly
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ProjectPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

Push-Location $ProjectRoot
try {
    if (-not (Test-Path $ProjectPython)) {
        if ($CheckOnly) { throw "Missing .venv; run scripts\setup.ps1 to create it." }
        Get-Command py.exe -ErrorAction Stop | Out-Null
        & py.exe -3.12 -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw "Python 3.12 virtual environment creation failed." }
    }
    & $ProjectPython -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 2)"
    if ($LASTEXITCODE -ne 0) {
        throw "Existing .venv is not Python 3.12. Preserve it and choose a clean checkout."
    }
    if (-not $CheckOnly) {
        Write-Output "Installing backend dependencies in the project virtual environment."
        & $ProjectPython -m pip install -e ".[dev]"
        if ($LASTEXITCODE -ne 0) { throw "Backend installation failed." }
    }
    & $ProjectPython -c "import fyp_iam, fastapi, pydantic, sqlalchemy, psycopg, alembic, pytest, ruff, mypy"
    if ($LASTEXITCODE -ne 0) { throw "Backend dependencies are incomplete." }
    if (-not $BackendOnly) {
        Get-Command node.exe, npm.cmd -ErrorAction Stop | Out-Null
        $NodeVersion = & node.exe --version
        if ($LASTEXITCODE -ne 0 -or $NodeVersion -notmatch '^v(\d+)\.') {
            throw "Node version could not be determined."
        }
        if ([int]$Matches[1] -lt 22) { throw "Install Node 22 or newer; CI uses Node 22." }
        Push-Location (Join-Path $ProjectRoot "frontend")
        try {
            if (-not $CheckOnly) {
                Write-Output "Installing frontend dependencies from package-lock.json."
                & npm.cmd ci
                if ($LASTEXITCODE -ne 0) { throw "Frontend installation failed." }
            }
            if (-not (Test-Path "node_modules\.bin\vite.cmd")) {
                throw "Frontend dependencies are incomplete; run npm ci in frontend."
            }
        } finally { Pop-Location }
    }
    Write-Output "Dependency checks passed. Next: scripts\check.ps1"
    Write-Output "No cloud resources, database migrations, credentials, or .env files were changed."
} finally { Pop-Location }
