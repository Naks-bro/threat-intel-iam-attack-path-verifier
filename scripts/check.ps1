[CmdletBinding()]
param(
    [switch]$IncludePostgres,
    [switch]$BackendOnly
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "Missing .venv. Create it with: py -3.12 -m venv .venv"
}

function Invoke-Check([string[]]$CheckArgs) {
    & $Python @CheckArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Python check failed. Exit code: $LASTEXITCODE"
    }
}

$DatabaseKeys = @(
    "FYP_DATABASE_URL", "FYP_TEST_DATABASE_URL", "FYP_DATABASE_DIRECT_URL",
    "FYP_DATABASE_SESSION_URL", "FYP_MIGRATION_DATABASE_URL", "FYP_DATABASE_SSLROOTCERT"
)
$SavedDatabaseEnvironment = @{}
foreach ($Key in $DatabaseKeys) {
    $SavedDatabaseEnvironment[$Key] = [Environment]::GetEnvironmentVariable($Key, "Process")
}

Push-Location $Root
try {
    if ($IncludePostgres) {
        # No migrations, reset, or seed are performed by this check command.
        Invoke-Check @("-m", "fyp_iam.persistence.test_guard")
    } else {
        # Empty overrides prevent Python's dotenv loader from importing a managed URL.
        foreach ($Key in $DatabaseKeys) {
            [Environment]::SetEnvironmentVariable($Key, " ", "Process")
        }
    }
    Invoke-Check @("-m", "ruff", "check", ".")
    Invoke-Check @("-m", "ruff", "format", "--check", ".")
    Invoke-Check @("-m", "mypy", "src")
    Invoke-Check @("scripts/quality_contract_types.py", "--check")
    Invoke-Check @("scripts/quality_contract_types.py", "--fixture", "--check")
    Invoke-Check @("scripts/quality_contract_types.py", "--verifier", "--check")
    Invoke-Check @("scripts/quality_contract_types.py", "--review", "--check")
    if ($IncludePostgres) {
        Invoke-Check @("-m", "pytest")
    } else {
        Invoke-Check @("-m", "pytest", "-m", "not postgres")
    }
    if (-not $BackendOnly) {
        if (-not (Test-Path (Join-Path $Root "frontend\node_modules"))) {
            throw "Missing frontend dependencies. Run npm ci in frontend first."
        }
        Push-Location (Join-Path $Root "frontend")
        try {
            & npm.cmd test
            if ($LASTEXITCODE -ne 0) { throw "Frontend tests failed." }
            & npm.cmd run build
            if ($LASTEXITCODE -ne 0) { throw "Frontend build failed." }
        } finally {
            Pop-Location
        }
    }
} finally {
    foreach ($Key in $DatabaseKeys) {
        [Environment]::SetEnvironmentVariable($Key, $SavedDatabaseEnvironment[$Key], "Process")
    }
    Pop-Location
}
