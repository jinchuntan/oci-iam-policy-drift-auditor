param(
    [switch]$SkipUpload,
    [switch]$RecreateVenv
)

$ErrorActionPreference = "Stop"

function Assert-LastExitCode {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"

$pythonExe = $null
$pythonPrefix = @()

if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonExe = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonExe = "py"
    $pythonPrefix = @("-3")
} else {
    throw "Python was not found. Install Python 3.10+ and ensure 'python' or 'py' is available in PATH."
}

if ($RecreateVenv -and (Test-Path ".venv")) {
    Write-Host "[INFO] Recreating virtual environment..."
    Remove-Item -Recurse -Force ".venv"
}

if (-not (Test-Path $venvPython)) {
    Write-Host "[INFO] Creating virtual environment..."
    & $pythonExe @pythonPrefix -m venv .venv
    Assert-LastExitCode "Virtual environment creation"
}

Write-Host "[INFO] Installing dependencies..."
& $venvPython -m pip install -r requirements.txt
Assert-LastExitCode "Dependency installation"

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
    Copy-Item ".env.example" ".env"
    Write-Host "[INFO] Created .env from .env.example"
}

$args = @("run_audit.py")
if ($SkipUpload) {
    $args += "--skip-upload"
}

Write-Host "[INFO] Running auditor..."
& $venvPython @args
$exitCode = $LASTEXITCODE

if ($exitCode -ne 0 -and -not $SkipUpload) {
    Write-Host "[INFO] Hint: if upload permissions are not ready yet, run with -SkipUpload for local report generation."
}

exit $exitCode
