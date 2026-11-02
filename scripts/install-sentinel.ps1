<#
.SYNOPSIS
  Install a Sentinel release on a Windows machine with one command (ADR-0013).

.DESCRIPTION
  1. Checks that uv is installed (it is never downloaded by this script).
  2. Verifies the wheel's SHA-256 against the release's SHA256SUMS file. A mismatch stops everything.
  3. Installs the wheel as a uv tool (`sentinel` on PATH). uv fetches Sentinel's pinned dependencies
     from PyPI (pypi.org, files.pythonhosted.org); nothing else is contacted.
  4. Checks for gitleaks and prints the install command if it is missing (never installs it).
  5. Prints the next steps (`sentinel init`, `sentinel doctor`).
  Read this script before running it. Use -CheckOnly to run steps 1, 2 and 4 without installing.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install-sentinel.ps1 -Release dist\0.5.0
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install-sentinel.ps1 -Release \\share\sentinel\0.5.0 -CheckOnly
#>
param(
    [Parameter(Mandatory = $true)][string]$Release,  # folder holding the wheel and SHA256SUMS
    [switch]$CheckOnly
)
$ErrorActionPreference = "Stop"

function Fail($message) { Write-Host "FAILED: $message" -ForegroundColor Red; exit 1 }

# 1. uv
$uv = Get-Command uv -ErrorAction SilentlyContinue
if (-not $uv) {
    Fail "uv is not installed. Install it from the official uv documentation (docs.astral.sh/uv), open a new terminal, then run this again."
}
Write-Host "[OK] uv: $($uv.Source)"

# 2. checksum
$wheels = @(Get-ChildItem -Path $Release -Filter "sentinel-*-py3-none-any.whl" -File)
if ($wheels.Count -ne 1) { Fail "expected exactly one sentinel wheel in $Release, found $($wheels.Count)" }
$wheel = $wheels[0]
$sums = Join-Path $Release "SHA256SUMS"
if (-not (Test-Path $sums)) { Fail "SHA256SUMS not found in $Release (never install an unverified wheel)" }
$expected = $null
foreach ($line in Get-Content $sums) {
    $parts = $line -split "\s+", 2
    if ($parts.Count -eq 2 -and $parts[1].Trim() -eq $wheel.Name) { $expected = $parts[0].ToLower() }
}
if (-not $expected) { Fail "$($wheel.Name) is not listed in SHA256SUMS" }
$actual = (Get-FileHash -Algorithm SHA256 -Path $wheel.FullName).Hash.ToLower()
if ($actual -ne $expected) { Fail "checksum mismatch for $($wheel.Name): the file is not the published release" }
Write-Host "[OK] checksum: $($wheel.Name) matches SHA256SUMS"

# 4. gitleaks (checked before installing so -CheckOnly reports everything)
$gitleaks = Get-Command gitleaks -ErrorAction SilentlyContinue
if (-not $gitleaks) {
    $winget = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Gitleaks*\gitleaks.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($winget) { $gitleaks = $winget }
}
if ($gitleaks) {
    Write-Host "[OK] gitleaks: found"
} else {
    Write-Host "[WARN] gitleaks not found. Install it (for example: winget install Gitleaks.Gitleaks), then open a new terminal." -ForegroundColor Yellow
}

if ($CheckOnly) { Write-Host "Check only: nothing was installed."; exit 0 }

# 3. install
& uv tool install --force $wheel.FullName
if ($LASTEXITCODE -ne 0) { Fail "uv tool install returned $LASTEXITCODE" }
Write-Host "[OK] installed: run 'sentinel --version' in a NEW terminal"

# 5. next steps
Write-Host ""
Write-Host "Next steps, in the project folder you want to protect:"
Write-Host "  sentinel init      (guided setup: config, state folder, GitHub token prompt)"
Write-Host "  sentinel doctor    (checks everything is ready)"
Write-Host "  sentinel run       (first run; Google usage is learned, not alerted, on the first run)"
