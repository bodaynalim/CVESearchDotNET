#Requires -Version 5.1
<#
.SYNOPSIS
    Pre-commit / pre-push validation gate (tickets T09 + T13).

.DESCRIPTION
    Runs the full local verification pipeline:
      1. Editorconfig compliance  (-SkipEditorconfig: omitted; pre-commit hook covers it)
      2. Solution build            (warnings-as-errors per Directory.Build.props)
      3. Test suite
      4. Doc-link check
    Invoked by git hooks (scripts/hooks/pre-push) or manually before commit/push.

.PARAMETER Fix
    Auto-fix editorconfig violations (dotnet format) instead of failing on them.
    Use locally before committing; CI and the pre-push hook always run verify-only.

.PARAMETER SkipTests
    Skip the test suite (fast pass for iterative commits; never use for push).

.PARAMETER SkipEditorconfig
    Skip the editorconfig verify step (the pre-commit hook already runs it).

.EXAMPLE
    ./scripts/preflight.ps1            # full gate
    ./scripts/preflight.ps1 -Fix       # auto-fix formatting, then full gate
    ./scripts/preflight.ps1 -SkipTests # quick pre-commit pass
#>
param(
    [switch]$Fix,
    [switch]$SkipTests,
    [switch]$SkipEditorconfig
)

# Native tools' stderr redirect (2>&1) raises non-terminating errors under PS 5.1 +
# Stop; every native step below is checked via $LASTEXITCODE instead.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Step($name) { Write-Host "`n=== $name ===" -ForegroundColor Cyan }

$failed = @()

# 1. Editorconfig (T13): pre-commit hook is the primary gate; pre-push passes
#    -SkipEditorconfig. Auto-fix only with -Fix (local, pre-commit).
if (-not $SkipEditorconfig) {
    Step 'editorconfig'
    if ($Fix) {
        dotnet format --include '*.cs'
    }
    dotnet format --verify-no-changes --severity warn 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { $failed += 'editorconfig (run preflight -Fix locally)'; Write-Host 'FAILED' -ForegroundColor Red }
    else { Write-Host 'ok' -ForegroundColor Green }
}

# 2. Build solution with warnings-as-errors (T01 policy).
Step 'build'
dotnet build Cve.Net.Search.sln --nologo 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { $failed += 'build'; Write-Host 'FAILED' -ForegroundColor Red }
else { Write-Host 'ok' -ForegroundColor Green }

# 3. Tests.
if (-not $SkipTests) {
    Step 'tests'
    dotnet test Tests/Cve.Net.Search.Tests --nologo 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { $failed += 'tests'; Write-Host 'FAILED' -ForegroundColor Red }
    else { Write-Host 'ok' -ForegroundColor Green }
}

# 4. Doc links.
Step 'doc links'
node scripts/check-docs.js 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { $failed += 'doc links'; Write-Host 'FAILED' -ForegroundColor Red }
else { Write-Host 'ok' -ForegroundColor Green }

Write-Host ''
if ($failed.Count -gt 0) {
    Write-Host "PREFLIGHT FAILED: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host 'PREFLIGHT OK' -ForegroundColor Green
