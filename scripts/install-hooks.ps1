# Activates the repo's git hooks (tickets T09 + T13): pre-commit, commit-msg, and pre-push.
# Run once per clone/worktree:  ./scripts/install-hooks.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
git -C $root config core.hooksPath scripts/hooks
Write-Host "Hooks installed: core.hooksPath = scripts/hooks (pre-commit, commit-msg, pre-push)" -ForegroundColor Green
