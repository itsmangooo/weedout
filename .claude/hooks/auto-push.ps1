$ErrorActionPreference = "Stop"

$repoRoot = git rev-parse --show-toplevel
Set-Location $repoRoot

$changes = git status --porcelain

if (-not $changes) {
    Write-Host "No changes."
    exit 0
}

Write-Host "Running tests..."
pytest

if ($LASTEXITCODE -ne 0) {
    Write-Host "Tests failed. Aborting push."
    exit $LASTEXITCODE
}

Write-Host "Running Ruff..."
ruff check .

if ($LASTEXITCODE -ne 0) {
    Write-Host "Ruff failed. Aborting push."
    exit $LASTEXITCODE
}

Write-Host "Staging..."
git add -A

Write-Host "Committing..."
git commit -m "chore: Claude Code update"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Commit failed."
    exit $LASTEXITCODE
}

Write-Host "Pushing..."
git push

if ($LASTEXITCODE -ne 0) {
    Write-Host "Push failed."
    exit $LASTEXITCODE
}

Write-Host "Push complete."