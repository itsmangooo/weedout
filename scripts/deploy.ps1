# Commit and push both Weedout repositories.
#
#   pwsh scripts/deploy.ps1 -Message "what changed"
#
# Checks before it pushes, in this order, and stops at the first failure:
#
#   1. no secrets about to be staged
#   2. the Go CLI builds, vets, formats and tests clean
#   3. the web app lints and its whole suite passes
#
# The secret check is first on purpose. Everything else costs a few minutes of
# CI; a key pushed to a public repository costs a rotation and cannot be
# un-published, so it is worth failing on before anything else runs.
#
# Nothing here force-pushes and nothing rewrites history. If a push is
# rejected, that means someone else moved the branch and the fix is to look,
# not to overwrite.
#
# Divergence is checked before anything is committed. Doing it afterwards
# leaves a commit behind on every rejected run, and three of those with the
# same message and the same tree look like a real conflict when they are not.

[CmdletBinding()]
param(
    [string]$Message = "",
    # The CLI repository's own subject. Falls back to -Message, but the run
    # stops and asks when both repositories are dirty: one message describing
    # two unrelated changes is how install.ps1 got committed under a commit
    # about the contact form.
    [string]$CliMessage = "",
    # Skip the test suites. For a docs-only change where the wait is not
    # buying anything.
    [switch]$SkipTests,
    # Show what would happen without committing or pushing.
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$AppRepo = "A:\Projects\Weedout"
$CliRepo = "A:\Projects\weedout-cli"

function Write-Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }
function Write-Ok($text) { Write-Host "  ok  $text" -ForegroundColor Green }
function Write-Warn($text) { Write-Host "  !   $text" -ForegroundColor Yellow }
function Fail($text) { Write-Host "`nSTOPPED: $text" -ForegroundColor Red; exit 1 }

function Invoke-Checked($label, $command) {
    Write-Host "  $label..." -NoNewline
    $output = & $command 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host ($output | Out-String)
        Fail "$label failed."
    }
    Write-Host " ok" -ForegroundColor Green
    return $output
}

# ---------------------------------------------------------------------------
# 1. Secrets
#
# `git add .` stages everything not ignored. These repositories contain live
# credentials in .env and .env.prod, which are gitignored  -  but a gitignore
# that stops matching is silent, so this checks what git would actually stage
# rather than trusting the rules.
# ---------------------------------------------------------------------------

$SecretPattern = '(^|[\\/])\.env($|\.)|secrets?\.(ya?ml|json|toml)$|\.pem$|\.p12$|id_rsa'

function Test-NoSecrets($repo) {
    Push-Location $repo
    try {
        # --dry-run tells us exactly what `git add .` would pick up.
        # git prints `add 'path'` per file. Single-quoted pattern because a
        # double-quoted one ending in `'$"` is a PowerShell parse error  -  the
        # `$"` is read as the start of an expansion.
        $staged = git add --dry-run --all . 2>&1 |
            ForEach-Object { if ($_ -match '^add ''(.+)''$') { $Matches[1] } }

        $suspects = $staged | Where-Object { $_ -match $SecretPattern }
        if ($suspects) {
            Write-Host ""
            $suspects | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
            Fail "files that look like secrets would be committed in $repo."
        }

        # A key in the *content* of an otherwise innocent file.
        #
        # The prefix alone is not enough to go on: `wo_` matched
        # `test_the_two_act_now_tiers_are_filled_not_tinted` on the first run.
        # A real key is base64url and always carries both an uppercase letter
        # and a digit; a snake_case identifier carries neither. The lookaheads
        # are what separate them, and they keep this specific enough to be
        # worth failing a deploy over.
        $KeyPattern = 'wo_(?=[A-Za-z0-9_-]{30,})(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{30,}|whsec_(?=[A-Za-z0-9]*[A-Z])[A-Za-z0-9]{20,}'

        $tracked = $staged | Where-Object { Test-Path $_ -PathType Leaf }
        foreach ($file in $tracked) {
            if ($file -match '\.(png|jpg|jpeg|gif|svg|ico|woff2?|exe|gz|zip)$') { continue }
            $hit = Select-String -Path $file -Pattern $KeyPattern `
                -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hit) {
                Write-Host ""
                Write-Host "      $file line $($hit.LineNumber)" -ForegroundColor Red
                Fail "what looks like a live key is about to be committed."
            }
        }
        Write-Ok "$repo  -  nothing secret staged"
    }
    finally { Pop-Location }
}

# ---------------------------------------------------------------------------
# 2. Is there anything to do
# ---------------------------------------------------------------------------

function Get-Dirty($repo) {
    Push-Location $repo
    try { return (git status --porcelain) } finally { Pop-Location }
}

# ---------------------------------------------------------------------------
# 3. Commit and push
# ---------------------------------------------------------------------------

function Test-UpToDate($repo, $label) {
    # Called before anything is committed. A branch that is behind its remote
    # cannot fast-forward, and finding that out after the commit is what
    # leaves duplicate commits lying around for the next run to trip over.
    Push-Location $repo
    try {
        $branch = (git rev-parse --abbrev-ref HEAD).Trim()
        # No 2>&1: redirecting a native command's stderr under PowerShell 5.1
        # wraps each line in an ErrorRecord, which $ErrorActionPreference=Stop
        # then treats as fatal even when git exited 0.
        git fetch origin $branch --quiet | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "$label  -  could not reach origin; pushing may fail"
            return
        }
        $behind = (git rev-list --count "HEAD..origin/$branch").Trim()
        if ($behind -ne "0") {
            Fail ("$label is $behind commit(s) behind origin/$branch. " +
                  "Pull and look at what changed before committing on top.")
        }
    }
    finally { Pop-Location }
}

function Publish($repo, $label, $commitMessage) {
    Push-Location $repo
    try {
        $branch = (git rev-parse --abbrev-ref HEAD).Trim()

        if ($DryRun) {
            Write-Warn "$label  -  dry run, not committing"
            git status --short
            return
        }

        git add --all .
        if ($LASTEXITCODE -ne 0) { Fail "git add failed in $repo" }

        # --- The trailers this project uses on every commit. ---
        $full = @"
$commitMessage

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01HzRFwbfa4yPNNk1C3bcNYU
"@

        # Written to a file rather than piped. Piping to `git commit -F -`
        # under PowerShell 5.1 prepends a UTF-8 BOM, which git keeps -- the
        # first commit made this way had an invisible character in front of
        # "feat:". UTF8Encoding($false) is the no-BOM constructor; the built-in
        # "utf8" encoding name is the one that emits it.
        $messageFile = [System.IO.Path]::GetTempFileName()
        try {
            [System.IO.File]::WriteAllText(
                $messageFile, $full, (New-Object System.Text.UTF8Encoding($false)))
            git commit -F $messageFile
            if ($LASTEXITCODE -ne 0) { Fail "git commit failed in $repo" }
        }
        finally { Remove-Item $messageFile -ErrorAction SilentlyContinue }

        Write-Host "  pushing $branch..." -NoNewline
        git push origin $branch
        if ($LASTEXITCODE -ne 0) {
            Write-Host ""
            Fail "push rejected in $repo. Someone else moved $branch  -  look before overwriting."
        }
        Write-Host " ok" -ForegroundColor Green

        $sha = (git rev-parse --short HEAD).Trim()
        Write-Ok "$label pushed as $sha"
    }
    finally { Pop-Location }
}

# ===========================================================================

Write-Host "Weedout deploy" -ForegroundColor White

foreach ($repo in @($AppRepo, $CliRepo)) {
    if (-not (Test-Path $repo)) { Fail "no repository at $repo" }
}

$appDirty = Get-Dirty $AppRepo
$cliDirty = Get-Dirty $CliRepo

if (-not $appDirty -and -not $cliDirty) {
    Write-Host "`nNothing to commit in either repository." -ForegroundColor Yellow
    exit 0
}

if (-not $Message) {
    Fail "pass -Message with what changed. An auto-generated message is a commit nobody can read later."
}

Write-Step "Checking for secrets"
if ($appDirty) { Test-NoSecrets $AppRepo }
if ($cliDirty) { Test-NoSecrets $CliRepo }

if (-not $SkipTests) {
    if ($cliDirty) {
        Write-Step "Go CLI"
        Push-Location $CliRepo
        try {
            Invoke-Checked "build" { go build ./... } | Out-Null
            Invoke-Checked "vet" { go vet ./... } | Out-Null

            Write-Host "  gofmt..." -NoNewline
            $unformatted = gofmt -l .
            if ($unformatted) {
                Write-Host ""
                Write-Host ($unformatted | Out-String) -ForegroundColor Red
                Fail "these files are not gofmt formatted."
            }
            Write-Host " ok" -ForegroundColor Green

            Invoke-Checked "test" { go test ./... } | Out-Null
        }
        finally { Pop-Location }
    }

    if ($appDirty) {
        Write-Step "Web app"
        Push-Location $AppRepo
        try {
            $python = ".\.venv\Scripts\python.exe"
            if (-not (Test-Path $python)) { Fail "no virtualenv at $AppRepo\.venv" }

            Invoke-Checked "ruff format" { & $python -m ruff format --check . } | Out-Null
            Invoke-Checked "ruff check" { & $python -m ruff check . } | Out-Null
            Invoke-Checked "pytest" { & $python -m pytest -q } | Out-Null
        }
        finally { Pop-Location }
    }
}
else {
    Write-Warn "tests skipped by request"
}

Write-Step "Publishing"

if ($cliDirty -and $appDirty -and -not $CliMessage) {
    Fail ("Both repositories have changes. Pass -CliMessage so the CLI commit " +
          "says what changed in the CLI, rather than inheriting the web app's " +
          "subject line.")
}

# Both checked before either is committed, so a stale branch stops the run
# while there is still nothing to unpick.
if ($cliDirty) { Test-UpToDate $CliRepo "weedout-cli" }
if ($appDirty) { Test-UpToDate $AppRepo "weedout" }

if ($cliDirty) {
    Publish $CliRepo "weedout-cli" $(if ($CliMessage) { $CliMessage } else { $Message })
}
if ($appDirty) { Publish $AppRepo "weedout" $Message }

Write-Host "`nDone." -ForegroundColor Green
