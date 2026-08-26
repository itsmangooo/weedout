#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/ship.sh "commit message" [-- path ...]

Runs Weedout's required checks, commits the task, and pushes it to origin/main.
Pass explicit paths after -- when the worktree contains unrelated changes.
EOF
}

fail() {
  printf '✗ %s\n' "$1" >&2
  exit 1
}

if [[ $# -lt 1 || -z "${1//[[:space:]]/}" ]]; then
  usage >&2
  fail "a concise commit message is required"
fi

commit_message=$1
shift
task_paths=()

if [[ $# -gt 0 ]]; then
  [[ $1 == "--" ]] || fail "paths must follow --"
  shift
  [[ $# -gt 0 ]] || fail "at least one path must follow --"
  task_paths=("$@")
fi

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || fail "not inside a Git repository"
cd "$repo_root"

[[ $(git branch --show-current) == "main" ]] || fail "shipping is only allowed from main"
git remote get-url origin >/dev/null 2>&1 || fail "the origin remote is not configured"

if ! git diff --cached --quiet; then
  fail "the index already contains staged changes; review and unstage them before shipping"
fi

if [[ -n "${WEEDOUT_PYTHON:-}" ]]; then
  python_bin=$WEEDOUT_PYTHON
elif [[ -x .venv/bin/python ]]; then
  python_bin=.venv/bin/python
elif [[ -x .venv/Scripts/python.exe ]]; then
  python_bin=.venv/Scripts/python.exe
elif command -v python3 >/dev/null 2>&1; then
  python_bin=python3
elif command -v python >/dev/null 2>&1; then
  python_bin=python
else
  fail "Python was not found"
fi

command -v npm >/dev/null 2>&1 || fail "npm was not found"
[[ -f frontend/package-lock.json ]] || fail "frontend/package-lock.json is missing"

printf 'Running Python lint and format checks...\n'
"$python_bin" -m ruff check .
"$python_bin" -m ruff format --check .

printf 'Checking database migrations...\n'
"$python_bin" -m alembic upgrade head
"$python_bin" -m alembic check

printf 'Installing and validating the frontend...\n'
(
  cd frontend
  npm ci
  npm run lint
  npm run test -- --run
  npm run build
)

printf 'Running Python tests...\n'
"$python_bin" -m pytest -q

# Fetch after validation so a branch that changed while checks ran is caught
# before this script creates a local commit.
printf 'Checking origin/main...\n'
git fetch --quiet origin main || fail "could not refresh origin/main; nothing was committed"

local_head=$(git rev-parse HEAD)
remote_head=$(git rev-parse refs/remotes/origin/main)
if [[ $local_head != "$remote_head" ]]; then
  fail "local main and origin/main differ; inspect and reconcile them before shipping"
fi

if [[ ${#task_paths[@]} -gt 0 ]]; then
  git add -A -- "${task_paths[@]}"
else
  git add -A
fi

# Windows commonly has core.filemode=false. Set the repository mode explicitly
# when this script itself is part of the task being shipped.
if git diff --cached --name-only | grep -qx 'scripts/ship.sh'; then
  git update-index --chmod=+x -- scripts/ship.sh
fi

git diff --cached --quiet && fail "no task changes were staged; nothing to commit"

git commit -m "$commit_message"

if ! git push origin HEAD:main; then
  fail "push to origin/main failed; the local commit was kept and history was not rewritten"
fi

printf '✓ tests passed\n'
printf '✓ committed\n'
printf '✓ pushed to origin/main\n'
