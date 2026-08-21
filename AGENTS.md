# Repository agent instructions

## Required shipping workflow

After completing every user-requested coding task, run the required tests. If they pass,
automatically commit the completed task and push it to `origin/main` using `scripts/ship.sh`. If
tests fail, do not commit or push.

Use a concise task-specific commit message:

```bash
./scripts/ship.sh "feat: describe the completed task"
```

When the worktree contains unrelated changes, pass only the paths owned by the completed task so
those unrelated changes remain untouched:

```bash
./scripts/ship.sh "feat: describe the completed task" -- path/to/file another/path
```

The script owns validation, staging, committing, and pushing. Stop and report any validation,
commit, remote-divergence, or push failure. Never force-push, hard-reset, or clean the worktree to
make shipping succeed.
