# Changelog

What shipped, newest first. Dates are when the work landed on `main`.

This is written for whoever picks the project up next, which for now is us. It
records the *decisions* as well as the features — a line saying a parser was
added is worth much less than one saying why it refuses to guess at a version.

Entries note breaking changes and anything a deployment has to do by hand.

---

## Unreleased

### 2026-08-24

**Tier gating audited end to end.** One sweep, `tests/test_tier_gating_audit.py`,
walks every Pro capability and asserts the server refuses it for Free — at the
endpoint, not only in the service. Two things keep it honest: it reads the plan
table rather than a hand-maintained list, so a new field cannot be added without
either a gate test or a written reason it needs none; and every Pro-only bullet
on the pricing page has to name a field that enforces it.

- **Fixed: `history_days` was advertised and enforced nowhere.** Pro sold a
  longer archive while every Free account already had an unlimited one. The
  Resolved and Dismissed tabs now stop at the plan's window — 30 days on Free, a
  year on Pro. Open and Filtered are never trimmed: a live vulnerability behind
  a paywall is not a plan limit.
- The Pro bullet said "Full alert history" where the table said 365 days. The
  table was right, so the bullet now says a year.
- The window travels in the response and the tab says how far back it reaches.
  An archive that silently ends 30 days ago reads as lost data.
- `list_findings` takes `tier` keyword-only with no default, so a new caller
  cannot quietly skip the window.
- A static check enforces what `app/tiers.py` has always claimed in its
  docstring: nothing outside the plan table branches on `user.tier is Tier.PRO`.
  Queries over the users table and the billing pages are exempt and say why.
- Every gate helper was mutation-tested — broken one at a time, each one caught.
- The CLI makes no tier decision locally at all, which is the cleanest form of
  "never trust a local flag".

### 2026-08-23

**Rust and JVM support.** Four new manifest formats across two new ecosystems:
`Cargo.lock` (crates.io), and `pom.xml`, `gradle.lockfile` and `build.sbt.lock`
(all Maven — Java, Kotlin and Scala publish to the same registry and OSV files
their advisories under one ecosystem).

- Maven version ordering is implemented properly rather than borrowed from
  semver. `5.3.20.RELEASE` did not parse, and an unparseable version is
  reported as *not affected*, so Spring projects would have scanned clean
  against real advisories.
- Fixed a second ecosystem allowlist in `osv.py` that would have dropped every
  Rust and JVM advisory on import.
- Uploaded POMs now refuse a document type declaration. External entities were
  already refused by expat; internal entity expansion was not, so a
  billion-laughs document parsed and grew.
- `pom.xml` is treated as a declaration, not a lockfile: ranges, undefined
  properties and versions inherited from a parent are named and skipped rather
  than guessed at.
- Scala is supported through `build.sbt.lock` only, which is the one sbt
  artefact stating resolved versions as fact.

**A project watches many manifests.** Previously one file per project, which
made a repository with a backend and a frontend into two projects with two API
keys. Manifests are rows now, and findings record which file they came from.

- One unreadable file no longer blinds the project to the rest — it is reported
  by name alongside the findings that did come back.
- Replacing a manifest with one of a different ecosystem is still refused;
  *adding* one is the new operation.
- **Deployment note:** the migration backfills existing projects. The old
  columns on `tracked_targets` stay as a mirror and are dropped later.

**Documentation corrected.** The CLI stopped being a Python package some time
ago; three places still said `pip install weedout-cli`, including the page new
users are sent to. Added two pages covering the CLI's read and rule commands
and API key scopes, neither of which was documented anywhere.

- Deleted `.github/workflows/publish-cli.yml`, which built a `cli/` directory
  that no longer exists and fired on every `v*` tag.
- **Deployment note:** run `reseed-starter-pages` to pick this up. It discards
  admin-panel edits, so check for any worth keeping first.

**Mobile layout and severity colour.** Tab rows wrapped onto a second line,
leaving the underline under the wrong row. Severity is a tint across the whole
row now rather than a rule down its left edge, which was invisible at the
widths where rows stack.

### 2026-08-22

**One theme across the product**, chosen by the reader: light by default, with
match-system and dark. Each shell used to pin its own palette on a wrapper div,
which is why the dashboard rendered as a dark island on a cream page.

- Status colours are per-palette. The dark set reads at 2.7:1 on cream.
- `theme-boot.js` applies the choice before the first paint.
- The public header is responsive for real — it used to hide every link but the
  last below 40rem, which made `/cli` and `/docs` unreachable on a phone.
- The React app gained a way to sign out. There had not been one.
- Nineteen internal links were still full page loads.

**The React migration finished.** Billing and the admin panel were the last
screens; `app/templates/` now holds only `base.html` and `error.html`, which
must keep working without the bundle because one thing they report is the
bundle being unavailable.

- Admin endpoints live under `/api/internal/admin/*` behind an is-admin check.
  `/admin/*` serves the same shell as everything else and holds no data.
- The typed-email confirmation on delete and the confirmed recipient count on
  send are enforced server-side, not in the dialog.

### 2026-08-21

- The landing page, findings, projects, alerts, settings, pricing, docs,
  contact and the CLI page moved to React.
- Fixed a **2FA bypass**: the endpoint caught an exception `verify_code` never
  raises — it returns a bool — so every wrong code created a session.
- Fixed a 2FA rate limit that used its own bucket, giving an attacker who had
  spent the password allowance a fresh budget for guessing six digits.
- Fixed a password-reset limit that used a literal `5` against a configured
  `10`, and answered `200` when throttled.

---

## Before this file

The project's history before 2026-08-21 is in the git log and in `HANDOFF.md`,
which carries the architectural decisions worth not re-litigating.
