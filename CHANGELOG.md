# Changelog

What shipped, newest first. Dates are when the work landed on `main`.

This is written for whoever picks the project up next, which for now is us. It
records the *decisions* as well as the features — a line saying a parser was
added is worth much less than one saying why it refuses to guess at a version.

Entries note breaking changes and anything a deployment has to do by hand.

---

## Unreleased

### 2026-08-24

**An account can say it is a company.** A label, not a capability — the plan,
the limits and everything the account may do are identical. It exists so
invoices and the interface can say the right thing, and so "are you a company?"
is asked once rather than inferred from an email domain.

It is **not** a team. One login, no members, no roles. Teams need invitations,
per-member audit, and an answer to what happens to a project when the person
who made it leaves; calling this a team would promise all of that.

**A trust section on the landing page, gated twice.** A company appears only
when it asked *and* somebody here checked the name was theirs to give.

- Consent, because for a security product naming a customer says publicly that
  they scan their dependencies with us. That is theirs to disclose, not ours.
  Off by default, one click to withdraw, no review on the way out.
- Approval, because consent alone would let anybody sign up as a well-known
  company and land on our front page — impersonation with our own marketing as
  the vehicle. Approving and revoking are audited.
- Renaming an approved company withdraws the approval. We checked that one
  name was theirs; the next is a different claim.
- Names, not logos. Three that are real beat twenty that are decoration, and
  the section disappears rather than padding itself.
- **Deployment note:** the migration is additive. Every existing account is
  personal, opted out, unapproved.

**A public status page at /status.** It opens by admitting what it cannot tell
you, which is the only honest way to run one from inside the thing it reports
on: if the service is down, this page is down with it. It is not an uptime
monitor and does not pretend to be.

What it is for is the failure nothing else catches. An outage is loud; a stale
advisory feed is not — scans keep running, the dashboard keeps rendering, and
every user of that ecosystem is quietly told they are clean.

- Freshness per ecosystem, not one aggregate line. A green "OSV" row while the
  Go export has been failing for a week is the same lie in a nicer font.
- Record counts, because a feed can succeed and still be broken.
- Error strings never reach it. They are written for us and name paths and
  hostnames; a visitor can act on "this feed is behind", not on a traceback.
  Whether *our* backups ran is filtered out for the same reason.
- Adoption numbers are off by default (`STATUS_SHOW_ADOPTION`). On a product
  with three accounts they undersell, and on a page whose whole purpose is
  being trusted, a figure chosen to flatter would poison everything above it.
  A switch somebody throws, not a rounding rule nobody can audit.
- Cached for a minute. This is the page people load when they think something
  is wrong, which is when the database can least afford six aggregates per
  visitor.

**A footer**, which the site did not have. Without one the status page would
have been reachable only by typing the URL — and the people who need it are the
ones already wondering whether something is broken. It links only to pages that
exist: a dead `/terms` link is worse than no link.

**`weedout auth`: a credential reaches a laptop without passing through one.**
What it replaces is worse than it looks — "create a key in Settings, copy it,
paste it into your terminal" puts a live credential through a clipboard, a
scrollback, a shell history, and often a chat window where somebody asked a
colleague for help. Every one of those outlives the moment.

The CLI prints a short code and a URL and waits. A signed-in browser shows the
same code; you approve; the token arrives over the poll's own TLS connection
and goes straight to a 0600 file. It is never printed, not even with
`--verbose`.

- Two secrets doing different jobs. The code a person reads is short and
  therefore guessable, so it can only *confirm* a request that already exists.
  The 256-bit device code is what collects the token, and only the waiting
  process has ever held it.
- Approval is session-authenticated and CSRF-protected. Without CSRF, a page
  somebody visits while signed in could hand an attacker a credential.
- Single use in both directions, rate limited at both ends, ten-minute window.
- The approval page shows the machine's label and address next to a plain
  statement that neither was verified. A page that just says "Approve?" trains
  people to click yes.
- Signed-in machines are listed in account settings and can be revoked. A login
  you can grant and cannot see is a login you cannot take back.

**A second credential type, kept apart from the first.** A project key pushes
scans and reads findings for one project, and is what sits in CI. A machine
credential creates projects and mints keys, and cannot read a single finding.
Separate tables, separate namespace, separate dependency — neither can be
widened into the other by getting a boolean wrong, and the route guardrail now
asserts that in both directions.

- `weedout create`, `weedout link`, `weedout key regenerate`: a project key is
  issued to the process that asked for it. Nobody copies one out of a browser.
- Rotation mints before it revokes, so a failure part-way leaves a working
  credential rather than none.

**A global config, so a developer with eight checkouts needs no setup.**
`~/.config/weedout/config.json` and its per-OS equivalents, 0600, written
atomically. Holds the machine credential and a map from repository path to
project key. Resolution order: `--api-key`, then `WEEDOUT_API_KEY`, then a
repository `.weedout`, then the global map. The environment still beats every
file, because a stray `.weedout` in a checkout must never override what a
pipeline was configured with.

- The `.weedout` dotfile is unchanged and still the right answer for CI and
  shared machines. The two are for different jobs and the docs say which.
- **Deployment note:** the migration is additive and inert until somebody runs
  `weedout auth`.

**Fixed: `.weedout.yml` was documented, parsed, gated as Pro — and never
uploaded by anything.** `/api/v1/scan` has accepted a `policy` multipart field
the whole time and no client sent one, so every rule anybody wrote in a
repository was dead text. The CLI now finds it from the manifest's directory
upward and sends it, which is also what makes `profile:` work.

- `.weedout.yaml` is accepted too. Insisting on one spelling of a YAML
  extension is a way to have people write a config that silently does nothing.
- A read failure is not fatal: the scan runs on the defaults, which can only
  produce more alerts than intended.
- `--verbose` names the file that applied, or says none was found.
- `weedout rules` told people to run `weedout init` to create one. `init`
  writes `.weedout`, which holds a credential.

**Rule profiles.** A named set of scan rules on the account, so a team with
eight services sets its standard once instead of configuring eight projects
identically and watching them drift. A profile is a `.weedout.yml` document
under a name — one syntax, one parser, and a working file can be lifted into a
profile by copying it.

- Precedence is now four layers: the repository file, the project's own
  settings, the profile, the built-in defaults. The profile sits *underneath*
  the project, because a shared standard is a baseline to override, not a
  ceiling — a profile that beat per-project settings would make those controls
  decorative.
- One account default, enforced by a partial unique index rather than
  application care, so "which rules apply when nobody said" has exactly one
  answer even under concurrent writes.
- `--profile production`, `profile:` in the repository file, or a choice on the
  project. **Resolved server-side**: a name that does not exist fails the scan
  with exit 2. A pipeline that believes it is enforcing a stricter standard
  than it is would find out at the worst possible moment.
- An unparseable profile is refused at save time, unlike the repository file —
  we can refuse this one, because somebody is standing there.
- A profile cannot name another profile.
- `weedout profiles` lists them and says which applies here. Read scope.
- **Deployment note:** the migration is additive and inert until a profile
  exists.

**An ignore rule can name a package, not only an advisory.** `@acme/*` covers
every advisory written about anything in that scope, including the ones
published after the rule. The case ignoring-by-id could not serve: a private
package mirrored under a name that also exists on the public registry matches
advisories about somebody else's code, and there is no fixed list of ids to
enumerate.

- Globs, not regular expressions. Every pattern is evaluated against every
  dependency on every scan, from input a user supplies, and a regular
  expression is where that becomes a way to hang the scanner on a crafted
  package name. `@acme/*` is also what people want to write.
- Available in `.weedout.yml` (`- package: "@acme/*"`), on the settings page,
  and as `weedout rules ignore --package`.
- A pattern matching every package is refused. That is the scan switched off,
  not a filter, and a project is switched off by deactivating it — which says
  so on the dashboard, where a rule that matches everything does not.
- Known exploitation and malware are still reported. This matters more here
  than for advisory rules: `@acme/*` is exactly the pattern somebody writes for
  their private scope, and a typosquat published into that scope must not be
  hidden by the rule written for registry-name collisions.
- **Deployment note:** the migration is additive. Existing rows default to
  `advisory` and mean what they always meant.

**Scan rules are documented.** A Pro feature with no page anywhere: the
`.weedout.yml` syntax existed only in the parser's docstring. New
`/docs/scan-rules` covers the three sources and their precedence, every key,
and the two things a rule cannot silence.

- Corrected three places claiming `weedout init` writes `.weedout.yml`. It
  writes `.weedout`, which holds a credential. `.weedout.yml` is the policy
  file and belongs in the repository — telling people not to commit the file
  that should be committed was the worst version of that mistake.

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
