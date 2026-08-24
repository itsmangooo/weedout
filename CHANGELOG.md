# Changelog

What shipped, newest first. Dates are when the work landed on `main`.

This is written for whoever picks the project up next, which for now is us. It
records the *decisions* as well as the features — a line saying a parser was
added is worth much less than one saying why it refuses to guess at a version.

Entries note breaking changes and anything a deployment has to do by hand.

---

## Unreleased

### 2026-08-24

**A plan change reaches a running CLI immediately.** Half of this already
worked and is now pinned; half was broken.

Reading the tier was already live — nothing caches it, so the next request
after an upgrade is served under the new plan, with no window and nothing to
invalidate. `test_plan_changes_take_effect.py` proves that in both directions,
and the downgrade direction matters more: a scanner still applying rules the
account no longer has is reporting on rules nobody is enforcing.

What was stale was the *schedule*. `next_scan_at` is written at the end of a
scan from the cadence in force at that moment, so upgrading a Free account
left it on daily checks until the next daily check happened to run — up to a
full day of having bought the four-hourly cadence and not receiving it. Every
plan change now goes through `plan_service.apply_tier_change`, and a static
test fails if anything assigns `user.tier` anywhere else. A rescheduling only
some of the three call sites did would be worse than none — it would work when
an admin changed a plan by hand and not when a customer actually paid.

**The CLI notices and says so, once.** A CLI cannot be pushed to, so every
machine-facing response now carries a `plan` block and the CLI compares it
against what it last saw:

> Your plan is now Pro. Scans reach the whole dependency tree, and your custom
> rules apply.

- Capabilities, not labels. "You are on Pro" tells somebody what their receipt
  already told them.
- The downgrade sentence says the rules are *kept, not deleted*, because that
  is the obvious fear on reading it.
- Silent on a first run, on a server that sends no plan block, and under
  `--quiet` and `--json`. Absence must never read as a downgrade, and a
  sentence in a JSON stream breaks whatever is parsing it.
- Recorded even when suppressed, or `--quiet` in a cron job leaves the machine
  primed to announce the same change later.
- Nothing is decided from it. Every limit stays server-side.

**Fixed: `weedout rules` listed rules that were not in force.** On a Free
account none of them apply, and the listing said nothing about it — a tidy page
of configuration doing nothing, which is the exact failure this product exists
to avoid, found on our own page about filtering. It now says so above the list
rather than below it, and says the rules are kept rather than deleted, because
that is the obvious next worry.

**The cross-repo docs check now cross-checks.** The list of documented commands
was a second copy of something the CLI repository already knows, which I
flagged when I wrote it. When both repositories are checked out side by side —
exactly when somebody is adding a command and forgetting the docs — it is
verified against the real dispatch switch, and skips otherwise. Verified by
injecting a fake command and watching it fail.

**The CLI documentation caught up with the CLI.** Eight commands shipped this
stretch and none of them appeared anywhere a user would look. `/docs/the-cli`
now covers every command and every flag, with a complete reference table and a
start-to-gated-pipeline walkthrough; `/cli` gained sections on signing a
machine in and on rules that travel with the scan; and
`scanning-your-project`, which still taught the old create-a-key-in-Settings
flow, leads with `weedout auth`.

The parts worth documenting most were the least discoverable: that a committed
`.weedout.yml` is found and uploaded with every scan, with nothing to
configure; that `--profile` is resolved server-side and a wrong name *fails*
the scan rather than quietly running on the defaults; and that the two
credentials cannot do each other's job.

**Guardrails so it cannot fall behind again.** In the CLI repository, three
tests parse the dispatch switch and require every command to appear in
`weedout --help` and in the README, and require the help text not to promise a
command that does not exist. On this side, a test requires every command and
the newer flags to appear on the documentation page.

- One of them immediately caught `TestEveryMenuEntryNamesARealCommand` keeping
  its own copy of the command list — a copy that had been passing since three
  real commands were added to the menu, which is the exact failure it existed
  to catch, one level up.
- The interactive menu gained the setup commands. Someone who turned it on
  with no credential was previously offered nine entries that all fail with
  "no API key" and no way forward.

**Licences chosen.** The server is [AGPL-3.0](LICENSE); the CLI is MIT. Both
repositories said "not yet chosen", which for a security tool is a real
blocker — people will not run an unlicensed binary, and "all rights reserved by
default" is the least useful thing an empty licence field can mean.

- AGPL for the server because the whole product is a hosted service, and a
  permissive licence there would make the code a competitor starter kit. It
  also means the thing deciding which vulnerabilities you hear about is
  readable, which for a tool whose pitch is filtering is not a nice-to-have.
- MIT for the CLI because it runs on other people's machines with their
  credentials in the environment, and should be vendorable without asking.
- AGPL §13 requires a networked service to offer its source to its users. The
  footer now links it — an obligation, not a flourish.

**Terms of service and a privacy policy**, at `/terms` and `/privacy`, written
from what the code actually does rather than from a template.

- Everything requiring a legal or business decision is marked `[[LIKE THIS]]`,
  and a test fails while any remains, so they cannot ship half-finished.
- The privacy claims are *tested against the code*. The policy says there is no
  analytics, and a test fails if any appears. It says a scan reaches no third
  party, and a test fails if the scan path grows an outbound call. A promise
  nothing verifies becomes false the first time somebody adds a snippet "just
  to see the numbers".
- The terms name what the product will miss — unpublished advisories,
  dependencies you did not declare, findings your own rules suppressed, and
  any period when a feed is stale — rather than saying "may not catch
  everything". A limitations section that names cases is a warning somebody
  can act on.

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
