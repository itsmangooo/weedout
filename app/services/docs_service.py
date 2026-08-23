"""Documentation page storage and the starter-content seed.

Reads are split by audience rather than filtered at the call site: `list_public`
and `get_published` can only ever return published pages, so a public route
cannot accidentally leak a draft by forgetting a predicate.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger
from app.markdown import extract_summary, slugify
from app.models import DocPage

log = get_logger(__name__)

__all__ = [
    "DocsError",
    "SlugTaken",
    "create_page",
    "get_published",
    "list_public",
    "reseed_starter_pages",
    "seed_starter_pages",
    "starter_page_drift",
    "update_page",
]


class DocsError(Exception):
    """A documentation change was rejected for a stated reason."""


class SlugTaken(DocsError):
    pass


# ---------------------------------------------------------------------------
# Public reads
# ---------------------------------------------------------------------------


async def list_public(db: AsyncSession) -> list[DocPage]:
    """Published pages in reading order. Never returns a draft."""
    return list(
        (
            await db.scalars(
                select(DocPage)
                .where(DocPage.published.is_(True))
                .order_by(DocPage.position, DocPage.title)
            )
        ).all()
    )


async def get_published(db: AsyncSession, slug: str) -> DocPage | None:
    """One published page by slug. Never returns a draft."""
    if not slug:
        return None
    return await db.scalar(select(DocPage).where(DocPage.slug == slug, DocPage.published.is_(True)))


# ---------------------------------------------------------------------------
# Admin reads and writes
# ---------------------------------------------------------------------------


async def list_all(db: AsyncSession) -> list[DocPage]:
    return list((await db.scalars(select(DocPage).order_by(DocPage.position, DocPage.title))).all())


async def get_by_id(db: AsyncSession, page_id: int) -> DocPage | None:
    return await db.get(DocPage, page_id)


async def _assert_slug_free(db: AsyncSession, slug: str, exclude_id: int | None = None) -> None:
    query = select(DocPage.id).where(DocPage.slug == slug)
    if exclude_id is not None:
        query = query.where(DocPage.id != exclude_id)
    if await db.scalar(query) is not None:
        raise SlugTaken(f"A page with the slug “{slug}” already exists.")


async def create_page(
    db: AsyncSession,
    title: str,
    slug: str = "",
    content: str = "",
    summary: str = "",
    published: bool = False,
    position: int | None = None,
) -> DocPage:
    """Create a page, deriving the slug from the title when not given."""
    slug = slugify(slug or title)
    await _assert_slug_free(db, slug)

    if position is None:
        highest = await db.scalar(select(func.max(DocPage.position)))
        position = (highest or 0) + 1

    page = DocPage(
        slug=slug,
        title=title.strip(),
        summary=(summary.strip() or extract_summary(content))[:300],
        content=content,
        published=published,
        position=position,
    )
    db.add(page)

    try:
        await db.flush()
    except IntegrityError as exc:
        # The unique index is the real guard; the pre-check above only produces
        # a better message when there is no race.
        await db.rollback()
        raise SlugTaken(f"A page with the slug “{slug}” already exists.") from exc

    log.info("docs.page_created", slug=page.slug, published=page.published)
    return page


async def update_page(
    db: AsyncSession,
    page: DocPage,
    title: str,
    slug: str,
    content: str,
    summary: str = "",
    published: bool = False,
    position: int | None = None,
) -> DocPage:
    slug = slugify(slug or title)
    await _assert_slug_free(db, slug, exclude_id=page.id)

    page.slug = slug
    page.title = title.strip()
    page.summary = (summary.strip() or extract_summary(content))[:300]
    page.content = content
    page.published = published
    if position is not None:
        page.position = position

    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise SlugTaken(f"A page with the slug “{slug}” already exists.") from exc

    log.info("docs.page_updated", slug=page.slug, published=page.published)
    return page


async def delete_page(db: AsyncSession, page: DocPage) -> None:
    log.info("docs.page_deleted", slug=page.slug)
    await db.delete(page)


# ---------------------------------------------------------------------------
# Starter content
# ---------------------------------------------------------------------------


#: Starter pages that have been replaced, and by what.
#:
#: Seeding is idempotent by slug, so a renamed page would otherwise leave the
#: old one published forever — and the old one is the problem: it is the page
#: that still tells people to authenticate CI with a session cookie. Retiring
#: it explicitly is the only way an existing deployment stops serving it.
SUPERSEDED_SLUGS: dict[str, str] = {
    "uploading-a-lockfile": "scanning-your-project",
    "ci-integration": "gate-your-pipeline",
}


async def retire_superseded_pages(db: AsyncSession) -> int:
    """Unpublish starter pages that a newer page replaces.

    Unpublished rather than deleted. An administrator may have edited the old
    page, and silently destroying their writing to install ours would be the
    wrong trade — a draft is recoverable, a deleted row is not. Its replacement
    must exist first, so a failed seed cannot leave a documentation gap.
    """
    live = {
        slug
        for (slug,) in (
            await db.execute(
                select(DocPage.slug).where(
                    DocPage.slug.in_(SUPERSEDED_SLUGS.values()), DocPage.published.is_(True)
                )
            )
        ).all()
    }

    retired = 0
    for old_slug, replacement in SUPERSEDED_SLUGS.items():
        if replacement not in live:
            continue
        page = await db.scalar(
            select(DocPage).where(DocPage.slug == old_slug, DocPage.published.is_(True))
        )
        if page is None:
            continue
        page.published = False
        retired += 1
        log.info("docs.page_retired", slug=old_slug, replaced_by=replacement)

    if retired:
        await db.flush()
    return retired


async def starter_page_drift(db: AsyncSession) -> list[tuple[str, bool]]:
    """Which starter pages differ from the content this release would seed.

    Seeding is idempotent by slug and deliberately never overwrites, so an
    improvement to the starter copy does not reach a deployment that already has
    the page. That is the right default — an administrator's edits are theirs —
    but it means "the docs were improved" and "the docs on the site improved"
    are two different statements.

    Returns `(slug, exists)` for every page whose stored content is not byte-for
    byte what `STARTER_PAGES` now holds.
    """
    rows = {
        page.slug: page
        for page in (await db.scalars(select(DocPage).where(DocPage.slug.in_(STARTER_SLUGS)))).all()
    }

    drifted: list[tuple[str, bool]] = []
    for page in STARTER_PAGES:
        stored = rows.get(page["slug"])
        if stored is None:
            drifted.append((page["slug"], False))
        elif stored.content.strip() != page["content"].strip():
            drifted.append((page["slug"], True))
    return drifted


async def reseed_starter_pages(db: AsyncSession) -> list[str]:
    """Overwrite the starter pages with this release's content.

    Destructive by design and never called automatically — an administrator may
    have rewritten a page, and silently replacing their words on deploy would be
    worse than shipping slightly stale docs. Exposed as
    `python -m app.manage reseed-docs --force` so the decision is a person's.

    Title, summary and body are replaced; `position` and `published` are left
    alone, because those are ordering and visibility choices rather than copy.
    """
    rows = {
        page.slug: page
        for page in (await db.scalars(select(DocPage).where(DocPage.slug.in_(STARTER_SLUGS)))).all()
    }

    updated: list[str] = []
    for position, page in enumerate(STARTER_PAGES, start=1):
        stored = rows.get(page["slug"])
        if stored is None:
            db.add(
                DocPage(
                    slug=page["slug"],
                    title=page["title"],
                    summary=page["summary"],
                    content=page["content"].strip(),
                    published=True,
                    position=position,
                )
            )
            updated.append(page["slug"])
            continue

        if stored.content.strip() == page["content"].strip():
            continue

        stored.title = page["title"]
        stored.summary = page["summary"]
        stored.content = page["content"].strip()
        updated.append(page["slug"])

    if updated:
        await db.flush()
        log.info("docs.starter_pages_reseeded", pages=len(updated))
    return updated


async def seed_starter_pages(db: AsyncSession) -> int:
    """Create the starter documentation if it is absent.

    Idempotent by slug, so it can run on every boot without duplicating pages
    or overwriting edits the administrator has made to them. Returns the number
    of pages created.
    """
    existing = {
        slug
        for (slug,) in (
            await db.execute(select(DocPage.slug).where(DocPage.slug.in_(STARTER_SLUGS)))
        ).all()
    }

    created = 0
    for position, page in enumerate(STARTER_PAGES, start=1):
        if page["slug"] in existing:
            continue
        db.add(
            DocPage(
                slug=page["slug"],
                title=page["title"],
                summary=page["summary"],
                content=page["content"].strip(),
                published=True,
                position=position,
            )
        )
        created += 1

    if created:
        await db.flush()
        log.info("docs.starter_pages_seeded", created=created)

    await retire_superseded_pages(db)
    return created


# Content is lifted from the README and `docs/reachability.md` rather than
# rewritten, so there is one explanation of the product's behaviour and it does
# not drift between the repository and the site.
STARTER_PAGES: list[dict[str, str]] = [
    {
        "slug": "getting-started",
        "title": "Getting started",
        "summary": "One command from your project directory to your first scan.",
        "content": """
Weedout watches your dependencies and tells you about two kinds of
vulnerability: the ones attackers are exploiting right now, and the ones that
are severe and reachable in the code you actually ship. Everything else is
recorded, counted, and left alone — visible, with the reason attached, but not
in your way.

## 1. Create an account

Sign up with an email address and a password of at least 10 characters. The free
plan tracks one project, checks it daily, and sends email alerts. No card.

## 2. Add the project

Adding a project is what creates the thing an API key can push to. Either:

- **Run the CLI** (below), which creates nothing on its own — so add the project
  in the browser first, then point a key at it. One upload or paste of any
  supported file is enough to get started.
- Or paste the contents on **Add a project** if you would rather not install
  anything yet.

| File | Ecosystem | Versions |
|---|---|---|
| `package-lock.json` | npm | Exact |
| `package.json` | npm | Ranges — resolved to a floor |
| `requirements.txt` | PyPI | Exact when pinned with `==` |
| `go.mod` | Go | Exact |

## 3. Create an API key

**Settings → API keys → Create key.** Pick the project it belongs to.

The key is shown once and stored only as a hash, so copy it now. Each key works
for a single project: one leaked from a build log can only push results for the
repository that build was for, which is why there is no account-wide key.

## 4. Scan from your terminal

```bash
curl -sSL https://weedout.dev/install.sh | sh
export WEEDOUT_API_KEY=wo_...
weedout scan
```

`weedout scan` finds the right file in the current directory, checks it, and
prints what came back:

```
demo-app  ./package-lock.json
412 dependencies scanned · 33 filtered out as noise

  1 exploited  ·  1 critical

  ! systeminformation@5.0.0  CVE-2021-21315  → 5.3.1
  • minimist@1.2.5           CVE-2021-44906  → 1.2.6

  https://weedout.dev/targets/12
```

Two numbers matter on that first line. **Dependencies scanned** is the size of
the problem; **filtered out as noise** is how much of it Weedout decided not to
interrupt you about. The second number is usually much larger than the list
above it — that is the product working, and every filtered advisory is one click
away with its reason.

`weedout init` writes the key to a `.weedout` file so you can stop exporting it.
**Add that file to `.gitignore`** — it holds a credential.

## 5. Wire it into CI

```bash
weedout scan --ci
```

`--ci` exits non-zero when something critical or actively exploited turns up.
Without it, findings are reported and the command still succeeds — so you can
add the step today and decide about gating later. See
*Gate your pipeline* for a complete workflow.

## What happens after that

Your stored manifest is re-checked on a schedule — daily on Free, every four
hours on Pro — so you get alerted about advisories published *after* your last
scan without doing anything.

You get **one digest email per scan**, covering only findings that are new. A
finding you have already seen is never emailed twice, a finding you dismiss
stays dismissed, and a scan you ran yourself never also arrives by email.

Upgrade a dependency past the fix and the next scan marks the finding resolved
rather than deleting it, so the history survives.
""",
    },
    {
        "slug": "scanning-your-project",
        "title": "Scanning your project",
        "summary": "One command from your terminal or your pipeline — and what the file you scan does to the answer.",
        "content": """
There are three ways to get a manifest in front of Weedout. They all reach the
same scanner and produce the same findings; they differ only in how much you
have to remember to do.

## From the command line

```bash
curl -sSL https://weedout.dev/install.sh | sh
weedout scan
```

`weedout scan` looks for a manifest in the current directory, uploads it, and
prints what came back. It needs an API key, which you create in **Settings**
against a specific project:

```bash
export WEEDOUT_API_KEY=wo_...
weedout scan
```

Or write it once per project with `weedout init`, which creates a `.weedout`
file. **Add that file to `.gitignore`** — it holds a credential.

A key belongs to one project. That is deliberate: a key leaked out of a build
log can only push results for the repository that build was for.

## From your pipeline

The same command, with `--ci` so it fails the build on anything critical or
actively exploited. See *Gate your pipeline* for a complete workflow.

## From the web

Upload or paste a manifest on **Add a project**. Nothing to install, and it is
the fastest way to see what Weedout does before wiring anything up. The
trade-off is that the stored manifest is whatever you last uploaded — if your
dependencies changed last week, scheduled scans are checking last week's tree.
The CLI exists to close that gap.

## Which file you scan changes the answer

This matters more than which method you use.

### A lockfile states a fact

`package-lock.json` and `go.mod` record the version that is actually installed.
A finding derived from one is a statement about your real dependency tree.

`weedout scan` prefers a lockfile automatically when it finds one, so running
it after your install step gets you the exact answer without thinking about it.

### A manifest states a range

`"lodash": "^4.17.4"` in `package.json` permits anything from 4.17.4 up to but
not including 5.0.0. The file does not say which of those you have.

Weedout resolves the range to the **lowest version it permits** — the
conservative floor — and marks the finding inexact. Every affected finding then
carries a note saying so:

> Your manifest requests `^4.17.4`, which does not pin an exact version.
> Weedout assumed the lowest version that range allows (4.17.4). Upload your
> lockfile for an exact answer — the version you actually have installed may
> already be patched.

### Why not just guess high?

Guessing the newest permitted version would hide real vulnerabilities in
projects that have not run an update in a while — precisely the projects most
likely to have one. Guessing low without saying so would produce
confident-looking alerts about versions you do not have. Guessing low and
labelling it is the only option that is both safe and honest.

## Specifiers that cannot be resolved

Some entries have no lower bound at all and are skipped rather than guessed:

- npm: `*`, `latest`, `<2.0.0`
- npm source installs: `file:`, `link:`, `git+…`, `workspace:`
- PyPI: an unpinned package name, or `!=` / `<` only
- Go: a module replaced by a local path

Each one is reported as a warning on the project page, so the gap in coverage
is visible rather than silent.

## requirements.txt has no dev/prod split

`package.json` distinguishes `dependencies` from `devDependencies`, and
Weedout uses that to filter heavily. `requirements.txt` has no equivalent, so
everything in it is treated as shipping to production. Splitting your Python
tooling into a separate `requirements-dev.txt` that you simply do not upload
gets you the same benefit.
""",
    },
    {
        "slug": "understanding-severity-tiers",
        "title": "Understanding severity tiers",
        "summary": "The three rules that decide whether a vulnerability interrupts you, and what gets filtered instead.",
        "content": """
Most advisories touching your dependency tree will never be exploited against
you. A tool that reports all of them trains you to ignore it. So a match is
promoted to an alert only when one of three things is true.

## What gets through

### 1. Exploited in the wild

The CVE is in [CISA's Known Exploited Vulnerabilities catalog][kev]. This
overrides everything else — severity, dependency depth, even dev-only scope.
If someone has a working exploit, "it only runs in CI" is thin comfort.

### 2. Critical and shipping

Critical severity in a package that reaches production, direct or transitive.
No evidence of exploitation is required; critical findings in running code
clear the bar on their own.

### 3. High severity in a direct dependency

High severity in a package your project declares itself. Direct dependencies
are the ones you can upgrade today, which is what makes them actionable rather
than merely true.

[kev]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## What gets filtered

Everything else is recorded with the reason attached, and is one tab away:

| Reason | Meaning |
|---|---|
| Dev-only dependency | Build or test tooling that never ships to production |
| Transitive, not exploited | Pulled in indirectly, and nobody is exploiting it |
| Below severity threshold | Moderate, low or unrated, with no exploitation evidence |
| Advisory withdrawn | The publisher retracted it |

Nothing is discarded. The count of advisories Weedout did *not* interrupt you
with is shown on your dashboard, because a claim you cannot inspect is a claim
you have to take on faith.

## How severity is decided

A CVSS v3.1 base score is computed from the vector when the advisory has one,
because it is precise and comparable. When there is no scorable vector, the
publisher's qualitative label is used — folding vocabularies like GitHub's
`MODERATE` and Red Hat's `IMPORTANT` onto the same ladder.

When there is neither, the severity is **unknown**, which sits below every
threshold. An unrated advisory only surfaces if it is on the KEV list.

## What `--ci` fails on

The three rules above decide what appears on your dashboard and in your email.
`weedout scan --ci` uses a **narrower** rule for failing a build: rules 1 and 2
only.

| | Dashboard + email | Fails `--ci` |
|---|---|---|
| Exploited in the wild | yes | **yes** |
| Critical, ships to production | yes | **yes** |
| High severity, direct dependency | yes | no |

High-severity findings are worth reading this week. They are not worth blocking
a deploy at 6pm, and a gate that fires often is a gate people learn to route
around. If your team wants those blocking too, fail on the count yourself — the
scan API returns severity counts as JSON.

## What "reachable" means here

Weedout reads manifests. It does **not** analyse your source code, and it
will never claim to know whether you call the vulnerable function. What it does
know is whether a package ships to production or only builds and tests your
project, and whether you declared it yourself or inherited it. Those two facts
remove most of the noise on their own.

This is also why a lockfile is worth more than a manifest here: the same two
facts are only as good as the versions they are applied to. See
*Scanning your project*.
""",
    },
    {
        "slug": "gate-your-pipeline",
        "title": "Gate your pipeline",
        "summary": "Fail a build on what is actually exploited or actually critical — and nothing else.",
        "content": """
Weedout re-checks your stored manifest on a schedule, so alerts arrive whether
or not you do anything. Wiring it into CI buys two things on top of that: the
stored manifest tracks the code you just merged, and a genuinely dangerous
dependency can stop a release before it ships.

## The whole thing

```yaml
# .github/workflows/security.yml
name: Security

on:
  push:
    branches: [main]
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      # Only for the pull request comment. Without it the scan still runs and
      # the step summary is still written.
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm

      # Install first, so the lockfile reflects what actually resolved.
      - run: npm ci

      - name: Scan dependencies
        uses: itsmangooo/weedout-cli@v1
        with:
          api-key: ${{ secrets.WEEDOUT_API_KEY }}
          fail-on: critical

  # Both of these wait for the scan. `needs:` is the entire mechanism: without
  # it the jobs run in parallel and the deploy ships regardless of what the scan
  # found, which is a notification, not a gate.
  build:
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
      - run: npm ci
      - run: npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

  deploy:
    needs: [security-scan, build]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/
      - run: echo "Deploying"
```

Three things about that shape are deliberate.

**`needs:` is the gate.** A failing job that nothing depends on is a red cross
next to a successful deploy. Every job that produces or ships an artefact has to
name `security-scan`, or it is not gated.

**`deploy` lists both.** `needs: [security-scan, build]` is not redundant with
`build`'s own `needs`. GitHub does propagate skips through the chain, but naming
the scan directly means the dependency survives someone later reorganising
`build` — and reading `deploy` tells you what it waited for without tracing the
graph.

**The scan runs after `npm ci`.** Before the install, the lockfile is whatever
was committed; after it, it is what actually resolved. Scanning the resolved
tree is the difference between an exact answer and an assumed one.

## What the action gives you

Beyond running the scan, it writes a summary into the Actions run — tier
counts, the findings that are blocking, and the fix version for each — and
posts the same summary as a pull request comment, updating that one comment
rather than adding a new one on every push.

It also publishes outputs, so a later step can react to the numbers:

```yaml
- uses: itsmangooo/weedout-cli@v1
  id: weedout
  with:
    api-key: ${{ secrets.WEEDOUT_API_KEY }}

- if: always() && steps.weedout.outputs.exploited-count != '0'
  run: echo "Exploited in the wild: ${{ steps.weedout.outputs.exploited-count }}"
```

`critical-count`, `high-count`, `exploited-count`, `blocking-count`,
`filtered-count` and `findings-url` are all available, on a failed run as well
as a passing one.

## On any other CI system

The action is a wrapper around one command. GitLab, CircleCI, Jenkins and a
bare shell all run the same thing:

```bash
curl -sSL https://weedout.dev/install.sh | sh
weedout scan --ci
```

On Windows, `irm https://weedout.dev/install.ps1 | iex`. Both scripts verify
the published checksum before installing anything.

The key comes from `WEEDOUT_API_KEY` in the environment. Set it as a secret in
your CI provider — never in the repository, and never as a command-line
argument, which shows up in process listings and some runner logs.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The scan ran. Nothing blocking. |
| `1` | The scan ran and found something critical or actively exploited. |
| `2` | The scan did **not** run — bad key, unreachable service, no manifest found. |

The gap between 1 and 2 is worth respecting. A pipeline that treats every
non-zero exit as "vulnerabilities found" will eventually treat an expired API
key as a security finding, and somebody will fix it by deleting the step. `2`
means you learned nothing, which is a different problem with a different fix.

Note that `weedout scan` **without** `--ci` always exits `0` unless something
went wrong. Start there: adding a security tool should not be the thing that
breaks the build first.

## Making it stick

A failing check is only a gate if it cannot be clicked past. On GitHub, go to
**Settings → Branches → Add branch protection rule** for your default branch,
enable **Require status checks to pass before merging**, and select
`security-scan`.

Until you do, the check is advice. After you do, it is a rule.

## What should actually block

By default `--ci` fails on two things and no more: critical severity, and
confirmed exploitation from CISA's KEV catalog. High-severity findings appear
in the output and on your dashboard but do not fail the build.

If that is too permissive for what you ship, raise the floor:

```yaml
- uses: itsmangooo/weedout-cli@v1
  with:
    api-key: ${{ secrets.WEEDOUT_API_KEY }}
    fail-on: high
```

or `weedout scan --ci --fail-on high` directly. Confirmed exploitation fails at
either setting — a vulnerability with working public exploitation is not a
medium problem because a scoring rubric said so.

There is no `medium` or `low`. A gate that fires on everything is a gate
somebody disables, and a disabled gate reports nothing at all.

That line is deliberate and it is on the strict side of what we would suggest
by default. Weedout is a watchlist first — the premise of the product is that
most advisories touching your tree are not worth stopping work for, and a gate
that fires often is a gate people learn to bypass. If your team finds even this
too noisy, run without `--ci` for a few weeks and look at what it would have
blocked before turning it on.

## Where to run it

On pull requests and on merges to your default branch. Scanning every branch
push adds little: feature branches produce dependency trees that mostly never
ship.

Each project is limited to 60 scans an hour, which is far above what a normal
pipeline needs and low enough that a misconfigured loop cannot run away.
""",
    },
    {
        "slug": "the-cli",
        "title": "The CLI, command by command",
        "summary": (
            "Scan, read and change what gets reported \u2014 without opening the dashboard."
        ),
        "content": """
The CLI is a single static binary with no dependencies. It does three kinds of
thing: it scans, it reads what the dashboard would show you, and it changes
what gets reported. Which of those a given key can do is decided by the key's
scope \u2014 see [API keys and scopes](/docs/api-keys-and-scopes).

## Install

```bash
curl -sSL https://weedout.dev/install.sh | sh
```

On Windows, `irm https://weedout.dev/install.ps1 | iex`. Both scripts verify
the checksum of the release they download. There is no package manager step and
nothing lands in your project's dependency tree.

## Point it at a project

The key is the configuration. It identifies the project, so there is nothing
else to set up.

### On your own machine

```bash
weedout auth
```

It prints an eight-character code and opens your browser. Check that the page
shows the same code, approve, and you are done \u2014 nothing is copied, pasted or
printed. The credential goes straight to a file only your account can read.

Then, in a project directory:

```bash
weedout create              # a new project, with a key saved for this directory
weedout link                # or connect to one you already have
weedout scan                # from now on this just works here
```

### In CI

A pipeline has no browser, so it gets a project key in an environment variable:

```bash
export WEEDOUT_API_KEY=wo_...
```

Create that key on the project's settings page, or with `weedout key regenerate`
from a linked directory. Use a **scan**-scoped key: it is the narrowest thing
that works, and it is the one that will end up in a build log.

`weedout init` writes the same key to a `.weedout` file, which is the local
equivalent for a machine where an environment variable is awkward. **Do not
commit it.**

`.weedout` is not `.weedout.yml`. The first holds a credential and stays out of
the repository; the second holds your scan rules and belongs in it. See
[Scan rules](/docs/scan-rules) and [Two credentials](#two-credentials) below.

## Scanning

```bash
weedout scan              # report, always exit 0
weedout scan --ci         # exit 1 if something blocking is found
weedout scan --json       # the same result, machine-readable
weedout scan --quiet      # print nothing; the exit code is the answer
```

`--fail-on high` widens the gate from the default `critical`. Confirmed
exploitation fails at either setting.

## Reading, without the dashboard

These need a key with **read** access. Everything the web dashboard shows is
available here, which is the point: if you would rather live in a terminal, you
never have to open a browser after setup.

| Command | Answers |
|---|---|
| `weedout status` | Counts, when it was last checked, when it is next due. |
| `weedout findings` | What is open, with fixes and how each one got in. |
| `weedout history` | Recent scans, and how the count has moved. |
| `weedout supply-chain` | Signals about the packages themselves. |

Every one of them takes `--json`, so they compose with `jq` and with whatever
your team already runs.

## Two credentials

There are two kinds, they do different things, and neither can do the other's
job. That is deliberate: it means losing one is a smaller problem than losing a
single credential that did everything.

| | Machine credential | Project key |
|---|---|---|
| From | `weedout auth` | `weedout create`, `weedout link`, or the project's settings page |
| Belongs to | your account | one project |
| Lives | in your OS config directory, on your machine | in `WEEDOUT_API_KEY`, or a `.weedout` file |
| Can | create projects, list them, issue keys | scan, read findings, edit rules \u2014 depending on scope |
| Cannot | read a single finding | create a project or reach another one |

A key taken from a CI runner reaches the one project that runner builds. A
credential taken from a laptop can make projects and keys, and cannot read what
you are vulnerable to. Both are worth revoking quickly; neither is everything.

### Which machines are signed in

Account settings lists them, with what each one called itself and when it was
last used. Sign one out there and it stops working immediately \u2014 `weedout
logout` on the machine itself only forgets the local copy.

Machine credentials expire after 180 days. A developer credential that never
expires is one that outlives the laptop it was issued to.

### One machine, many checkouts

`weedout link` records the project against the directory's absolute path, in
one file rather than a dotfile per repository. Eight checkouts need one
`weedout auth` and eight `weedout link`s, and then `weedout scan` works in all
of them with nothing else set up.

```bash
weedout whoami        # which account, and what this directory is linked to
weedout unlink        # forget this directory
weedout logout        # forget the account credential (--all drops project keys)
```

Where a key comes from, strongest first:

1. `--api-key` on the command line
2. `WEEDOUT_API_KEY` in the environment
3. `api_key` in a `.weedout` file, searched from here upward
4. the key `weedout link` stored for this directory

The environment beating both files is the one that matters. CI injects secrets
as environment variables, and a `.weedout` accidentally committed to a
repository must never quietly override the key a pipeline was configured with
\u2014 a build that authenticates as the wrong account is worse than one that
fails to authenticate at all.

### Rotating a key

```bash
weedout key regenerate
```

Issues a new key for the linked project and saves it. The old one keeps working
until you revoke it in the project's settings, so a rotation that fails
part-way leaves you with something that works rather than nothing.

## Changing what gets reported

These need a key with **manage** access.

```bash
weedout rules                                   # what is in force
weedout rules ignore GHSA-xxxx --reason "..."   # stop reporting one advisory
weedout rules ignore --package "@acme/*" --reason "..."
                                                # stop reporting a family
weedout rules unignore GHSA-xxxx                # report it again
```

A reason is required, and it is recorded. Six months from now the question is
never "is this ignored" \u2014 it is "who decided that, and why".

Quote the glob. An unquoted `@acme/*` is expanded by your shell against the
working directory before Weedout ever sees it.

Full syntax, and the rules that cannot be silenced, in
[Scan rules](/docs/scan-rules).

## Everything else

```bash
weedout version           # what you are running
weedout update            # install the newest release
weedout --interactive     # turn the menu on for this installation
```

`--interactive` is a preference, saved next to the binary, not a flag you pass
every time.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | It ran. Nothing blocking. |
| `1` | It ran and found something blocking. `--ci` only. |
| `2` | It did **not** run \u2014 bad key, unreachable service, or no manifest. |

The gap between `1` and `2` is the one that matters. A pipeline treating every
non-zero exit as "vulnerabilities found" will eventually treat an expired key as
a security finding, and somebody will fix that by deleting the step.
""",
    },
    {
        "slug": "scan-rules",
        "title": "Scan rules",
        "summary": "Thresholds, ignores and .weedout.yml \u2014 and the two things a rule cannot silence.",
        "content": """
Weedout's defaults are deliberate, and most projects should leave them alone.
Scan rules exist for the cases where your codebase knows something the advisory
feed does not.

Rules are part of the **Pro** plan. They are enforced when a scan runs, not when
they are saved, so a subscription that lapses stops applying them without
deleting anything you configured.

## Four places a rule can live

| Where | Good for |
|---|---|
| `.weedout.yml` in your repository | Anything a reviewer should see. This is the default answer. |
| The project's settings page | One-off decisions, and anything you would rather not publish. |
| `weedout rules` from the CLI | The same as the settings page, from a terminal. |
| A **rule profile** on your account | One standard shared by every project. See below. |

They stack in that order, strongest first: the file beats the project's
settings, which beat the profile, which beats the built-in defaults.

**The file wins.** A rule about a codebase belongs beside the codebase: it goes
through review, it moves with a branch, and `git log` answers "who silenced this
and when" without a separate audit trail. A settings page that could quietly
override the file would make a CI run depend on something invisible from the
checkout.

**The profile sits underneath the project**, because that is what a shared
standard is: a baseline every project starts from, which any one project may
override where it needs something different. A profile that beat the project's
own settings would make the per-project controls decorative.

Precedence is per setting, not all-or-nothing. A file that only sets thresholds
does not wipe out ignores you added in the interface \u2014 it says nothing about
them, and silence is not an instruction. Ignores from every layer are unioned
for the same reason: no layer un-ignores what another ignored, and the only way
to stop ignoring something is to remove the rule that says so.

## `.weedout.yml`

Commit this one. It is not `.weedout`, which holds your API key and must stay
out of the repository.

```yaml
severity:
  direct: high        # a dependency you declared
  transitive: critical  # something further down the tree
  dev: critical       # something that never ships

epss:
  alert_above: 0.5    # exploitation probability, 0 to 1

ignore:
  - cve: CVE-2021-23337
    reason: Not reachable from any entry point we ship.

  - package: "@acme/*"
    reason: Our own packages, mirrored under a name that also exists publicly.
```

Every key is optional. A file that sets one thing changes one thing.

### Severity floors

`low`, `medium`, `high` or `critical`. A finding below the floor for its
position is recorded and filed rather than raised.

`dev` is the odd one out: leaving it unset does not mean "use the default", it
means dev-only findings stay filed the way they always have. Setting it says
something more precise \u2014 tell me about build tooling, but only when it is
this bad. A critical in a linter is not a critical in a web framework, and it is
not nothing either.

### Ignoring one advisory

```yaml
ignore:
  - cve: CVE-2021-23337
    reason: The affected code path is not reachable from our entry points.
```

Matched against every alias the advisory carries, so ignoring the CVE also
covers the GHSA that aliases it. A rule that only worked if you happened to name
the same identifier the feed did would be a rule that quietly stopped working.

### Ignoring a family of packages

```yaml
ignore:
  - package: "@acme/*"
    reason: Internal packages mirrored under a name that also exists publicly.
```

For the case an advisory id cannot serve. A private package sharing a name with
a public one matches advisories written about somebody else's code, and there is
no fixed list of ids to enumerate \u2014 the next advisory that other project
publishes is a new one.

`*` matches any run of characters and `?` matches exactly one. Matching is
case-insensitive. These are globs, not regular expressions: every pattern is
evaluated against every dependency on every scan, and a regular expression is
where that becomes a way to hang the scanner on a crafted package name.

A pattern that matches every package is refused. That is not a filter, it is the
scan switched off, and a project is switched off by deactivating it \u2014 which
says so on the dashboard, where a rule that happens to match everything does
not.

### The reason is required

An entry without one is skipped, and the scan says so. Not because we can check
the reason, but because writing one is the difference between a decision and a
reflex, and because six months later it is the only thing that makes the entry
reviewable.

## Rule profiles

A team with eight services usually wants the same floors on all of them, a
looser set on the internal tools, and something stricter on the one facing the
internet. Configuring that project by project means eight copies that drift, and
changing the standard means eight edits.

A profile is a policy document \u2014 the same YAML as above \u2014 stored on your
account under a name. Create them in **Settings**.

```
Production           account default
  Everything customer-facing.

Internal tools
  Dashboards and the admin console.
```

### Which one applies

Most specific first:

1. `--profile production` on the scan command.
2. `profile: production` in the repository's `.weedout.yml`.
3. The profile chosen on the project's settings page.
4. Your account default.
5. None, and the built-in rules apply.

The first two are the exception to "the file wins", and deliberately. The file
wins on **rules**; *which profile to use* is chosen at the moment a scan is
asked for, and a flag typed there is the more local statement.

### Names

`--profile` matches a normalised form, so you do not have to reproduce
capitalisation or spacing. "Production APIs", `production-apis` and
`PRODUCTION_APIS` all reach the same profile. The exact string is shown beside
the name in Settings, and `weedout profiles` prints it.

Renaming a profile changes what `--profile` matches, so a pipeline naming the
old one starts failing. That is a refusal, not a silent fall back \u2014 see
below.

### A name that does not exist fails the scan

```
$ weedout scan --profile prodcution
There is no rule profile called 'prodcution' on this account.
$ echo $?
2
```

Exit 2, meaning the scan did not run, rather than a scan on the built-in rules
reporting success. A pipeline that believes it is enforcing a stricter standard
than it is would find out at the worst possible moment.

The name is resolved on the server against your account's own profiles. Nothing
a pipeline sends decides which rules apply \u2014 it only asks.

### From the terminal

```bash
weedout profiles                       # what exists, and what applies here
weedout scan --profile production      # scan under a named one
```

`weedout profiles` needs a key with **read** access. Knowing which rule sets
exist is part of understanding a result; a CI key that can see the name it is
meant to pass fails with a useful message rather than a puzzle.

### Deleting one

Any project using it moves to the account default. Nothing is refused: a profile
you cannot delete until you have visited every project using it is a profile
people work around by emptying its document instead, which leaves a rule set
that looks configured and does nothing.

## What a rule cannot silence

Two things are reported however you have configured the project.

**Known exploitation.** An ignore is a judgement about a risk, made at a moment
in time. A CISA KEV listing is new information about that same risk, so the
judgement is out of date rather than binding. The finding is raised, and the
rule is marked on the settings page as having been set aside \u2014 whoever wrote
"ignore this, it is disputed" needs to see that it is now being exploited.

**Malware.** An advisory saying a package *is* malicious is not the risk your
rule was a judgement about. This matters most for package globs: `@acme/*` is
exactly the pattern somebody writes for their private scope, and if an attacker
publishes a typosquat into that scope, the rule written to silence registry-name
collisions must not be what hides it.

## Nothing is deleted

An ignored finding stays on the **Filtered** tab with the rule named as the
reason. "What am I not being told about?" has to have an answer, and a filter
you cannot audit is a filter you have to take on faith.

## A broken file fails loudly, in the safe direction

If `.weedout.yml` cannot be parsed, the whole file is discarded and the scan
runs on the defaults. Every ignore in it stops applying and every raised
threshold reverts, so the failure mode is extra alerts \u2014 never silence. The
error is reported on the project page and by `weedout rules`.

Unknown keys are skipped with a warning rather than refused: a file mentioning
something this version does not know about was written for a later one, and
breaking a repository on every upgrade would be the wrong trade.
""",
    },
    {
        "slug": "api-keys-and-scopes",
        "title": "API keys and scopes",
        "summary": "What each kind of key can do, and why a CI key should be the weakest one.",
        "content": """
Every key belongs to **one project** and carries **one scope**. Create them in
Settings, on the project they are for.

A key is shown once, when you create it. We store only a hash, so we cannot
show it to you again and neither can anyone who reads our database.

## The three scopes

| Scope | Can | Cannot |
|---|---|---|
| `scan` | Push a scan. | Read findings, change rules. |
| `read` | Push a scan, read findings, history and supply-chain signals. | Change rules. |
| `manage` | All of it, including ignoring advisories. | \u2014 |

`scan` is the default, and it is what every key created before scopes existed
already was.

## Why the split exists

A CI key lives in an environment variable. Anyone who can read a build log, open
a pull request against your workflow, or compromise a runner can take it.

If that key could add an ignore rule, whoever took it could **silence the alert
for the vulnerability they are about to exploit** \u2014 and the dashboard would
show a clean project while it happened. That is the whole reason a scan key
cannot change what gets reported.

So: put a `scan` key in CI. Keep `read` for a laptop or a dashboard script.
Create a `manage` key when you need one and revoke it when you are done.

## What a rejected key looks like

Every failure \u2014 missing, malformed, unknown, revoked, or belonging to a
suspended account \u2014 returns the same `401`. Distinguishing "revoked" from
"never existed" would tell anyone holding a list of leaked strings which ones
were once real.

A key with the *wrong scope* is different: that returns `403`, because the
credential is genuine and saying so leaks nothing. A `401` there would send a
pipeline into a retry loop over a permission problem no retry can fix.

## Rotating

Revoke the old key, create a new one, update the secret. There is no grace
period and no partial state: a revoked key stops working on the next request.
""",
    },
]

STARTER_SLUGS = [page["slug"] for page in STARTER_PAGES]
