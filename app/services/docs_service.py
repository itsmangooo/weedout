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
    "seed_starter_pages",
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
        "summary": "Add your first project and read your first scan, in about a minute.",
        "content": """
Weedout watches your dependency manifests and tells you about two kinds of
vulnerability: the ones attackers are actively exploiting right now, and the
ones that are severe and reachable in the code you actually ship. Everything
else is recorded, counted, and left alone.

## 1. Create an account

Sign up with an email address and a password of at least 10 characters. The
free plan tracks one project, checks it daily, and sends email alerts. No card
is required.

## 2. Add a project

Go to **Add a project** and either upload a manifest file or paste its
contents. Four formats are supported:

| File | Ecosystem | Versions |
|---|---|---|
| `package.json` | npm | Ranges — resolved to a floor |
| `package-lock.json` | npm | Exact |
| `requirements.txt` | PyPI | Exact when pinned with `==` |
| `go.mod` | Go | Exact |

**Scan a lockfile if you have one.** See *Scanning your project* for why it
matters, and for how to run the same scan from your terminal or your pipeline
with one command instead of a browser.

## 3. Read the first scan

The scan runs immediately — you do not wait for a schedule. When it finishes
you will see two numbers:

- **Open** — findings that cleared the alerting bar and are worth your time.
- **Filtered** — advisories that genuinely affect your versions but were
  deliberately not surfaced, each with the reason attached.

The filtered number is usually the larger one. That is the point of the
product, and the tab is there so you can check the reasoning rather than take
it on trust.

## 4. What happens next

Your project is re-checked on a schedule — daily on Free, every four hours on
Pro. You get **one digest email per scan**, covering only findings that are
new. A finding you have already seen is never emailed twice, and a finding you
dismiss stays dismissed.

If you upgrade a dependency past the fix, the next scan marks the finding
resolved rather than deleting it, so the history survives.
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
pip install weedout-cli
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

## What "reachable" means here

Weedout reads manifests. It does **not** analyse your source code, and it
will never claim to know whether you call the vulnerable function. What it does
know is whether a package ships to production or only builds and tests your
project, and whether you declared it yourself or inherited it. Those two facts
remove most of the noise on their own.
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
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm

      # Install first, so the lockfile reflects what actually resolved.
      - run: npm ci

      - name: Scan dependencies
        uses: weedout/weedout@v1
        with:
          api-key: ${{ secrets.WEEDOUT_API_KEY }}

  deploy:
    needs: security-scan
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying"
```

`needs: security-scan` is the part that makes this a gate rather than a
notification. Without it the two jobs run in parallel and the deploy goes out
regardless of what the scan found.

## Without the action

The action is a thin wrapper. Any CI system runs the same two commands:

```bash
pip install weedout-cli
weedout scan --ci
```

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

`--ci` fails on two things and no more: critical severity, and confirmed
exploitation from CISA's KEV catalog. High-severity findings appear in the
output and on your dashboard but do not fail the build.

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
]

STARTER_SLUGS = [page["slug"] for page in STARTER_PAGES]
