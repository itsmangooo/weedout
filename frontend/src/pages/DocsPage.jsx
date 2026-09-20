import { useState } from "react";
import { ArrowUpRight } from "@phosphor-icons/react/ArrowUpRight";
import { Link, useParams } from "react-router";

import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { useDocsIndex, useDocsPage } from "../features/marketing/hooks/useMarketing";
import { usePageTitle } from "../app/usePageTitle";
import { relativeTime } from "../lib/time";

export function DocsIndexPage() {
  const query = useDocsIndex();
  const [search, setSearch] = useState("");

  return (
    <div className="docs-directory public-editorial">
      <header className="page-head">
        <p className="section-label">Documentation</p>
        <h1>How it works, in order.</h1>
      </header>

      <div className="docs-directory__body"><label className="search-field">Find a guide<input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search documentation" /></label>
      {query.isPending ? <AsyncLoading>Loading pages…</AsyncLoading> : null}
      {query.isError ? (
        <AsyncError error={query.error} onRetry={() => query.refetch()} />
      ) : null}

      {query.isSuccess ? (
        query.data.pages.length === 0 ? (
          <p className="empty-state">Nothing published yet.</p>
        ) : (
          <ul className="docs-index">
            {query.data.pages.filter((page) => `${page.title} ${page.summary ?? ""}`.toLowerCase().includes(search.toLowerCase())).map((page, index) => (
              <li key={page.slug}>
                <Link to={`/docs/${page.slug}`}>
                  <span className="docs-index__number">{String(index + 1).padStart(2,"0")}</span><div><strong>{page.title}</strong>
                  {page.summary ? <span>{page.summary}</span> : null}</div><ArrowUpRight size={18} aria-hidden="true" />
                </Link>
              </li>
            ))}
          </ul>
        )
      ) : null}
      {query.isSuccess && query.data.pages.length > 0 && !query.data.pages.some((page) => `${page.title} ${page.summary ?? ""}`.toLowerCase().includes(search.toLowerCase())) && <p className="empty-state">No guides match this search.</p>}</div>
    </div>
  );
}

export function DocsArticlePage() {
  const { slug } = useParams();
  const query = useDocsPage(slug);

  // The route table cannot know this one, and "Docs" on every article makes a
  // row of open tabs useless.
  usePageTitle(query.data?.data?.title);

  if (query.isPending) {
    return (
      <div className="page-narrow">
        <AsyncLoading>Loading…</AsyncLoading>
      </div>
    );
  }

  if (query.isError) {
    // A draft and a page that never existed answer identically, which is what
    // makes "unpublished" mean anything — so this says the same for both.
    const missing = query.error?.status === 404;
    return (
      <div className="page-narrow">
        <header className="page-head">
          <h1>{missing ? "No such page" : "Could not load that page"}</h1>
          <p className="page-head__lede">
            {missing ? (
              <>
                Nothing is published at that address. <Link to="/docs">All pages</Link>.
              </>
            ) : (
              query.error.message
            )}
          </p>
        </header>
      </div>
    );
  }

  const { data: page, pages } = query.data;

  return (
    <div className="docs-layout">
      <nav aria-label="Documentation" className="docs-nav">
        <Link className="docs-nav__home" to="/docs">
          All pages
        </Link>
        <ul>
          {pages.map((entry) => (
            <li key={entry.slug}>
              <Link
                aria-current={entry.slug === page.slug ? "page" : undefined}
                to={`/docs/${entry.slug}`}
              >
                {entry.title}
              </Link>
            </li>
          ))}
        </ul>
      </nav>

      <article className="docs-article"><p className="eyebrow">Documentation / field guide</p>
        <h1>{page.title}</h1>
        {page.updated_at ? (
          <p className="docs-article__meta">Updated {relativeTime(page.updated_at)}</p>
        ) : null}
        {/* Server-rendered markdown. Not sanitised — stronger than that: the
            parser runs with html:false, so raw tags in the source are escaped
            into visible text and never become markup. Verified: a <script> in
            a docs page renders as the literal characters. Shipping a markdown
            parser to every visitor to redo work already done would be a
            strange trade, and the guarantee has to live somewhere trusted. */}
        <div className="prose" dangerouslySetInnerHTML={{ __html: page.body_html }} /><footer className="article-footer"><Link to="/docs">All documentation</Link><Link to="/contact">Something unclear? Tell us →</Link></footer>
      </article>
    </div>
  );
}
