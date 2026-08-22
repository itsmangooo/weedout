import { useParams } from "react-router";

import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { useDocsIndex, useDocsPage } from "../features/marketing/hooks/useMarketing";
import { relativeTime } from "../lib/time";

export function DocsIndexPage() {
  const query = useDocsIndex();

  return (
    <div className="page-narrow">
      <header className="page-head">
        <p className="section-label">Documentation</p>
        <h1>How it works, in order.</h1>
      </header>

      {query.isPending ? <AsyncLoading>Loading pages…</AsyncLoading> : null}
      {query.isError ? (
        <AsyncError error={query.error} onRetry={() => query.refetch()} />
      ) : null}

      {query.isSuccess ? (
        query.data.pages.length === 0 ? (
          <p className="empty-state">Nothing published yet.</p>
        ) : (
          <ul className="docs-index">
            {query.data.pages.map((page) => (
              <li key={page.slug}>
                <a href={`/docs/${page.slug}`}>
                  <strong>{page.title}</strong>
                  {page.summary ? <span>{page.summary}</span> : null}
                </a>
              </li>
            ))}
          </ul>
        )
      ) : null}
    </div>
  );
}

export function DocsArticlePage() {
  const { slug } = useParams();
  const query = useDocsPage(slug);

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
                Nothing is published at that address. <a href="/docs">All pages</a>.
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
        <a className="docs-nav__home" href="/docs">
          All pages
        </a>
        <ul>
          {pages.map((entry) => (
            <li key={entry.slug}>
              <a aria-current={entry.slug === page.slug ? "page" : undefined} href={`/docs/${entry.slug}`}>
                {entry.title}
              </a>
            </li>
          ))}
        </ul>
      </nav>

      <article className="docs-article">
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
        <div className="prose" dangerouslySetInnerHTML={{ __html: page.body_html }} />
      </article>
    </div>
  );
}
