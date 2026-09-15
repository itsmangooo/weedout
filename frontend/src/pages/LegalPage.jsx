import { useQuery } from "@tanstack/react-query";
import { Link, useLocation } from "react-router";

import { getLegalPage } from "../api/legal";
import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";

/**
 * The terms of service and the privacy policy.
 *
 * One component for both, because they are the same shape: a title and a body
 * of prose the server rendered. Two nearly identical files would drift.
 *
 * The markdown is rendered server-side and sanitised there, which is why this
 * sets `dangerouslySetInnerHTML` — the alternative is shipping a markdown
 * parser to every visitor to redo work already done, and the strict CSP means
 * nothing in that HTML can execute regardless.
 */

const SLUGS = {
  "/terms": "terms",
  "/privacy": "privacy",
};

export function LegalPage() {
  const location = useLocation();
  const slug = SLUGS[location.pathname] ?? "terms";

  const query = useQuery({
    queryKey: ["legal", slug],
    queryFn: ({ signal }) => getLegalPage(slug, { signal }),
    // It changes when we deploy, not while somebody is reading it.
    staleTime: Infinity,
    retry: false,
  });

  if (query.isPending) {
    return (
      <div className="legal-page public-editorial">
        <AsyncLoading>Loading…</AsyncLoading>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="legal-page public-editorial">
        <AsyncError error={query.error} onRetry={() => query.refetch()} />
      </div>
    );
  }

  const page = query.data.data;

  return (
    <div className="legal-page public-editorial">
      <header className="page-head">
        <p className="section-label">Weedout / Legal</p>
        <h1>{page.title}</h1><nav className="legal-nav" aria-label="Legal documents"><Link to="/terms" aria-current={slug === "terms" ? "page" : undefined}>Terms of service</Link><Link to="/privacy" aria-current={slug === "privacy" ? "page" : undefined}>Privacy policy</Link></nav>
      </header>

      <article
        className="prose"
        // Rendered and sanitised on the server by the same renderer the
        // documentation uses.
        dangerouslySetInnerHTML={{ __html: page.body_html }}
      />
    </div>
  );
}
