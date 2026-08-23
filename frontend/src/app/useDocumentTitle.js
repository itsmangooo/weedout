import { useEffect } from "react";
import { useMatches } from "react-router";

/**
 * The tab title, from the route table.
 *
 * Every page shared one title until now — the built `index.html` said
 * "Dashboard · Weedout", so that is what a visitor saw on the marketing page,
 * on the pricing page and on every admin screen. It is the label on a
 * bookmark, a browser-history entry and a shared tab, so it is worth being
 * right.
 *
 * Titles are declared on the routes rather than inside each page: a page that
 * forgets to set one would otherwise inherit whatever the last page set, which
 * is a stale title rather than a missing one.
 */

export const SITE_NAME = "Weedout";

export function useDocumentTitle() {
  const matches = useMatches();

  useEffect(() => {
    // The deepest match that names one wins: /admin/users is a page in its own
    // right, not "Admin".
    const named = [...matches].reverse().find((match) => match.handle?.title);
    const title = named?.handle?.title;

    document.title = title ? `${title} · ${SITE_NAME}` : SITE_NAME;
  }, [matches]);
}
