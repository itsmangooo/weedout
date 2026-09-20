import { useEffect } from "react";

import { SITE_NAME } from "./useDocumentTitle";

/**
 * A title the route table cannot know: a doc page's own heading, say.
 *
 * Runs after `useDocumentTitle`, which sets the route's static title on every
 * navigation — so this overwrites it once the content is in hand, and a
 * navigation away resets it. Pass `null` while loading rather than a
 * placeholder: the route's own title is a better thing to show for the half
 * second than the word "Loading" in somebody's tab strip.
 */
export function usePageTitle(title) {
  useEffect(() => {
    if (!title) return;
    document.title = `${title} · ${SITE_NAME}`;
  }, [title]);
}
