import "server-only";

import { marked } from "marked";
import sanitizeHtml from "sanitize-html";

export function renderMarkdown(source: string) {
  const rendered = marked.parse(source, { async: false }) as string;
  return sanitizeHtml(rendered, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(["h1", "h2", "h3", "h4", "pre", "code"]),
    allowedAttributes: { a: ["href", "title", "rel"], code: ["class"] },
    allowedSchemes: ["http", "https", "mailto"],
    transformTags: { a: sanitizeHtml.simpleTransform("a", { rel: "noopener noreferrer" }, true) },
  });
}
