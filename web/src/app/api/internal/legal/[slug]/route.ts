import { readFile } from "node:fs/promises";
import path from "node:path";
import { publicResponse } from "@/server/http/responses";
import { renderMarkdown } from "@/server/content/markdown";

const pages = { terms: "Terms of service", privacy: "Privacy policy" } as const;
export async function GET(_request: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  if (!(slug in pages)) return publicResponse({ error: { code: "NOT_FOUND", message: "That page doesn't exist." } }, 600, { status: 404 });
  const body = await readFile(path.join(process.cwd(), "content", `${slug}.md`), "utf8");
  return publicResponse({ data: { slug, title: pages[slug as keyof typeof pages], body_html: renderMarkdown(body) } }, 600);
}
