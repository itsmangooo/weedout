import { db } from "@/server/db/client";
import { renderMarkdown } from "@/server/content/markdown";
import { publicResponse } from "@/server/http/responses";
export async function GET(_request: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const rows = await db()<Array<{ slug: string; title: string; summary: string; content: string; updated_at: Date }>>`SELECT slug, title, summary, content, updated_at FROM doc_pages WHERE slug = ${slug} AND published = true LIMIT 1`;
  if (!rows.length) return publicResponse({ error: { code: "NOT_FOUND", message: "That page doesn't exist." } }, 120, { status: 404 });
  const pages = await db()<Array<{ slug: string; title: string }>>`SELECT slug, title FROM doc_pages WHERE published = true ORDER BY position, title`;
  const page = rows[0];
  return publicResponse({ data: { slug: page.slug, title: page.title, summary: page.summary, body_html: renderMarkdown(page.content), updated_at: page.updated_at }, pages }, 120);
}
