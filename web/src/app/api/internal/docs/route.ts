import { db } from "@/server/db/client";
import { publicResponse } from "@/server/http/responses";
export async function GET() {
  const pages = await db()<Array<{ slug: string; title: string; summary: string }>>`SELECT slug, title, summary FROM doc_pages WHERE published = true ORDER BY position, title`;
  return publicResponse({ data: { pages } }, 120);
}
