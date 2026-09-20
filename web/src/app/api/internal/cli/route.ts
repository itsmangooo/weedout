import { publicResponse } from "@/server/http/responses";

export async function GET() {
  return publicResponse({ data: {
    repo: "itsmangooo/weedout-cli",
    status: "work_in_progress",
    release: { available: false, version: null, published_at: null, notes_url: null, assets: [] },
    go_module: { available: false, module_path: null, go_version: null, dependencies: [] },
  } }, 300);
}
