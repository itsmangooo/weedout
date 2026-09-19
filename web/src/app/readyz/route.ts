import { engineHealth } from "@/server/engine/client";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const engine = await engineHealth();
    return Response.json(
      { status: "ready", service: "weedout-web", engine },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch {
    return Response.json(
      { status: "not_ready", service: "weedout-web", engine: "unavailable" },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }
}
