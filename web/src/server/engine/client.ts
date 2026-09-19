import "server-only";

import type { ScanRequest, ScanResult } from "./types";

const engineOrigin = () => process.env.ENGINE_INTERNAL_URL ?? "http://engine:8080";

export async function scan(request: ScanRequest, signal?: AbortSignal): Promise<ScanResult> {
  const response = await fetch(`${engineOrigin()}/v1/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ ...request, schema_version: "v1" }),
    cache: "no-store",
    signal,
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Detection engine returned ${response.status}: ${detail.slice(0, 500)}`);
  }
  const result = (await response.json()) as ScanResult;
  if (result.schema_version !== "v1") throw new Error("Unsupported engine result schema");
  return result;
}

export async function engineHealth(): Promise<{ status: string; version: string }> {
  const response = await fetch(`${engineOrigin()}/healthz`, {
    cache: "no-store",
    signal: AbortSignal.timeout(2_000),
  });
  if (!response.ok) throw new Error(`Detection engine health returned ${response.status}`);
  return (await response.json()) as { status: string; version: string };
}
