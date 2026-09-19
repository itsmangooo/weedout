export type EngineFinding = {
  id: string;
  verdict: "filtered" | "actionable" | "blocking";
  dependency: { name: string; version: string };
  fixed_version?: string;
  explanation: string;
};

// An IDE should call its authenticated product/backend adapter. The adapter
// calls the private engine; browser/editor clients do not receive mirror access.
export async function findingsFromBackend(endpoint: string): Promise<EngineFinding[]> {
  const response = await fetch(endpoint, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`scan failed: ${response.status}`);
  return (await response.json()).findings;
}
