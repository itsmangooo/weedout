import type { Finding, FindingsResponse, ScanResponse } from "./types";

export class WeedoutApi {
  constructor(private readonly baseUrl: string) {}

  private async request<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
    const response = await fetch(`${this.baseUrl.replace(/\/$/, "")}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...init.headers,
      },
    });
    const payload = await response.json().catch(() => ({})) as Record<string, unknown>;
    if (!response.ok) {
      const detail = payload.detail as Record<string, unknown> | string | undefined;
      const message = typeof detail === "string" ? detail : String(detail?.message ?? payload.message ?? `Request failed (${response.status})`);
      throw new Error(message);
    }
    return payload as T;
  }

  startAuth(deviceLabel: string) {
    return this.request<{ user_code: string; verification_url: string; device_code: string; expires_in: number; interval: number }>(
      "/api/cli-auth/start", { method: "POST", body: JSON.stringify({ device_label: deviceLabel }) },
    );
  }

  pollAuth(deviceCode: string) {
    return this.request<{ state: string; interval?: number; token?: string; email?: string }>(
      "/api/cli-auth/poll", { method: "POST", body: JSON.stringify({ device_code: deviceCode }) },
    );
  }

  whoAmI(machineToken: string) {
    return this.request<{ email: string }>("/api/account/whoami", {}, machineToken);
  }

  createProject(machineToken: string, body: { name: string; filename: string; content: string }) {
    return this.request<{ project: { id: number; name: string }; key: string }>(
      "/api/account/projects", { method: "POST", body: JSON.stringify({ ...body, scope: "manage" }) }, machineToken,
    );
  }

  deleteProject(machineToken: string, projectId: number) {
    return this.request<{ deleted: boolean }>(`/api/account/projects/${projectId}`, { method: "DELETE" }, machineToken);
  }

  async scan(projectKey: string, filename: string, content: Uint8Array, policy?: Uint8Array): Promise<{ scan: ScanResponse; findings: Finding[] }> {
    const form = new FormData();
    form.append("manifest", new Blob([Uint8Array.from(content).buffer]), filename);
    if (policy) form.append("policy", new Blob([Uint8Array.from(policy).buffer]), ".weedout.yml");
    const scan = await this.request<ScanResponse>("/api/v1/scan", { method: "POST", body: form }, projectKey);
    const result = await this.request<FindingsResponse>("/api/v1/findings?show=open&limit=200", {}, projectKey);
    return { scan, findings: result.findings };
  }
}
