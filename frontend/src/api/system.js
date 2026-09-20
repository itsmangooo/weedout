import { api } from "./client";

export function getSystemStatus({ signal } = {}) {
  return api("/healthz", { signal });
}
