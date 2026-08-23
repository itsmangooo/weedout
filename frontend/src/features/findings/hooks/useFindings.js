import { useQuery } from "@tanstack/react-query";

import { getFindings } from "../../../api/findings";

export const FINDINGS_LIMIT = 100;

export function findingsQueryKey(show, limit = FINDINGS_LIMIT) {
  return ["findings", show, limit];
}

/**
 * Findings across every project, for one tab.
 *
 * Returns the findings alongside `historyDays` — how far back this tab reaches
 * on the current plan, or null where nothing is trimmed. The rest of the
 * envelope stays here: it exists so the response can be validated, and a
 * caller reaching through it would carry the transport's shape into the view.
 */
export function useFindings({ show = "open", limit = FINDINGS_LIMIT } = {}) {
  return useQuery({
    queryKey: findingsQueryKey(show, limit),
    queryFn: async ({ signal }) => {
      const payload = await getFindings({ show, limit, signal });
      return { findings: payload.data, historyDays: payload.meta.history_days ?? null };
    },
    staleTime: 30_000,
  });
}
