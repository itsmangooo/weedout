import { useQuery } from "@tanstack/react-query";

import { getFindings } from "../../../api/findings";

export const FINDINGS_LIMIT = 100;

export function findingsQueryKey(show, limit = FINDINGS_LIMIT) {
  return ["findings", show, limit];
}

/**
 * Findings across every project, for one tab.
 *
 * Returns the array rather than the envelope: the meta block exists so the
 * response can be validated, and a caller that had to reach through it would
 * be carrying the transport's shape into the view.
 */
export function useFindings({ show = "open", limit = FINDINGS_LIMIT } = {}) {
  return useQuery({
    queryKey: findingsQueryKey(show, limit),
    queryFn: async ({ signal }) => {
      const payload = await getFindings({ show, limit, signal });
      return payload.data;
    },
    staleTime: 30_000,
  });
}
