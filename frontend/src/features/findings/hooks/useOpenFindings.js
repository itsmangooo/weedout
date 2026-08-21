import { useQuery } from "@tanstack/react-query";

import { getFindings } from "../../../api/findings";

export const OPEN_FINDINGS_LIMIT = 25;
export const openFindingsQueryKey = ["findings", "open", OPEN_FINDINGS_LIMIT];

export function useOpenFindings({ enabled = true } = {}) {
  return useQuery({
    queryKey: openFindingsQueryKey,
    queryFn: ({ signal }) =>
      getFindings({ show: "open", limit: OPEN_FINDINGS_LIMIT, signal }),
    enabled,
    staleTime: 30_000,
  });
}
