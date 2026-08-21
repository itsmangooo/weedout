import { useQuery } from "@tanstack/react-query";

import { getLandingData } from "../../../api/landing";

export const landingQueryKey = ["landing"];

export function useLandingData() {
  return useQuery({
    queryKey: landingQueryKey,
    queryFn: ({ signal }) => getLandingData({ signal }),
    // The server caches this for five minutes and it is identical for every
    // visitor, so re-fetching it on a remount buys nothing.
    staleTime: 5 * 60_000,
    retry: false,
  });
}
