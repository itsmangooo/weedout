import { useQuery } from "@tanstack/react-query";

import { getCliFacts, getDocsIndex, getDocsPage, getPricing } from "../../../api/marketing";

/** Public and identical for every visitor, so a long stale time costs nothing. */
const PUBLIC_STALE_MS = 5 * 60_000;

export function usePricing() {
  return useQuery({
    queryKey: ["pricing"],
    queryFn: ({ signal }) => getPricing({ signal }),
    staleTime: PUBLIC_STALE_MS,
  });
}

export function useCliFacts() {
  return useQuery({
    queryKey: ["cli-facts"],
    queryFn: ({ signal }) => getCliFacts({ signal }),
    staleTime: PUBLIC_STALE_MS,
  });
}

export function useDocsIndex() {
  return useQuery({
    queryKey: ["docs"],
    queryFn: ({ signal }) => getDocsIndex({ signal }),
    staleTime: PUBLIC_STALE_MS,
  });
}

export function useDocsPage(slug) {
  return useQuery({
    queryKey: ["docs", slug],
    queryFn: ({ signal }) => getDocsPage(slug, { signal }),
    enabled: Boolean(slug),
    staleTime: PUBLIC_STALE_MS,
    retry: false,
  });
}
