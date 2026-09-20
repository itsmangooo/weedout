import { QueryClient } from "@tanstack/react-query";

import { ApiError } from "../api/client";

export function shouldRetryRequest(failureCount, error) {
  if (failureCount >= 1) {
    return false;
  }

  if (error instanceof ApiError && error.status >= 400 && error.status < 500) {
    return false;
  }

  return true;
}

export function createQueryClient(overrides = {}) {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: shouldRetryRequest,
        staleTime: 30_000,
        refetchOnWindowFocus: false,
        ...overrides.queries,
      },
      mutations: {
        retry: false,
        ...overrides.mutations,
      },
    },
  });
}

export const queryClient = createQueryClient();
