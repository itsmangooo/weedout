import { useQuery, useQueryClient } from "@tanstack/react-query";

import { getCurrentUser } from "../../../api/auth";

export const currentUserQueryKey = ["auth", "current-user"];

export function useCurrentUser() {
  return useQuery({
    queryKey: currentUserQueryKey,
    queryFn: ({ signal }) => getCurrentUser({ signal }),
    staleTime: 60_000,
  });
}

/**
 * Re-read who the browser is, and wait for the answer.
 *
 * Needed after anything that changes the session. The cached identity is stale
 * the instant a cookie is set or cleared, and navigating on stale data means
 * the destination's own guard bounces the user straight back — signing in and
 * landing on the sign-in page, which reads as a failure.
 *
 * `refetchQueries` rather than `invalidateQueries` because the caller needs to
 * navigate *after* the new answer is in hand; invalidation alone resolves
 * before the refetch completes.
 */
export function useAuthRefresh() {
  const queryClient = useQueryClient();

  return () => queryClient.refetchQueries({ queryKey: currentUserQueryKey });
}
