import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { getProfiles } from "../../../api/profiles";

export const profilesQueryKey = ["profiles"];

export function useProfiles() {
  return useQuery({
    queryKey: profilesQueryKey,
    queryFn: ({ signal }) => getProfiles({ signal }),
    staleTime: 15_000,
  });
}

/**
 * Change a profile, then re-read the list.
 *
 * Every one of these changes what the list is showing — making one the default
 * clears the flag on another, deleting one moves projects onto it. Refetching
 * afterwards keeps the screen from disagreeing with the server about what was
 * just done.
 */
export function useProfilesMutation(mutationFn, options = {}) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn,
    ...options,
    onSuccess: async (...args) => {
      await queryClient.invalidateQueries({ queryKey: profilesQueryKey });
      // The project page shows which profile applies, so it is stale now too.
      await queryClient.invalidateQueries({ queryKey: ["project"] });
      await options.onSuccess?.(...args);
    },
  });
}
