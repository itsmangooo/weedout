import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { getSettings } from "../../../api/settings";

export const settingsQueryKey = ["settings"];

export function useSettings() {
  return useQuery({
    queryKey: settingsQueryKey,
    queryFn: ({ signal }) => getSettings({ signal }),
    staleTime: 15_000,
  });
}

/**
 * Run something that changes the account, then re-read it.
 *
 * Everything on this page changes what the page is showing — a revoked session
 * leaves the list, a new key joins it, turning two-factor on changes what the
 * section offers. Refetching after each one keeps the screen from disagreeing
 * with the server about what was just done.
 */
export function useSettingsMutation(mutationFn, options = {}) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn,
    ...options,
    onSuccess: async (...args) => {
      await queryClient.invalidateQueries({ queryKey: settingsQueryKey });
      await options.onSuccess?.(...args);
    },
  });
}
