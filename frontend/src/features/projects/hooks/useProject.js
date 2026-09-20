import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { getProject } from "../../../api/projects";

export function projectQueryKey(id, show = "open") {
  return ["project", String(id), show];
}

export function useProject(id, show = "open") {
  return useQuery({
    queryKey: projectQueryKey(id, show),
    queryFn: ({ signal }) => getProject(id, { show, signal }),
    staleTime: 15_000,
    enabled: Boolean(id),
  });
}

/**
 * Run something that changes a project, then re-read it.
 *
 * Every mutation on this page changes what the page is showing — a rescan
 * changes the findings, a rule changes which of them are filtered, a key
 * changes the key list. Refetching after each one means the screen never
 * disagrees with the server about what was just done.
 */
export function useProjectMutation(id, mutationFn, options = {}) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn,
    ...options,
    onSuccess: async (...args) => {
      await queryClient.invalidateQueries({ queryKey: ["project", String(id)] });
      // The dashboard counts came from the same rows.
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      await options.onSuccess?.(...args);
    },
  });
}
