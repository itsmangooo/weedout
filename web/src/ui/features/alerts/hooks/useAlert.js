import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { getAlert, setAlertStatus } from "../../../api/findings";

export function alertQueryKey(id) {
  return ["alert", String(id)];
}

export function useAlert(id) {
  return useQuery({
    queryKey: alertQueryKey(id),
    queryFn: ({ signal }) => getAlert(id, { signal }),
    enabled: Boolean(id),
    staleTime: 15_000,
  });
}

export function useAlertStatus(id) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input) => setAlertStatus(id, input),
    onSuccess: async () => {
      // Dismissing changes which tab this finding is on, and the counts every
      // other screen shows. Leaving those stale would have the dashboard
      // disagree with the page the user is looking at.
      await queryClient.invalidateQueries({ queryKey: alertQueryKey(id) });
      await queryClient.invalidateQueries({ queryKey: ["findings"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      await queryClient.invalidateQueries({ queryKey: ["project"] });
    },
  });
}
