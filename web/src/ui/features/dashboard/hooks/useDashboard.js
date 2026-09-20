import { useQuery } from "@tanstack/react-query";

import { getDashboard } from "../../../api/dashboard";

export const dashboardQueryKey = ["dashboard"];

export function useDashboard() {
  return useQuery({
    queryKey: dashboardQueryKey,
    queryFn: ({ signal }) => getDashboard({ signal }),
    staleTime: 30_000,
  });
}
