import { useQuery } from "@tanstack/react-query";

import { getSystemStatus } from "../../../api/system";

export const systemKeys = {
  all: ["system"],
  status: () => [...systemKeys.all, "status"],
};

export function useSystemStatus() {
  return useQuery({
    queryKey: systemKeys.status(),
    queryFn: ({ signal }) => getSystemStatus({ signal }),
  });
}
