import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { dashboardQueryKey } from "../../dashboard/hooks/useDashboard";
import { openFindingsQueryKey } from "../../findings/hooks/useOpenFindings";

export const LIVE_UPDATES_PATH = "/events";
export const LIVE_UPDATE_EVENT = "stats";

export function useLiveDashboardUpdates() {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState(() =>
    typeof EventSource === "undefined" ? "unavailable" : "connecting",
  );

  useEffect(() => {
    if (typeof EventSource === "undefined") {
      return undefined;
    }

    const source = new EventSource(LIVE_UPDATES_PATH, { withCredentials: true });
    const handleOpen = () => setStatus("live");
    const handleError = () => setStatus("reconnecting");
    const handleStats = () => {
      void queryClient.invalidateQueries({ queryKey: dashboardQueryKey });
      void queryClient.invalidateQueries({ queryKey: openFindingsQueryKey });
    };

    source.addEventListener("open", handleOpen);
    source.addEventListener("error", handleError);
    source.addEventListener(LIVE_UPDATE_EVENT, handleStats);

    return () => {
      source.removeEventListener("open", handleOpen);
      source.removeEventListener("error", handleError);
      source.removeEventListener(LIVE_UPDATE_EVENT, handleStats);
      source.close();
    };
  }, [queryClient]);

  return status;
}
