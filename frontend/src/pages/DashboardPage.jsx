import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { ApiError } from "../api/client";
import { currentUserQueryKey } from "../features/auth/hooks/useCurrentUser";
import { AttentionSummary } from "../features/dashboard/components/AttentionSummary";
import { DashboardEmptyState } from "../features/dashboard/components/DashboardEmptyState";
import { DashboardHeader } from "../features/dashboard/components/DashboardHeader";
import {
  DashboardError,
  DashboardLoading,
} from "../features/dashboard/components/DashboardQueryState";
import { FindingSummary } from "../features/dashboard/components/FindingSummary";
import { ProjectList } from "../features/dashboard/components/ProjectList";
import { useDashboard } from "../features/dashboard/hooks/useDashboard";
import { OpenFindingsSection } from "../features/findings/components/OpenFindingsSection";
import { useOpenFindings } from "../features/findings/hooks/useOpenFindings";
import { useLiveDashboardUpdates } from "../features/live/hooks/useLiveDashboardUpdates";

export function DashboardPage() {
  const dashboard = useDashboard();
  const findings = useOpenFindings({ enabled: dashboard.isSuccess });
  const liveStatus = useLiveDashboardUpdates();
  const queryClient = useQueryClient();

  useEffect(() => {
    const sessionError = [dashboard.error, findings.error].find(
      (error) => error instanceof ApiError && error.status === 401,
    );
    if (sessionError) {
      queryClient.invalidateQueries({ queryKey: currentUserQueryKey });
    }
  }, [dashboard.error, findings.error, queryClient]);

  if (dashboard.isPending) {
    return <DashboardLoading />;
  }

  if (dashboard.isError) {
    return <DashboardError error={dashboard.error} onRetry={() => dashboard.refetch()} />;
  }

  const { projects, summary } = dashboard.data;

  return (
    <div className="dashboard-page">
      <DashboardHeader
        dependencies={summary.dependencies}
        liveStatus={liveStatus}
        projects={summary.projects}
      />
      <AttentionSummary summary={summary} />
      <OpenFindingsSection query={findings} />
      <div className="dashboard-secondary">
        {projects.length > 0 ? <ProjectList projects={projects} /> : <DashboardEmptyState />}
        <FindingSummary summary={summary} />
      </div>
    </div>
  );
}
