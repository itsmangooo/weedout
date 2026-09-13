import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router";
import { ArrowRight, Plus, Radio } from "lucide-react";
import { ApiError } from "../api/client";
import { currentUserQueryKey } from "../features/auth/hooks/useCurrentUser";
import { PageFrame, DataMetric } from "../components/ui/PageFrame";
import { DashboardEmptyState } from "../features/dashboard/components/DashboardEmptyState";
import { DashboardError, DashboardLoading } from "../features/dashboard/components/DashboardQueryState";
import { ProjectsDirectory } from "../features/dashboard/components/ProjectsDirectory";
import { useDashboard } from "../features/dashboard/hooks/useDashboard";
import { OpenFindingsSection } from "../features/findings/components/OpenFindingsSection";
import { useOpenFindings } from "../features/findings/hooks/useOpenFindings";
import { useLiveDashboardUpdates } from "../features/live/hooks/useLiveDashboardUpdates";

export function DashboardPage() {
  const dashboard = useDashboard();
  const findings = useOpenFindings({ enabled: dashboard.isSuccess });
  const live = useLiveDashboardUpdates();
  const client = useQueryClient();
  const [params] = useSearchParams();
  const directory = params.get("view") === "projects";
  useEffect(() => {
    if ([dashboard.error, findings.error].some((error) => error instanceof ApiError && error.status === 401)) client.invalidateQueries({ queryKey: currentUserQueryKey });
  }, [dashboard.error, findings.error, client]);
  if (dashboard.isPending) return <DashboardLoading />;
  if (dashboard.isError) return <DashboardError error={dashboard.error} onRetry={() => dashboard.refetch()} />;
  const { projects, summary } = dashboard.data;
  const attention = summary.exploited_findings > 0 ? "Exploited in the wild" : summary.open_findings > 0 ? "Open findings need a decision" : "No open findings";
  return <PageFrame className="dashboard-page" eyebrow="Workspace / dependency intelligence" title={directory ? "Projects" : "Security overview"} description={directory ? "Every project, its latest check, and the findings that need attention." : "A working view of your dependencies. Start with the findings that need a decision."} actions={<Link className="button button--primary" to="/targets/new"><Plus size={16} aria-hidden="true" />Add project</Link>}>
    {!directory && <><div className="workspace-live" role="status"><Radio size={13} aria-hidden="true" />{live === "live" ? "Live updates" : live === "reconnecting" ? "Reconnecting" : live === "unavailable" ? "Live updates unavailable" : "Connecting live updates"}</div><dl className="metric-strip"><DataMetric label="Open findings" value={summary.open_findings} tone={summary.open_findings ? "warning" : "neutral"} /><DataMetric label="Critical" value={summary.critical_findings} tone={summary.critical_findings ? "critical" : "neutral"} /><DataMetric label="Dependencies" value={summary.dependencies} /><DataMetric label="Projects" value={summary.projects} /></dl>
    <div className="overview-decision"><section className="attention-line"><span className={`signal-point ${summary.exploited_findings ? "is-critical" : ""}`} aria-hidden="true" /><div><h2>{attention}</h2><p>{summary.exploited_findings > 0 ? `${summary.exploited_findings} open findings appear on CISA’s known-exploited list.` : "Alert policy determines this queue. Reachability remains a separate source-evidence result."}</p></div>{summary.open_findings > 0 && <Link to="/alerts?show=open">Review findings <ArrowRight size={15} aria-hidden="true" /></Link>}</section><aside className="filter-ledger"><span className="eyebrow">Filtered from attention</span><strong>{summary.filter_rate_percent}%</strong><p>{summary.filtered_findings} filtered · {summary.dismissed_findings} dismissed · {summary.resolved_findings} resolved</p><Link to="/alerts?show=filtered">Inspect the reasons ↗</Link></aside></div>
    <OpenFindingsSection query={findings} /></>}
    {projects.length ? <ProjectsDirectory projects={projects} /> : <DashboardEmptyState />}
  </PageFrame>;
}
