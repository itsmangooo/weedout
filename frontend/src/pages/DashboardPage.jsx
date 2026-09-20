import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router";
import { ArrowRight } from "@phosphor-icons/react/ArrowRight";
import { Plus } from "@phosphor-icons/react/Plus";
import { Radio } from "@phosphor-icons/react/Radio";
import { ApiError } from "../api/client";
import { currentUserQueryKey } from "../features/auth/hooks/useCurrentUser";
import { PageFrame, DataMetric } from "../components/ui/PageFrame";
import { DashboardEmptyState } from "../features/dashboard/components/DashboardEmptyState";
import { DashboardError, DashboardLoading } from "../features/dashboard/components/DashboardQueryState";
import { ProjectRow } from "../features/dashboard/components/ProjectRow";
import { useDashboard } from "../features/dashboard/hooks/useDashboard";
import { OpenFindingsSection } from "../features/findings/components/OpenFindingsSection";
import { useOpenFindings } from "../features/findings/hooks/useOpenFindings";
import { useLiveDashboardUpdates } from "../features/live/hooks/useLiveDashboardUpdates";

export function DashboardPage() {
  const dashboard = useDashboard();
  const findings = useOpenFindings({ enabled: dashboard.isSuccess });
  const live = useLiveDashboardUpdates();
  const client = useQueryClient();
  useEffect(() => {
    if ([dashboard.error, findings.error].some((error) => error instanceof ApiError && error.status === 401)) client.invalidateQueries({ queryKey: currentUserQueryKey });
  }, [dashboard.error, findings.error, client]);
  if (dashboard.isPending) return <DashboardLoading />;
  if (dashboard.isError) return <DashboardError error={dashboard.error} onRetry={() => dashboard.refetch()} />;
  const { projects, summary } = dashboard.data;
  const attention = summary.exploited_findings > 0 ? "Exploited in the wild" : summary.open_findings > 0 ? "Open findings need a decision" : "No open findings";
  return <PageFrame className="dashboard-page" eyebrow="Workspace / live security state" title="Overview" description="A compact view of what needs attention, which projects are being watched, and what changed recently." actions={<Link className="button button--primary" to="/targets/new"><Plus size={16} aria-hidden="true" />Add project</Link>}>
    <div className="workspace-live" role="status"><Radio size={13} aria-hidden="true" />{live === "live" ? "Live updates" : live === "reconnecting" ? "Reconnecting" : live === "unavailable" ? "Live updates unavailable" : "Connecting live updates"}</div><dl className="metric-strip overview-metrics"><DataMetric label="Needs attention" value={summary.open_findings} tone={summary.open_findings ? "warning" : "neutral"} /><DataMetric label="Critical" value={summary.critical_findings} tone={summary.critical_findings ? "critical" : "neutral"} /><DataMetric label="Known exploited" value={summary.exploited_findings} tone={summary.exploited_findings ? "critical" : "neutral"} /><DataMetric label="Watched projects" value={summary.projects} /></dl>
    <div className="overview-decision"><section className="attention-line"><span className={`signal-point ${summary.exploited_findings ? "is-critical" : ""}`} aria-hidden="true" /><div><h2>{attention}</h2><p>{summary.exploited_findings > 0 ? `${summary.exploited_findings} open findings appear on CISA’s known-exploited list.` : "Alert policy determines this queue. Reachability remains a separate source-evidence result."}</p></div>{summary.open_findings > 0 && <Link to="/alerts?show=open">Review findings <ArrowRight size={15} aria-hidden="true" /></Link>}</section><aside className="filter-ledger"><span className="eyebrow">Advisories filtered</span><strong>{summary.filtered_findings}</strong><p>{summary.filter_rate_percent}% filtered · {summary.dismissed_findings} dismissed · {summary.resolved_findings} resolved</p><Link to="/alerts?show=filtered">Inspect the reasons ↗</Link></aside></div>
    <OpenFindingsSection query={findings} />{projects.length ? <RecentChecks projects={projects} /> : <DashboardEmptyState />}
  </PageFrame>;
}

function RecentChecks({ projects }) {
  const recent = [...projects].sort((left, right) => Date.parse(right.last_scanned_at || 0) - Date.parse(left.last_scanned_at || 0)).slice(0, 5);
  return <section className="recent-checks" aria-labelledby="recent-checks-heading"><div className="recent-checks__heading"><div><p className="section-label">Latest project state</p><h2 id="recent-checks-heading">Recently checked</h2></div><Link to="/projects">All projects <ArrowRight size={14} aria-hidden="true" /></Link></div><div>{recent.map((project) => <ProjectRow project={project} key={project.id} />)}</div></section>;
}
