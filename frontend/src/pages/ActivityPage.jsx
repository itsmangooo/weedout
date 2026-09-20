import { ArrowUpRight } from "@phosphor-icons/react/ArrowUpRight";
import { CheckCircle } from "@phosphor-icons/react/CheckCircle";
import { WarningCircle } from "@phosphor-icons/react/WarningCircle";
import { Link } from "react-router";

import { PageFrame } from "../components/ui/PageFrame";
import { DashboardError, DashboardLoading } from "../features/dashboard/components/DashboardQueryState";
import { useDashboard } from "../features/dashboard/hooks/useDashboard";
import { relativeTime } from "../lib/time";

export function ActivityPage() {
  const query = useDashboard();
  if (query.isPending) return <DashboardLoading />;
  if (query.isError) return <DashboardError error={query.error} onRetry={() => query.refetch()} />;
  const activity = [...query.data.projects].filter((project) => project.last_scanned_at).sort((left, right) => Date.parse(right.last_scanned_at) - Date.parse(left.last_scanned_at));
  return <PageFrame className="activity-page" eyebrow="Workspace / latest checks" title="Activity" description="Recent automatic project checks and the security state each one produced.">
    {activity.length === 0 ? <p className="empty-state">Project checks will appear here after Weedout receives the first scan.</p> : <ol className="activity-timeline">{activity.map((project) => { const attention = project.last_scan_failed || project.findings.open > 0; const Icon = attention ? WarningCircle : CheckCircle; return <li key={project.id}><Icon size={18} weight="fill" /><div><strong>{project.name}</strong><p>{project.last_scan_failed ? "The latest check failed." : project.findings.open ? `${project.findings.open} open finding${project.findings.open === 1 ? "" : "s"} after the latest check.` : "No open findings after the latest check."}</p></div><time dateTime={project.last_scanned_at}>{relativeTime(project.last_scanned_at)}</time><Link to={`/targets/${project.id}`} aria-label={`Open ${project.name}`}><ArrowUpRight size={16} /></Link></li>; })}</ol>}
  </PageFrame>;
}
