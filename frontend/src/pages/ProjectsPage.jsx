import { Plus } from "@phosphor-icons/react/Plus";
import { Link } from "react-router";

import { PageFrame } from "../components/ui/PageFrame";
import { DashboardEmptyState } from "../features/dashboard/components/DashboardEmptyState";
import { DashboardError, DashboardLoading } from "../features/dashboard/components/DashboardQueryState";
import { ProjectsDirectory } from "../features/dashboard/components/ProjectsDirectory";
import { useDashboard } from "../features/dashboard/hooks/useDashboard";

export function ProjectsPage() {
  const query = useDashboard();
  if (query.isPending) return <DashboardLoading />;
  if (query.isError) return <DashboardError error={query.error} onRetry={() => query.refetch()} />;
  const { projects } = query.data;
  return <PageFrame className="projects-page" eyebrow="Workspace / projects" title="Projects" description="Every watched repository, its current scan state, and the findings attached to it." actions={<Link className="button button--primary" to="/targets/new"><Plus size={16} />Add project</Link>}>
    {projects.length ? <ProjectsDirectory projects={projects} title="Watched projects" /> : <DashboardEmptyState />}
  </PageFrame>;
}
