import { RefreshCw } from "lucide-react";
import { useState } from "react";
import { useParams, useSearchParams } from "react-router";

import { rescanProject } from "../api/projects";
import { Button } from "../components/ui/Button";
import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { InlineNotice } from "../components/ui/InlineNotice";
import { ProjectFindings } from "../features/projects/components/ProjectFindings";
import { ProjectOverview } from "../features/projects/components/ProjectOverview";
import { ProjectSettings } from "../features/projects/components/ProjectSettings";
import { useProject, useProjectMutation } from "../features/projects/hooks/useProject";
import { dueTime, relativeTime } from "../lib/time";

const VIEWS = [
  { id: "findings", label: "Findings" },
  { id: "overview", label: "Overview" },
  { id: "settings", label: "Settings" },
];

const TABS = [
  { id: "open", label: "Open" },
  { id: "filtered", label: "Filtered out" },
  { id: "dismissed", label: "Dismissed" },
  { id: "resolved", label: "Resolved" },
];

export function ProjectPage() {
  const { projectId } = useParams();
  const [params, setParams] = useSearchParams();

  const show = TABS.some((tab) => tab.id === params.get("show")) ? params.get("show") : "open";
  const query = useProject(projectId, show);

  if (query.isPending) {
    return (
      <div className="project-page">
        <AsyncLoading>Opening the project…</AsyncLoading>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="project-page">
        <AsyncError error={query.error} onRetry={() => query.refetch()} />
      </div>
    );
  }

  const page = query.data;
  const project = page.data;

  // Findings is the default because it is what somebody clicking through from
  // the dashboard came for — the dashboard already showed them the counts. A
  // project with no manifest is the exception: it has no findings to show, so
  // landing there would be an empty table that can only tell you to leave.
  const requested = params.get("view");
  const view = VIEWS.some((entry) => entry.id === requested)
    ? requested
    : project.has_manifest
      ? "findings"
      : "overview";

  function setParam(key, value) {
    const next = new URLSearchParams(params);
    next.set(key, value);
    setParams(next, { replace: true });
  }

  return (
    <div className="project-page">
      <ProjectHeader project={project} />

      <nav aria-label="Project views" className="view-tabs">
        {VIEWS.map((entry) => (
          <button
            aria-current={view === entry.id ? "page" : undefined}
            className={`view-tab${view === entry.id ? " view-tab--active" : ""}`}
            key={entry.id}
            onClick={() => setParam("view", entry.id)}
            type="button"
          >
            {entry.label}
          </button>
        ))}
      </nav>

      {view === "findings" ? (
        <ProjectFindings
          findings={page.findings}
          onShowChange={(value) => setParam("show", value)}
          show={show}
          tabs={TABS}
          tabCounts={project.tab_counts}
        />
      ) : null}

      {view === "overview" ? <ProjectOverview page={page} /> : null}

      {view === "settings" ? <ProjectSettings page={page} projectId={projectId} /> : null}
    </div>
  );
}

function ProjectHeader({ project }) {
  const [message, setMessage] = useState(null);

  const rescan = useProjectMutation(project.id, () => rescanProject(project.id), {
    onSuccess: (result) => {
      setMessage(
        `Checked ${project.name}: ${result.actionable} to act on, ${result.suppressed} filtered out.`,
      );
    },
  });

  const checked = relativeTime(project.last_scanned_at);
  const due = dueTime(project.next_scan_at);

  return (
    <header className="project-head">
      <div className="project-head__identity">
        <p className="section-label">{project.manifest_kind || project.ecosystem}</p>
        <h1>{project.name}</h1>
        <p className="project-head__meta">
          {project.dependency_count}{" "}
          {project.dependency_count === 1 ? "dependency" : "dependencies"}
          {checked ? ` · checked ${checked}` : " · never checked"}
          {due ? ` · next ${due === "overdue" ? "check overdue" : due}` : ""}
        </p>
      </div>

      <div className="project-head__actions">
        <Button
          disabled={rescan.isPending || !project.has_manifest}
          onClick={() => rescan.mutate()}
          variant="secondary"
        >
          <RefreshCw aria-hidden="true" size={15} />
          {rescan.isPending ? "Checking…" : "Check now"}
        </Button>
      </div>

      {project.last_scan_error ? (
        <div className="project-head__notice">
          <InlineNotice tone="danger" title="The last check failed">
            {project.last_scan_error} The counts below are from the last scan that finished.
          </InlineNotice>
        </div>
      ) : null}

      {project.unreached_by_depth > 0 ? (
        <div className="project-head__notice">
          <InlineNotice tone="warning">
            {project.unreached_by_depth} dependencies were not reached at your plan&apos;s
            depth. They were not examined, which is not the same as being clean.
          </InlineNotice>
        </div>
      ) : null}

      {rescan.isError ? (
        <div className="project-head__notice">
          <InlineNotice tone="danger">{rescan.error.message}</InlineNotice>
        </div>
      ) : null}

      {message ? (
        <div className="project-head__notice">
          <InlineNotice tone="success">{message}</InlineNotice>
        </div>
      ) : null}
    </header>
  );
}
