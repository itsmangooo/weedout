import {
  ArrowUpRight,
  CircleAlert,
  CircleCheck,
  Clock3,
  FileWarning,
  FolderOpen,
  ListFilter,
  Pause,
} from "lucide-react";

import { EntityContextMenu } from "../../../components/ui/EntityContextMenu";
import { relativeTime } from "../../../lib/time";

function projectState(project) {
  if (project.findings.exploited > 0) {
    return { icon: CircleAlert, label: "Exploited finding", tone: "danger" };
  }
  if (project.findings.open > 0) {
    return { icon: CircleAlert, label: "Needs attention", tone: "open" };
  }
  if (!project.is_active) {
    return { icon: Pause, label: "Paused", tone: "paused" };
  }
  if (!project.has_manifest) {
    return { icon: FileWarning, label: "Manifest needed", tone: "setup" };
  }
  if (project.last_scan_failed) {
    return { icon: CircleAlert, label: "Last check failed", tone: "danger" };
  }
  if (!project.last_scanned_at) {
    return { icon: Clock3, label: "Awaiting first check", tone: "pending" };
  }
  return { icon: CircleCheck, label: "Watching", tone: "clear" };
}

export function ProjectRow({ project }) {
  const state = projectState(project);
  const Icon = state.icon;
  const checked = relativeTime(project.last_scanned_at);
  const projectHref = `/targets/${project.id}`;
  const menuItems = [
    { href: projectHref, icon: FolderOpen, label: "Open project" },
    { type: "separator" },
    { href: "/alerts?show=open", icon: ListFilter, label: "Review open findings" },
  ];

  return (
    <EntityContextMenu items={menuItems} label={`Actions for project ${project.name}`}>
      <article
        className={`project-row project-row--${state.tone}`}
        data-context-scope="project"
        data-project-id={project.id}
      >
        <div className="project-row__main">
          <div className="project-row__identity">
            <div className="project-row__title-line">
              <h3 aria-label={project.name}>
                <a aria-label={`Open project ${project.name}`} href={projectHref}>
                  {project.name}
                </a>
              </h3>
              <span className={`project-row__state project-row__state--${state.tone}`}>
                <Icon aria-hidden="true" size={14} /> {state.label}
              </span>
            </div>
            <p>
              {project.manifest_kind || project.ecosystem} · {project.dependency_count}{" "}
              {project.dependency_count === 1 ? "dependency" : "dependencies"}
              {checked ? ` · checked ${checked}` : ""}
            </p>
          </div>

          <dl className="project-row__findings">
            <div><dt>Open</dt><dd>{project.findings.open}</dd></div>
            <div><dt>Exploited</dt><dd>{project.findings.exploited}</dd></div>
            <div><dt>Filtered</dt><dd>{project.findings.filtered}</dd></div>
          </dl>

          <ArrowUpRight aria-hidden="true" className="project-row__arrow" size={17} />
        </div>
      </article>
    </EntityContextMenu>
  );
}
