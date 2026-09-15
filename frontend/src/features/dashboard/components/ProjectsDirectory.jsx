import { useState } from "react";
import { ProjectRow } from "./ProjectRow";
import { SectionHeading } from "../../../components/ui/PageFrame";

export function ProjectsDirectory({ projects, title = "Watched projects" }) {
  const [search, setSearch] = useState("");
  const [state, setState] = useState("all");
  const rows = projects.filter((project) => `${project.name} ${project.ecosystem} ${project.manifest_kind ?? ""}`.toLowerCase().includes(search.toLowerCase()) && (state === "all" || (state === "attention" ? project.findings.open > 0 : !project.has_manifest)));
  return <section className="projects-directory" aria-labelledby="projects-heading">
    <SectionHeading title={title} id="projects-heading"><span className="mono muted">{projects.length} projects</span></SectionHeading>
    <div className="list-toolbar"><label className="search-field"><span>Find a project</span><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Name, ecosystem, manifest…" /></label><label className="compact-select"><span>Project state</span><select value={state} onChange={(event) => setState(event.target.value)}><option value="all">All projects</option><option value="attention">Needs attention</option><option value="setup">Needs a manifest</option></select></label></div>
    <div className="directory-columns" aria-hidden="true"><span>Project / latest check</span><span>Open · exploited · filtered</span></div>
    <div className="project-list__rows">{rows.map((project) => <ProjectRow project={project} key={project.id} />)}</div>
    {rows.length === 0 && projects.length > 0 && <p className="empty-state">No projects match these filters.</p>}
  </section>;
}
