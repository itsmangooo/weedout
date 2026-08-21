import { ProjectRow } from "./ProjectRow";

export function ProjectList({ projects }) {
  return (
    <section className="project-list" aria-labelledby="project-list-heading">
      <div className="project-list__heading">
        <div>
          <p className="section-label">Project state</p>
          <h2 id="project-list-heading">Watched projects</h2>
        </div>
        <span>{projects.length}</span>
      </div>
      <div className="project-list__rows">
        {projects.map((project) => (
          <ProjectRow key={project.id} project={project} />
        ))}
      </div>
    </section>
  );
}
