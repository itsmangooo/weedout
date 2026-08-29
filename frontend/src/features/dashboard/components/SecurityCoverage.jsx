import { ArrowUpRight, Code2, FileKey2, GitBranch, PackageSearch } from "lucide-react";
import { Link } from "react-router";

const PLANNED_MODULES = [
  {
    Icon: Code2,
    title: "Source code",
    note: "Planned full code analysis. Dependency import evidence already lives under Dependencies.",
  },
  {
    Icon: FileKey2,
    title: "Secrets",
    note: "Reserved for credential and sensitive-value findings.",
  },
  {
    Icon: GitBranch,
    title: "CI & config",
    note: "Reserved for workflow and configuration findings.",
  },
];

export function SecurityCoverage({ summary }) {
  return (
    <section className="security-coverage" aria-labelledby="security-coverage-heading">
      <div className="security-coverage__heading">
        <div>
          <p className="section-label">Security coverage</p>
          <h2 id="security-coverage-heading">Analysis modules</h2>
        </div>
        <p>One project model, with every future domain kept in a clear place.</p>
      </div>

      <div className="security-coverage__grid">
        <Link className="security-module security-module--active" to="/alerts">
          <div className="security-module__top">
            <span className="security-module__icon"><PackageSearch aria-hidden="true" size={18} /></span>
            <span className="security-module__status is-active">Active</span>
          </div>
          <strong>Dependencies</strong>
          <p>{summary.dependencies} packages watched across {summary.projects} {summary.projects === 1 ? "project" : "projects"}.</p>
          <span className="security-module__metric">
            {summary.open_findings} open <ArrowUpRight aria-hidden="true" size={14} />
          </span>
        </Link>

        {PLANNED_MODULES.map(({ Icon, title, note }) => (
          <article className="security-module security-module--planned" key={title}>
            <div className="security-module__top">
              <span className="security-module__icon"><Icon aria-hidden="true" size={18} /></span>
              <span className="security-module__status">Planned</span>
            </div>
            <strong>{title}</strong>
            <p>{note}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
