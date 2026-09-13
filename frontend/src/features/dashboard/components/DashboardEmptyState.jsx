import { FilePlus2 } from "lucide-react";
import { Link } from "react-router";

export function DashboardEmptyState() {
  return (
    <section className="dashboard-empty" aria-labelledby="dashboard-empty-heading">
      <FilePlus2 aria-hidden="true" size={28} strokeWidth={1.6} />
      <div>
        <p className="section-label">No projects yet</p>
        <h2 id="dashboard-empty-heading">Add a project to start watching.</h2>
        <p>
          Upload a supported manifest, paste its contents, or create a project to connect from the CLI.
        </p>
      </div>
      <Link className="button button--primary" to="/targets/new">
        Add project
      </Link>
    </section>
  );
}
