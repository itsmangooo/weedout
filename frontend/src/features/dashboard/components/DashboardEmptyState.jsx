import { FilePlus2 } from "lucide-react";

export function DashboardEmptyState() {
  return (
    <section className="dashboard-empty" aria-labelledby="dashboard-empty-heading">
      <FilePlus2 aria-hidden="true" size={28} strokeWidth={1.6} />
      <div>
        <p className="section-label">No projects yet</p>
        <h2 id="dashboard-empty-heading">Add a project to start watching.</h2>
        <p>
          Upload a supported manifest in the existing Weedout flow. Its first check still runs in
          Python exactly as it does today.
        </p>
      </div>
      <a className="button button--primary" href="/targets/new">
        Add project
      </a>
    </section>
  );
}
