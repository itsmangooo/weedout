import { Plus } from "lucide-react";
import { Link } from "react-router";

const LIVE_STATUS = {
  connecting: { label: "Connecting live updates", title: "Opening the live update stream" },
  live: { label: "Live updates", title: "Finding counts refresh as scans finish" },
  reconnecting: { label: "Reconnecting", title: "Updates will resume automatically" },
};

export function DashboardHeader({ dependencies, liveStatus, projects }) {
  const live = LIVE_STATUS[liveStatus];

  return (
    <header className="dashboard-header">
      <div>
        <div className="dashboard-header__eyebrow">
          <p className="eyebrow">Workspace overview</p>
          {live ? (
            <span
              className="live-status"
              data-state={liveStatus}
              role="status"
              title={live.title}
            >
              <span aria-hidden="true" /> {live.label}
            </span>
          ) : null}
        </div>
        <h1>Security overview</h1>
        <p className="dashboard-header__lede">
          Everything that needs a decision, across every project and analysis module.
        </p>
        <dl className="dashboard-header__context">
          <div><dt>Projects</dt><dd>{projects}</dd></div>
          <div><dt>Dependencies</dt><dd>{dependencies}</dd></div>
        </dl>
      </div>
      <div className="dashboard-header__actions">
        <Link className="button button--primary" to="/targets/new">
          <Plus aria-hidden="true" size={16} /> Add project
        </Link>
      </div>
    </header>
  );
}
