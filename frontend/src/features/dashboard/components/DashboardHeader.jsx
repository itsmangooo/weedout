import { Plus } from "lucide-react";

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
        <h1>What needs your attention?</h1>
        <dl className="dashboard-header__context">
          <div><dt>Projects</dt><dd>{projects}</dd></div>
          <div><dt>Dependencies</dt><dd>{dependencies}</dd></div>
        </dl>
      </div>
      <div className="dashboard-header__actions">
        <a className="button button--primary" href="/targets/new">
          <Plus aria-hidden="true" size={16} /> Add project
        </a>
      </div>
    </header>
  );
}
