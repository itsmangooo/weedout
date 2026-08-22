import { Bell, FolderKanban, LayoutDashboard, Settings, Sprout } from "lucide-react";
import { NavLink, Outlet } from "react-router";

import { useCurrentUser } from "../../features/auth/hooks/useCurrentUser";

export function AppShell() {
  const { data } = useCurrentUser();

  // ProtectedRoute waits for an authenticated answer before rendering this, so
  // `data` is populated in practice. Reading through it unguarded still made
  // the shell impossible to render on its own and would turn any future change
  // to that ordering into a blank screen rather than a missing email.
  const account = data?.user;

  return (
    <div className="app-shell min-h-screen" data-theme="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className="app-sidebar">
        <NavLink className="app-shell__brand" to="/dashboard">
          <span className="app-shell__brand-mark" aria-hidden="true">
            <Sprout size={17} strokeWidth={2} />
          </span>
          <span>Weedout</span>
        </NavLink>

        <nav className="app-shell__nav" aria-label="Application">
          <NavLink
            className={({ isActive }) => `app-shell__nav-link${isActive ? " is-active" : ""}`}
            to="/dashboard"
          >
            <LayoutDashboard aria-hidden="true" size={16} /> Dashboard
          </NavLink>
          <a className="app-shell__nav-link" href="/alerts">
            <Bell aria-hidden="true" size={16} /> Findings
          </a>
          <a className="app-shell__nav-link" href="/targets">
            <FolderKanban aria-hidden="true" size={16} /> Projects
          </a>
        </nav>

        <div className="app-shell__account">
          <span className="app-shell__account-copy">
            <span className="app-shell__account-email">{account?.email}</span>
            <span className="app-shell__account-tier">{account?.tier} workspace</span>
          </span>
          <a aria-label="Open legacy settings" className="app-shell__account-link" href="/settings">
            <Settings aria-hidden="true" size={16} />
          </a>
        </div>
      </aside>
      <main className="app-shell__main" id="main">
        <Outlet />
      </main>
    </div>
  );
}
