import { Bell, FolderKanban, LayoutDashboard, Settings, ShieldCheck, Sprout } from "lucide-react";
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
          <NavLink
            className={({ isActive }) => `app-shell__nav-link${isActive ? " is-active" : ""}`}
            to="/alerts"
          >
            <Bell aria-hidden="true" size={16} /> Findings
          </NavLink>
          {/* /targets, the projects index, went with the Jinja panel — the
              dashboard is the project list now. This points at adding one,
              which is the only thing that page offered beyond the list. */}
          <NavLink
            className={({ isActive }) => `app-shell__nav-link${isActive ? " is-active" : ""}`}
            to="/targets/new"
          >
            <FolderKanban aria-hidden="true" size={16} /> Add a project
          </NavLink>

          {/* Convenience only. The access control is on
              /api/internal/admin/*; hiding this link protects nothing. */}
          {data?.user?.is_admin ? (
            <NavLink
              className={({ isActive }) => `app-shell__nav-link${isActive ? " is-active" : ""}`}
              to="/admin"
            >
              <ShieldCheck aria-hidden="true" size={16} /> Admin
            </NavLink>
          ) : null}
        </nav>


        <div className="app-shell__account">
          <span className="app-shell__account-copy">
            <span className="app-shell__account-email">{account?.email}</span>
            <span className="app-shell__account-tier">{account?.tier} workspace</span>
          </span>
          <NavLink aria-label="Settings" className="app-shell__account-link" to="/settings">
            <Settings aria-hidden="true" size={16} />
          </NavLink>
        </div>
      </aside>
      <main className="app-shell__main" id="main">
        <Outlet />
      </main>
    </div>
  );
}
