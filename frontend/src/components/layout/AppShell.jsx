import {
  Bell,
  CreditCard,
  FolderKanban,
  LayoutDashboard,
  LogOut,
  Menu,
  Settings,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";
import { useEffect, useId, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router";

import { signOut } from "../../api/authActions";
import { WeedoutLogo } from "../brand/WeedoutLogo";
import { useAuthRefresh, useCurrentUser } from "../../features/auth/hooks/useCurrentUser";
import { ThemeControl } from "../../features/theme/ThemeControl";

const SECTIONS = [
  { to: "/dashboard", label: "Dashboard", Icon: LayoutDashboard },
  { to: "/alerts", label: "Findings", Icon: Bell },
  // /targets, the projects index, went with the Jinja panel — the dashboard is
  // the project list now, so this points at the one thing that page offered
  // beyond the list.
  { to: "/targets/new", label: "Add a project", Icon: FolderKanban },
  { to: "/billing", label: "Billing", Icon: CreditCard },
  { to: "/cli", label: "CLI", Icon: Terminal },
  { to: "/settings", label: "Settings", Icon: Settings },
];

export function AppShell() {
  const { data } = useCurrentUser();
  const location = useLocation();
  const navigate = useNavigate();
  const refreshAuth = useAuthRefresh();

  const navId = useId();

  // The route the panel was opened on, rather than a boolean: navigating makes
  // it stale and the panel closes, with no effect writing state during render.
  const [openedAt, setOpenedAt] = useState(null);
  const navOpen = openedAt === location.pathname;
  const toggleNav = () => setOpenedAt(navOpen ? null : location.pathname);

  // ProtectedRoute waits for an authenticated answer before rendering this, so
  // `data` is populated in practice. Reading through it unguarded still made
  // the shell impossible to render on its own and would turn any future change
  // to that ordering into a blank screen rather than a missing email.
  const account = data?.user;

  useEffect(() => {
    if (!navOpen) return undefined;

    function onKeyDown(event) {
      if (event.key === "Escape") setOpenedAt(null);
    }

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [navOpen]);

  async function onSignOut() {
    await signOut();
    // Re-read before navigating: the guard on the destination reads the cached
    // identity, and a stale one sends you straight back in.
    await refreshAuth();
    navigate("/login");
  }

  return (
    <div className={`app-shell min-h-screen${navOpen ? " is-nav-open" : ""}`}>
      <a className="skip-link" href="#main">
        Skip to content
      </a>

      <aside className="app-sidebar">
        <div className="app-sidebar__top">
          <NavLink className="app-shell__brand" to="/dashboard">
            <WeedoutLogo />
          </NavLink>

          {/* Only ever visible at narrow widths, where the sidebar has
              collapsed into this bar. */}
          <button
            aria-controls={navId}
            aria-expanded={navOpen}
            aria-label={navOpen ? "Close navigation" : "Open navigation"}
            className="app-shell__menu"
            onClick={toggleNav}
            type="button"
          >
            {navOpen ? <X size={19} /> : <Menu size={19} />}
          </button>
        </div>

        <div className="app-sidebar__panel" id={navId}>
          <nav aria-label="Application" className="app-shell__nav">
            {SECTIONS.map(({ to, label, Icon }) => (
              <NavLink
                className={({ isActive }) => `app-shell__nav-link${isActive ? " is-active" : ""}`}
                end={to === "/dashboard"}
                key={to}
                to={to}
              >
                <Icon aria-hidden="true" size={16} /> {label}
              </NavLink>
            ))}

            {/* Convenience only. The access control is on
                /api/internal/admin/*; hiding this link protects nothing. */}
            {account?.is_admin ? (
              <NavLink
                className={({ isActive }) => `app-shell__nav-link${isActive ? " is-active" : ""}`}
                to="/admin"
              >
                <ShieldCheck aria-hidden="true" size={16} /> Admin
              </NavLink>
            ) : null}
          </nav>

          <div className="app-shell__foot">
            <ThemeControl />

            <div className="app-shell__account">
              <span className="app-shell__account-copy">
                <span className="app-shell__account-email">{account?.email}</span>
                <span className="app-shell__account-tier">{account?.tier} workspace</span>
              </span>
            </div>

            <button className="app-shell__nav-link" onClick={onSignOut} type="button">
              <LogOut aria-hidden="true" size={16} /> Sign out
            </button>
          </div>
        </div>
      </aside>

      <main className="app-shell__main" id="main">
        <Outlet />
      </main>
    </div>
  );
}
