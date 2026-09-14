import { Bell } from "@phosphor-icons/react/Bell";
import { FolderSimple as FolderKanban } from "@phosphor-icons/react/FolderSimple";
import { SquaresFour as LayoutDashboard } from "@phosphor-icons/react/SquaresFour";
import { List as Menu } from "@phosphor-icons/react/List";
import { ShieldCheck } from "@phosphor-icons/react/ShieldCheck";
import { Terminal } from "@phosphor-icons/react/Terminal";
import { X } from "@phosphor-icons/react/X";
import { Plus } from "@phosphor-icons/react/Plus";
import { Link, NavLink, Outlet, useLocation } from "react-router";
import { useCurrentUser } from "../../features/auth/hooks/useCurrentUser";
import { WeedoutLogo } from "../brand/WeedoutLogo";
import { PageTransition } from "../motion/PageTransition";
import { PanelAccountControls } from "./PanelAccountControls";
import { useNavigationDisclosure } from "./useNavigationDisclosure";

const LINKS = [
  ["/dashboard", "Overview", LayoutDashboard],
  ["/dashboard?view=projects", "Projects", FolderKanban],
  ["/alerts", "Dependency findings", Bell],
  ["/targets/new", "Add a project", Plus],
  ["/cli", "CLI", Terminal],
];

export function AppShell() {
  const { data } = useCurrentUser();
  const { pathname, search } = useLocation();
  const {
    id: menuId,
    trigger: triggerRef,
    open: menuOpen,
    toggle: toggleMenu,
  } = useNavigationDisclosure();
  const context = pathname.startsWith("/targets/")
    ? pathname === "/targets/new" ? "New project" : "Project"
    : pathname.startsWith("/alerts/") ? "Finding"
      : pathname === "/settings" ? "Settings" : "Workspace";

  return (
    <div className={`workspace-shell app-shell ${menuOpen ? "is-nav-open" : ""}`}>
      <a className="skip-link" href="#main">Skip to content</a>
      <header className="workspace-top">
        <Link className="brand" to="/dashboard" aria-label="Weedout overview"><WeedoutLogo /></Link>
        <div className="workspace-context" aria-label="Current area">
          <span>Workspace</span><span>/</span><strong>{context}</strong>
        </div>
        <Link className="workspace-top__docs" to="/docs">Documentation</Link>
        <button ref={triggerRef} className="nav-toggle" type="button" aria-controls={menuId}
          aria-expanded={menuOpen} aria-label={menuOpen ? "Close navigation" : "Open navigation"}
          onClick={toggleMenu}>
          {menuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </header>

      <div className="workspace-body">
        <aside className="workspace-rail">
          <div className="app-sidebar__panel workspace-navigation" id={menuId}>
            <div>
              <p className="workspace-label eyebrow">Product</p>
              <nav aria-label="Application">
                {LINKS.map(([to, label, Icon]) => {
                  const projects = new URLSearchParams(search).get("view") === "projects";
                  const active = to.startsWith("/dashboard")
                    ? pathname === "/dashboard" && to.includes("?") === projects
                    : pathname === to || pathname.startsWith(`${to}/`);
                  return (
                    <Link key={to} to={to} aria-current={active ? "page" : undefined}
                      className={`workspace-link${active ? " is-active" : ""}`}>
                      <Icon size={17} aria-hidden="true" /><span>{label}</span>
                    </Link>
                  );
                })}
                {data?.user?.is_admin && (
                  <NavLink className="workspace-link" to="/admin">
                    <ShieldCheck size={17} aria-hidden="true" /><span>Admin</span>
                  </NavLink>
                )}
              </nav>
            </div>
            <div className="workspace-navigation__footer">
              <PanelAccountControls user={data?.user} />
            </div>
          </div>
        </aside>
        <main tabIndex={-1} id="main" className="workspace-content app-shell__main">
          <PageTransition key={`${pathname}${search}`}><Outlet /></PageTransition>
        </main>
      </div>
    </div>
  );
}
