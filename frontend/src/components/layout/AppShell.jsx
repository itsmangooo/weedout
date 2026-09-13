import { Bell } from "@phosphor-icons/react/Bell";
import { FolderSimple as FolderKanban } from "@phosphor-icons/react/FolderSimple";
import { SquaresFour as LayoutDashboard } from "@phosphor-icons/react/SquaresFour";
import { SignOut as LogOut } from "@phosphor-icons/react/SignOut";
import { List as Menu } from "@phosphor-icons/react/List";
import { Gear as Settings } from "@phosphor-icons/react/Gear";
import { ShieldCheck } from "@phosphor-icons/react/ShieldCheck";
import { Terminal } from "@phosphor-icons/react/Terminal";
import { X } from "@phosphor-icons/react/X";
import { Plus } from "@phosphor-icons/react/Plus";
import { useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { signOut } from "../../api/authActions";
import { useAuthRefresh, useCurrentUser } from "../../features/auth/hooks/useCurrentUser";
import { ThemeControl } from "../../features/theme/ThemeControl";
import { WeedoutLogo } from "../brand/WeedoutLogo";
import { PageTransition } from "../motion/PageTransition";
import { InlineNotice } from "../ui/InlineNotice";
import { LiquidGlass } from "../ui/LiquidGlass";
import { useNavigationDisclosure } from "./useNavigationDisclosure";
const LINKS = [["/dashboard", "Overview", LayoutDashboard], ["/dashboard?view=projects", "Projects", FolderKanban], ["/alerts", "Dependency findings", Bell], ["/targets/new", "Add a project", Plus], ["/cli", "CLI", Terminal], ["/settings", "Settings", Settings]];

export function AppShell() {
  const { data } = useCurrentUser();
  const { pathname, search } = useLocation();
  const navigate = useNavigate();
  const refresh = useAuthRefresh();
  const { id: menuId, trigger: triggerRef, open: menuOpen, toggle: toggleMenu } = useNavigationDisclosure();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function logout() {
    setBusy(true); setError("");
    try { await signOut(); await refresh(); navigate("/login"); }
    catch { setError("Could not sign out. Try again."); setBusy(false); }
  }
  const context = pathname.startsWith("/targets/") && pathname !== "/targets/new" ? "Project workspace" : pathname.startsWith("/alerts/") ? "Finding investigation" : "Workspace";
  return <div className={`workspace-shell app-shell ${menuOpen ? "is-nav-open" : ""}`}>
    <a className="skip-link" href="#main">Skip to content</a>
    <LiquidGlass as="header" className="workspace-top" interactive><Link className="brand" to="/dashboard" aria-label="Weedout overview"><WeedoutLogo /></Link><div className="workspace-context"><span>Workspace</span><span>/</span><strong>{context === "Workspace" ? "Dependency intelligence" : context}</strong></div><Link className="workspace-top__docs" to="/docs">Documentation ↗</Link><button ref={triggerRef} className="nav-toggle" type="button" aria-controls={menuId} aria-expanded={menuOpen} aria-label={menuOpen ? "Close navigation" : "Open navigation"} onClick={toggleMenu}>{menuOpen ? <X size={20} /> : <Menu size={20} />}</button></LiquidGlass>
    <div className="workspace-body"><aside className="workspace-rail"><div className="app-sidebar__panel workspace-navigation" id={menuId}>
      <p className="workspace-label eyebrow">Your workspace</p><nav aria-label="Application">{LINKS.map(([to, label, Icon]) => {
        const projects = new URLSearchParams(search).get("view") === "projects";
        const active = to.startsWith("/dashboard") ? pathname === "/dashboard" && to.includes("?") === projects : pathname === to || pathname.startsWith(`${to}/`);
        return <Link key={to} to={to} aria-current={active ? "page" : undefined} className={`workspace-link${active ? " is-active" : ""}`}><Icon size={17} aria-hidden="true" /><span>{label}</span></Link>;
      })}{data?.user?.is_admin && <NavLink className="workspace-link" to="/admin"><ShieldCheck size={17} aria-hidden="true" /><span>Admin</span></NavLink>}</nav>
      <div className="workspace-account"><span className="account-initial" aria-hidden="true">{data?.user?.email?.[0]?.toUpperCase() ?? "W"}</span><div><strong>{data?.user?.email}</strong><small>{data?.user?.tier ?? "free"} workspace</small></div></div><ThemeControl /><button className="workspace-link signout" disabled={busy} onClick={logout} type="button"><LogOut size={16} aria-hidden="true" />{busy ? "Signing out…" : "Sign out"}</button>{error && <InlineNotice tone="danger">{error}</InlineNotice>}
    </div></aside><main tabIndex={-1} id="main" className="workspace-content app-shell__main"><PageTransition key={pathname}><Outlet /></PageTransition></main></div>
  </div>;
}
