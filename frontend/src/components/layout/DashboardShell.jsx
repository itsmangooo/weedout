import { Bell } from "@phosphor-icons/react/Bell";
import { BookOpen } from "@phosphor-icons/react/BookOpen";
import { ClipboardText } from "@phosphor-icons/react/ClipboardText";
import { CreditCard } from "@phosphor-icons/react/CreditCard";
import { Envelope } from "@phosphor-icons/react/Envelope";
import { FolderSimple } from "@phosphor-icons/react/FolderSimple";
import { ClockCounterClockwise } from "@phosphor-icons/react/ClockCounterClockwise";
import { House } from "@phosphor-icons/react/House";
import { List } from "@phosphor-icons/react/List";
import { PlugsConnected } from "@phosphor-icons/react/PlugsConnected";
import { SlidersHorizontal } from "@phosphor-icons/react/SlidersHorizontal";
import { ShieldCheck } from "@phosphor-icons/react/ShieldCheck";
import { SquaresFour } from "@phosphor-icons/react/SquaresFour";
import { Terminal } from "@phosphor-icons/react/Terminal";
import { Users } from "@phosphor-icons/react/Users";
import { X } from "@phosphor-icons/react/X";
import { Link, Outlet, useLocation } from "react-router";

import { useUnreadCount } from "../../features/admin/hooks/useAdmin";
import { useCurrentUser } from "../../features/auth/hooks/useCurrentUser";
import { WeedoutLogo } from "../brand/WeedoutLogo";
import { PageTransition } from "../motion/PageTransition";
import { PanelAccountControls } from "./PanelAccountControls";
import { useNavigationDisclosure } from "./useNavigationDisclosure";

const WORKSPACE_ITEMS = [
  { to: "/dashboard", label: "Overview", Icon: House, exact: true },
  { to: "/alerts", label: "Findings", Icon: Bell },
  { to: "/projects", label: "Projects", Icon: FolderSimple },
  { to: "/rules", label: "Rules", Icon: SlidersHorizontal },
  { to: "/integrations", label: "Integrations", Icon: PlugsConnected },
  { to: "/activity", label: "Activity", Icon: ClockCounterClockwise },
  { to: "/docs", label: "Documentation", Icon: BookOpen, exact: true },
];

const ADMIN_ITEMS = [
  { to: "/admin", label: "Admin overview", Icon: SquaresFour, exact: true },
  { to: "/admin/users", label: "Users", Icon: Users },
  { to: "/admin/billing", label: "Billing", Icon: CreditCard },
  { to: "/admin/inbox", label: "Inbox", Icon: Envelope, unread: true },
  { to: "/admin/email", label: "Compose", Icon: Terminal },
  { to: "/admin/docs", label: "Docs", Icon: BookOpen },
  { to: "/admin/audit", label: "Audit log", Icon: ClipboardText },
];

function isActive(item, pathname) {
  return item.exact ? pathname === item.to : pathname === item.to || pathname.startsWith(`${item.to}/`);
}

function NavigationSection({ items, label, pathname, unread }) {
  return (
    <section className="dashboard-nav-section" aria-labelledby={`dashboard-nav-${label.toLowerCase().replaceAll(" ", "-")}`}>
      <p className="workspace-label eyebrow" id={`dashboard-nav-${label.toLowerCase().replaceAll(" ", "-")}`}>
        {label}
      </p>
      <div className="dashboard-nav-list">
        {items.map((item) => {
          const active = isActive(item, pathname);
          const Icon = item.Icon;

          return (
            <Link
              aria-current={active ? "page" : undefined}
              className={`workspace-link${active ? " is-active" : ""}`}
              key={item.to}
              to={item.to}
            >
              <Icon size={16} aria-hidden="true" />
              <span>{item.label}</span>
              {item.unread && unread > 0 && (
                <span className="status-tag" aria-label={`${unread} unread`}>{unread}</span>
              )}
            </Link>
          );
        })}
      </div>
    </section>
  );
}

function currentPage(pathname) {
  if (pathname === "/dashboard") return "Overview";
  if (pathname === "/projects") return "Projects";
  if (pathname === "/rules") return "Rules";
  if (pathname === "/integrations") return "Integrations";
  if (pathname === "/activity") return "Activity";
  if (pathname === "/targets/new") return "Add a project";
  if (pathname.startsWith("/targets/")) return "Project";
  if (pathname === "/alerts") return "Findings";
  if (pathname.startsWith("/alerts/")) return "Finding";
  if (pathname === "/settings") return "Settings";
  if (pathname === "/admin") return "Overview";
  if (pathname.startsWith("/admin/users/")) return "User";
  if (pathname.startsWith("/admin/users")) return "Users";
  if (pathname.startsWith("/admin/billing")) return "Billing";
  if (pathname.startsWith("/admin/inbox/")) return "Message";
  if (pathname.startsWith("/admin/inbox")) return "Inbox";
  if (pathname.startsWith("/admin/email")) return "Compose";
  if (pathname.startsWith("/admin/docs/")) return "Edit docs";
  if (pathname.startsWith("/admin/docs")) return "Docs";
  if (pathname.startsWith("/admin/audit")) return "Audit log";
  return "Workspace";
}

export function DashboardShell() {
  const { data } = useCurrentUser();
  const { pathname, search } = useLocation();
  const adminContext = pathname === "/admin" || pathname.startsWith("/admin/");
  const unread = useUnreadCount({ enabled: adminContext && Boolean(data?.user?.is_admin) });
  const {
    id: menuId,
    trigger: triggerRef,
    open: menuOpen,
    toggle: toggleMenu,
  } = useNavigationDisclosure();

  const sections = adminContext
    ? [
        { label: "Main", items: [{ to: "/dashboard", label: "Workspace", Icon: SquaresFour, exact: true }] },
        { label: "Administration", items: ADMIN_ITEMS },
      ]
    : [
        { label: "Workspace", items: WORKSPACE_ITEMS },
        ...(data?.user?.is_admin
          ? [{ label: "Administration", items: [{ to: "/admin", label: "Administration", Icon: ShieldCheck, exact: true }] }]
          : []),
      ];

  return (
    <div className={`workspace-shell dashboard-shell ${menuOpen ? "is-nav-open" : ""}`}>
      <a className="skip-link" href="#dashboard-main">Skip to content</a>
      <header className="workspace-top">
        <Link className="brand" to="/dashboard" aria-label="Weedout workspace">
          <WeedoutLogo />
        </Link>
        <div className="workspace-context" aria-label="Current area">
          <span>{adminContext ? "Administration" : "Workspace"}</span>
          <span>/</span>
          <strong>{currentPage(pathname)}</strong>
        </div>
        <Link className="workspace-top__docs" to="/docs">Documentation</Link>
        <button
          ref={triggerRef}
          className="nav-toggle"
          type="button"
          aria-controls={menuId}
          aria-expanded={menuOpen}
          aria-label={menuOpen ? "Close navigation" : "Open navigation"}
          onClick={toggleMenu}
        >
          {menuOpen ? <X size={20} /> : <List size={20} />}
        </button>
      </header>

      <div className="workspace-body">
        <aside className="workspace-rail">
          <div className="dashboard-sidebar__panel workspace-navigation" id={menuId}>
            <nav className="dashboard-nav-sections" aria-label="Dashboard navigation">
              {sections.map((section) => (
                <NavigationSection
                  items={section.items}
                  key={section.label}
                  label={section.label}
                  pathname={pathname}
                  unread={unread}
                />
              ))}
            </nav>
            <div className="workspace-navigation__footer">
              <PanelAccountControls user={data?.user} />
            </div>
          </div>
        </aside>
        <main tabIndex={-1} id="dashboard-main" className="workspace-content dashboard-shell__main">
          <PageTransition key={`${pathname}${search}`}><Outlet /></PageTransition>
        </main>
      </div>
    </div>
  );
}
