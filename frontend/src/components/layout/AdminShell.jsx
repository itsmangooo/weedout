import { BookOpen } from "@phosphor-icons/react/BookOpen";
import { ClipboardText as ClipboardList } from "@phosphor-icons/react/ClipboardText";
import { CreditCard } from "@phosphor-icons/react/CreditCard";
import { SquaresFour as LayoutDashboard } from "@phosphor-icons/react/SquaresFour";
import { Envelope as Mail } from "@phosphor-icons/react/Envelope";
import { List as Menu } from "@phosphor-icons/react/List";
import { PaperPlaneTilt as Send } from "@phosphor-icons/react/PaperPlaneTilt";
import { ShieldCheck } from "@phosphor-icons/react/ShieldCheck";
import { Users } from "@phosphor-icons/react/Users";
import { X } from "@phosphor-icons/react/X";
import { NavLink, Outlet, useLocation } from "react-router";
import { useUnreadCount } from "../../features/admin/hooks/useAdmin";
import { useCurrentUser } from "../../features/auth/hooks/useCurrentUser";
import { WeedoutLogo } from "../brand/WeedoutLogo";
import { PageTransition } from "../motion/PageTransition";
import { PanelAccountControls } from "./PanelAccountControls";
import { useNavigationDisclosure } from "./useNavigationDisclosure";

const LINKS = [
  ["/admin", "Overview", LayoutDashboard],
  ["/admin/users", "Users", Users],
  ["/admin/billing", "Billing", CreditCard],
  ["/admin/inbox", "Inbox", Mail],
  ["/admin/email", "Compose", Send],
  ["/admin/docs", "Docs", BookOpen],
  ["/admin/audit", "Audit log", ClipboardList],
];

export function AdminShell() {
  const { data } = useCurrentUser();
  const unread = useUnreadCount();
  const { pathname } = useLocation();
  const {
    id: menuId,
    trigger: triggerRef,
    open: menuOpen,
    toggle: toggleMenu,
  } = useNavigationDisclosure();

  return (
    <div className={`operations-shell admin-shell ${menuOpen ? "is-nav-open" : ""}`}>
      <a className="skip-link" href="#admin-main">Skip to content</a>
      <header className="operations-top">
        <NavLink className="brand" aria-label="Weedout admin overview" to="/admin">
          <WeedoutLogo />
        </NavLink>
        <span className="operations-mode">
          <ShieldCheck size={15} aria-hidden="true" /> Administration
        </span>
        <span className="operations-identity">{data?.user?.email}</span>
        <button ref={triggerRef} className="nav-toggle" type="button" aria-controls={menuId}
          aria-expanded={menuOpen} aria-label={menuOpen ? "Close admin navigation" : "Open admin navigation"}
          onClick={toggleMenu}>
          {menuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </header>

      <div className="operations-body">
        <aside className="operations-rail">
          <div className="operations-navigation admin-sidebar__panel" id={menuId}>
            <div>
              <p className="operations-label eyebrow">Control panel</p>
              <nav aria-label="Admin sections">
                {LINKS.map(([to, label, Icon]) => (
                  <NavLink key={to} to={to} end={to === "/admin"}
                    className={({ isActive }) => (isActive ? "is-active" : "")}>
                    <Icon size={16} aria-hidden="true" /><span>{label}</span>
                    {to === "/admin/inbox" && unread > 0 && (
                      <span className="status-tag" aria-label={`${unread} unread`}>{unread}</span>
                    )}
                  </NavLink>
                ))}
              </nav>
            </div>
            <div className="operations-navigation__footer">
              <PanelAccountControls showBackToApp user={data?.user} />
            </div>
          </div>
        </aside>
        <main tabIndex={-1} id="admin-main" className="operations-content admin-shell__main">
          <PageTransition key={pathname}><Outlet /></PageTransition>
        </main>
      </div>
    </div>
  );
}
