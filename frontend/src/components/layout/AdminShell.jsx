import {
  ArrowLeft,
  BookOpen,
  ClipboardList,
  CreditCard,
  FileText,
  LayoutDashboard,
  Mail,
  Menu,
  Send,
  ShieldCheck,
  Users,
  X,
} from "lucide-react";
import { useEffect, useId, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router";

import { useUnreadCount } from "../../features/admin/hooks/useAdmin";
import { useCurrentUser } from "../../features/auth/hooks/useCurrentUser";
import { ThemeControl } from "../../features/theme/ThemeControl";
import { WeedoutLogo } from "../brand/WeedoutLogo";

const SECTIONS = [
  { to: "/admin", label: "Overview", Icon: LayoutDashboard, end: true },
  { to: "/admin/users", label: "Users", Icon: Users },
  { to: "/admin/billing", label: "Billing", Icon: CreditCard },
  { to: "/admin/inbox", label: "Inbox", Icon: Mail, badge: "unread" },
  { to: "/admin/email", label: "Compose", Icon: Send },
  { to: "/admin/docs", label: "Docs", Icon: BookOpen },
  { to: "/admin/audit", label: "Audit log", Icon: ClipboardList },
];

export function AdminShell() {
  const { data } = useCurrentUser();
  const unread = useUnreadCount();
  const location = useLocation();
  const navigationId = useId();
  const [openedAt, setOpenedAt] = useState(null);
  const navigationOpen = openedAt === location.pathname;

  useEffect(() => {
    if (!navigationOpen) return undefined;
    const close = (event) => {
      if (event.key === "Escape") setOpenedAt(null);
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [navigationOpen]);

  return (
    <div className={`admin-shell${navigationOpen ? " is-nav-open" : ""}`}>
      <a className="skip-link" href="#admin-main">
        Skip to content
      </a>

      <aside className="admin-sidebar">
        <div className="admin-sidebar__top">
          <NavLink aria-label="Weedout admin overview" className="admin-sidebar__brand" to="/admin">
            <WeedoutLogo compact />
            <span className="admin-tag">
              <ShieldCheck aria-hidden="true" size={12} /> Admin
            </span>
          </NavLink>
          <button
            aria-controls={navigationId}
            aria-expanded={navigationOpen}
            aria-label={navigationOpen ? "Close admin navigation" : "Open admin navigation"}
            className="admin-sidebar__menu"
            onClick={() => setOpenedAt(navigationOpen ? null : location.pathname)}
            type="button"
          >
            {navigationOpen ? <X aria-hidden="true" size={18} /> : <Menu aria-hidden="true" size={18} />}
          </button>
        </div>

        <div className="admin-sidebar__panel" id={navigationId}>
          <nav aria-label="Admin sections" className="admin-sidebar__nav">
            <p>Administration</p>
            {SECTIONS.map(({ to, label, Icon, end, badge }) => (
              <NavLink
                className={({ isActive }) =>
                  `admin-sidebar__link${isActive ? " is-active" : ""}`
                }
                end={end}
                key={to}
                to={to}
              >
                <Icon aria-hidden="true" size={16} />
                <span>{label}</span>
                {badge === "unread" && unread > 0 ? (
                  <strong aria-label={`${unread} unread`}>{unread}</strong>
                ) : null}
              </NavLink>
            ))}
          </nav>

          <div className="admin-sidebar__foot">
            <ThemeControl />
            <NavLink className="admin-sidebar__back" to="/dashboard">
              <ArrowLeft aria-hidden="true" size={15} /> Back to app
            </NavLink>
            <p title={data?.user?.email}>
              <FileText aria-hidden="true" size={13} /> {data?.user?.email}
            </p>
          </div>
        </div>
      </aside>

      <main className="admin-shell__main" id="admin-main">
        <Outlet />
      </main>
    </div>
  );
}
