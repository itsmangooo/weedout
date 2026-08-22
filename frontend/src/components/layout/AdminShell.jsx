import { NavLink, Outlet } from "react-router";

import { useCurrentUser } from "../../features/auth/hooks/useCurrentUser";
import { useUnreadCount } from "../../features/admin/hooks/useAdmin";

/**
 * Chrome for the admin panel.
 *
 * Deliberately the same visual language as the rest of the app — same tokens,
 * same type, same spacing. The only distinguishing mark is a small "Admin" tag
 * beside the account, so it is obvious which side of the product you are
 * looking at without the panel becoming a different-looking application.
 */

const SECTIONS = [
  { to: "/admin", label: "Overview", end: true },
  { to: "/admin/users", label: "Users" },
  { to: "/admin/billing", label: "Billing" },
  { to: "/admin/inbox", label: "Inbox", badge: "unread" },
  { to: "/admin/email", label: "Compose" },
  { to: "/admin/docs", label: "Docs" },
  { to: "/admin/audit", label: "Audit log" },
];

export function AdminShell() {
  const { data } = useCurrentUser();
  const unread = useUnreadCount();

  return (
    <div className="admin-shell" data-theme="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>

      <div className="admin-head">
        <div>
          <p className="eyebrow">
            <span className="admin-tag">Admin</span>
            Signed in as {data?.user?.email}
          </p>
        </div>
        <NavLink className="admin-head__exit" to="/dashboard">
          Back to the app
        </NavLink>
      </div>

      <nav aria-label="Admin sections" className="tabs">
        {SECTIONS.map((section) => (
          <NavLink
            className={({ isActive }) => `tab${isActive ? " is-active" : ""}`}
            end={section.end}
            key={section.to}
            to={section.to}
          >
            {section.label}
            {/* Only rendered when there is something waiting. A badge showing
                zero is a permanent decoration that stops meaning anything. */}
            {section.badge === "unread" && unread > 0 ? (
              <span className="pill pill--sm pill--high">{unread}</span>
            ) : null}
          </NavLink>
        ))}
      </nav>

      <main id="main">
        <Outlet />
      </main>
    </div>
  );
}
