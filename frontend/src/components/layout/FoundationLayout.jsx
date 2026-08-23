import { Menu, Sprout, X } from "lucide-react";
import { useEffect, useId, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router";

import { useCurrentUser } from "../../features/auth/hooks/useCurrentUser";
import { ThemeControl } from "../../features/theme/ThemeControl";

const SECTIONS = [
  { to: "/cli", label: "CLI" },
  { to: "/docs", label: "Docs" },
  { to: "/pricing", label: "Pricing" },
];

/**
 * The public header.
 *
 * Every link is present at every width. The previous version hid all but the
 * last one below 40rem with `display: none`, which is not a responsive layout
 * — it is the CLI and Docs pages becoming unreachable on a phone, which is
 * exactly how somebody concludes there is no CLI page.
 */
export function FoundationLayout({ children }) {
  const location = useLocation();
  const { data } = useCurrentUser();
  const signedIn = data?.authenticated === true;

  const menuId = useId();

  // The route the menu was opened on, rather than a boolean. Navigating then
  // closes it by making this stale — derived, so there is no effect racing the
  // render. Leaving it open over the page you just asked for makes the tap
  // that opened it look like it did nothing.
  const [openedAt, setOpenedAt] = useState(null);
  const menuOpen = openedAt === location.pathname;
  const toggleMenu = () => setOpenedAt(menuOpen ? null : location.pathname);

  useEffect(() => {
    if (!menuOpen) return undefined;

    function onKeyDown(event) {
      if (event.key === "Escape") setOpenedAt(null);
    }

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [menuOpen]);

  return (
    <div className="foundation-shell min-h-screen">
      <a className="skip-link" href="#main">
        Skip to content
      </a>

      <header className="foundation-header">
        <div className="foundation-header__inner mx-auto flex w-full items-center justify-between">
          <Link aria-label="Weedout home" className="foundation-brand" to="/">
            <span aria-hidden="true" className="foundation-brand__mark">
              <Sprout size={17} strokeWidth={2} />
            </span>
            <span>Weedout</span>
          </Link>

          <nav aria-label="Main" className="foundation-header__nav">
            {SECTIONS.map((section) => (
              <NavLink
                className={({ isActive }) => (isActive ? "is-active" : undefined)}
                key={section.to}
                to={section.to}
              >
                {section.label}
              </NavLink>
            ))}
          </nav>

          <div className="foundation-header__end">
            <ThemeControl />
            {signedIn ? (
              <Link className="button button--primary button--sm" to="/dashboard">
                Dashboard
              </Link>
            ) : (
              <>
                <Link className="foundation-header__signin" to="/login">
                  Sign in
                </Link>
                <Link className="button button--primary button--sm" to="/signup">
                  Start free
                </Link>
              </>
            )}
          </div>

          <button
            aria-controls={menuId}
            aria-expanded={menuOpen}
            aria-label={menuOpen ? "Close menu" : "Open menu"}
            className="foundation-header__menu"
            onClick={toggleMenu}
            type="button"
          >
            {menuOpen ? <X size={19} /> : <Menu size={19} />}
          </button>
        </div>

        {/* Rendered only when open, so its links are not in the tab order of a
            page that is not showing them. */}
        {menuOpen ? (
          <div className="foundation-menu" id={menuId}>
            <nav aria-label="Main, expanded" className="foundation-menu__nav">
              {SECTIONS.map((section) => (
                <NavLink
                  className={({ isActive }) => (isActive ? "is-active" : undefined)}
                  key={section.to}
                  to={section.to}
                >
                  {section.label}
                </NavLink>
              ))}
            </nav>

            <div className="foundation-menu__end">
              {signedIn ? (
                <Link className="button button--primary" to="/dashboard">
                  Dashboard
                </Link>
              ) : (
                <>
                  <Link className="button button--secondary" to="/login">
                    Sign in
                  </Link>
                  <Link className="button button--primary" to="/signup">
                    Start free
                  </Link>
                </>
              )}
              <ThemeControl />
            </div>
          </div>
        ) : null}
      </header>

      <main id="main">{children ?? <Outlet />}</main>
    </div>
  );
}
