import { Menu, Sprout, X } from "lucide-react";
import { useEffect, useId, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router";

import { useCurrentUser } from "../../features/auth/hooks/useCurrentUser";
import { ThemeControl } from "../../features/theme/ThemeControl";

//: Where the source lives. Required rather than offered: AGPL-3.0 section 13
//: obliges a service to give its users a way to get the code it is running.
const SOURCE_URL = "https://github.com/itsmangooo/weedout";

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

      {/* The landing page brings its own, richer footer -- brand, diagnostics,
          the lot. Two footers on one page is worse than either alone, so the
          utility strip stands down there. */}
      {location.pathname === "/" ? null : <Footer />}
    </div>
  );
}

/**
 * The public footer.
 *
 * Small on purpose. Its whole job is to make three things reachable that
 * nothing else links to — the status page most of all, because the people who
 * need it are the ones already wondering whether something is wrong, and a
 * status page you have to guess the URL of is a status page nobody reads.
 *
 * Only links to pages that exist. A footer with a dead /terms is worse than a
 * footer without one: it turns a missing page into a broken promise.
 */
function Footer() {
  return (
    <footer className="foundation-footer">
      <div className="foundation-footer__inner">
        <p className="foundation-footer__note">
          Weedout watches your dependencies and tells you about the vulnerabilities that
          can actually reach you.
        </p>
        <nav aria-label="Footer" className="foundation-footer__nav">
          <Link to="/status">Status</Link>
          <Link to="/docs">Docs</Link>
          <Link to="/cli">CLI</Link>
          <Link to="/terms">Terms</Link>
          <Link to="/privacy">Privacy</Link>
          <Link to="/contact">Contact</Link>
          {/* Not decoration. Weedout is AGPL-3.0, and section 13 requires a
              service to offer its source to the people using it over a
              network. This link is how that obligation is met — and it is
              also the honest answer to "what is deciding which
              vulnerabilities I hear about?". */}
          <a href={SOURCE_URL} rel="noopener" target="_blank">
            Source
          </a>
        </nav>
      </div>
    </footer>
  );
}
