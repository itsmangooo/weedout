import { Menu, X, ArrowUpRight } from "lucide-react";
import { Link, NavLink, Outlet, useLocation } from "react-router";
import { useCurrentUser } from "../../features/auth/hooks/useCurrentUser";
import { ThemeControl } from "../../features/theme/ThemeControl";
import { SystemStatus } from "../../features/system/components/SystemStatus";
import { WeedoutLogo } from "../brand/WeedoutLogo";
import { PageTransition } from "../motion/PageTransition";
import { useNavigationDisclosure } from "./useNavigationDisclosure";
const SOURCE = "https://github.com/itsmangooo/weedout";

export function FoundationLayout({ children }) {
  const { data } = useCurrentUser();
  const { pathname } = useLocation();
  const { id: menuId, trigger: triggerRef, open: menuOpen, toggle: toggleMenu } = useNavigationDisclosure();
  const landing = pathname === "/";
  const links = landing ? [["/cli", "CLI"], ["/docs", "Docs"], [SOURCE, "GitHub"]] : [["/cli", "CLI"], ["/docs", "Docs"], ["/pricing", "Pricing"]];
  function navigation(label) { return <nav aria-label={label}>{links.map(([to, text]) => to.startsWith("https") ? <a key={to} href={to} target="_blank" rel="noopener noreferrer">{text}</a> : <NavLink key={to} to={to}>{text}</NavLink>)}</nav>; }
  function account() { return data?.authenticated ? <Link className="button button--primary" to="/dashboard">Dashboard <ArrowUpRight size={14} aria-hidden="true" /></Link> : <><Link to="/login">Sign in</Link><Link className="button button--primary" to="/signup">{landing ? "Start scanning free" : "Start free"}</Link></>; }
  return <div className={`public-shell foundation-shell ${landing ? "public-shell--landing" : ""}`}>
    <a className="skip-link" href="#main">Skip to content</a>
    <header className="public-header"><Link className="brand" to="/" aria-label="Weedout home"><WeedoutLogo /></Link><div className="public-header__desktop">{navigation("Main")}</div><div className="public-header__account"><ThemeControl />{account()}</div><button className="nav-toggle" ref={triggerRef} type="button" onClick={toggleMenu} aria-controls={menuId} aria-expanded={menuOpen} aria-label={menuOpen ? "Close menu" : "Open menu"}>{menuOpen ? <X size={20} /> : <Menu size={20} />}</button></header>
    {menuOpen && <div className="public-mobile" id={menuId}>{navigation("Main, expanded")}<ThemeControl /><div className="public-mobile__account">{account()}</div></div>}
    <main tabIndex={-1} id="main" className={landing ? "public-main public-main--landing" : "public-main"}><PageTransition key={pathname}>{children ?? <Outlet />}</PageTransition></main>
    <footer className="public-footer"><div><Link className="brand" to="/" aria-label="Weedout home"><WeedoutLogo /></Link><p>Security findings.<br />With the context to fix them.</p></div><nav aria-label="Product"><span className="eyebrow">Product</span><Link to="/dashboard">Open workspace</Link><Link to="/cli">CLI</Link><Link to="/docs">Docs</Link><Link to="/pricing">Free product</Link></nav><nav aria-label="Company"><span className="eyebrow">Weedout</span><Link to="/contact">Contact</Link><a href={SOURCE} target="_blank" rel="noopener noreferrer">Source ↗</a><Link to="/status">Status</Link></nav><nav aria-label="Legal"><span className="eyebrow">Details</span><Link to="/terms">Terms</Link><Link to="/privacy">Privacy</Link></nav><div className="public-footer__bottom"><span>© Weedout</span><details className="service-disclosure"><summary>Live service status</summary><SystemStatus /></details></div></footer>
  </div>;
}
