import { Sprout } from "lucide-react";
import { Outlet } from "react-router";

export function FoundationLayout({ children }) {
  return (
    <div className="foundation-shell min-h-screen" data-theme="public">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="foundation-header">
        <div className="foundation-header__inner mx-auto flex w-full items-center justify-between">
          <a className="foundation-brand" href="/" aria-label="Weedout home">
            <span className="foundation-brand__mark" aria-hidden="true">
              <Sprout size={17} strokeWidth={2} />
            </span>
            <span>Weedout</span>
          </a>
          <nav className="foundation-header__nav" aria-label="Preview navigation">
            <a href="/docs">Docs</a>
            <a href="/cli">CLI</a>
            <a href="/dashboard">Dashboard</a>
          </nav>
        </div>
      </header>
      <main id="main">{children ?? <Outlet />}</main>
    </div>
  );
}
