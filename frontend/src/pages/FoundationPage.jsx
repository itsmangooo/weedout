import { ScanSearch, Sprout } from "lucide-react";

import { HeroSignalField } from "../features/landing/components/HeroSignalField";
import { MagneticLink } from "../features/landing/components/MagneticLink";
import { ProductWorkflow } from "../features/landing/components/ProductWorkflow";
import { ScrollFilterStory } from "../features/landing/components/ScrollFilterStory";
import { SystemStatus } from "../features/system/components/SystemStatus";

export function FoundationPage() {
  return (
    <div className="landing-page">
      <HeroSignalField />
      <ScrollFilterStory />
      <ProductWorkflow />

      <section className="landing-close" aria-labelledby="landing-close-title">
        <div className="landing-close__copy">
          <p className="section-label">Attention, earned</p>
          <h2 id="landing-close-title">Ship the fix. Ignore the noise.</h2>
          <p>
            Give the team one defensible decision instead of another vulnerability backlog.
          </p>
          <MagneticLink to="/dashboard">Open the attention queue</MagneticLink>
        </div>
        <div className="landing-close__signal" aria-label="Final actionable finding">
          <span><ScanSearch aria-hidden="true" size={16} /> Final signal</span>
          <strong>CVE-2026-5001</strong>
          <span>minimist@1.2.5</span>
          <span>runtime transitive</span>
          <em>exploited</em>
        </div>
      </section>

      <footer className="landing-footer">
        <div className="landing-footer__main">
          <a className="foundation-brand" href="/" aria-label="Weedout home">
            <span className="foundation-brand__mark" aria-hidden="true">
              <Sprout size={17} strokeWidth={2} />
            </span>
            <span>Weedout</span>
          </a>
          <p>Vulnerability noise, reduced to a reachable signal.</p>
          <nav aria-label="Footer navigation">
            <a href="/docs">Docs</a>
            <a href="/cli">CLI</a>
            <a href="/dashboard">Dashboard</a>
          </nav>
        </div>

        <details className="landing-diagnostics">
          <summary>Local preview status</summary>
          <SystemStatus />
        </details>
      </footer>
    </div>
  );
}
