import { ScanSearch } from "lucide-react";

import { HeroSignalField } from "../features/landing/components/HeroSignalField";
import { LandingCli } from "../features/landing/components/LandingCli";
import { LiveSignal } from "../features/landing/components/LiveSignal";
import { MagneticLink } from "../features/landing/components/MagneticLink";
import { StageShowcase } from "../features/landing/components/StageShowcase";
import { UsedBy } from "../features/landing/components/UsedBy";
import { ScrollFilterStory } from "../features/landing/components/ScrollFilterStory";
import { SystemStatus } from "../features/system/components/SystemStatus";
import { Link } from "react-router";

import { WeedoutLogo } from "../components/brand/WeedoutLogo";

export function FoundationPage() {
  return (
    <div className="landing-page">
      <HeroSignalField />
      <ScrollFilterStory />
      <StageShowcase />
      <LandingCli />
      <LiveSignal />
      <UsedBy />

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
          <Link className="foundation-brand" to="/" aria-label="Weedout home">
            <WeedoutLogo />
          </Link>
          <p>Vulnerability noise, reduced to a reachable signal.</p>
          <nav aria-label="Footer navigation">
            <Link to="/cli">CLI</Link>
            <Link to="/docs">Docs</Link>
            <Link to="/pricing">Pricing</Link>
            {/* The people who load this are already wondering whether
                something is broken, so it must not be a URL they have to
                guess. */}
            <Link to="/status">Status</Link>
            <Link to="/terms">Terms</Link>
            <Link to="/privacy">Privacy</Link>
            {/* AGPL-3.0 section 13: a service has to offer its users the
                source it is running. */}
            <a href="https://github.com/itsmangooo/weedout" rel="noopener" target="_blank">
              Source
            </a>
            {/* Reachable from the public footer as well as from inside the
                app: somebody who cannot sign in is exactly who needs to be
                able to tell us so. */}
            <Link to="/contact">Contact</Link>
          </nav>
        </div>

        <details className="landing-diagnostics">
          <summary>Service status</summary>
          <SystemStatus />
        </details>
      </footer>
    </div>
  );
}
