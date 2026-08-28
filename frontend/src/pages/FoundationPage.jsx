import {
  ArrowRight,
  Check,
  GitBranch,
  ScanSearch,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react";
import { Link } from "react-router";

import ownerPhoto from "../assets/emanuel-rm-linkedin.jpg";
import { WeedoutLogo } from "../components/brand/WeedoutLogo";
import { FindingContext } from "../features/landing/components/FindingContext";
import { ProductScreenshot } from "../features/landing/components/ProductScreenshot";
import { SystemStatus } from "../features/system/components/SystemStatus";

const PRODUCT_PROOF = [
  "Free to start",
  "Eight manifest and lockfile formats",
  "OSV + CISA KEV context",
  "Web, CLI and CI workflows",
];

const CAPABILITIES = [
  {
    Icon: GitBranch,
    index: "01",
    title: "Trace the dependency path",
    description:
      "See whether a package is direct or transitive, how deep it sits, and the manifest-derived chain that brought it into the project.",
  },
  {
    Icon: ScanSearch,
    index: "02",
    title: "Read the evidence",
    description:
      "Keep severity, known exploitation, fixed versions and manifest-level reachability together instead of chasing context across tools.",
  },
  {
    Icon: ShieldCheck,
    index: "03",
    title: "Work the useful queue",
    description:
      "Use alert rules and project context to reduce background noise, then review the findings that still need a decision.",
  },
];

const WORKFLOW = [
  {
    index: "01",
    title: "Point Weedout at a project",
    description: "Add a supported manifest in the web app or scan the project from the CLI.",
  },
  {
    index: "02",
    title: "Classify what was found",
    description: "Advisory, dependency and exploit signals are evaluated against the project context.",
  },
  {
    index: "03",
    title: "Fix from a shorter list",
    description: "Review the path, evidence and available fixed version before choosing the next action.",
  },
];

export function FoundationPage() {
  return (
    <div className="landing-page">
      <section className="landing-hero" aria-labelledby="landing-title">
        <div className="landing-wrap landing-hero__grid">
          <div className="landing-hero__copy">
            <span className="landing-eyebrow">
              <ShieldCheck aria-hidden="true" size={15} /> Dependency vulnerability intelligence
            </span>
            <h1 id="landing-title">Security findings with the context to fix them.</h1>
            <p className="landing-hero__lede">
              Find vulnerable dependencies, understand how they entered your project, inspect the
              evidence, and focus on what is worth fixing.
            </p>
            <div className="landing-actions">
              <Link className="button button--primary landing-action" to="/signup">
                Start scanning free <ArrowRight aria-hidden="true" size={16} />
              </Link>
              <Link className="button button--ghost landing-action" to="/cli">
                Explore the CLI
              </Link>
            </div>
            <p className="landing-hero__note">
              <Check aria-hidden="true" size={14} /> No credit card required to start.
            </p>
          </div>

          <div className="landing-hero__product">
            <ProductScreenshot />
          </div>
        </div>
      </section>

      <div className="landing-proof" aria-label="Product facts">
        <div className="landing-wrap">
          {PRODUCT_PROOF.map((item) => (
            <span key={item}><Check aria-hidden="true" size={13} /> {item}</span>
          ))}
        </div>
      </div>

      <section className="landing-context" id="product" aria-labelledby="context-title">
        <div className="landing-wrap">
          <div className="landing-context__grid">
            <div className="landing-section-copy">
              <p className="section-label">The useful part starts after the match</p>
              <h2 id="context-title">From a CVE to actual project context.</h2>
              <p>
                A vulnerable package name is only the beginning. Weedout keeps the dependency path,
                available fix and reason a finding surfaced close to the advisory so you can make a
                better decision.
              </p>
              <p className="landing-honesty">
                Reachability is based on dependency manifests. Weedout does not pretend to map a CVE
                to a source line or prove that a vulnerable function executes.
              </p>
            </div>
            <FindingContext />
          </div>

          <div className="landing-capabilities" aria-label="Current Weedout capabilities">
            {CAPABILITIES.map(({ Icon, index, title, description }) => (
              <article key={title}>
                <div className="landing-capabilities__top">
                  <span>{index}</span>
                  <Icon aria-hidden="true" size={18} />
                </div>
                <h3>{title}</h3>
                <p>{description}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="landing-workflow" aria-labelledby="workflow-title">
        <div className="landing-wrap">
          <div className="landing-workflow__heading">
            <div>
              <p className="section-label">How it works</p>
              <h2 id="workflow-title">From manifest to decision, in three steps.</h2>
            </div>
            <p>
              One focused workflow for the web app, local development and CI—without inventing a
              second set of security results.
            </p>
          </div>

          <ol className="landing-workflow__steps">
            {WORKFLOW.map(({ index, title, description }) => (
              <li key={title}>
                <span>{index}</span>
                <div>
                  <h3>{title}</h3>
                  <p>{description}</p>
                </div>
              </li>
            ))}
          </ol>

          <div className="landing-cli">
            <div className="landing-cli__copy">
              <TerminalSquare aria-hidden="true" size={20} />
              <p className="section-label">CLI + CI</p>
              <h2>Run the same check where you build.</h2>
              <p>
                Authenticate once, scan a supported project and use CI mode when critical or known
                exploited findings should fail the job.
              </p>
              <Link className="text-link" to="/cli">
                Read the CLI guide <ArrowRight aria-hidden="true" size={15} />
              </Link>
            </div>

            <div className="landing-cli__terminal" aria-label="Example Weedout CLI session">
              <div className="landing-cli__bar" aria-hidden="true"><span /><span /><span /></div>
              <pre><code><span>$ weedout scan --ci</span>{"\n"}{"\n"}demo-app ./package-lock.json{"\n"}412 dependencies scanned · 33 filtered out as noise{"\n"}<em>1 exploited · 1 critical</em>{"\n"}{"\n"}<strong>! systeminformation@5.0.0 CVE-2021-21315 → 5.3.1</strong></code></pre>
            </div>
          </div>
        </div>
      </section>

      <section className="landing-final" aria-labelledby="landing-close-title">
        <div className="landing-wrap">
          <div className="owner-word">
            <a
              className="owner-word__portrait"
              href="https://www.linkedin.com/in/emanuel-rm?utm_source=share_via&utm_content=profile&utm_medium=member_android"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Emanuel RM on LinkedIn"
            >
              <img src={ownerPhoto} alt="Emanuel RM" width="200" height="200" loading="lazy" />
            </a>
            <div className="owner-word__copy">
              <p className="section-label">Owner&apos;s word</p>
              <blockquote>
                I built Weedout because security tools should help you decide what to fix—not bury
                you under another list of CVEs.
              </blockquote>
              <p>
                <strong>Emanuel RM</strong>
                <a
                  href="https://www.linkedin.com/in/emanuel-rm?utm_source=share_via&utm_content=profile&utm_medium=member_android"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Founder · LinkedIn
                </a>
              </p>
            </div>
          </div>

          <div className="landing-close">
            <div>
              <p className="section-label">Start with the signal</p>
              <h2 id="landing-close-title">Scan a project. See what actually needs attention.</h2>
            </div>
            <div className="landing-actions">
              <Link className="button button--primary" to="/signup">
                Start scanning free <ArrowRight aria-hidden="true" size={16} />
              </Link>
              <Link className="button button--secondary" to="/docs">Read the docs</Link>
            </div>
          </div>
        </div>
      </section>

      <footer className="landing-footer">
        <div className="landing-wrap landing-footer__main">
          <div className="landing-footer__brand">
            <Link className="foundation-brand" to="/" aria-label="Weedout home">
              <WeedoutLogo />
            </Link>
            <p>Dependency findings, reduced to an actionable signal.</p>
          </div>

          <nav aria-label="Product">
            <strong>Product</strong>
            <Link to="/dashboard">Dashboard</Link>
            <Link to="/cli">CLI</Link>
            <Link to="/docs">Docs</Link>
          </nav>
          <nav aria-label="Company">
            <strong>Company</strong>
            <Link to="/contact">Contact</Link>
            <a href="https://github.com/itsmangooo/weedout" rel="noopener" target="_blank">Source</a>
            <a
              href="https://www.linkedin.com/in/emanuel-rm?utm_source=share_via&utm_content=profile&utm_medium=member_android"
              rel="noopener noreferrer"
              target="_blank"
            >
              LinkedIn
            </a>
          </nav>
          <nav aria-label="Legal and operations">
            <strong>Legal + operations</strong>
            <Link to="/status">Status</Link>
            <Link to="/terms">Terms</Link>
            <Link to="/privacy">Privacy</Link>
          </nav>
        </div>

        <div className="landing-wrap landing-footer__bottom">
          <span>© Weedout</span>
          <details className="landing-diagnostics">
            <summary>Live service status</summary>
            <SystemStatus />
          </details>
        </div>
      </footer>
    </div>
  );
}
