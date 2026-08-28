import {
  ArrowRight,
  Check,
  Code2,
  FileKey2,
  GitBranch,
  PackageSearch,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react";
import { Link } from "react-router";

import ownerPhoto from "../assets/emanuel-rm-linkedin.jpg";
import { WeedoutLogo } from "../components/brand/WeedoutLogo";
import { ProductScreenshot } from "../features/landing/components/ProductScreenshot";
import { SystemStatus } from "../features/system/components/SystemStatus";

const MODULES = [
  {
    Icon: PackageSearch,
    title: "Dependency intelligence",
    description:
      "Scan supported manifests, connect exploit and reachability signals, and filter findings that do not deserve attention.",
    status: "Available now",
    available: true,
  },
  {
    Icon: Code2,
    title: "Source-code analysis",
    description:
      "A future analysis surface for code-level findings, designed to live beside dependency risk instead of in another tool.",
    status: "Planned",
  },
  {
    Icon: FileKey2,
    title: "Secrets detection",
    description:
      "A reserved project module for exposed credentials and sensitive values, with no scanner implied before it exists.",
    status: "Planned",
  },
  {
    Icon: GitBranch,
    title: "CI & configuration",
    description:
      "A future home for workflow, infrastructure and security configuration findings at project level.",
    status: "Planned",
  },
];

const CURRENT_CAPABILITIES = [
  "Supported manifest scanning",
  "OSV advisory matching",
  "Known-exploited prioritisation",
  "Reachability and depth context",
  "Alert rules and noise filtering",
  "Web, CLI and CI workflows",
];

export function FoundationPage() {
  return (
    <div className="landing-page">
      <section className="landing-section landing-hero" aria-labelledby="landing-title">
        <div className="landing-hero__copy">
          <span className="landing-pill">
            <ShieldCheck aria-hidden="true" size={15} /> Dependency security, without the noise
          </span>
          <h1 id="landing-title">See the security issues that actually deserve attention.</h1>
          <p className="landing-hero__lede">
            Weedout turns vulnerable dependency data into a clear project-level decision queue.
            Start with dependency risk today, inside a workspace designed to grow without becoming
            another wall of red.
          </p>
          <div className="landing-actions">
            <Link className="button button--primary landing-action" to="/signup">
              Start scanning free <ArrowRight aria-hidden="true" size={16} />
            </Link>
            <a className="button button--ghost landing-action" href="#product">
              See the product
            </a>
          </div>
          <div className="landing-hero__proof" aria-label="Current product capabilities">
            <span><Check aria-hidden="true" size={14} /> Open source</span>
            <span><Check aria-hidden="true" size={14} /> CLI + web</span>
            <span><Check aria-hidden="true" size={14} /> No card required</span>
          </div>
        </div>

        <div className="landing-hero__product">
          <ProductScreenshot />
        </div>
      </section>

      <section className="landing-trust" aria-label="Weedout product principles">
        <p>Built for small teams that need security clarity, not security theatre.</p>
        <div>
          <span>AGPL-3.0</span>
          <span>OSV advisories</span>
          <span>CISA KEV context</span>
          <a
            href="https://votekicker.com/weedout?utm_source=votekicker&utm_medium=badge&utm_campaign=weedout"
            rel="noopener noreferrer"
            target="_blank"
          >
            Featured on Votekicker
          </a>
        </div>
      </section>

      <section className="landing-section landing-product" id="product" aria-labelledby="product-title">
        <div className="landing-section__intro">
          <p className="section-label">The product today</p>
          <h2 id="product-title">A calm workspace for dependency risk.</h2>
          <p>
            Weedout does not celebrate finding the largest number of CVEs. It combines severity,
            exploitation and project context so the queue stays useful when it matters.
          </p>
        </div>

        <div className="landing-product__grid">
          <div className="landing-product__copy">
            <ol className="landing-steps">
              <li>
                <span>01</span>
                <div>
                  <strong>Add a real project</strong>
                  <p>Upload a supported manifest or connect the existing CLI and CI flow.</p>
                </div>
              </li>
              <li>
                <span>02</span>
                <div>
                  <strong>Let context remove noise</strong>
                  <p>
                    Alert rules, dependency depth and exploit signals separate urgent work from
                    background noise.
                  </p>
                </div>
              </li>
              <li>
                <span>03</span>
                <div>
                  <strong>Work the attention queue</strong>
                  <p>Review the few findings that remain, with project context close at hand.</p>
                </div>
              </li>
            </ol>
          </div>

          <ProductScreenshot compact />
        </div>
      </section>

      <section className="landing-section landing-platform" aria-labelledby="platform-title">
        <div className="landing-section__intro landing-section__intro--wide">
          <p className="section-label">A focused platform</p>
          <h2 id="platform-title">Ready to expand. Honest about what exists.</h2>
          <p>
            Dependency intelligence is available now. The workspace is structured for adjacent
            security modules without presenting roadmap ideas as shipped product.
          </p>
        </div>

        <div className="landing-modules">
          {MODULES.map(({ Icon, title, description, status, available }) => (
            <article className={`landing-module${available ? " is-available" : ""}`} key={title}>
              <div className="landing-module__top">
                <span className="landing-module__icon">
                  <Icon aria-hidden="true" size={18} />
                </span>
                <span className={`landing-module__status${available ? " is-available" : ""}`}>
                  {status}
                </span>
              </div>
              <h3>{title}</h3>
              <p>{description}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="landing-section landing-capabilities" aria-labelledby="capabilities-title">
        <div className="landing-section__intro">
          <p className="section-label">Built with a point of view</p>
          <h2 id="capabilities-title">Useful context beats a longer finding list.</h2>
          <p>
            The current product stays deliberately narrow: supported dependency data, practical
            risk signals, and workflows a small team can operate without a security department.
          </p>
        </div>

        <ul aria-label="Available Weedout capabilities">
          {CURRENT_CAPABILITIES.map((capability) => (
            <li key={capability}>
              <Check aria-hidden="true" size={15} /> {capability}
            </li>
          ))}
        </ul>
      </section>

      <section className="landing-section landing-cli" aria-labelledby="cli-title">
        <div className="landing-cli__copy">
          <span className="landing-module__icon">
            <TerminalSquare aria-hidden="true" size={19} />
          </span>
          <p className="section-label">CLI and CI ready</p>
          <h2 id="cli-title">Bring the same attention queue into the delivery loop.</h2>
          <p>
            Scan supported manifests from the command line, use the existing API-key flow, and
            keep project findings visible in the web workspace.
          </p>
          <Link className="text-link" to="/cli">
            Explore the CLI <ArrowRight aria-hidden="true" size={15} />
          </Link>
        </div>

        <div className="landing-cli__terminal" aria-label="Example Weedout CLI session">
          <div aria-hidden="true"><span /><span /><span /></div>
          <pre><code><span>$ weedout scan requirements.txt</span>{"\n"}{"\n"}Scanning supported dependencies…{"\n"}<em>42 advisories classified</em>{"\n"}<strong>2 findings need attention</strong>{"\n"}{"\n"}Open the project queue for context.</code></pre>
        </div>
      </section>

      <section className="owner-word" aria-labelledby="owner-word-title">
        <div className="owner-word__identity">
          <a
            className="owner-word__portrait"
            href="https://www.linkedin.com/in/emanuel-rm?utm_source=share_via&utm_content=profile&utm_medium=member_android"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Emanuel RM on LinkedIn"
          >
            <img
              src={ownerPhoto}
              alt="Emanuel RM"
              width="200"
              height="200"
              loading="lazy"
            />
          </a>
          <div>
            <p className="section-label" id="owner-word-title">Owner&apos;s word</p>
            <strong>Emanuel RM</strong>
            <a
              href="https://www.linkedin.com/in/emanuel-rm?utm_source=share_via&utm_content=profile&utm_medium=member_android"
              target="_blank"
              rel="noopener noreferrer"
            >
              Founder · LinkedIn
            </a>
          </div>
        </div>

        <blockquote>
          I built Weedout because security tools should help you decide what to fix—not bury you
          under another list of CVEs.
        </blockquote>
      </section>

      <section className="landing-section landing-close" aria-labelledby="landing-close-title">
        <div>
          <p className="section-label">Start with the signal</p>
          <h2 id="landing-close-title">Turn dependency noise into a decision queue.</h2>
          <p>Start free, scan a supported manifest, and see what actually needs attention.</p>
        </div>
        <Link className="button button--primary" to="/signup">
          Create an account <ArrowRight aria-hidden="true" size={16} />
        </Link>
      </section>

      <footer className="landing-footer">
        <div className="landing-footer__main">
          <div>
            <Link className="foundation-brand" to="/" aria-label="Weedout home">
              <WeedoutLogo />
            </Link>
            <p>Vulnerability noise, reduced to a reachable signal.</p>
          </div>
          <nav aria-label="Footer navigation">
            <Link to="/cli">CLI</Link>
            <Link to="/docs">Docs</Link>
            <Link to="/pricing">Pricing</Link>
            <Link to="/status">Status</Link>
            <Link to="/terms">Terms</Link>
            <Link to="/privacy">Privacy</Link>
            <a href="https://github.com/itsmangooo/weedout" rel="noopener" target="_blank">
              Source
            </a>
            <a
              href="https://www.linkedin.com/in/emanuel-rm?utm_source=share_via&utm_content=profile&utm_medium=member_android"
              rel="noopener noreferrer"
              target="_blank"
            >
              LinkedIn
            </a>
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
