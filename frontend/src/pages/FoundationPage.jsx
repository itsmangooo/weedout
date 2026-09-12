import {
  ArrowDown,
  ArrowRight,
  Check,
  FileCode2,
  GitBranch,
  ListChecks,
  ShieldCheck,
} from "lucide-react";
import { Link } from "react-router";

import ownerPhoto from "../assets/emanuel-rm-linkedin.jpg";
import { WeedoutLogo } from "../components/brand/WeedoutLogo";
import { CliDemo } from "../features/landing/components/CliDemo";
import { ProductScreenshot } from "../features/landing/components/ProductScreenshot";
import { Reveal } from "../features/landing/components/Reveal";
import { SignalDemo } from "../features/landing/components/SignalDemo";
import { SystemStatus } from "../features/system/components/SystemStatus";

const PRODUCT_PROOF = [
  "Free to start",
  "Eight manifest and lockfile formats",
  "OSV + CISA KEV context",
  "Web, CLI and CI workflows",
];
const WORKFLOW = [
  {
    Icon: FileCode2,
    index: "01",
    artifact: "package-lock.json",
    title: "Scan a project",
    description:
      "Upload a supported manifest in the web app, or scan from your terminal. CLI scans can include bounded JavaScript and TypeScript source evidence.",
  },
  {
    Icon: GitBranch,
    index: "02",
    artifact: "advisory → path → evidence",
    title: "Put each match in context",
    description:
      "Weedout adds advisory and dependency context, applies your project rules, and prioritizes the findings that need attention.",
  },
  {
    Icon: ListChecks,
    index: "03",
    artifact: "finding → decision → fix",
    title: "Work the shortlist",
    description:
      "Inspect the reason, follow the dependency path, and review the fixed version. Make a decision with the evidence in front of you.",
  },
];

export function FoundationPage() {
  return (
    <div className="landing-page">
      <section className="landing-hero" aria-labelledby="landing-title">
        <div className="landing-hero__line" aria-hidden="true" />
        <div className="landing-wrap landing-hero__grid">
          <div className="landing-hero__copy">
            <span className="landing-eyebrow">
              <ShieldCheck aria-hidden="true" size={15} /> Dependency
              vulnerability intelligence
            </span>
            <h1 id="landing-title">
              Security findings with the <span>context to fix them.</span>
            </h1>
            <p className="landing-hero__lede">
              The CVE is the starting point. See how a vulnerable dependency got
              in, what the evidence says, and what to do next.
            </p>
            <div className="landing-actions">
              <Link
                className="button button--primary landing-action"
                to="/signup"
              >
                Start scanning free <ArrowRight aria-hidden="true" size={16} />
              </Link>
              <a
                className="button button--ghost landing-action"
                href="#product"
              >
                See how it works <ArrowDown aria-hidden="true" size={15} />
              </a>
            </div>
            <p className="landing-hero__note">
              <Check aria-hidden="true" size={14} /> No credit card required to
              start.
            </p>
          </div>
          <div className="landing-hero__product">
            <ProductScreenshot />
          </div>
        </div>
        <div className="landing-wrap landing-hero__foot">
          <span>LESS TRIAGE. MORE CONTEXT.</span>
          <a href="#product">
            Follow the signal <ArrowDown size={14} aria-hidden="true" />
          </a>
        </div>
      </section>

      <div className="landing-proof" aria-label="Product facts">
        <div className="landing-wrap">
          {PRODUCT_PROOF.map((item) => (
            <span key={item}>
              <Check aria-hidden="true" size={13} /> {item}
            </span>
          ))}
        </div>
      </div>

      <section
        className="landing-context"
        id="product"
        aria-labelledby="context-title"
      >
        <div className="landing-wrap">
          <Reveal className="landing-problem">
            <p className="section-label">01 / The problem with another alert</p>
            <h2>
              A long list of CVEs.
              <br />
              <span>Still no clear next move.</span>
            </h2>
            <p>
              Severity tells you how bad a vulnerability can be. It doesn’t tell
              you how the package entered your project, what was observed, or
              which dependency to update.
            </p>
          </Reveal>
          <Reveal className="landing-context__heading">
            <div>
              <p className="section-label">02 / Add the missing context</p>
              <h2 id="context-title">From a CVE to actual project context.</h2>
            </div>
            <p>
              Same project. Same matches.
              <br />A more useful place to start.
              <br />
              <span>Try the example below.</span>
            </p>
          </Reveal>
          <Reveal>
            <SignalDemo />
          </Reveal>
          <div className="landing-honesty">
            <span className="section-label">Evidence, with its limits.</span>
            <p>
              Node reachability comes from static import and require
              observations; dynamic or incomplete analysis stays Unknown.
              Weedout does not claim that observing a package import proves a
              vulnerable function executes. A manifest-only web scan reports
              reachability as Unknown.
            </p>
            <Link to="/docs">
              Read the docs <ArrowRight size={14} aria-hidden="true" />
            </Link>
          </div>
        </div>
      </section>

      <section
        className="landing-workflow"
        id="workflow"
        aria-labelledby="workflow-title"
      >
        <div className="landing-wrap">
          <Reveal className="landing-workflow__heading">
            <p className="section-label">03 / Turn context into action</p>
            <h2 id="workflow-title">
              From manifest to decision,{" "}
              <br />
              in three steps.
            </h2>
          </Reveal>
          <Reveal>
            <ol className="landing-workflow__steps">
              {WORKFLOW.map(({ Icon, index, artifact, title, description }) => (
                <li key={index}>
                  <div className="landing-workflow__node">
                    <span>{index}</span>
                    <Icon size={21} aria-hidden="true" />
                  </div>
                  <code>{artifact}</code>
                  <h3>{title}</h3>
                  <p>{description}</p>
                </li>
              ))}
            </ol>
          </Reveal>
          <div className="landing-cli" id="cli-demo">
            <Reveal className="landing-cli__copy">
              <p className="section-label">04 / Where you build</p>
              <h2>
                Same context.
                <br />
                Your terminal.
              </h2>
              <p>
                Run a scan from your project. Add <code>--ci</code> to fail the
                job on your configured blocking threshold, malicious packages or
                known exploitation.
              </p>
              <p>
                A finding’s reachability stays a separate result. A failed scan
                never passes as a clean one.
              </p>
              <Link className="text-link" to="/cli">
                Explore the CLI <ArrowRight size={15} aria-hidden="true" />
              </Link>
            </Reveal>
            <CliDemo />
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
              <img
                src={ownerPhoto}
                alt="Emanuel RM"
                width="200"
                height="200"
                loading="lazy"
              />
            </a>
            <div className="owner-word__copy">
              <p className="section-label">Owner&apos;s word</p>
              <blockquote>
                I built Weedout because security tools should help you decide
                what to fix—not bury you under another list of CVEs.
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
              <h2 id="landing-close-title">
                Scan a project. See what actually needs attention.
              </h2>
            </div>
            <div className="landing-actions">
              <Link className="button button--primary" to="/signup">
                Start scanning free <ArrowRight aria-hidden="true" size={16} />
              </Link>
              <Link className="button button--secondary" to="/docs">
                Read the docs
              </Link>
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
            <a
              href="https://github.com/itsmangooo/weedout"
              rel="noopener"
              target="_blank"
            >
              Source
            </a>
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
