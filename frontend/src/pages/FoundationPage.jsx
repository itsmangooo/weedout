import { ArrowRight } from "@phosphor-icons/react/ArrowRight";
import { ArrowUpRight } from "@phosphor-icons/react/ArrowUpRight";
import { Browser } from "@phosphor-icons/react/Browser";
import { Check } from "@phosphor-icons/react/Check";
import { FileCode } from "@phosphor-icons/react/FileCode";
import { GitBranch } from "@phosphor-icons/react/GitBranch";
import { GitPullRequest } from "@phosphor-icons/react/GitPullRequest";
import { ListChecks } from "@phosphor-icons/react/ListChecks";
import { ShieldWarning } from "@phosphor-icons/react/ShieldWarning";
import { TerminalWindow } from "@phosphor-icons/react/TerminalWindow";
import { useRef } from "react";
import { Link } from "react-router";
import heroArtwork from "../assets/dependency-signal-hero.webp";
import ownerPhoto from "../assets/emanuel-rm-linkedin.jpg";
import { AnalysisStory } from "../features/landing/components/AnalysisStory";
import { CliDemo } from "../features/landing/components/CliDemo";
import { FindingExplorer } from "../features/landing/components/FindingExplorer";
import { MagneticLink } from "../features/landing/components/MagneticLink";
import { MotionControl } from "../features/landing/components/MotionControl";
import { useLandingMotion } from "../features/landing/useLandingMotion";
import { useMotionPreference } from "../features/landing/useMotionPreference";

const FACTS = ["8 manifest + lockfile formats", "OSV + CISA KEV context", "Web, CLI + CI", "Free to start"];

const USAGE_MODES = [
  { label: "Web", Icon: Browser, copy: "Upload a manifest and review prioritized findings in the dashboard." },
  { label: "CLI", Icon: TerminalWindow, copy: "Scan the current project and inspect prioritized findings from your terminal." },
  { label: "CI", Icon: GitPullRequest, copy: "Run Weedout in CI and fail at your project’s configured blocking threshold." },
];

const SIGNALS = [
  ["Package + version", "The dependency and version that matched the advisory."],
  ["Severity", "The advisory’s reported severity, kept as one signal rather than the whole decision."],
  ["Known exploitation", "Whether the CVE appears in CISA’s Known Exploited Vulnerabilities catalogue."],
  ["Dependency path", "The route from your project to the affected package."],
  ["Reachability", "Supported source evidence, with incomplete analysis left Unknown."],
  ["Fix context", "The fixed version reported by the advisory and a concrete next action."],
  ["Project rules", "Your thresholds and ignore decisions, applied without hiding their reasons."],
  ["Advisory evidence", "The source, identifiers, and explanation behind the match."],
];

const FORMATS = [
  ["package-lock.json", "npm · exact"],
  ["package.json", "npm · declared range"],
  ["requirements.txt", "PyPI"],
  ["go.mod", "Go"],
  ["Cargo.lock", "Rust · exact"],
  ["pom.xml", "Maven"],
  ["gradle.lockfile", "Gradle · exact"],
  ["build.sbt.lock", "Scala · exact"],
];

export function FoundationPage() {
  const root = useRef(null);
  const { reduced } = useMotionPreference();
  useLandingMotion(root, reduced);

  return <div className="landing-page" ref={root}>
    <section className="landing-hero" data-section aria-labelledby="landing-title">
      <div className="landing-hero__top" data-hero-copy>
        <div><MotionControl /><a href="https://github.com/itsmangooo/weedout" target="_blank" rel="noopener noreferrer">Open source <ArrowUpRight size={14} aria-hidden="true" /></a></div>
      </div>
      <div className="landing-hero__copy">
        <h1 id="landing-title" aria-label="Dependency security that tells you what actually needs fixing."><span className="text-mask"><span data-text-line>Dependency security</span></span><span className="text-mask"><span data-text-line>that tells you what</span></span><span className="text-mask"><span data-text-line><em>actually</em> needs fixing.</span></span></h1>
        <div className="landing-hero__intro" data-hero-copy>
          <p>Weedout scans your project dependencies, filters vulnerability noise, and surfaces the findings that actually need attention — with the evidence and fix context behind each one.</p>
          <div className="landing-hero__actions"><MagneticLink to="/signup">Start scanning free <ArrowRight size={18} aria-hidden="true" /></MagneticLink><a className="text-link" href="#analysis">See how it works <span aria-hidden="true">↓</span></a></div>
        </div>
      </div>
      <figure className="landing-hero__visual" data-hero-depth data-hero-copy>
        <img src={heroArtwork} alt="An abstract dependency graph resolving from many signals into three clear paths" width="1536" height="1024" fetchPriority="high" />
        <figcaption>Illustrative dependency signal</figcaption>
        <div className="hero-result" aria-label="Illustrative result: 47 advisories processed by Weedout become 3 findings that need attention"><span><b>47</b> advisories</span><i aria-hidden="true">→</i><span className="hero-result__brand">Weedout</span><i aria-hidden="true">→</i><span><b>3</b> need attention</span></div>
        <div className="hero-finding" aria-hidden="true"><ShieldWarning size={18} weight="fill" /><span><b>HIGH</b><small>CVE-2021-23337 · lodash</small></span><strong>Fix 4.17.21</strong></div>
      </figure>
    </section>

    <div className="landing-marquee" aria-label={FACTS.join(", ")} data-section><div>{[...FACTS, ...FACTS].map((fact, index) => <span key={`${fact}-${index}`}><Check size={15} weight="bold" aria-hidden="true" />{fact}</span>)}</div></div>

    <AnalysisStory reducedMotion={reduced} />

    <section className="landing-signals" data-section aria-labelledby="signals-title">
      <header data-reveal><h2 id="signals-title">The signals behind<br /><em>the shortlist.</em></h2><p>Weedout does not treat severity as the answer. It combines advisory data with the dependency and project context available for the scan.</p></header>
      <ol className="signal-ledger">{SIGNALS.map(([title, copy], index) => <li key={title} data-reveal><span>{String(index + 1).padStart(2, "0")}</span><div><h3>{title}</h3><p>{copy}</p></div></li>)}</ol>
    </section>

    <section className="landing-inspect" id="context" data-section aria-labelledby="context-title">
      <header className="landing-section-heading" data-reveal><h2 id="context-title">One finding.<br /><em>Every reason.</em></h2><p>See why it was surfaced, where the vulnerable dependency enters your project, whether it appears reachable, and which version fixes it.</p></header>
      <div className="landing-product-frame" data-reveal><div className="landing-product-frame__bar"><span>demo-app / findings</span><span>Interactive product demo</span></div><FindingExplorer /></div>
      <div className="evidence-note" data-reveal><span className="eyebrow">Precision includes limits.</span><p>Node reachability comes from static import and require observations; dynamic or incomplete analysis stays Unknown. Weedout does not claim that observing a package import proves a vulnerable function executes.</p><Link to="/docs">Understand the evidence <ArrowUpRight size={15} aria-hidden="true" /></Link></div>
    </section>

    <section className="landing-formats" data-section aria-labelledby="formats-title">
      <header data-reveal><h2 id="formats-title">Bring the files<br />your project already has.</h2><p>Lockfiles give Weedout the strongest version evidence. Declared manifests are supported with their uncertainty kept visible.</p></header>
      <div className="format-ledger" data-reveal>{FORMATS.map(([name, detail]) => <div key={name}><code>{name}</code><span>{detail}</span></div>)}</div>
    </section>

    <section className="landing-method" data-section aria-labelledby="workflow-title">
      <div className="landing-method__heading" data-reveal><h2 id="workflow-title">Project in.<br /><em>Decision out.</em></h2><p>Give Weedout a project or manifest. It checks the dependencies, adds vulnerability and project context, and returns a prioritized shortlist.</p></div>
      <ol className="method-rail">
        <li data-reveal><span className="method-rail__number">01</span><FileCode size={30} weight="duotone" aria-hidden="true" /><div><h3>Scan a project</h3><p>Upload a supported manifest or run the CLI from your project.</p><code>package-lock.json</code></div></li>
        <li data-reveal><span className="method-rail__number">02</span><GitBranch size={30} weight="duotone" aria-hidden="true" /><div><h3>Weedout adds context</h3><p>Advisories meet dependency paths, project rules, and bounded source evidence.</p><code>47 matches → 3 decisions</code></div></li>
        <li data-reveal><span className="method-rail__number">03</span><ListChecks size={30} weight="duotone" aria-hidden="true" /><div><h3>Act on the shortlist</h3><p>Review the evidence, choose the fix, and scan again.</p><code>fixed in 4.17.21</code></div></li>
      </ol>
      <div className="usage-modes" data-reveal>
        <h3>Use Weedout where you scan.</h3>
        <div>{USAGE_MODES.map(({ label, Icon, copy }) => <article key={label}><Icon size={24} weight="duotone" aria-hidden="true" /><h4>{label}</h4><p>{copy}</p></article>)}</div>
      </div>
    </section>

    <section className="landing-comparison" data-section aria-labelledby="comparison-title">
      <header data-reveal><h2 id="comparison-title">More useful findings.<br /><em>Not more findings.</em></h2><p>Weedout is not trying to find more vulnerabilities. It is trying to make the findings more useful.</p></header>
      <div className="comparison-ledger" data-reveal>
        <section><h3>Typical dependency scanner</h3><ol><li>Find matching advisories</li><li>Return severity</li><li>Produce a long list</li><li>Leave prioritization to the developer</li></ol></section>
        <section className="comparison-ledger__weedout"><h3>Weedout</h3><ol><li>Find matching advisories</li><li>Add dependency and project context</li><li>Prioritize the findings</li><li>Explain why each one needs attention</li><li>Keep the fix and evidence attached</li></ol></section>
      </div>
    </section>

    <section className="landing-terminal" id="terminal" data-section aria-labelledby="terminal-title">
      <header data-reveal><h2 id="terminal-title">The answer,<br /><em>inside your flow.</em></h2><p>Run the same dependency analysis from your terminal. In CI, Weedout can fail at the blocking threshold configured for the project.</p><Link className="button button--secondary" to="/cli">Read the CLI guide <ArrowUpRight size={16} aria-hidden="true" /></Link></header>
      <div className="landing-terminal__body" data-reveal><CliDemo reducedMotion={reduced} /><div className="terminal-annotation"><span className="eyebrow">Real command. Useful exit code.</span><p><code>weedout scan --ci</code> fails on the configured blocking threshold, malicious packages, or known exploitation.</p></div></div>
    </section>

    <section className="landing-trust" data-section aria-labelledby="trust-title">
      <header data-reveal><h2 id="trust-title">Your project data<br /><em>is not the product.</em></h2><p>Dependency matching happens on Weedout infrastructure against mirrored advisory catalogues.</p></header>
      <ul data-reveal><li><strong>No analytics or tracking</strong><span>No tracking pixel, advertising identifier, or session recorder.</span></li><li><strong>No dependency-data sales</strong><span>Project and dependency data is not sold or rented.</span></li><li><strong>No model training</strong><span>Your data is not used to train machine-learning models.</span></li></ul>
      <Link data-reveal to="/privacy">Read the privacy policy <ArrowUpRight size={15} aria-hidden="true" /></Link>
    </section>

    <section className="landing-conclusion" data-section aria-labelledby="landing-close-title">
      <div className="founder-note" data-reveal><img src={ownerPhoto} alt="Emanuel RM" width="88" height="110" loading="lazy" /><blockquote>“Security tools should help you decide what to fix.”<a href="https://www.linkedin.com/in/emanuel-rm" target="_blank" rel="noopener noreferrer">Emanuel RM · Founder <ArrowUpRight size={13} aria-hidden="true" /></a></blockquote></div>
      <h2 id="landing-close-title" data-reveal>Scan a project.<br /><em>Know what actually<br />needs attention.</em></h2><div className="landing-conclusion__actions" data-reveal><MagneticLink to="/signup">Start scanning free <ArrowRight size={18} aria-hidden="true" /></MagneticLink><Link className="text-link" to="/docs">Read the docs <ArrowUpRight size={15} aria-hidden="true" /></Link></div>
    </section>
  </div>;
}
