import { ArrowRight } from "@phosphor-icons/react/ArrowRight";
import { ArrowUpRight } from "@phosphor-icons/react/ArrowUpRight";
import { Check } from "@phosphor-icons/react/Check";
import { FileCode } from "@phosphor-icons/react/FileCode";
import { GitBranch } from "@phosphor-icons/react/GitBranch";
import { ListChecks } from "@phosphor-icons/react/ListChecks";
import { ShieldWarning } from "@phosphor-icons/react/ShieldWarning";
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

export function FoundationPage() {
  const root = useRef(null);
  const { reduced } = useMotionPreference();
  useLandingMotion(root, reduced);

  return <div className="landing-page" ref={root}>
    <section className="landing-hero" data-section aria-labelledby="landing-title">
      <div className="landing-hero__top" data-hero-copy>
        <span className="eyebrow">Dependency security / signal over noise</span>
        <div><MotionControl /><a href="https://github.com/itsmangooo/weedout" target="_blank" rel="noopener noreferrer">Open source <ArrowUpRight size={14} aria-hidden="true" /></a></div>
      </div>
      <div className="landing-hero__copy">
        <h1 id="landing-title" aria-label="Security findings with the context to fix them."><span className="text-mask"><span data-text-line>Security findings</span></span><span className="text-mask"><span data-text-line>with the context</span></span><span className="text-mask"><span data-text-line>to <em>fix them.</em></span></span></h1>
        <div className="landing-hero__intro" data-hero-copy>
          <p>Weedout turns dependency alerts into a shortlist you can act on—complete with paths, evidence, fixed versions, and a clear next move.</p>
          <div className="landing-hero__actions"><MagneticLink to="/signup">Start scanning free <ArrowRight size={18} aria-hidden="true" /></MagneticLink><a className="text-link" href="#analysis">See how it works <span aria-hidden="true">↓</span></a></div>
        </div>
      </div>
      <figure className="landing-hero__visual" data-hero-depth data-hero-copy>
        <img src={heroArtwork} alt="An abstract dependency graph resolving from many signals into three clear paths" width="1536" height="1024" fetchPriority="high" />
        <figcaption>Illustrative dependency signal</figcaption>
        <div className="hero-result" aria-label="Illustrative result: 47 vulnerability alerts reduced to 3 findings needing attention"><span><b>47</b> vulnerability alerts</span><i aria-hidden="true">→</i><span className="hero-result__brand">Weedout</span><i aria-hidden="true">→</i><span><b>3</b> need attention</span></div>
        <div className="hero-finding" aria-hidden="true"><ShieldWarning size={18} weight="fill" /><span><b>HIGH</b><small>CVE-2021-23337 · lodash</small></span><strong>Fix 4.17.21</strong></div>
      </figure>
    </section>

    <div className="landing-marquee" aria-label={FACTS.join(", ")} data-section><div>{[...FACTS, ...FACTS].map((fact, index) => <span key={`${fact}-${index}`}><Check size={15} weight="bold" aria-hidden="true" />{fact}</span>)}</div></div>

    <AnalysisStory reducedMotion={reduced} />

    <section className="landing-inspect" id="context" data-section aria-labelledby="context-title">
      <header className="landing-section-heading" data-reveal><p className="eyebrow">02 / Inspect the decision</p><h2 id="context-title">One finding.<br /><em>Every reason.</em></h2><p>Severity is the headline. The dependency path, observed evidence, available fix, and recommended action are the story.</p></header>
      <div className="landing-product-frame" data-reveal><div className="landing-product-frame__bar"><span>demo-app / findings</span><span>Interactive product demo</span></div><FindingExplorer /></div>
      <div className="evidence-note" data-reveal><span className="eyebrow">Precision includes limits.</span><p>Node reachability comes from static import and require observations; dynamic or incomplete analysis stays Unknown. Weedout does not claim that observing a package import proves a vulnerable function executes.</p><Link to="/docs">Understand the evidence <ArrowUpRight size={15} aria-hidden="true" /></Link></div>
    </section>

    <section className="landing-method" data-section aria-labelledby="workflow-title">
      <div className="landing-method__heading" data-reveal><p className="eyebrow">03 / One connected workflow</p><h2 id="workflow-title">Project in.<br /><em>Decision out.</em></h2><p>Every step narrows the question until the next action is clear.</p></div>
      <ol className="method-rail">
        <li data-reveal><span className="method-rail__number">01</span><FileCode size={30} weight="duotone" aria-hidden="true" /><div><h3>Scan a project</h3><p>Upload a supported manifest or run the CLI from your project.</p><code>package-lock.json</code></div></li>
        <li data-reveal><span className="method-rail__number">02</span><GitBranch size={30} weight="duotone" aria-hidden="true" /><div><h3>Weedout adds context</h3><p>Advisories meet dependency paths, project rules, and bounded source evidence.</p><code>47 matches → 3 decisions</code></div></li>
        <li data-reveal><span className="method-rail__number">03</span><ListChecks size={30} weight="duotone" aria-hidden="true" /><div><h3>Act on the shortlist</h3><p>Review the evidence, choose the fix, and scan again.</p><code>fixed in 4.17.21</code></div></li>
      </ol>
    </section>

    <section className="landing-terminal" id="terminal" data-section aria-labelledby="terminal-title">
      <header data-reveal><p className="eyebrow">04 / Close to the code</p><h2 id="terminal-title">The answer,<br /><em>inside your flow.</em></h2><p>Use the supported CLI to scan locally or block CI at the project’s configured threshold.</p><Link className="button button--secondary" to="/cli">Read the CLI guide <ArrowUpRight size={16} aria-hidden="true" /></Link></header>
      <div className="landing-terminal__body" data-reveal><CliDemo reducedMotion={reduced} /><div className="terminal-annotation"><span className="eyebrow">Real command. Useful exit code.</span><p><code>weedout scan --ci</code> fails on the configured blocking threshold, malicious packages, or known exploitation.</p></div></div>
    </section>

    <section className="landing-conclusion" data-section aria-labelledby="landing-close-title">
      <div className="founder-note" data-reveal><img src={ownerPhoto} alt="Emanuel RM" width="88" height="110" loading="lazy" /><blockquote>“Security tools should help you decide what to fix.”<a href="https://www.linkedin.com/in/emanuel-rm" target="_blank" rel="noopener noreferrer">Emanuel RM · Founder <ArrowUpRight size={13} aria-hidden="true" /></a></blockquote></div>
      <p className="eyebrow" data-reveal>Now it’s your project.</p><h2 id="landing-close-title" data-reveal>Scan a project.<br /><em>See what actually<br />needs attention.</em></h2><div className="landing-conclusion__actions" data-reveal><MagneticLink to="/signup">Start scanning free <ArrowRight size={18} aria-hidden="true" /></MagneticLink><Link className="text-link" to="/docs">Read the docs <ArrowUpRight size={15} aria-hidden="true" /></Link></div>
    </section>
  </div>;
}
