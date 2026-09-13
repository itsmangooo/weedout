import { ArrowRight, ArrowUpRight, Check, FileCode2, GitBranch, ListChecks } from "lucide-react";
import { useRef } from "react";
import { Link } from "react-router";
import { AnalysisStory } from "../features/landing/components/AnalysisStory";
import { FindingExplorer } from "../features/landing/components/FindingExplorer";
import { CliDemo } from "../features/landing/components/CliDemo";
import { MagneticLink } from "../features/landing/components/MagneticLink";
import { useLandingMotion } from "../features/landing/useLandingMotion";
import ownerPhoto from "../assets/emanuel-rm-linkedin.jpg";

export function FoundationPage() {
  const root = useRef(null);
  useLandingMotion(root);
  return <div className="landing-page" ref={root}>
    <section className="landing-intro" aria-labelledby="landing-title">
      <div className="landing-intro__edition"><span className="eyebrow">Dependency intelligence / built for the next decision</span><a href="https://github.com/itsmangooo/weedout" target="_blank" rel="noopener noreferrer">Open source <ArrowUpRight size={14} aria-hidden="true" /></a></div>
      <h1 id="landing-title"><span className="text-mask"><span data-text-line>Security findings.</span></span>{" "}<span className="text-mask"><span data-text-line>With <em>context.</em></span></span></h1>
      <div className="landing-intro__baseline"><span className="landing-intro__index" aria-hidden="true">[ W / 01 ]</span><p>Know what matched. See how it got in.<br />Decide what to fix.<span>Weedout brings dependency paths, vulnerability evidence and available fixes into one clear shortlist.</span></p><div><MagneticLink to="/signup">Start scanning free <ArrowRight size={17} aria-hidden="true" /></MagneticLink><a className="text-link" href="#analysis">Explore the analysis ↓</a><small>No credit card required.</small></div></div>
    </section>
    <AnalysisStory />
    <div className="landing-facts">{["Eight manifest and lockfile formats", "OSV + CISA KEV context", "Web, CLI and CI workflows", "Free to start"].map((fact) => <span key={fact}><Check size={14} aria-hidden="true" />{fact}</span>)}</div>
    <section className="landing-inspect" id="context" aria-labelledby="context-title">
      <header className="landing-section-heading" data-reveal><p className="eyebrow">02 / Context you can inspect</p><h2 id="context-title">The reason.<br />The path.<br /><em>The next step.</em></h2><p>A severity label is useful.<br />A severity label with evidence is a place to start.</p></header>
      <div data-reveal><FindingExplorer /></div>
      <div className="evidence-note"><span className="eyebrow">Precision includes limits.</span><p>Node reachability comes from static import and require observations; dynamic or incomplete analysis stays Unknown. Weedout does not claim that observing a package import proves a vulnerable function executes.</p><Link to="/docs">Understand the evidence <ArrowUpRight size={15} aria-hidden="true" /></Link></div>
    </section>
    <section className="landing-method" aria-labelledby="workflow-title">
      <div className="landing-method__title" data-reveal><p className="eyebrow">03 / A workflow, not another queue</p><h2 id="workflow-title">From project<br />to clear action.</h2></div>
      <div className="landing-manifest" aria-hidden="true"><FileCode2 size={28} /><code>package-lock.json</code><span>project input</span></div>
      <ol className="method-rail">
        <li data-reveal><span>01</span><FileCode2 size={20} aria-hidden="true" /><div><h3>Scan a project</h3><p>Upload a supported manifest or run the CLI from your project. CLI scans can include bounded JavaScript and TypeScript source evidence.</p></div></li>
        <li data-reveal><span>02</span><GitBranch size={20} aria-hidden="true" /><div><h3>Add project context</h3><p>Weedout adds advisory details and dependency paths, applies project rules, and prioritizes findings. Manifest-only web scans report source reachability as Unknown.</p></div></li>
        <li data-reveal><span>03</span><ListChecks size={20} aria-hidden="true" /><div><h3>Make the next decision</h3><p>Review a shortlist with the evidence and available fixed versions attached. Follow the dependency path, choose an action, and rescan.</p></div></li>
      </ol>
    </section>
    <section className="landing-terminal" id="terminal" aria-labelledby="terminal-title">
      <header data-reveal><p className="eyebrow">04 / Close to the code</p><h2 id="terminal-title">Your terminal.<br /><em>The same answer.</em></h2><Link className="button button--secondary" to="/cli">Read the CLI guide <ArrowUpRight size={16} aria-hidden="true" /></Link></header>
      <div className="landing-terminal__body"><CliDemo /><div className="terminal-annotation"><span className="eyebrow">A useful exit code.</span><p><code>weedout scan --ci</code> fails on the configured blocking threshold, malicious packages or known exploitation.</p><p>A failed scan stays a failed scan. Missing evidence stays Unknown.</p></div></div>
    </section>
    <section className="landing-conclusion" aria-labelledby="landing-close-title">
      <div className="founder-note"><img src={ownerPhoto} alt="Emanuel RM" width="64" height="80" loading="lazy" /><blockquote>“Security tools should help you decide what to fix.”<a href="https://www.linkedin.com/in/emanuel-rm" target="_blank" rel="noopener noreferrer">Emanuel RM · Founder <ArrowUpRight size={13} aria-hidden="true" /></a></blockquote></div>
      <p className="eyebrow">Now it’s your project.</p><h2 id="landing-close-title" data-reveal>Scan a project.<br /><em>See what actually<br />needs attention.</em></h2><div className="landing-conclusion__actions"><MagneticLink to="/signup">Start scanning free <ArrowRight size={18} aria-hidden="true" /></MagneticLink><Link className="text-link" to="/docs">Read the docs <ArrowUpRight size={15} aria-hidden="true" /></Link></div>
    </section>
  </div>;
}
