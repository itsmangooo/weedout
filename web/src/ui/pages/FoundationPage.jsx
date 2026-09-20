import { ArrowRight } from "@phosphor-icons/react/ArrowRight";
import { ArrowUpRight } from "@phosphor-icons/react/ArrowUpRight";
import { BracketsCurly } from "@phosphor-icons/react/BracketsCurly";
import { CheckCircle } from "@phosphor-icons/react/CheckCircle";
import { Code } from "@phosphor-icons/react/Code";
import { FileCode } from "@phosphor-icons/react/FileCode";
import { GitBranch } from "@phosphor-icons/react/GitBranch";
import { PlugsConnected } from "@phosphor-icons/react/PlugsConnected";
import { ShieldCheck } from "@phosphor-icons/react/ShieldCheck";
import { TerminalWindow } from "@phosphor-icons/react/TerminalWindow";
import { Warning } from "@phosphor-icons/react/Warning";
import { useRef, useState } from "react";
import { Link } from "react-router";

import { MotionControl } from "../features/landing/components/MotionControl";
import { useLandingMotion } from "../features/landing/useLandingMotion";
import { useMotionPreference } from "../features/landing/useMotionPreference";

const SOURCE = "https://github.com/itsmangooo/weedout";
const VSCODE = `${SOURCE}/tree/main/integrations/vscode`;
const JETBRAINS = `${SOURCE}/tree/main/integrations/jetbrains`;

const FLOW = [
  ["Dependency changes", "package.json is saved"],
  ["Weedout checks", "Automatic, debounced analysis"],
  ["CVE appears", "Inline in the editor"],
  ["You upgrade", "Fix context stays attached"],
  ["Warning clears", "No refresh required"],
];

const CAPABILITIES = [
  { Icon: PlugsConnected, title: "Lives inside the IDE", copy: "VS Code and JetBrains watch supported dependency files, update native diagnostics, and keep a focused findings view in sync." },
  { Icon: ShieldCheck, title: "Context before volume", copy: "Severity, known exploitation, dependency path, reachability evidence, and available fixes stay attached to each finding." },
  { Icon: FileCode, title: "Rules travel with the code", copy: "Save .weedout.yml and the project is reevaluated automatically. The same deterministic policy follows the repository." },
  { Icon: BracketsCurly, title: "One detection engine", copy: "The modular Go engine produces the same canonical result for the IDE, dashboard, and future integrations." },
];

function IdeDetectionDemo() {
  const [resolved, setResolved] = useState(false);
  return (
    <div className={`ide-demo${resolved ? " is-resolved" : ""}`} data-hero-depth data-hero-copy>
      <div className="ide-demo__chrome">
        <span className="ide-demo__traffic" aria-hidden="true"><i /><i /><i /></span>
        <span>demo-api / package.json</span>
        <span className="ide-demo__connected"><i /> Weedout connected</span>
      </div>
      <div className="ide-demo__body">
        <div className="ide-demo__rail" aria-hidden="true"><Code size={18} weight="duotone" /><GitBranch size={18} /><ShieldCheck size={18} weight="fill" /></div>
        <div className="ide-demo__editor">
          <div className="ide-demo__tab"><FileCode size={14} /> package.json <span>×</span></div>
          <div className="code-window" aria-label={resolved ? "Demo dependency updated to the fixed version" : "Demo vulnerable lodash dependency with an inline Weedout warning"}>
            <span className="line-no">10</span><code>&nbsp;&nbsp;&quot;dependencies&quot;: &#123;</code>
            <span className="line-no">11</span><code className="dependency-line">&nbsp;&nbsp;&nbsp;&nbsp;&quot;lodash&quot;: &quot;{resolved ? "^4.17.21" : "4.17.15"}&quot;<mark>{resolved ? "No finding" : "CVE-2021-23337 · Fix 4.17.21"}</mark></code>
            <span className="line-no">12</span><code>&nbsp;&nbsp;&nbsp;&nbsp;&quot;zod&quot;: &quot;^3.24.2&quot;</code>
            <span className="line-no">13</span><code>&nbsp;&nbsp;&#125;</code>
          </div>
          <div className="ide-demo__diagnostic" role="status" aria-live="polite">
            {resolved ? <><CheckCircle size={19} weight="fill" /><div><strong>Finding removed automatically</strong><span>The dependency now uses the reported fixed version.</span></div></> : <><Warning size={19} weight="fill" /><div><strong>High · CVE-2021-23337</strong><span>lodash@4.17.15 · direct dependency · fixed in 4.17.21</span></div><button type="button" onClick={() => setResolved(true)}>Apply fix</button></>}
          </div>
        </div>
        <aside className="ide-demo__findings">
          <div><span>WEEDOUT FINDINGS</span><b>{resolved ? 0 : 1}</b></div>
          {resolved ? <p className="ide-demo__clear"><CheckCircle size={22} /> No findings in this project.</p> : <button type="button" className="ide-finding is-active"><span><Warning size={14} weight="fill" /> HIGH</span><strong>CVE-2021-23337</strong><small>lodash · 4.17.15</small></button>}
        </aside>
      </div>
      <div className="ide-demo__switch" aria-label="Product demo state">
        <button type="button" aria-pressed={!resolved} onClick={() => setResolved(false)}>Vulnerable dependency</button>
        <button type="button" aria-pressed={resolved} onClick={() => setResolved(true)}>After upgrade</button>
      </div>
    </div>
  );
}

export function FoundationPage() {
  const root = useRef(null);
  const { reduced } = useMotionPreference();
  useLandingMotion(root, reduced);

  return <div className="landing-page landing-page--ide" ref={root}>
    <section className="landing-hero" data-section aria-labelledby="landing-title">
      <div className="landing-hero__top" data-hero-copy><span>Automatic dependency security for your editor</span><MotionControl /></div>
      <div className="landing-hero__grid">
        <div className="landing-hero__copy">
          <h1 id="landing-title" aria-label="Vulnerable dependencies. Found where you code."><span className="text-mask"><span data-text-line>Vulnerable dependencies.</span></span><span className="text-mask"><span data-text-line>Found where you code.</span></span></h1>
          <p data-hero-copy>Weedout watches dependency files, detects vulnerable packages and CVEs, and reports the evidence and fixed version directly inside VS Code or JetBrains. Change a dependency and the finding updates automatically.</p>
          <div className="landing-hero__actions" data-hero-copy>
            <a className="button button--primary" href={VSCODE} target="_blank" rel="noopener noreferrer">Install for VS Code <ArrowUpRight size={16} /></a>
            <a className="button button--secondary" href={JETBRAINS} target="_blank" rel="noopener noreferrer">Install for JetBrains <ArrowUpRight size={16} /></a>
            <Link className="text-link" to="/dashboard">Open Dashboard <ArrowRight size={15} /></Link>
          </div>
          <p className="landing-hero__note" data-hero-copy><i /> Starts with the project. No Scan, Rescan, Refresh, or Sync command.</p>
        </div>
        <IdeDetectionDemo />
      </div>
    </section>

    <section className="landing-flow" data-section aria-labelledby="flow-title">
      <header data-reveal><h2 id="flow-title">Open the project. Keep coding.</h2><p>Dependency security follows the work instead of becoming another manual workflow.</p></header>
      <ol>{FLOW.map(([title, copy], index) => <li key={title} data-reveal><span>{String(index + 1).padStart(2, "0")}</span><div><strong>{title}</strong><small>{copy}</small></div>{index < FLOW.length - 1 && <ArrowRight size={17} aria-hidden="true" />}</li>)}</ol>
    </section>

    <section className="landing-capabilities" data-section aria-labelledby="capabilities-title">
      <header data-reveal><h2 id="capabilities-title">The useful signal,<br />kept close to the code.</h2><p>Weedout combines advisory data with project context, then shows how it reached the decision. Findings are useful in the editor and available for deeper investigation in the dashboard.</p></header>
      <div className="capability-grid">{CAPABILITIES.map(({ Icon, title, copy }, index) => <article key={title} data-reveal><span>{String(index + 1).padStart(2, "0")}</span><Icon size={24} weight="duotone" /><h3>{title}</h3><p>{copy}</p></article>)}</div>
    </section>

    <section className="landing-rules" data-section aria-labelledby="rules-title">
      <div data-reveal><h2 id="rules-title">Policy belongs<br />in the repository.</h2><p>Use <code>.weedout.yml</code> to define severity thresholds, ignored advisories, package exceptions, and organization policy. Saving the file triggers reevaluation in the IDE.</p><Link to="/docs/scan-rules">Read the rules reference <ArrowUpRight size={15} /></Link></div>
      <pre data-reveal aria-label="Example Weedout rules file"><span>.weedout.yml</span><code>{`severity:\n  direct: high\n  transitive: critical\n\nignore:\n  - cve: CVE-2024-0000\n    reason: not shipped`}</code></pre>
    </section>

    <section className="landing-dashboard-preview" data-section aria-labelledby="dashboard-title">
      <header data-reveal><h2 id="dashboard-title">A workspace for the findings<br />that need a closer look.</h2><p>Search across projects, filter by exploitation and reachability, inspect dependency paths, and keep the remediation evidence attached.</p><Link className="button button--secondary" to="/dashboard">Open Dashboard <ArrowRight size={16} /></Link></header>
      <div className="dashboard-miniature" data-reveal>
        <div className="dashboard-miniature__nav"><strong>WEEDOUT</strong><span>Overview</span><span className="is-active">Findings</span><span>Projects</span><span>Rules</span><span>Integrations</span></div>
        <div className="dashboard-miniature__content"><div><small>FINDINGS / DEMO API</small><h3>Dependency findings</h3></div><div className="mini-filter"><span>Search findings</span><span>Severity: all</span><span>Reachability: all</span></div><article><span className="severity-dot" /><div><strong>CVE-2021-23337</strong><small>lodash@4.17.15 · demo-api</small></div><div><b>HIGH</b><small>direct · reachable</small></div><ArrowUpRight size={16} /></article><article><span className="severity-dot is-muted" /><div><strong>GHSA-example-0002</strong><small>transitive-package@2.1.0 · web</small></div><div><b>MEDIUM</b><small>transitive · unknown</small></div><ArrowUpRight size={16} /></article></div>
      </div>
    </section>

    <section className="landing-engine" data-section aria-labelledby="engine-title">
      <header data-reveal><h2 id="engine-title">One engine.<br />More than one interface.</h2><p>The standalone Go detection engine normalizes dependency graphs, advisory sources, matching, reachability, rules, and explanations. Weedout’s web app and IDE integrations consume the same canonical result.</p></header>
      <div className="engine-map" data-reveal><div><span>Advisory mirror</span><small>OSV · KEV · EPSS context</small></div><ArrowRight /><div className="engine-map__core"><ShieldCheck size={22} weight="duotone" /><span>Go detection engine</span><small>deterministic result</small></div><ArrowRight /><div><span>IDE · Dashboard · CI</span><small>shared finding contract</small></div></div>
      <a className="text-link" href={`${SOURCE}/tree/main/engine`} target="_blank" rel="noopener noreferrer">Explore the engine source <ArrowUpRight size={15} /></a>
    </section>

    <section className="landing-cli" data-section aria-labelledby="cli-title">
      <div data-reveal><span className="wip-badge">Work in progress</span><h2 id="cli-title">CLI, when the terminal is the right place.</h2><p>The CLI remains available as a secondary interface while the automatic IDE workflow becomes the primary way to use Weedout.</p></div><div className="cli-line" data-reveal><TerminalWindow size={18} /><code>weedout scan --ci</code><span>secondary workflow</span></div>
    </section>

    <section className="landing-conclusion" data-section aria-labelledby="landing-close-title">
      <p data-reveal>Dependency security that keeps up with the code.</p><h2 id="landing-close-title" data-reveal>Install Weedout.<br />Open a project.<br />Keep coding.</h2><div className="landing-conclusion__actions" data-reveal><a className="button button--primary" href={VSCODE} target="_blank" rel="noopener noreferrer">Install for VS Code <ArrowUpRight size={16} /></a><a className="button button--secondary" href={JETBRAINS} target="_blank" rel="noopener noreferrer">Install for JetBrains <ArrowUpRight size={16} /></a><Link className="text-link" to="/docs">Read the docs <ArrowRight size={15} /></Link></div>
    </section>
  </div>;
}
