import {
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  CircleDot,
  FolderKanban,
  LayoutDashboard,
  PackageSearch,
  Settings,
  ShieldCheck,
  Sparkles,
} from "lucide-react";

const FINDINGS = [
  {
    packageName: "runtime package",
    severity: "Critical",
    signal: "Known exploited",
    tone: "critical",
  },
  {
    packageName: "transitive package",
    severity: "High",
    signal: "Runtime reachable",
    tone: "high",
  },
  {
    packageName: "development package",
    severity: "Medium",
    signal: "Filtered out",
    tone: "filtered",
  },
];

export function ProductScreenshot({ compact = false }) {
  return (
    <figure className={`product-shot${compact ? " product-shot--compact" : ""}`}>
      <figcaption className="product-shot__caption">
        <span><CircleDot aria-hidden="true" size={13} /> Product preview</span>
        <span>Example project</span>
      </figcaption>

      <div className="product-shot__window">
        <aside aria-hidden="true" className="product-shot__sidebar">
          <div className="product-shot__brand">
            <ShieldCheck size={17} /> <span>WEEDOUT</span>
          </div>
          <div className="product-shot__nav">
            <span className="is-active"><LayoutDashboard size={14} /> Overview</span>
            <span><FolderKanban size={14} /> Projects</span>
            <span><PackageSearch size={14} /> Findings</span>
          </div>
          <span className="product-shot__settings"><Settings size={14} /> Settings</span>
        </aside>

        <div className="product-shot__content">
          <header className="product-shot__head">
            <div>
              <span className="product-shot__eyebrow">Workspace overview</span>
              <strong className="product-shot__title">Security overview</strong>
              <p>Everything that needs a decision, across every project.</p>
            </div>
            <span className="product-shot__button" aria-hidden="true">Add project</span>
          </header>

          <div className="product-shot__metrics">
            <article>
              <span>Open findings</span>
              <strong>3</strong>
              <small><CircleAlert size={12} /> 1 known exploited</small>
            </article>
            <article>
              <span>Dependencies</span>
              <strong>143</strong>
              <small><CheckCircle2 size={12} /> 1 project checked</small>
            </article>
            <article>
              <span>Noise removed</span>
              <strong>73%</strong>
              <small><Sparkles size={12} /> 8 filtered findings</small>
            </article>
          </div>

          <section className="product-shot__panel">
            <div className="product-shot__panel-head">
              <div>
                <span>Dependency findings</span>
                <strong>Needs attention</strong>
              </div>
              <span>View all <ChevronRight size={12} /></span>
            </div>
            <div className="product-shot__rows">
              {FINDINGS.map((finding) => (
                <div className="product-shot__row" key={finding.packageName}>
                  <span className={`product-shot__severity is-${finding.tone}`} />
                  <strong>{finding.packageName}</strong>
                  <span>{finding.signal}</span>
                  <em className={`is-${finding.tone}`}>{finding.severity}</em>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </figure>
  );
}
