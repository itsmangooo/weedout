import {
  ChevronRight,
  CircleAlert,
  CircleDot,
  FolderKanban,
  LayoutDashboard,
  PackageSearch,
  Settings,
  ShieldCheck,
} from "lucide-react";

const FINDINGS = [
  {
    identifier: "CVE-2021-21315",
    packageName: "systeminformation@5.0.0",
    project: "demo-app",
    severity: "Critical",
    signal: "Review now",
    tone: "critical",
  },
  {
    identifier: "CVE-2021-44906",
    packageName: "minimist@1.2.5",
    project: "demo-app",
    severity: "High",
    signal: "Runtime transitive",
    tone: "high",
  },
];

export function ProductScreenshot() {
  return (
    <figure className="product-shot">
      <figcaption className="product-shot__caption">
        <span><CircleDot aria-hidden="true" size={13} /> Product preview</span>
        <span>Example project data</span>
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
              <span className="product-shot__eyebrow">What needs attention</span>
              <strong className="product-shot__title">Security overview</strong>
              <p>Open dependency findings across your projects.</p>
            </div>
            <span className="product-shot__button" aria-hidden="true">Add project</span>
          </header>

          <div className="product-shot__summary" aria-label="Example project summary">
            <div>
              <span>Needs attention</span>
              <strong>2</strong>
            </div>
            <dl>
              <div><dt>Project</dt><dd>demo-app</dd></div>
              <div><dt>Dependencies scanned</dt><dd>412</dd></div>
              <div><dt>Filtered as noise</dt><dd>33</dd></div>
            </dl>
          </div>

          <section className="product-shot__panel">
            <div className="product-shot__panel-head">
              <div>
                <span>Open findings</span>
                <strong>Start with the signal</strong>
              </div>
              <span>View all <ChevronRight size={12} /></span>
            </div>
            <div className="product-shot__rows">
              {FINDINGS.map((finding) => (
                <div className="product-shot__row" key={finding.identifier}>
                  <span className={`product-shot__severity is-${finding.tone}`} />
                  <div>
                    <strong>{finding.identifier}</strong>
                    <span>{finding.packageName}</span>
                  </div>
                  <span className="product-shot__project">{finding.project}</span>
                  <span className="product-shot__signal">
                    {finding.tone === "critical" ? <CircleAlert aria-hidden="true" size={12} /> : null}
                    {finding.signal}
                  </span>
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
