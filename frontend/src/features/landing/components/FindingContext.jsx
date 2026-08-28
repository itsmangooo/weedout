import { ArrowRight, CheckCircle2, GitBranch, PackageSearch, Wrench } from "lucide-react";

export function FindingContext() {
  return (
    <article className="finding-context" aria-label="Example Weedout finding context">
      <header className="finding-context__head">
        <div>
          <span className="finding-context__eyebrow">Illustrative finding</span>
          <h3>CVE-2021-44906</h3>
        </div>
        <span className="finding-context__severity">High severity</span>
      </header>

      <div className="finding-context__package">
        <PackageSearch aria-hidden="true" size={18} />
        <div>
          <span>Affected package</span>
          <strong>minimist@1.2.5</strong>
        </div>
        <ArrowRight aria-hidden="true" size={16} />
        <div>
          <span>Fixed version</span>
          <strong>1.2.6</strong>
        </div>
      </div>

      <div className="finding-context__path">
        <div className="finding-context__label">
          <GitBranch aria-hidden="true" size={16} /> Dependency path
        </div>
        <ol aria-label="Example dependency path">
          <li>demo-app</li>
          <li>mkdirp</li>
          <li>minimist</li>
        </ol>
      </div>

      <dl className="finding-context__facts">
        <div>
          <dt>Reachability</dt>
          <dd>Runtime transitive</dd>
          <small>
            Manifest-level context: it ships with the application. Weedout does not claim the
            vulnerable function executes.
          </small>
        </div>
        <div>
          <dt>Why it surfaced</dt>
          <dd><CheckCircle2 aria-hidden="true" size={14} /> Runtime dependency · high severity</dd>
        </div>
        <div>
          <dt>Suggested action</dt>
          <dd><Wrench aria-hidden="true" size={14} /> Update to 1.2.6 or later</dd>
        </div>
      </dl>
    </article>
  );
}
