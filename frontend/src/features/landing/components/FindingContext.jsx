import { ArrowRight, GitBranch, RotateCcw, Wrench } from "lucide-react";
import { useState } from "react";

import { DEMO_FINDINGS } from "../demo";

export function FindingContext({
  finding = DEMO_FINDINGS[0],
  compact = false,
}) {
  const [trace, setTrace] = useState(0);
  return (
    <article
      className={`finding-context ${compact ? "finding-context--compact" : ""}`}
      aria-label={`Context for ${finding.packageName}`}
    >
      {!compact && (
        <header className="finding-context__head">
          <div>
            <span className="demo-label">CVE</span>
            <h3>{finding.id}</h3>
          </div>
          <span
            className={`demo-severity is-${finding.severity.toLowerCase()}`}
          >
            {finding.severity} severity
          </span>
        </header>
      )}
      <dl className="finding-context__package">
        <div>
          <dt>Package</dt>
          <dd>
            {finding.packageName}@{finding.version}
          </dd>
        </div>
        <ArrowRight aria-hidden="true" size={16} />
        <div>
          <dt>Fixed version</dt>
          <dd>{finding.fixed}</dd>
        </div>
      </dl>
      <div className="finding-context__path">
        <div className="finding-context__label">
          <span>
            <GitBranch size={14} aria-hidden="true" /> Dependency path
          </span>
          <button
            type="button"
            onClick={() => setTrace((value) => value + 1)}
            aria-label="Replay dependency path"
          >
            <RotateCcw size={13} aria-hidden="true" /> Trace
          </button>
        </div>
        <ol key={trace} aria-label="Example dependency path">
          {finding.path.map((part) => (
            <li key={part}>
              <code>{part}</code>
            </li>
          ))}
        </ol>
      </div>
      <details className="finding-context__evidence">
        <summary>
          Evidence <span>{finding.reachability}</span>
        </summary>
        <div>
          <code>{finding.source}</code>
          <p>{finding.evidence}</p>
        </div>
      </details>
      <div className="finding-context__action">
        <Wrench size={15} aria-hidden="true" />
        <div>
          <span>Recommended action</span>
          <p>{finding.action}</p>
        </div>
      </div>
    </article>
  );
}
