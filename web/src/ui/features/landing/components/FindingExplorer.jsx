import { ArrowRight } from "@phosphor-icons/react/ArrowRight";
import { CaretDown as ChevronDown } from "@phosphor-icons/react/CaretDown";
import { GitBranch } from "@phosphor-icons/react/GitBranch";
import { Wrench } from "@phosphor-icons/react/Wrench";
import { useId, useState } from "react";
import { DEMO_FINDINGS } from "../demo";

export function FindingExplorer() {
  const [selected, setSelected] = useState(0);
  const id = useId();
  const finding = DEMO_FINDINGS[selected];
  return <div className="finding-explorer">
    <div className="finding-explorer__queue"><p className="eyebrow">Illustrative shortlist / demo-app</p><h3>Choose your<br />next decision.</h3>
      <div role="group" aria-label="Demo findings">{DEMO_FINDINGS.map((item, index) => <button key={item.id} type="button" aria-label={`0${index + 1} ${item.packageName} ${item.id}, ${item.severity}`} aria-pressed={selected === index} aria-controls={id} onClick={() => setSelected(index)}><span className="mono">0{index + 1}</span><span><strong>{item.packageName}</strong><small>{item.id}</small></span><span className={`status-tag status-tag--${item.severity.toLowerCase()}`}>{item.severity}</span><ArrowRight size={16} aria-hidden="true" /></button>)}</div>
      <details><summary>And the other 44? <ChevronDown size={14} aria-hidden="true" /></summary><p>Project rules filter the remaining matches in this example. Filtered findings remain reviewable with their suppression reason. Source reachability is a separate signal.</p></details>
    </div>
    <article id={id} className="finding-explorer__detail" aria-label={`Context for ${finding.packageName}`}>
      <div key={finding.id} className="detail-change">
        <header><span className="eyebrow">CVE / {finding.id}</span><span className={`status-tag status-tag--${finding.severity.toLowerCase()}`}>{finding.severity} severity</span></header>
        <h3>{finding.packageName}<span>@{finding.version}</span></h3>
        <dl className="explorer-facts"><div><dt>Package</dt><dd>{finding.packageName}@{finding.version}</dd></div><div><dt>Fixed version</dt><dd>{finding.fixed}</dd></div><div><dt>Reachability</dt><dd>{finding.reachability}</dd></div></dl>
        <p className="eyebrow"><GitBranch size={14} aria-hidden="true" /> Dependency path</p>
        <ol className="dependency-path" aria-label="Dependency path">{finding.path.map((node) => <li key={node}><code>{node}</code></li>)}</ol>
        <details className="evidence-disclosure"><summary>Evidence <ChevronDown size={15} aria-hidden="true" /></summary><code>{finding.source}</code><p>{finding.evidence}</p></details>
        <div className="recommended-action"><Wrench size={17} aria-hidden="true" /><div><p className="eyebrow">Recommended action</p><p>{finding.action}</p></div></div>
      </div>
    </article>
  </div>;
}
