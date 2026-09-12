import { ArrowUpRight, CircleDot } from "lucide-react";
import { useId, useState } from "react";

import { DEMO_FINDINGS } from "../demo";
import { FindingContext } from "./FindingContext";

export function ProductScreenshot() {
  const [selected, setSelected] = useState(DEMO_FINDINGS[0]);
  const detailId = useId();
  return (
    <figure className="product-shot">
      <figcaption className="product-shot__caption">
        <span>
          <CircleDot aria-hidden="true" size={13} /> Product preview
        </span>
        <span>Illustrative demo · not a live scan</span>
      </figcaption>
      <div className="product-shot__content">
        <div className="product-shot__head">
          <div>
            <span className="demo-label">demo-app / findings</span>
            <h2>
              A shorter list.
              <br />A clearer next step.
            </h2>
          </div>
          <span className="product-shot__count">
            03<span>need attention</span>
          </span>
        </div>
        <p className="product-shot__hint">
          Select a finding to inspect its context{" "}
          <ArrowUpRight size={13} aria-hidden="true" />
        </p>
        <div className="demo-findings" aria-label="Preview findings">
          {DEMO_FINDINGS.map((finding, index) => (
            <button
              className={`demo-finding ${selected.id === finding.id ? "is-selected" : ""}`}
              key={finding.id}
              type="button"
              aria-label={`0${index + 1} ${finding.packageName}, ${finding.id}, ${finding.severity} severity`}
              aria-pressed={selected.id === finding.id}
              aria-controls={detailId}
              onClick={() => setSelected(finding)}
            >
              <span className="demo-finding__index">0{index + 1}</span>
              <span>
                <strong>{finding.packageName}</strong>
                <small>{finding.id}</small>
              </span>
              <span
                className={`demo-severity is-${finding.severity.toLowerCase()}`}
              >
                {finding.severity}
              </span>
              <ArrowUpRight size={15} aria-hidden="true" />
            </button>
          ))}
        </div>
        <div id={detailId}>
          <FindingContext key={selected.id} finding={selected} compact />
        </div>
      </div>
    </figure>
  );
}
