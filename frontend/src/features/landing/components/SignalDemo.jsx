import { ArrowDown, ArrowRight, RotateCcw } from "lucide-react";
import { useId, useState } from "react";

import { WeedoutLogo } from "../../../components/brand/WeedoutLogo";
import { DEMO_FINDINGS } from "../demo";
import { FindingContext } from "./FindingContext";

export function SignalDemo() {
  const [applied, setApplied] = useState(false);
  const [selected, setSelected] = useState(DEMO_FINDINGS[0]);
  const resultId = useId();
  const detailId = useId();
  return (
    <div className={`signal-demo ${applied ? "is-applied" : ""}`}>
      <div className="signal-demo__caption">
        <span>Interactive example / demo-app</span>
        <span>Illustrative counts, not product metrics</span>
      </div>
      <div className="signal-demo__flow">
        <div className="signal-demo__input">
          <span className="demo-label">01 / The noise</span>
          <p className="signal-demo__number">47</p>
          <h3>vulnerability alerts</h3>
          <div className="signal-demo__marks" aria-hidden="true">
            {Array.from({ length: 47 }, (_, index) => (
              <span key={index} className={index < 3 ? "is-kept" : ""} />
            ))}
          </div>
          <p>Every match asks for your attention.</p>
        </div>
        <div className="signal-demo__processor">
          <ArrowRight
            className="signal-demo__arrow"
            aria-hidden="true"
            size={24}
          />
          <div className="signal-demo__brand">
            <WeedoutLogo />
          </div>
          <p>
            Advisory + dependency path
            <br />+ project rules
          </p>
          <button
            className="button button--primary"
            type="button"
            aria-expanded={applied}
            aria-controls={resultId}
            onClick={() => setApplied((value) => !value)}
          >
            {applied ? (
              <>
                <RotateCcw size={14} aria-hidden="true" /> Reset demo
              </>
            ) : (
              <>
                Add project context <ArrowRight size={15} aria-hidden="true" />
              </>
            )}
          </button>
          <ArrowRight
            className="signal-demo__arrow"
            aria-hidden="true"
            size={24}
          />
        </div>
        <div className="signal-demo__output">
          <span className="demo-label">02 / The decision</span>
          <p className="signal-demo__number">3</p>
          <h3>findings that need attention</h3>
          <p>A shortlist with the reasons attached.</p>
          <span className="signal-demo__instruction">
            <ArrowDown size={14} aria-hidden="true" />{" "}
            {applied
              ? "Select a finding below"
              : "Add context to open the shortlist"}
          </span>
        </div>
      </div>
      <div id={resultId} hidden={!applied} className="signal-demo__result">
        <div className="signal-demo__queue">
          <p className="demo-label">03 / Inspect the context</p>
          <h3>
            Three findings.
            <br />
            Your next decision.
          </h3>
          <div className="demo-findings" aria-label="Shortlisted demo findings">
            {DEMO_FINDINGS.map((finding) => (
              <button
                className={`demo-finding ${selected.id === finding.id ? "is-selected" : ""}`}
                key={finding.id}
                type="button"
                aria-pressed={selected.id === finding.id}
                aria-controls={detailId}
                onClick={() => setSelected(finding)}
              >
                <span>
                  <strong>{finding.packageName}</strong>
                  <small>{finding.id}</small>
                </span>
                <span
                  className={`demo-severity is-${finding.severity.toLowerCase()}`}
                >
                  {finding.severity}
                </span>
                <ArrowRight size={15} aria-hidden="true" />
              </button>
            ))}
          </div>
          <details className="signal-demo__filtered">
            <summary>What happened to the other 44?</summary>
            <p>
              In this example, project rules filter the remaining matches.
              Filtered findings keep their suppression reason and remain
              available for review. Source reachability is separate from the
              alert policy.
            </p>
          </details>
        </div>
        <div id={detailId}>
          <FindingContext key={selected.id} finding={selected} />
        </div>
      </div>
    </div>
  );
}
