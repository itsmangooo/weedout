import { useEffect, useRef, useState } from "react";
import { ArrowRight } from "@phosphor-icons/react/ArrowRight";
import { LiquidGlass } from "../../../components/ui/LiquidGlass";
import { DependencyField } from "./DependencyField";

const STAGES = [
  { label: "Raw alerts", title: "Your dependency scanner found 47 vulnerabilities. Now what?", copy: "Traditional scanners are good at finding vulnerabilities. Weedout adds project context so you can focus on the findings that actually need attention.", marker: "47", unit: "advisories" },
  { label: "Add context", title: "Weedout adds the missing context.", copy: "It checks dependency paths, known exploitation data, severity, project rules, and supported reachability evidence.", marker: "Weedout", unit: "dependency + project context" },
  { label: "Clear action", title: "Three findings that need attention.", copy: "Each surfaced finding keeps its evidence, dependency path, and fixed version attached, so the next action is clear.", marker: "3", unit: "prioritized findings" },
];

export function AnalysisStory({ reducedMotion = false }) {
  const ref = useRef(null);
  const [stage, setStage] = useState(0);
  const [progress, setProgress] = useState(0);
  useEffect(() => {
    const node = ref.current;
    const update = (event) => { const next = Math.min(2, Math.floor(event.detail * 2.99)); setStage(next); setProgress(next / 2); };
    node.addEventListener("analysis-progress", update);
    return () => node.removeEventListener("analysis-progress", update);
  }, []);
  function select(index) {
    setStage(index); setProgress(index / 2);
    ref.current.dispatchEvent(new CustomEvent("analysis-progress", { detail: index / 2 }));
  }
  const current = STAGES[stage];
  return <section className="analysis-story" id="analysis" ref={ref} data-analysis-story data-section aria-labelledby="analysis-heading">
    <LiquidGlass className="analysis-stage" data-analysis-stage interactive>
      <div className="analysis-flow" aria-label="47 advisories processed by Weedout become 3 findings that need attention"><span><strong>47 advisories</strong></span><ArrowRight size={18} aria-hidden="true" /><strong className="analysis-flow__brand">Weedout</strong><ArrowRight size={18} aria-hidden="true" /><span><strong>3 findings</strong> that need attention</span><small>Interactive example · not a live scan</small></div>
      <div className="analysis-stage__body">
        <div className="analysis-stage__copy" key={stage}><span className={`analysis-stage__counter${current.marker === "Weedout" ? " is-word" : ""}`}>{current.marker}</span><p className="analysis-stage__unit">{current.unit}</p><h2 id="analysis-heading">{current.title}</h2><p>{current.copy}</p></div>
        <DependencyField storyRef={ref} progress={progress} reducedMotion={reducedMotion} />
      </div>
      <div className="analysis-controls" role="group" aria-label="Analysis stages">{STAGES.map((item, index) => <button key={item.label} type="button" aria-pressed={stage === index} onClick={() => select(index)}><span>0{index + 1}</span>{item.label}<span aria-hidden="true">↗</span></button>)}</div>
    </LiquidGlass>
  </section>;
}
