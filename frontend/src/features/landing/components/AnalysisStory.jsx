import { useEffect, useRef, useState } from "react";
import { ArrowDownRight } from "@phosphor-icons/react/ArrowDownRight";
import { LiquidGlass } from "../../../components/ui/LiquidGlass";
import { DependencyField } from "./DependencyField";

const STAGES = [
  { label: "Raw alerts", title: "A match is only the beginning.", copy: "47 advisories. One project. A list of package names still leaves you with the hard part: deciding what matters.", count: 47, unit: "raw alerts" },
  { label: "Add context", title: "Follow the dependency. Read the evidence.", copy: "Weedout adds dependency paths, advisory details and source-import evidence. Project rules determine which matches need attention.", count: null, unit: "analysis + project rules" },
  { label: "Clear action", title: "Three findings. Reasons attached.", copy: "Inspect the path, the observed evidence and the available fixed version. The other matches remain available for review.", count: 3, unit: "findings to review" },
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
      <div className="analysis-stage__rail"><span className="eyebrow">01 — From security noise to a decision</span><span className="eyebrow">Interactive example · not a live scan</span></div>
      <div className="analysis-stage__body">
        <div className="analysis-stage__copy" key={stage}><span className="analysis-stage__counter">{current.count ?? <ArrowDownRight size={60} aria-hidden="true" />}</span><p className="eyebrow">{current.unit}</p><h2 id="analysis-heading">{current.title}</h2><p>{current.copy}</p></div>
        <DependencyField storyRef={ref} progress={progress} reducedMotion={reducedMotion} />
      </div>
      <div className="analysis-controls" role="group" aria-label="Analysis stages">{STAGES.map((item, index) => <button key={item.label} type="button" aria-pressed={stage === index} onClick={() => select(index)}><span>0{index + 1}</span>{item.label}<span aria-hidden="true">↗</span></button>)}</div>
    </LiquidGlass>
  </section>;
}
