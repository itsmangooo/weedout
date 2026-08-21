import { CheckCircle2, GitBranch, RotateCcw, ScanLine, ShieldAlert } from "lucide-react";
import { AnimatePresence, motion, useAnimate, useInView, useReducedMotion } from "motion/react";
import { useEffect, useState } from "react";

const WORKFLOW = [
  {
    icon: GitBranch,
    label: "Lockfile",
    primary: "package-lock.json",
    detail: "528 dependencies",
  },
  {
    icon: ScanLine,
    label: "Scan",
    primary: "weedout scan",
    detail: "47 advisory matches",
  },
  {
    icon: CheckCircle2,
    label: "Reachability",
    primary: "3 runtime paths",
    detail: "44 removed from attention",
  },
  {
    icon: ShieldAlert,
    label: "CI decision",
    primary: "1 exploited finding",
    detail: "block and assign",
  },
];

export function ProductWorkflow() {
  const reduceMotion = useReducedMotion();
  const [scope, animate] = useAnimate();
  const inView = useInView(scope, { amount: 0.45, once: true });
  const [active, setActive] = useState(() => (reduceMotion ? WORKFLOW.length - 1 : 0));
  const [run, setRun] = useState(0);

  useEffect(() => {
    if (!inView || reduceMotion) return undefined;

    let cancelled = false;
    let animation;
    const play = async () => {
      try {
        for (let index = 1; index < WORKFLOW.length; index += 1) {
          animation = animate(
            `[data-workflow-step="${index}"]`,
            { opacity: [0.35, 1], x: [-5, 0] },
            { duration: 0.25, ease: [0.16, 1, 0.3, 1] },
          );
          await animation;
          if (cancelled) return;
          setActive(index);
        }
      } catch (error) {
        if (!cancelled) throw error;
      }
    };
    void play();

    return () => {
      cancelled = true;
      animation?.stop();
    };
  }, [animate, inView, reduceMotion, run]);

  function replay() {
    setActive(0);
    setRun((value) => value + 1);
  }

  return (
    <section className="workflow-section" aria-labelledby="workflow-title" ref={scope}>
      <div className="workflow-section__heading">
        <p className="section-label">From repository to decision</p>
        <h2 id="workflow-title">The path is the product.</h2>
        <p>
          Weedout keeps the evidence attached while advisory volume collapses, so the final result
          can move straight into a CI decision.
        </p>
        <button className="workflow-section__replay" onClick={replay} type="button">
          <RotateCcw aria-hidden="true" size={14} /> Replay scan
        </button>
      </div>

      <div className="workflow-sequence">
        <svg aria-hidden="true" className="workflow-sequence__line" preserveAspectRatio="none" viewBox="0 0 1000 60">
          <motion.path
            animate={{ pathLength: active / (WORKFLOW.length - 1) }}
            d="M 15 30 C 220 30, 250 30, 340 30 S 560 30, 660 30 S 820 30, 985 30"
            fill="none"
            initial={false}
            transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1] }}
          />
        </svg>

        <ol>
          {WORKFLOW.map((step, index) => {
            const Icon = step.icon;
            return (
              <li
                className={`${index <= active ? "is-active" : ""}${index === active ? " is-current" : ""}`}
                data-workflow-step={index}
                key={step.label}
              >
                <span className="workflow-sequence__node"><Icon aria-hidden="true" size={17} /></span>
                <span className="workflow-sequence__index">0{index + 1} · {step.label}</span>
                <strong>{step.primary}</strong>
                <small>{step.detail}</small>
              </li>
            );
          })}
        </ol>

        <AnimatePresence mode="wait">
          {active === WORKFLOW.length - 1 ? (
            <motion.div
              animate={{ opacity: 1, x: 0 }}
              className="workflow-sequence__result"
              initial={{ opacity: 0, x: -8 }}
              key="result"
              transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
            >
              <span>CVE-2026-5001</span>
              <strong>minimist@1.2.5</strong>
              <span>checkout-api › commander › minimist</span>
              <em>Exploited · reachable · assign now</em>
            </motion.div>
          ) : null}
        </AnimatePresence>
      </div>
    </section>
  );
}
