import {
  AnimatePresence,
  motion,
  useMotionValueEvent,
  useReducedMotion,
  useScroll,
  useSpring,
  useTransform,
} from "motion/react";
import { useRef, useState } from "react";

import { ADVISORIES, FILTER_STAGES } from "../data";
import { AnimatedNumber } from "./AnimatedNumber";

export function ScrollFilterStory() {
  const sectionRef = useRef(null);
  const reduceMotion = useReducedMotion();
  const [stage, setStage] = useState(() => (reduceMotion ? FILTER_STAGES.length - 1 : 0));
  const { scrollYProgress } = useScroll({
    target: sectionRef,
    offset: ["start start", "end end"],
  });
  const progress = useSpring(scrollYProgress, { damping: 34, stiffness: 150 });
  const progressScale = useTransform(progress, [0, 1], [0.04, 1]);
  const fieldDrift = useTransform(progress, [0, 1], [24, -18]);

  useMotionValueEvent(scrollYProgress, "change", (latest) => {
    if (reduceMotion) return;
    const next = Math.min(FILTER_STAGES.length - 1, Math.floor(latest * FILTER_STAGES.length));
    setStage((current) => (current === next ? current : next));
  });

  const currentStage = FILTER_STAGES[stage];
  const visibleAdvisories = ADVISORIES.filter((item) => item.survives >= stage);

  return (
    <section className={`filter-story filter-story--${currentStage.id}`} ref={sectionRef}>
      <div className="filter-story__sticky">
        <div className="filter-story__intro">
          <p className="section-label">The Weedout moment</p>
          <h2>Watch the page get quieter.</h2>
          <p>
            Every step removes a reason to interrupt the team. What remains has a dependency path,
            runtime reachability, and a reason to act now.
          </p>
        </div>

        <div className="filter-story__progress" aria-hidden="true">
          <motion.span style={{ scaleX: progressScale }} />
        </div>

        <div className="filter-story__stage">
          <ol className="filter-story__steps" aria-label="Filtering stages">
            {FILTER_STAGES.map((item, index) => (
              <li className={index <= stage ? "is-active" : ""} key={item.id}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong>{item.label}</strong>
                <small>{item.value}</small>
              </li>
            ))}
          </ol>

          <motion.div className="filter-story__field" style={{ y: reduceMotion ? 0 : fieldDrift }}>
            <div className="filter-story__measure" aria-live="polite">
              <AnimatedNumber value={currentStage.value} />
              <span>{currentStage.label}</span>
            </div>

            <motion.ul layout aria-label={`${currentStage.label} after filtering`}>
              <AnimatePresence initial={false} mode="popLayout">
                {visibleAdvisories.map((item) => (
                  <motion.li
                    className={item.survives === 3 ? "is-exploited" : ""}
                    exit={{ opacity: 0, x: 18, height: 0, filter: "blur(3px)" }}
                    key={item.id}
                    layout
                    transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1], layout: { duration: 0.32 } }}
                  >
                    <span>{item.advisory}</span>
                    <strong>{item.packageName}<small>@{item.version}</small></strong>
                    <span>{stage >= 1 ? item.reachability : item.path}</span>
                    {stage === 3 ? <em>Actionable signal</em> : null}
                  </motion.li>
                ))}
              </AnimatePresence>
            </motion.ul>
          </motion.div>
        </div>

        <div className="filter-story__payoff" aria-label="Filtering outcome">
          <span><strong>47</strong> advisories</span>
          <span aria-hidden="true">→</span>
          <span><strong>3</strong> reachable</span>
          <span aria-hidden="true">→</span>
          <span className="is-exploited"><strong>1</strong> exploited</span>
        </div>
      </div>
    </section>
  );
}
