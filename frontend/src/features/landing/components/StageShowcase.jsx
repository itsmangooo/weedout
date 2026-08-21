import { Pause, Play, RotateCcw } from "lucide-react";
import { AnimatePresence, motion, useInView, useReducedMotion } from "motion/react";
import { useEffect, useRef, useState } from "react";

import { ADVISORY_FIELD, SHOWCASE_STAGES, STAGE_DURATION_MS } from "../stages";
import { AnimatedNumber } from "./AnimatedNumber";

/**
 * The four stages, played through as one continuous graphic.
 *
 * Deliberately one field of dots that changes state four times, rather than
 * four separate illustrations. The claim being made is that a large number
 * becomes a small one without anything being hidden — and you can only show
 * that by keeping the same dots on screen while most of them go quiet.
 *
 * Each stage holds for three seconds. That is slow on purpose: the previous
 * version of this section advanced every quarter of a second, which meant the
 * numbers changed before anyone had finished reading them.
 */
export function StageShowcase() {
  const containerRef = useRef(null);
  const reduceMotion = useReducedMotion();
  const inView = useInView(containerRef, { amount: 0.4, once: true });

  // With reduced motion the last stage is the honest thing to show: it is the
  // outcome the section exists to describe, and the intermediate states are
  // only interesting as movement.
  const [chosen, setActive] = useState(0);

  // Derived rather than stored. useReducedMotion resolves after the first
  // render, and somebody can change the setting mid-visit — deriving means
  // either of those lands on the outcome instead of freezing the story
  // halfway through, without an effect that writes state back.
  const active = reduceMotion ? SHOWCASE_STAGES.length - 1 : chosen;
  const [playing, setPlaying] = useState(true);
  const [reachedEnd, setFinished] = useState(false);
  const finished = reduceMotion || reachedEnd;

  useEffect(() => {
    if (!inView || reduceMotion || !playing || finished) return undefined;

    const timer = setTimeout(() => {
      setActive((current) => {
        if (current >= SHOWCASE_STAGES.length - 1) {
          setFinished(true);
          return current;
        }
        return current + 1;
      });
    }, STAGE_DURATION_MS);

    return () => clearTimeout(timer);
  }, [active, finished, inView, playing, reduceMotion]);

  const stage = SHOWCASE_STAGES[active];

  // Zero-length when motion is reduced, rather than simply unanimated.
  //
  // AnimatePresence keeps an exiting node mounted until its exit animation
  // reports completion, and an animation that never runs never reports. Left
  // alone, every stage change leaves its predecessor in the DOM — two captions
  // stacked inside an aria-live region, which a screen reader reads out both
  // of.
  const swap = reduceMotion
    ? { duration: 0 }
    : { duration: 0.4, ease: [0.16, 1, 0.3, 1] };

  function replay() {
    setActive(0);
    setFinished(false);
    setPlaying(true);
  }

  return (
    <section aria-labelledby="showcase-title" className="showcase" ref={containerRef}>
      <div className="showcase__heading">
        <p className="section-label">How the number gets small</p>
        <h2 id="showcase-title">Four passes. Nothing thrown away quietly.</h2>
        <p>
          Every advisory that stops being an alert is still there, with the reason it
          was set aside. The point is not a smaller number — it is a number you can
          defend.
        </p>
      </div>

      <div className="showcase__stage">
        <AdvisoryField
          neutral={Boolean(stage.neutral)}
          reduceMotion={reduceMotion}
          threshold={stage.threshold}
        />

        <div className="showcase__readout">
          <AnimatePresence initial={false}>
            <motion.div
              animate={{ opacity: 1, y: 0 }}
              className="showcase__metric"
              exit={{ opacity: 0, y: -10 }}
              initial={{ opacity: 0, y: 10 }}
              key={stage.id}
              transition={swap}
            >
              <strong>
                <AnimatedNumber value={stage.metric.value} />
              </strong>
              <span>{stage.metric.unit}</span>
            </motion.div>
          </AnimatePresence>
        </div>
      </div>

      {/* aria-live so the caption is announced as it changes; the graphic
          itself is decorative and hidden from assistive technology. */}
      <div aria-live="polite" className="showcase__caption">
        <AnimatePresence initial={false}>
          <motion.div
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            initial={{ opacity: 0, y: 8 }}
            key={stage.id}
            transition={swap}
          >
            <h3>{stage.headline}</h3>
            <p>{stage.body}</p>
          </motion.div>
        </AnimatePresence>
      </div>

      <ol className="showcase__steps">
        {SHOWCASE_STAGES.map((entry, index) => (
          <li
            className={`showcase__step${index === active ? " is-current" : ""}${
              index < active ? " is-done" : ""
            }`}
            key={entry.id}
          >
            <button
              aria-current={index === active ? "step" : undefined}
              onClick={() => {
                setActive(index);
                setFinished(index === SHOWCASE_STAGES.length - 1);
              }}
              type="button"
            >
              <span className="showcase__step-index">{entry.index}</span>
              <span className="showcase__step-label">{entry.label}</span>
            </button>

            {/* The bar tracks the hold, so somebody can see how long is left
                rather than wondering whether it has stalled. */}
            <span className="showcase__step-track">
              <motion.span
                animate={{
                  scaleX: index < active ? 1 : index === active && !finished ? [0, 1] : 0,
                }}
                className="showcase__step-fill"
                initial={false}
                key={`${entry.id}-${active}-${finished}`}
                transition={
                  index === active && !finished && !reduceMotion
                    ? { duration: STAGE_DURATION_MS / 1000, ease: "linear" }
                    : { duration: 0.2 }
                }
              />
            </span>
          </li>
        ))}
      </ol>

      {!reduceMotion ? (
        <div className="showcase__controls">
          {finished ? (
            <button onClick={replay} type="button">
              <RotateCcw aria-hidden="true" size={13} /> Play again
            </button>
          ) : (
            <button onClick={() => setPlaying((value) => !value)} type="button">
              {playing ? (
                <>
                  <Pause aria-hidden="true" size={13} /> Pause
                </>
              ) : (
                <>
                  <Play aria-hidden="true" size={13} /> Resume
                </>
              )}
            </button>
          )}
        </div>
      ) : null}
    </section>
  );
}

/**
 * The field of 47.
 *
 * A dot is never removed — it dims. That is the whole argument: an advisory
 * that stops being an alert has not been discarded, and a graphic that deleted
 * it would be illustrating a different, worse product.
 */
function AdvisoryField({ neutral, reduceMotion, threshold }) {
  return (
    <svg
      aria-hidden="true"
      className="showcase__field"
      preserveAspectRatio="xMidYMid meet"
      viewBox="0 0 640 360"
    >
      {ADVISORY_FIELD.map((node, index) => {
        const lit = node.survives > threshold;
        const exploited = node.survives === 3 && threshold >= 1;

        return (
          <motion.circle
            animate={{
              opacity: neutral ? 0.5 : lit ? 1 : 0.13,
              r: lit ? node.r : node.r * 0.62,
            }}
            className={`showcase__dot${exploited ? " showcase__dot--exploited" : ""}${
              lit && !neutral ? " is-lit" : ""
            }`}
            cx={node.x}
            cy={node.y}
            initial={false}
            key={node.id}
            r={node.r}
            transition={
              reduceMotion
                ? { duration: 0 }
                : {
                    duration: 0.7,
                    // Staggered by position so the field settles in a wave
                    // rather than blinking at once — the eye can follow a wave.
                    delay: (index % 12) * 0.03,
                    ease: [0.16, 1, 0.3, 1],
                  }
            }
          />
        );
      })}

      {/* The one that matters, ringed once it is the only one left. */}
      {threshold >= 1 ? (
        <motion.circle
          animate={{ opacity: [0, 1], scale: [0.6, 1] }}
          className="showcase__halo"
          cx={ADVISORY_FIELD[0].x}
          cy={ADVISORY_FIELD[0].y}
          initial={false}
          r={22}
          transition={reduceMotion ? { duration: 0 } : { duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
        />
      ) : null}
    </svg>
  );
}
