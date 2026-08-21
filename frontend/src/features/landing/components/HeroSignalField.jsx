import { RotateCcw, ScanSearch } from "lucide-react";
import {
  AnimatePresence,
  motion,
  useAnimate,
  useInView,
  useMotionValue,
  useReducedMotion,
  useSpring,
  useTransform,
} from "motion/react";
import { useEffect, useState } from "react";

import { ADVISORIES, FILTER_STAGES } from "../data";
import { AnimatedNumber } from "./AnimatedNumber";
import { MagneticLink } from "./MagneticLink";

/**
 * How long the hero takes.
 *
 * Roughly five and a half seconds end to end, against about one before. The
 * story it tells
 * — 47 advisories become 1 decision — only works if each number is on screen
 * long enough to be read, and the previous timing changed them faster than the
 * eye could follow.
 */
const HOLD_FIRST_MS = 700;
const HOLD_STAGE_MS = 1100;
const SWEEP_SECONDS = 0.38;

export function HeroSignalField() {
  const reduceMotion = useReducedMotion();
  const [scope, animate] = useAnimate();
  const inView = useInView(scope, { amount: 0.3, once: true });
  const [stage, setStage] = useState(() => (reduceMotion ? FILTER_STAGES.length - 1 : 0));
  const [run, setRun] = useState(0);
  const pointerX = useMotionValue(0);
  const pointerY = useMotionValue(0);
  const smoothX = useSpring(pointerX, { damping: 28, stiffness: 150 });
  const smoothY = useSpring(pointerY, { damping: 28, stiffness: 150 });
  const rotateY = useTransform(smoothX, [-0.5, 0.5], [-0.65, 0.65]);
  const rotateX = useTransform(smoothY, [-0.5, 0.5], [0.5, -0.5]);

  useEffect(() => {
    if (!inView || reduceMotion) return undefined;

    let cancelled = false;
    let animation;
    let timer;

    const hold = (ms) =>
      new Promise((resolve) => {
        timer = setTimeout(resolve, ms);
      });

    const play = async () => {
      try {
        // The first stage is on screen already; hold it so the starting
        // number registers before anything moves.
        await hold(HOLD_FIRST_MS);
        if (cancelled) return;

        for (let nextStage = 1; nextStage < FILTER_STAGES.length; nextStage += 1) {
          animation = animate(
            ".hero-signal__sweep",
            { scaleX: [0, 1] },
            { duration: SWEEP_SECONDS, ease: [0.16, 1, 0.3, 1] },
          );
          await animation;
          if (cancelled) return;
          setStage(nextStage);

          // And hold each result. Without this the count went 47 → 12 → 3 → 1
          // in about a second, which reads as a flicker rather than an
          // argument.
          await hold(HOLD_STAGE_MS);
          if (cancelled) return;
        }

        animation = animate(
          ".hero-signal__payoff",
          { scale: [0.97, 1], x: [-4, 0] },
          { duration: 0.5, ease: [0.16, 1, 0.3, 1] },
        );
        await animation;
      } catch (error) {
        if (!cancelled) throw error;
      }
    };
    void play();

    return () => {
      cancelled = true;
      clearTimeout(timer);
      animation?.stop();
    };
  }, [animate, inView, reduceMotion, run]);

  const currentStage = FILTER_STAGES[stage];
  const visibleAdvisories = reduceMotion
    ? ADVISORIES
    : ADVISORIES.filter((item) => item.survives >= stage);

  function handlePointerMove(event) {
    if (reduceMotion || event.pointerType === "touch") return;
    const bounds = event.currentTarget.getBoundingClientRect();
    pointerX.set((event.clientX - bounds.left) / bounds.width - 0.5);
    pointerY.set((event.clientY - bounds.top) / bounds.height - 0.5);
  }

  function resetPointer() {
    pointerX.set(0);
    pointerY.set(0);
  }

  function replay() {
    setStage(0);
    setRun((value) => value + 1);
  }

  return (
    <section className="landing-hero" aria-labelledby="foundation-title" ref={scope}>
      <div className="landing-hero__heading">
        <p className="eyebrow">Dependency CVE alerts, filtered by reachability</p>
        <div className="landing-hero__title-mask">
          <motion.h1
            animate={{ y: 0 }}
            id="foundation-title"
            initial={reduceMotion ? false : { y: "108%" }}
            transition={{ duration: 0.68, ease: [0.16, 1, 0.3, 1] }}
          >
            Most CVE alerts cannot reach your code.
          </motion.h1>
        </div>
        <p>
          Weedout watches your lockfiles, matches every advisory against them, then traces
          whether your application can actually reach the vulnerable code. You hear about the
          ones that can — the ones being exploited first.
        </p>
      </div>

      <motion.div
        className={`hero-signal hero-signal--${currentStage.id}${reduceMotion ? " hero-signal--reduced" : ""}`}
        onPointerLeave={resetPointer}
        onPointerMove={handlePointerMove}
        style={{ rotateX, rotateY, transformPerspective: 1400 }}
      >
        <div className="hero-signal__meta">
          <span><ScanSearch aria-hidden="true" size={15} /> package-lock.json</span>
          <AnimatePresence mode="wait" initial={false}>
            <motion.span
              animate={{ opacity: 1, y: 0 }}
              className="hero-signal__phase"
              exit={{ opacity: 0, y: -5 }}
              initial={{ opacity: 0, y: 5 }}
              key={currentStage.id}
            >
              {currentStage.verb} · {currentStage.label.toLowerCase()}
            </motion.span>
          </AnimatePresence>
          <button className="hero-signal__replay" onClick={replay} type="button">
            <RotateCcw aria-hidden="true" size={13} /> Replay filter
          </button>
        </div>

        <span aria-hidden="true" className="hero-signal__sweep" />

        <div aria-hidden="true" className="hero-signal__current-count">
          <AnimatedNumber value={currentStage.value} />
          <small>{currentStage.label}</small>
        </div>

        <motion.ul
          aria-label="Illustrative advisory filtering result"
          className="hero-signal__advisories"
          layout
        >
          <AnimatePresence initial={false} mode="popLayout">
            {visibleAdvisories.map((item) => (
              <motion.li
                className={[
                  item.survives === 3 ? "hero-signal__payoff" : "",
                  reduceMotion && item.survives < 2 ? "is-filtered" : "",
                  reduceMotion && item.survives === 2 ? "is-reachable" : "",
                ].filter(Boolean).join(" ")}
                exit={{ opacity: 0, scale: 0.82, y: -8, filter: "blur(4px)" }}
                initial={{ opacity: 0, scale: 0.96 }}
                key={item.id}
                layout
                style={{ "--entry-rotate": `${item.rotate}deg`, "--entry-x": `${item.x}%`, "--entry-y": `${item.y}%` }}
                transition={{ duration: 0.26, ease: [0.16, 1, 0.3, 1], layout: { duration: 0.32 } }}
              >
                <span className="hero-signal__advisory">{item.advisory}</span>
                <strong>{item.packageName} <small>{item.version}</small></strong>
                <span className="hero-signal__path">{item.path}</span>
                {stage >= 1 ? <span className="hero-signal__reachability">{item.reachability}</span> : null}
                {item.survives === 3 && stage === 3 ? (
                  <span className="hero-signal__exploited">Exploited in the wild</span>
                ) : null}
              </motion.li>
            ))}
          </AnimatePresence>
        </motion.ul>

        <dl className="hero-signal__counts" aria-live="polite">
          <div className={stage >= 0 ? "is-active" : ""}>
            <dt>Advisories</dt>
            <dd>47</dd>
          </div>
          <div className={stage >= 2 ? "is-active" : ""}>
            <dt>Reachable</dt>
            <dd>{stage >= 2 ? 3 : "—"}</dd>
          </div>
          <div className={stage >= 3 ? "is-active is-payoff" : ""}>
            <dt>Exploited</dt>
            <dd>{stage >= 3 ? <AnimatedNumber value={1} /> : "—"}</dd>
          </div>
        </dl>
      </motion.div>

      <div className="landing-hero__actions">
        <MagneticLink to="/dashboard">See what needs attention</MagneticLink>
        <span>Free for one project · no card · results in about a minute</span>
      </div>
    </section>
  );
}
