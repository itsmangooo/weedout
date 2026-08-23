import { motion, useInView, useReducedMotion } from "motion/react";
import { useRef } from "react";
import { Link } from "react-router";

import { LANE_COUNT, PARTICLES, PIPELINE_FACTS, SURVIVOR_ID } from "../pipeline";

/**
 * The CLI, on the landing page.
 *
 * The graphic is the product's whole argument in one motion: a stream of
 * dependencies drifts toward a gate, almost all of them stop there, and one
 * comes out the other side — which is the one that fails your build.
 *
 * Deliberately a *flow*, not another field of dots. The page already has two
 * scattered-dot treatments; a third would read as the same idea drawn again.
 * A left-to-right stream through a gate is the shape of a pipeline, which is
 * where this particular claim lives.
 *
 * The motion is CSS keyframes with per-particle delays rather than a
 * JavaScript loop: thirty-four elements animated on the compositor cost
 * nothing, and a rAF loop on a marketing page is a battery cost somebody else
 * pays. Reduced motion gets the end state, which is the honest still frame —
 * the stream stopped, one particle through.
 */
export function LandingCli() {
  const sectionRef = useRef(null);
  const reduceMotion = useReducedMotion();
  const inView = useInView(sectionRef, { amount: 0.3, once: true });
  const running = inView && !reduceMotion;

  return (
    <section aria-labelledby="landing-cli-title" className="landing-cli" ref={sectionRef}>
      <div className="landing-cli__copy">
        <p className="section-label">In your pipeline</p>
        <h2 id="landing-cli-title">
          One binary between
          <br />
          a merge and a mistake.
        </h2>
        <p className="landing-cli__lede">
          The same filtering runs in CI. <code>weedout scan --ci</code> reads your lockfile, and
          exits non-zero only for the findings that are reachable or already being exploited —
          so a red build means something, and a green one is not a shrug.
        </p>

        <pre className="landing-cli__command">
          <code>curl -sSL https://weedout.dev/install.sh | sh</code>
        </pre>

        <div className="landing-cli__actions">
          <Link className="button button--primary" to="/cli">
            How the CLI works
          </Link>
          <Link className="landing-cli__secondary" to="/docs">
            Read the docs
          </Link>
        </div>
      </div>

      <div className="landing-cli__stage">
        <Pipeline running={running} />

        <dl className="landing-cli__legend">
          <div>
            <dt>Scanned</dt>
            <dd>{PIPELINE_FACTS.scanned.toLocaleString()}</dd>
          </div>
          <div>
            <dt>Advisories</dt>
            <dd>{PIPELINE_FACTS.advisories}</dd>
          </div>
          <div>
            <dt>Reachable</dt>
            <dd>{PIPELINE_FACTS.reachable}</dd>
          </div>
          <div className="is-blocking">
            <dt>Blocks the build</dt>
            <dd>{PIPELINE_FACTS.exploited}</dd>
          </div>
        </dl>
      </div>
    </section>
  );
}

function Pipeline({ running }) {
  return (
    <div className={`pipeline${running ? " is-running" : ""}`}>
      {/* The graphic restates the sentence beside it, so it is decorative to a
          screen reader rather than a second, wordless copy of the argument. */}
      <div aria-hidden="true" className="pipeline__field">
        {Array.from({ length: LANE_COUNT }, (_, lane) => (
          <span className="pipeline__lane" key={lane} />
        ))}

        {PARTICLES.map((particle) => (
          <span
            className={`pipeline__dot${particle.id === SURVIVOR_ID ? " is-survivor" : ""}`}
            key={particle.id}
            style={{
              "--lane": particle.lane,
              "--offset": particle.offset,
              "--speed": particle.speed,
              "--size": `${particle.size}px`,
            }}
          />
        ))}

        <span className="pipeline__gate">
          <span className="pipeline__gate-label">weedout scan --ci</span>
        </span>
      </div>

      <motion.p
        animate={running ? { opacity: 1 } : { opacity: 1 }}
        className="pipeline__verdict"
        initial={false}
      >
        <span className="pipeline__verdict-code">exit 1</span>
        <span>
          {PIPELINE_FACTS.exploited} finding at critical severity or confirmed exploitation
        </span>
      </motion.p>
    </div>
  );
}
