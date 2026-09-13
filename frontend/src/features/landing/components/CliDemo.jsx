import { Pause, Play, RotateCcw } from "lucide-react";
import { useEffect, useRef, useState } from "react";

// Format verified against weedout-cli/internal/cli/cli.go report() and scan().
// An excerpt of one illustrative scan, not a command executed in the browser.
const LINES = [
  "$ weedout scan --ci",
  "",
  "demo-app  package-lock.json",
  "412 dependencies scanned · 44 filtered out as noise",
  "",
  "  1 critical  ·  2 high",
  "",
  "  • axios@0.21.1  CVE-2021-3749  → 0.21.2",
  "    reachability: reachable",
  "    src/api.js:1 imports axios",
  "",
  "Failing: 1 finding(s) at critical severity or confirmed exploitation.",
];

export function CliDemo({ reducedMotion = false }) {
  const ref = useRef(null);
  const [inView, setInView] = useState(
    () => typeof IntersectionObserver === "undefined",
  );
  const [paused, setPaused] = useState(false);
  const [line, setLine] = useState(1);
  const complete = reducedMotion || line >= LINES.length;
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const observer = new IntersectionObserver(
      ([entry]) => setInView(entry.isIntersecting),
      { threshold: 0.2 },
    );
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    if (!inView || paused || complete) return;
    const timer = window.setTimeout(() => setLine((value) => value + 1), 300);
    return () => window.clearTimeout(timer);
  }, [inView, paused, complete, line]);
  return (
    <figure className="landing-cli__terminal" ref={ref}>
      <div className="landing-cli__bar">
        <span>TERMINAL / demo-app</span>
        {!reducedMotion && (
          <button
            type="button"
            onClick={() => {
              if (complete) {
                setLine(1);
                setPaused(false);
              } else {
                setPaused((value) => !value);
              }
            }}
          >
            {complete ? (
              <RotateCcw size={13} aria-hidden="true" />
            ) : paused ? (
              <Play size={13} aria-hidden="true" />
            ) : (
              <Pause size={13} aria-hidden="true" />
            )}
            {complete ? "Replay" : paused ? "Play" : "Pause"}
          </button>
        )}
      </div>
      <pre aria-label="Illustrative CLI output excerpt">
        <code>
          {LINES.map((text, index) => (
            <span
              key={index}
              className={`terminal-line ${index < line || complete ? "is-visible" : ""} ${index === 0 ? "is-command" : ""} ${index === 11 ? "is-failing" : ""}`}
            >
              {text || "\u00a0"}
              {"\n"}
            </span>
          ))}
        </code>
      </pre>
      <figcaption>
        Illustrative output excerpt · configured project · CI exits 1 for a
        blocking finding.
      </figcaption>
    </figure>
  );
}
