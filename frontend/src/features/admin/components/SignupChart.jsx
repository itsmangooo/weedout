import { useMemo } from "react";

/**
 * Cumulative accounts over time.
 *
 * One series on one axis, so there is no legend — the heading names it. New
 * signups per day and the running total are the same measure at two scales,
 * and putting both on a second y-axis would let the shape of one be read as a
 * claim about the other. The daily number lives in the tooltip and the table
 * instead.
 *
 * Hover targets are full-height invisible rectangles carrying a native
 * `<title>`, which is a real tooltip layer that needs no JavaScript. The
 * rendered version used the same trick to survive the strict CSP; keeping it
 * here means the chart still explains itself if the interaction layer is ever
 * stripped.
 */

const WIDTH = 720;
const HEIGHT = 220;
const PAD_LEFT = 46;
const PAD_RIGHT = 14;
const PAD_TOP = 14;
const BASELINE = HEIGHT - 26;

function niceCeiling(value) {
  if (value <= 4) return 4;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  return Math.ceil(value / magnitude) * magnitude;
}

export function SignupChart({ points, days }) {
  const chart = useMemo(() => {
    if (!points?.length) return null;

    const top = niceCeiling(Math.max(...points.map((point) => point.cumulative), 1));
    const span = Math.max(points.length - 1, 1);
    const usable = WIDTH - PAD_LEFT - PAD_RIGHT;

    const placed = points.map((point, index) => ({
      ...point,
      x: PAD_LEFT + (index / span) * usable,
      y: BASELINE - (point.cumulative / top) * (BASELINE - PAD_TOP),
      hitX: PAD_LEFT + ((index - 0.5) / span) * usable,
      hitWidth: usable / span,
    }));

    const line = placed
      .map((point, index) => `${index === 0 ? "M" : "L"}${point.x.toFixed(1)} ${point.y.toFixed(1)}`)
      .join(" ");

    const first = placed[0];
    const last = placed.at(-1);

    return {
      points: placed,
      last,
      linePath: line,
      areaPath: `${line} L${last.x.toFixed(1)} ${BASELINE} L${first.x.toFixed(1)} ${BASELINE} Z`,
      grid: [0, 0.5, 1].map((fraction) => ({
        y: BASELINE - fraction * (BASELINE - PAD_TOP),
        label: String(Math.round(top * fraction)),
      })),
      // First, middle, last. The outer two are anchored inward: a centred
      // label on the last point overhangs the viewBox and gets clipped, which
      // is how the end of the range ends up reading "Aug 2".
      xLabels: [placed[0], placed[Math.floor(placed.length / 2)], last]
        .filter(Boolean)
        .map((point, index, all) => ({
          x: point.x,
          label: shortDay(point.day),
          anchor: index === 0 ? "start" : index === all.length - 1 ? "end" : "middle",
        })),
    };
  }, [points]);

  if (!chart) {
    return (
      <p className="muted u-text-sm u-mt-5">
        No accounts yet. The chart appears after the first signup.
      </p>
    );
  }

  return (
    <>
      <svg
        aria-labelledby="signups-heading signups-desc"
        className="chart"
        preserveAspectRatio="xMidYMid meet"
        role="img"
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      >
        <desc id="signups-desc">
          Cumulative account total over the last {days} days, ending at {chart.last.cumulative}.
        </desc>

        {chart.grid.map((line) => (
          <g key={line.label}>
            <line className="chart__grid" x1={PAD_LEFT} x2={WIDTH - PAD_RIGHT} y1={line.y} y2={line.y} />
            <text className="chart__ylabel" textAnchor="end" x={PAD_LEFT - 8} y={line.y + 4}>
              {line.label}
            </text>
          </g>
        ))}

        <path className="chart__area" d={chart.areaPath} />
        <path className="chart__line" d={chart.linePath} />
        <circle className="chart__dot" cx={chart.last.x} cy={chart.last.y} r={4} />

        {chart.xLabels.map((label) => (
          <text
            className="chart__xlabel"
            key={label.label}
            textAnchor={label.anchor}
            x={label.x}
            y={HEIGHT - 8}
          >
            {label.label}
          </text>
        ))}

        {chart.points.map((point) => (
          <rect
            className="chart__hit"
            height={BASELINE - PAD_TOP}
            key={point.day}
            width={point.hitWidth}
            x={point.hitX}
            y={PAD_TOP}
          >
            <title>
              {shortDay(point.day)} — {point.cumulative} total
              {point.count ? `, +${point.count} new` : ""}
            </title>
          </rect>
        ))}
      </svg>

      {/* The table the chart is an alternative to, not a replacement for. */}
      <details className="chart-table">
        <summary>View as table</summary>
        <div className="table-scroll u-scroll-y">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Day</th>
                <th scope="col">New</th>
                <th scope="col">Total</th>
              </tr>
            </thead>
            <tbody>
              {[...points].reverse().map((point) => (
                <tr key={point.day}>
                  <td className="mono">{point.day}</td>
                  <td className="mono">{point.count || "—"}</td>
                  <td className="mono">{point.cumulative}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </>
  );
}

function shortDay(day) {
  const parsed = new Date(`${day}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) return day;
  return parsed.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
}
