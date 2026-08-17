"""Server-rendered SVG chart geometry.

The page's Content-Security-Policy allows no external scripts and the admin
panel ships no charting library, so the coordinates are computed here and the
template just emits the shapes. That keeps the arithmetic testable — a chart
whose axis is silently wrong is worse than no chart, and geometry computed
inside a Jinja template cannot be asserted on.

Deliberately one series and one axis. Daily signups and the running total have
different magnitudes, and plotting both against two y-scales is the single most
misleading thing a chart can do; the daily figure is a stat tile beside the
chart instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

__all__ = ["LineChart", "build_signup_chart"]

# A 3:1-ish canvas that stays legible when scaled to a card's width.
WIDTH = 720
HEIGHT = 200
PAD_LEFT = 46
PAD_RIGHT = 14
PAD_TOP = 14
PAD_BOTTOM = 28


@dataclass(frozen=True, slots=True)
class ChartPoint:
    x: float
    y: float
    label: str
    value: int
    #: Daily delta, shown in the native tooltip alongside the running total.
    delta: int
    #: Left edge and width of the invisible hover target for this point.
    hit_x: float
    hit_width: float


@dataclass(slots=True)
class GridLine:
    y: float
    label: str


@dataclass(slots=True)
class LineChart:
    """Everything the template needs to draw the chart, already positioned."""

    width: int = WIDTH
    height: int = HEIGHT
    points: list[ChartPoint] = field(default_factory=list)
    grid: list[GridLine] = field(default_factory=list)
    x_labels: list[tuple[float, str]] = field(default_factory=list)
    line_path: str = ""
    area_path: str = ""
    baseline_y: float = 0.0
    y_max: int = 0
    #: True when there is nothing to draw, so the template shows a message
    #: rather than an empty axis pretending to be data.
    empty: bool = True

    @property
    def last_point(self) -> ChartPoint | None:
        return self.points[-1] if self.points else None


def _nice_ceiling(value: int) -> int:
    """Round up to a readable axis maximum (1, 2 or 5 x a power of ten).

    An axis topping out at 37 makes the reader do arithmetic; one topping out
    at 40 does not.
    """
    if value <= 5:
        return max(value, 5)

    magnitude = 10 ** (len(str(value)) - 1)
    for step in (1, 2, 5, 10):
        candidate = step * magnitude
        if candidate >= value:
            return candidate
    return 10 * magnitude


def build_signup_chart(points) -> LineChart:
    """Lay out cumulative signups as a single-series line.

    `points` is a sequence of `app.services.admin_service.SignupPoint`.
    """
    chart = LineChart()
    if not points:
        return chart

    values = [p.cumulative for p in points]
    chart.y_max = _nice_ceiling(max(values))
    chart.baseline_y = HEIGHT - PAD_BOTTOM

    plot_width = WIDTH - PAD_LEFT - PAD_RIGHT
    plot_height = HEIGHT - PAD_TOP - PAD_BOTTOM
    count = len(points)
    # A single data point has no span; place it mid-canvas rather than dividing
    # by zero or pinning it to the left edge.
    step = plot_width / (count - 1) if count > 1 else 0.0

    laid_out: list[ChartPoint] = []
    for index, point in enumerate(points):
        x = PAD_LEFT + (index * step if count > 1 else plot_width / 2)
        ratio = point.cumulative / chart.y_max if chart.y_max else 0.0
        y = HEIGHT - PAD_BOTTOM - (ratio * plot_height)

        hit_width = step if count > 1 else plot_width
        hit_x = x - hit_width / 2
        # Clamp the outermost hit areas inside the plot so they do not overhang
        # the axis labels and steal their hover.
        hit_x = max(PAD_LEFT, min(hit_x, WIDTH - PAD_RIGHT - hit_width))

        laid_out.append(
            ChartPoint(
                x=round(x, 2),
                y=round(y, 2),
                label=_format_day(point.day),
                value=point.cumulative,
                delta=point.count,
                hit_x=round(hit_x, 2),
                hit_width=round(max(hit_width, 1.0), 2),
            )
        )

    chart.points = laid_out
    chart.empty = False

    chart.line_path = "M " + " L ".join(f"{p.x} {p.y}" for p in laid_out)
    chart.area_path = (
        f"{chart.line_path} "
        f"L {laid_out[-1].x} {chart.baseline_y} "
        f"L {laid_out[0].x} {chart.baseline_y} Z"
    )

    # Four gridlines including zero: enough to read a value off, few enough to
    # stay recessive.
    for fraction in (0.0, 0.5, 1.0):
        value = round(chart.y_max * fraction)
        chart.grid.append(
            GridLine(
                y=round(HEIGHT - PAD_BOTTOM - fraction * plot_height, 2),
                label=str(value),
            )
        )

    # First, middle and last dates only — a label per day collides at any width
    # this card will realistically be rendered at.
    label_indices = {0, count - 1} if count < 6 else {0, count // 2, count - 1}
    chart.x_labels = [
        (laid_out[i].x, laid_out[i].label) for i in sorted(label_indices) if i < count
    ]

    return chart


def _format_day(day: date) -> str:
    return day.strftime("%-d %b") if _supports_dash_flag() else day.strftime("%d %b")


def _supports_dash_flag() -> bool:
    """`%-d` strips the leading zero on glibc but raises on Windows."""
    try:
        date(2024, 1, 5).strftime("%-d")
    except ValueError:
        return False
    return True
