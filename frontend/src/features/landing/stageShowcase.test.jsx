import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MotionConfig } from "motion/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { StageShowcase } from "./components/StageShowcase";
import { ADVISORY_FIELD, SHOWCASE_STAGES, STAGE_DURATION_MS } from "./stages";

/**
 * The four-stage showcase.
 *
 * Two things are worth holding onto. The first is that it advances on its own
 * and slowly — the version this replaced moved every quarter of a second,
 * which meant the numbers changed before anyone had read them, and "it went
 * too fast" is not something a test catches unless the duration is asserted.
 *
 * The second is that the dots are never removed, only dimmed. That is the
 * argument the section is making: an advisory that stops being an alert has
 * not been thrown away.
 */

function renderShowcase() {
  return render(
    <MotionConfig reducedMotion="never">
      <StageShowcase />
    </MotionConfig>,
  );
}

beforeEach(() => {
  // IntersectionObserver is stubbed in setup.js to report immediately, so the
  // section counts as in view and starts playing.
  vi.useFakeTimers({ shouldAdvanceTime: true });
});

afterEach(() => {
  vi.useRealTimers();
});

describe("the four-stage showcase", () => {
  it("starts on the first stage", () => {
    renderShowcase();

    expect(screen.getByText(SHOWCASE_STAGES[0].headline)).toBeInTheDocument();
  });

  it("advances on its own, one stage at a time", async () => {
    renderShowcase();

    for (let index = 1; index < SHOWCASE_STAGES.length; index += 1) {
      await vi.advanceTimersByTimeAsync(STAGE_DURATION_MS);
      await waitFor(() => {
        expect(screen.getByText(SHOWCASE_STAGES[index].headline)).toBeInTheDocument();
      });
    }
  });

  it("holds each stage long enough to read", async () => {
    renderShowcase();

    // Just short of the hold: still on the first stage. This is the assertion
    // that would have failed on the previous timing, which advanced in a
    // quarter of a second.
    await vi.advanceTimersByTimeAsync(STAGE_DURATION_MS - 400);

    expect(screen.getByText(SHOWCASE_STAGES[0].headline)).toBeInTheDocument();
    expect(screen.queryByText(SHOWCASE_STAGES[1].headline)).not.toBeInTheDocument();
  });

  it("stops on the last stage rather than looping", async () => {
    renderShowcase();

    // Stage by stage, waiting for each render. The next stage's timer is only
    // scheduled once the current one has committed — the effect keys off the
    // active stage — so jumping the clock in one leap never schedules them.
    for (let index = 1; index < SHOWCASE_STAGES.length; index += 1) {
      await vi.advanceTimersByTimeAsync(STAGE_DURATION_MS);
      await waitFor(() => {
        expect(screen.getByText(SHOWCASE_STAGES[index].headline)).toBeInTheDocument();
      });
    }

    const last = SHOWCASE_STAGES[SHOWCASE_STAGES.length - 1];
    await waitFor(() => {
      expect(screen.getByText(last.headline)).toBeInTheDocument();
    });

    // And then it stays there. Looping back to the start would restart an
    // argument the reader has already followed to its end.
    //
    // Asserted on the step list rather than on the caption: an exiting caption
    // is still in the DOM until its animation finishes, and animations do not
    // run under fake timers — so a "the old text is gone" assertion here would
    // be testing the test harness.
    await vi.advanceTimersByTimeAsync(STAGE_DURATION_MS * 3);

    const current = screen.getAllByRole("button", { current: "step" });
    expect(current).toHaveLength(1);
    expect(current[0]).toHaveTextContent(last.label);
  });

  it("can be paused", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderShowcase();

    await user.click(screen.getByRole("button", { name: /pause/i }));
    await vi.advanceTimersByTimeAsync(STAGE_DURATION_MS * 3);

    expect(screen.getByText(SHOWCASE_STAGES[0].headline)).toBeInTheDocument();
  });

  it("lets a reader jump straight to a stage", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderShowcase();

    await user.click(screen.getByRole("button", { name: /trace what is reachable/i }));

    expect(screen.getByText(SHOWCASE_STAGES[3].headline)).toBeInTheDocument();
  });

  it("keeps every advisory on screen at every stage", async () => {
    const { container } = renderShowcase();

    const count = () => container.querySelectorAll(".showcase__dot").length;
    expect(count()).toBe(ADVISORY_FIELD.length);

    await vi.advanceTimersByTimeAsync(STAGE_DURATION_MS * SHOWCASE_STAGES.length);

    // Dimmed, never deleted. A graphic that removed them would be illustrating
    // a product that hides things, which is the opposite of the claim.
    await waitFor(() => {
      expect(count()).toBe(ADVISORY_FIELD.length);
    });
  });

  it("announces the caption to assistive technology", () => {
    const { container } = renderShowcase();

    const live = container.querySelector("[aria-live='polite']");
    expect(live).not.toBeNull();
    expect(live).toHaveTextContent(SHOWCASE_STAGES[0].headline);
  });

  it("hides the decorative field from assistive technology", () => {
    const { container } = renderShowcase();

    expect(container.querySelector(".showcase__field")).toHaveAttribute("aria-hidden", "true");
  });
});

describe("the field itself", () => {
  it("draws as many dots as the story claims", () => {
    // 47 advisories, and 47 dots. A graphic claiming one number and drawing
    // another is the small dishonesty this product exists to complain about.
    expect(ADVISORY_FIELD).toHaveLength(47);
  });

  it("has exactly the survivors each stage promises", () => {
    const survivors = (threshold) =>
      ADVISORY_FIELD.filter((node) => node.survives > threshold).length;

    expect(survivors(-1)).toBe(47);
    expect(survivors(0)).toBe(12);
    expect(survivors(1)).toBe(3);
    expect(survivors(2)).toBe(1);
  });

  it("quotes the number it is actually drawing", () => {
    const survivors = (threshold) =>
      ADVISORY_FIELD.filter((node) => node.survives > threshold).length;

    // Derived from each stage's own threshold rather than from hardcoded
    // indices, so this keeps holding if a stage is added or reordered. The
    // first stage is exempt: it counts dependencies, not advisories, and the
    // field is showing the tree rather than alerts.
    for (const stage of SHOWCASE_STAGES.filter((entry) => !entry.neutral)) {
      expect(stage.metric.value).toBe(survivors(stage.threshold));
    }
  });

  it("gives every dot a stable position", () => {
    // Fixed coordinates, not generated at render. A layout that reshuffles is
    // a layout nobody can point at twice.
    for (const node of ADVISORY_FIELD) {
      expect(Number.isFinite(node.x)).toBe(true);
      expect(Number.isFinite(node.y)).toBe(true);
    }
  });
});
