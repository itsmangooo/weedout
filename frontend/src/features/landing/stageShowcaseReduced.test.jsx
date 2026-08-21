import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { StageShowcase } from "./components/StageShowcase";
import { SHOWCASE_STAGES } from "./stages";

/**
 * The showcase when the visitor has asked for less motion.
 *
 * In its own file, on real timers. The auto-advance tests next door mock the
 * clock, and `useReducedMotion` resolves through an effect that a mocked clock
 * holds up — which made these fail while the component was behaving perfectly.
 *
 * The stub is on `matchMedia`, not on MotionConfig. useReducedMotion reads the
 * media query directly and ignores MotionConfig, so a first attempt at these
 * tests passed while quietly exercising the ordinary path.
 */
beforeEach(() => {
  vi.stubGlobal("matchMedia", (query) => ({
    matches: query.includes("prefers-reduced-motion"),
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  }));
});

describe("with motion reduced", () => {
  it("shows the outcome rather than the first frame of a story that will not play", async () => {
    render(<StageShowcase />);

    const last = SHOWCASE_STAGES[SHOWCASE_STAGES.length - 1];
    await waitFor(() => {
      expect(screen.getByText(last.headline)).toBeInTheDocument();
    });
  });

  it("leaves exactly one caption behind when the stage changes", async () => {
    // AnimatePresence keeps an exiting node mounted until its exit animation
    // completes, and an animation that never runs never completes. Without a
    // zero-length transition the old caption stays, and the aria-live region
    // ends up holding two — which a screen reader reads out both of.
    const user = userEvent.setup();
    const { container } = render(<StageShowcase />);

    await user.click(screen.getByRole("button", { name: /watch the lockfile/i }));

    await waitFor(() => {
      expect(container.querySelectorAll(".showcase__caption h3")).toHaveLength(1);
    });
    expect(container.querySelectorAll(".showcase__metric")).toHaveLength(1);
  });

  it("offers no playback controls for a thing that does not play", async () => {
    const { container } = render(<StageShowcase />);

    await waitFor(() => {
      expect(container.querySelector(".showcase__controls")).toBeNull();
    });
  });
});
