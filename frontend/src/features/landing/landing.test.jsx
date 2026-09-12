import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useReducedMotion } from "motion/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CliDemo } from "./components/CliDemo";
import { ProductScreenshot } from "./components/ProductScreenshot";
import { SignalDemo } from "./components/SignalDemo";

vi.mock("motion/react", () => ({ useReducedMotion: vi.fn(() => false) }));

afterEach(() => vi.useRealTimers());

describe("landing product demonstrations", () => {
  it("lets a keyboard user select a finding and inspect its matching path, evidence and fix", async () => {
    const user = userEvent.setup();
    const request = vi.spyOn(globalThis, "fetch");
    render(<ProductScreenshot />);
    await user.tab();
    expect(screen.getByRole("button", { name: /01 axios/ })).toHaveFocus();
    await user.tab();
    await user.keyboard("{Enter}");

    const selected = screen.getByRole("button", { name: /02 minimist/ });
    expect(selected).toHaveAttribute("aria-pressed", "true");
    expect(selected).toHaveFocus();
    const detail = within(
      screen.getByRole("article", { name: "Context for minimist" }),
    );
    expect(detail.getByText("minimist@1.2.5")).toBeInTheDocument();
    expect(detail.getByText("1.2.6")).toBeInTheDocument();
    expect(detail.getByText("argument-helper")).toBeInTheDocument();
    await user.click(detail.getByText("Evidence"));
    expect(
      detail
        .getByText("src/cli.js:2 imports argument-helper")
        .closest("details"),
    ).toHaveAttribute("open");
    expect(
      detail.getByText(/Update the parent dependency/),
    ).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it("keeps unknown evidence honest and resets the disclosure on finding changes", async () => {
    const user = userEvent.setup();
    render(<ProductScreenshot />);
    await user.click(screen.getByText("Evidence"));
    await user.click(screen.getByRole("button", { name: /03 lodash/ }));
    const detail = within(
      screen.getByRole("article", { name: "Context for lodash" }),
    );
    expect(detail.getByText("Unknown")).toBeInTheDocument();
    expect(detail.getByText("Evidence").closest("details")).not.toHaveAttribute(
      "open",
    );
    await user.click(detail.getByText("Evidence"));
    expect(detail.getByText(/Unknown does not mean safe/)).toBeInTheDocument();
    expect(detail.getByText("4.17.21")).toBeInTheDocument();
  });

  it("opens and resets the 47-to-3 demo without exposing hidden controls in the tab order", async () => {
    const user = userEvent.setup();
    render(<SignalDemo />);
    const apply = screen.getByRole("button", { name: "Add project context" });
    const result = document.getElementById(apply.getAttribute("aria-controls"));
    expect(result).not.toBeVisible();
    expect(
      screen.queryByRole("button", { name: /minimist/ }),
    ).not.toBeInTheDocument();
    await user.click(apply);
    expect(result).toBeVisible();
    expect(screen.getByRole("button", { name: "Reset demo" })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
    expect(
      within(screen.getByLabelText("Shortlisted demo findings")).getAllByRole(
        "button",
      ),
    ).toHaveLength(3);
    await user.click(screen.getByRole("button", { name: /minimist/ }));
    expect(
      screen.getByRole("heading", { name: "CVE-2021-44906" }),
    ).toBeInTheDocument();
    await user.click(screen.getByText("What happened to the other 44?"));
    expect(
      screen.getByText(/remain available for review/).closest("details"),
    ).toHaveAttribute("open");
    await user.click(screen.getByRole("button", { name: "Reset demo" }));
    expect(result).not.toBeVisible();
    expect(
      screen.getByRole("button", { name: "Add project context" }),
    ).toHaveFocus();
  });

  it("keeps the hero selection independent from the larger demo", async () => {
    const user = userEvent.setup();
    render(
      <>
        <ProductScreenshot />
        <SignalDemo />
      </>,
    );
    await user.click(
      screen.getByRole("button", { name: "Add project context" }),
    );
    await user.click(screen.getByRole("button", { name: /^minimist/ }));
    expect(screen.getByRole("button", { name: /01 axios/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    const controls = screen
      .getAllByRole("button", { name: /minimist/ })
      .map((button) => button.getAttribute("aria-controls"));
    expect(new Set(controls).size).toBe(2);
  });
});

describe("landing CLI playback", () => {
  it("pauses, completes and replays a bounded supported-command transcript", () => {
    vi.useFakeTimers();
    render(<CliDemo />);
    const firstOutput = screen.getByText("demo-app package-lock.json");
    expect(firstOutput).not.toHaveClass("is-visible");
    fireEvent.click(screen.getByRole("button", { name: "Pause" }));
    act(() => vi.advanceTimersByTime(5000));
    expect(firstOutput).not.toHaveClass("is-visible");
    fireEvent.click(screen.getByRole("button", { name: "Play" }));
    for (let index = 0; index < 12; index++)
      act(() => vi.advanceTimersByTime(300));
    expect(firstOutput).toHaveClass("is-visible");
    expect(screen.getByText(/Failing: 1 finding/)).toHaveClass("is-visible");
    fireEvent.click(screen.getByRole("button", { name: "Replay" }));
    expect(firstOutput).not.toHaveClass("is-visible");
    expect(screen.getByText("$ weedout scan --ci")).toHaveClass("is-visible");
  });

  it("shows the complete transcript immediately with reduced motion", () => {
    vi.mocked(useReducedMotion).mockReturnValue(true);
    render(<CliDemo />);
    expect(screen.getByText(/Failing: 1 finding/)).toHaveClass("is-visible");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
