import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useReducedMotion } from "motion/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CliDemo } from "./components/CliDemo";
import { FindingExplorer } from "./components/FindingExplorer";
import { AnalysisStory } from "./components/AnalysisStory";

vi.mock("motion/react", () => ({ useReducedMotion: vi.fn(() => false) }));

afterEach(() => vi.useRealTimers());

describe("landing product demonstrations", () => {
  it("lets a keyboard user select a finding and inspect its matching path, evidence and fix", async () => {
    const user = userEvent.setup();
    const request = vi.spyOn(globalThis, "fetch");
    render(<FindingExplorer />);
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
    render(<FindingExplorer />);
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

  it("transforms 47 alerts into three findings with keyboard controls and an SVG fallback", async () => {
    const user = userEvent.setup();
    const { container } = render(<AnalysisStory />);
    expect(screen.getByText("47")).toBeInTheDocument();
    expect(screen.getByText(/not a live scan/)).toBeInTheDocument();
    const graph = container.querySelector("svg.dependency-field__fallback");
    expect(graph.querySelectorAll("circle")).toHaveLength(47);
    const original = graph.querySelector("circle").getAttribute("cx");
    await user.tab(); await user.tab(); await user.keyboard("{Enter}");
    expect(screen.getByRole("button", {name: /Add context/})).toHaveAttribute("aria-pressed", "true");
    await user.tab(); await user.keyboard("{Enter}");
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(graph.querySelector("circle").getAttribute("cx")).not.toBe(original);
    await user.click(screen.getByRole("button", {name: /Raw alerts/}));
    expect(screen.getByText("47")).toBeInTheDocument();
  });

  it("responds to the scroll story without changing the independent finding selection", async () => {
    const user = userEvent.setup();
    render(<><AnalysisStory /><FindingExplorer /></>);
    await user.click(screen.getByRole("button", {name: /02 minimist/}));
    act(() => document.querySelector("[data-analysis-story]").dispatchEvent(new CustomEvent("analysis-progress", {detail: 1})));
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByRole("button", {name: /02 minimist/})).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("article", {name: "Context for minimist"})).toBeInTheDocument();
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
