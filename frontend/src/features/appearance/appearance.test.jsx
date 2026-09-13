import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { AppearanceSection } from "./AppearanceSection";
import { APPEARANCE_STORAGE_KEY, initializeAppearance } from "./useAppearance";

afterEach(() => {
  window.localStorage.clear();
  for (const name of ["scheme", "font", "scale", "glass"]) delete document.documentElement.dataset[name];
});

describe("appearance settings", () => {
  it("applies and persists the selected palette, type, scale and surface style", async () => {
    const user = userEvent.setup();
    render(<AppearanceSection />);

    await user.click(screen.getByRole("radio", { name: "Clay" }));
    await user.click(screen.getByRole("radio", { name: /Technical/ }));
    await user.click(screen.getByRole("radio", { name: /Large/ }));
    await user.click(screen.getByRole("checkbox", { name: "Liquid surfaces" }));

    expect(document.documentElement).toHaveAttribute("data-scheme", "clay");
    expect(document.documentElement).toHaveAttribute("data-font", "technical");
    expect(document.documentElement).toHaveAttribute("data-scale", "large");
    expect(document.documentElement).toHaveAttribute("data-glass", "solid");
    expect(JSON.parse(window.localStorage.getItem(APPEARANCE_STORAGE_KEY))).toEqual({
      scheme: "clay",
      font: "technical",
      scale: "large",
      glass: false,
    });

    for (const name of ["scheme", "font", "scale", "glass"]) delete document.documentElement.dataset[name];
    initializeAppearance();
    expect(document.documentElement).toHaveAttribute("data-scheme", "clay");
    expect(document.documentElement).toHaveAttribute("data-glass", "solid");
  });
});
