import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FolderOpen } from "@phosphor-icons/react/FolderOpen";
import { describe, expect, it, vi } from "vitest";

import { EntityContextMenu } from "./EntityContextMenu";

function Fixture({ onDisabled = vi.fn() }) {
  const items = [
    { href: "/project/8", icon: FolderOpen, label: "Open project" },
    { type: "separator" },
    { disabled: true, label: "Unavailable action", onSelect: onDisabled },
    { href: "/findings", label: "Review findings" },
  ];

  return (
    <EntityContextMenu items={items} label="Project actions">
      <div data-testid="project-row">
        <a href="/project/8">Project link</a>
        <span>Project surface</span>
      </div>
    </EntityContextMenu>
  );
}

describe("EntityContextMenu", () => {
  it("opens at the pointer only for the entity surface", async () => {
    render(<Fixture />);

    fireEvent.contextMenu(screen.getByText("Project surface"), { clientX: 100, clientY: 120 });

    const menu = await screen.findByRole("menu", { name: "Project actions" });
    expect(menu).toHaveStyle({ left: "100px", top: "120px" });
    expect(screen.getByRole("menuitem", { name: "Open project" })).toHaveAttribute(
      "href",
      "/project/8",
    );
    expect(screen.getByRole("separator")).toBeInTheDocument();
  });

  it("preserves the native context menu on ordinary links", async () => {
    render(<Fixture />);
    const event = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });

    screen.getByRole("link", { name: "Project link" }).dispatchEvent(event);

    expect(event.defaultPrevented).toBe(false);
    await waitFor(() => expect(screen.queryByRole("menu")).not.toBeInTheDocument());
  });

  it("supports the visible trigger, arrow keys, Escape, and focus restoration", async () => {
    const user = userEvent.setup();
    render(<Fixture />);
    const trigger = screen.getByRole("button", { name: "Project actions" });

    await user.click(trigger);
    const first = await screen.findByRole("menuitem", { name: "Open project" });
    await waitFor(() => expect(first).toHaveFocus());

    await user.keyboard("{ArrowDown}");
    expect(screen.getByRole("menuitem", { name: "Review findings" })).toHaveFocus();

    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("menu")).not.toBeInTheDocument());
    await waitFor(() => expect(trigger).toHaveFocus());
  });

  it("supports disabled items and closes on outside interaction", async () => {
    const onDisabled = vi.fn();
    const user = userEvent.setup();
    render(<Fixture onDisabled={onDisabled} />);

    await user.click(screen.getByRole("button", { name: "Project actions" }));
    const disabled = await screen.findByRole("menuitem", { name: "Unavailable action" });
    expect(disabled).toHaveAttribute("aria-disabled", "true");
    await user.click(disabled);
    expect(onDisabled).not.toHaveBeenCalled();

    fireEvent.pointerDown(document.body);
    await waitFor(() => expect(screen.queryByRole("menu")).not.toBeInTheDocument());
  });
});
