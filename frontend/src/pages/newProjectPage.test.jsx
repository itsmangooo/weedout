import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { NewProjectPage } from "./NewProjectPage";

function renderPage() {
  const router = createMemoryRouter(
    [
      { path: "/targets/new", element: <NewProjectPage /> },
      { path: "/targets/:id", element: <p>Project created</p> },
    ],
    { initialEntries: ["/targets/new"] },
  );

  render(<RouterProvider router={router} />);
}

describe("creating an empty project", () => {
  it.each([
    ["npm", "npm"],
    ["PyPI", "PyPI"],
    ["Go", "Go"],
  ])("sends the API ecosystem value for %s", async (label, expected) => {
    const user = userEvent.setup();
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { id: 17, name: "ecosystem-contract" } }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );
    renderPage();

    await user.click(screen.getByRole("radio", { name: /Start empty/ }));
    await user.type(screen.getByLabelText("Project name"), "ecosystem-contract");
    await user.selectOptions(screen.getByLabelText("Ecosystem"), label);
    await user.click(screen.getByRole("button", { name: "Create project" }));

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));
    const [path, request] = fetchSpy.mock.calls[0];
    expect(path).toBe("/api/internal/projects");
    expect(request.method).toBe("POST");
    expect(request.body).toBeInstanceOf(FormData);
    expect(request.body.get("ecosystem")).toBe(expected);
    expect(await screen.findByText("Project created")).toBeInTheDocument();
  });
});
