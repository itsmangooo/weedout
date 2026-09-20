import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { createQueryClient } from "../app/queryClient";
import { ProjectsDirectory } from "../features/dashboard/components/ProjectsDirectory";
import { ProjectPage } from "./ProjectPage";
import { AlertPage } from "./AlertPage";
import { AlertsPage } from "./AlertsPage";
import { ThemeControl } from "../features/theme/ThemeControl";

function mount(element, path = "/", pattern = "*") {
  return render(<QueryClientProvider client={createQueryClient({ queries: { retry: false } })}><MemoryRouter initialEntries={[path]}><Routes><Route path={pattern} element={element} /></Routes></MemoryRouter></QueryClientProvider>);
}
function respond(body) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(new Response(JSON.stringify(body), {headers: {"Content-Type":"application/json"}})));
}
const project = { id: 7, name: "checkout", ecosystem: "npm", manifest_kind: "package-lock.json", dependency_count: 12, has_manifest: true, is_active: true, last_scan_failed: false, last_scanned_at: "2026-09-01T10:00:00Z", findings: {open: 2, exploited: 0, filtered: 8} };
const finding = { id: 9, identifier: "TEST-ADVISORY", package_name: "test-package", installed_version: "1.0.0", severity: "high", reachability: "unknown", status: "open", project: {id:7,name:"checkout"}, is_exploited: false, detected_at: "2026-09-01T10:00:00Z" };

describe("rebuilt workspace interactions", () => {
  it("filters real projects by name and setup state without another request", async () => {
    const user = userEvent.setup();
    const request = vi.spyOn(globalThis, "fetch");
    mount(<ProjectsDirectory projects={[project, {...project,id:8,name:"worker",has_manifest:false}]} />);
    await user.type(screen.getByRole("searchbox", {name:"Find a project"}), "checkout");
    expect(screen.getByRole("link", {name:"Open project checkout"})).toBeInTheDocument();
    expect(screen.queryByRole("link", {name:"Open project worker"})).not.toBeInTheDocument();
    await user.clear(screen.getByRole("searchbox"));
    await user.selectOptions(screen.getByLabelText("Project state"), "setup");
    expect(screen.getByRole("link", {name:"Open project worker"})).toBeInTheDocument();
    expect(screen.queryByRole("link", {name:"Open project checkout"})).not.toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });
  it("opens history on the existing project route and never presents a failed run as clean", async () => {
    const user = userEvent.setup();
    respond({data:{...project,tab_counts:{open:2},reachability_source_count:0}, findings:[],dependencies:[],rules:[],api_keys:[],webhook:{},supply_chain:[],recent_runs:[{started_at:"2026-09-01T10:00:00Z",error:"Manifest could not be resolved",actionable_count:0}]});
    mount(<ProjectPage />, "/targets/7?view=history", "/targets/:projectId");
    const failed = (await screen.findByText("Failed")).closest("li");
    expect(failed).toHaveTextContent("Manifest could not be resolved");
    expect(failed).not.toHaveTextContent("0 matched");
    expect(screen.getByRole("button", {name:"Scan history"})).toHaveAttribute("aria-current","page");
    await user.click(screen.getByRole("button", {name:"Dependencies"}));
    expect(screen.getByText("Nothing resolved yet.")).toBeInTheDocument();
  });
  it("shows missing evidence and an absent fix explicitly without inventing a resolution", async () => {
    respond({data:{...finding,fixed_version:null,reachability_evidence:[]}, explanation:{risk:"A matched dependency advisory.",why:"Above the project threshold.",fix:"Review the available advisory."},kev:null,deliveries:[]});
    mount(<AlertPage />, "/alerts/9", "/alerts/:alertId");
    expect(await screen.findByText("No fixed version reported")).toBeInTheDocument();
    expect(screen.getByText(/Missing or incomplete analysis is not a safe result/)).toBeInTheDocument();
    expect(screen.getByText("No source evidence was returned for this finding.")).toBeInTheDocument();
    expect(screen.getByRole("navigation", {name:"Investigation"}).querySelectorAll("a")).toHaveLength(5);
    expect(screen.getByRole("button", {name:"Dismiss this finding"})).toBeInTheDocument();
    expect(screen.queryByRole("button", {name:/resolve|mark.*fixed/i})).not.toBeInTheDocument();
  });
  it("combines finding severity and text search within the declared loaded limit", async () => {
    const user = userEvent.setup();
    respond({data:[finding,{...finding,id:10,identifier:"TEST-SECOND",package_name:"second-package",severity:"critical"}],meta:{show:"open",limit:100,count:2,history_days:null}});
    mount(<AlertsPage />);
    await screen.findByText("TEST-ADVISORY");
    await user.selectOptions(screen.getByLabelText("Severity"),"critical");
    expect(screen.queryByText("TEST-ADVISORY")).not.toBeInTheDocument();
    expect(screen.getByText("TEST-SECOND")).toBeInTheDocument();
    await user.type(screen.getByRole("searchbox"),"does-not-exist");
    expect(screen.getByText("No loaded findings match these filters.")).toBeInTheDocument();
    expect(screen.getByText(/0 of 2 loaded findings · up to 100 per state/)).toBeInTheDocument();
  });
  it("keeps multiple theme controls synchronized and supports arrow keys", async () => {
    localStorage.clear();
    const user = userEvent.setup();
    render(<><ThemeControl /><ThemeControl /></>);
    const groups=screen.getAllByRole("radiogroup");
    await user.click(within(groups[0]).getByRole("radio", {name:"Dark"}));
    expect(within(groups[1]).getByRole("radio", {name:"Dark"})).toHaveAttribute("aria-checked","true");
    await user.keyboard("{Home}");
    expect(within(groups[0]).getByRole("radio", {name:"Light"})).toHaveFocus();
    expect(within(groups[1]).getByRole("radio", {name:"Light"})).toHaveAttribute("aria-checked","true");
    expect(localStorage.getItem("weedout-theme")).toBe("light");
  });
});
