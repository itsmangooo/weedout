import { useState } from "react";
import { PageFrame } from "../components/ui/PageFrame";
import { useSearchParams } from "react-router";

import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { FindingRow } from "../features/findings/components/FindingRow";
import { useFindings, FINDINGS_LIMIT } from "../features/findings/hooks/useFindings";

const TABS = [
  { id: "open", label: "Open" },
  { id: "filtered", label: "Filtered out" },
  { id: "dismissed", label: "Dismissed" },
  { id: "resolved", label: "Resolved" },
];

/**
 * What an empty tab means, which differs per tab.
 *
 * The filtered tab matters most here: "nothing here" could equally be read as
 * the filtering being broken, and this is the number the product is proud of.
 */
const EMPTY = {
  open: "Nothing to act on across any project.",
  filtered:
    "Nothing was filtered out. Every advisory that matched one of your dependencies was worth reporting.",
  dismissed: "Nothing dismissed.",
  resolved: "Nothing has been resolved yet.",
};

/**
 * How far back an archive tab reaches, said out loud.
 *
 * Without it, a tab that ends 30 days ago looks like findings went missing.
 * The sentence names the window and, on the plan where it is short, what
 * changes it — once, above the list, not as a badge on every row.
 */
function historyNote(days) {
  if (days === null) return null;
  if (days >= 365) return "Showing the past year.";
  return `Showing the past ${days} days.`;
}

export function AlertsPage() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [exploitation, setExploitation] = useState("all");
  const [reachability, setReachability] = useState("all");
  const [project, setProject] = useState("all");
  const [sort, setSort] = useState("newest");
  const [params, setParams] = useSearchParams();
  const requested = params.get("show");
  const show = TABS.some((tab) => tab.id === requested) ? requested : "open";

  const query = useFindings({ show });
  const findings = query.data?.findings ?? [];
  const note = query.isSuccess ? historyNote(query.data.historyDays) : null;
  const projects = [...new Map(findings.map((finding) => [String(finding.project.id), finding.project])).entries()];

  const severityRank = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  const visible = findings
    .filter((finding) => (severity === "all" || finding.severity === severity)
      && (exploitation === "all" || finding.is_exploited)
      && (reachability === "all" || finding.reachability === reachability)
      && (project === "all" || String(finding.project.id) === project)
      && `${finding.identifier} ${finding.package_name} ${finding.project.name}`.toLowerCase().includes(search.toLowerCase()))
    .toSorted((left, right) => sort === "severity"
      ? (severityRank[left.severity] ?? 5) - (severityRank[right.severity] ?? 5)
      : sort === "package"
        ? left.package_name.localeCompare(right.package_name)
        : Date.parse(right.detected_at) - Date.parse(left.detected_at));

  function setShow(value) {
    const next = new URLSearchParams(params);
    next.set("show", value);
    setParams(next, { replace: true });
  }

  return (
    <PageFrame className="alerts-page" eyebrow="Dependencies / across every project" title="Dependency findings" description="Inspect the match, understand the evidence, and make a decision.">
      <nav aria-label="Finding filters" className="filter-tabs">
        {TABS.map((tab) => (
          <button
            aria-current={show === tab.id ? "true" : undefined}
            className={`filter-tab${show === tab.id ? " filter-tab--active" : ""}`}
            key={tab.id}
            onClick={() => setShow(tab.id)}
            type="button"
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {query.isPending ? <AsyncLoading>Loading findings…</AsyncLoading> : null}

      {query.isError ? (
        <AsyncError error={query.error} onRetry={() => query.refetch()} />
      ) : null}

      {query.isSuccess && findings.length > 0 && <div className="list-toolbar findings-toolbar"><label className="search-field">Search this list<input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Package, advisory or project" /></label><label className="compact-select">Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option>{["critical","high","medium","low","unknown"].map((value) => <option key={value} value={value}>{value}</option>)}</select></label><label className="compact-select">Exploitation<select value={exploitation} onChange={(event) => setExploitation(event.target.value)}><option value="all">Any state</option><option value="exploited">Known exploited</option></select></label><label className="compact-select">Reachability<select value={reachability} onChange={(event) => setReachability(event.target.value)}><option value="all">Any evidence</option>{["reachable","potentially_reachable","not_observed","unknown"].map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select></label><label className="compact-select">Project<select value={project} onChange={(event) => setProject(event.target.value)}><option value="all">All projects</option>{projects.map(([id, item]) => <option key={id} value={id}>{item.name}</option>)}</select></label><label className="compact-select">Sort<select value={sort} onChange={(event) => setSort(event.target.value)}><option value="newest">Newest first</option><option value="severity">Highest severity</option><option value="package">Package name</option></select></label><p className="filter-note">Filtering {findings.length} loaded findings (up to {FINDINGS_LIMIT}). {visible.length} shown.</p></div>}
      {query.isSuccess && findings.length > 0 && visible.length === 0 && <p className="empty-state">No loaded findings match these filters.</p>}
      {note ? <p className="filter-note">{note}</p> : null}

      {query.isSuccess ? (
        findings.length === 0 ? (
          <p className="empty-state">{EMPTY[show]}</p>
        ) : (
          <ul className="finding-list">
            {visible.map((finding) => (
              <FindingRow finding={finding} key={finding.id} />
            ))}
          </ul>
        )
      ) : null}
    </PageFrame>
  );
}
