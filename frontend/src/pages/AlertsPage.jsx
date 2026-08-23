import { useSearchParams } from "react-router";

import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { FindingRow } from "../features/findings/components/FindingRow";
import { useFindings } from "../features/findings/hooks/useFindings";

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
  return `Showing the past ${days} days. Pro keeps a year.`;
}

export function AlertsPage() {
  const [params, setParams] = useSearchParams();
  const requested = params.get("show");
  const show = TABS.some((tab) => tab.id === requested) ? requested : "open";

  const query = useFindings({ show });
  const findings = query.data?.findings ?? [];
  const note = query.isSuccess ? historyNote(query.data.historyDays) : null;

  function setShow(value) {
    const next = new URLSearchParams(params);
    next.set("show", value);
    setParams(next, { replace: true });
  }

  return (
    <div className="alerts-page">
      <header className="page-head">
        <p className="section-label">Across every project</p>
        <h1>Findings</h1>
      </header>

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

      {note ? <p className="filter-note">{note}</p> : null}

      {query.isSuccess ? (
        findings.length === 0 ? (
          <p className="empty-state">{EMPTY[show]}</p>
        ) : (
          <ul className="finding-list">
            {findings.map((finding) => (
              <FindingRow finding={finding} key={finding.id} />
            ))}
          </ul>
        )
      ) : null}
    </div>
  );
}
