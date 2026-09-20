import { FindingRow } from "../../findings/components/FindingRow";

/**
 * What an empty tab means, which differs per tab.
 *
 * "Nothing here" is ambiguous on the filtered tab in particular: it could
 * equally mean the filtering is broken. Saying what the emptiness means
 * removes the question.
 */
const EMPTY = {
  open: "No open findings under the current alert rules. Source reachability is a separate result.",
  filtered: "Nothing was filtered out. Every advisory that matched was worth reporting.",
  dismissed: "Nothing dismissed.",
  resolved: "Nothing resolved yet.",
};

export function ProjectFindings({ findings, onShowChange, show, tabs, tabCounts }) {
  return (
    <section aria-labelledby="findings-title" className="project-section">
      <h2 className="visually-hidden" id="findings-title">
        Findings
      </h2>

      <nav aria-label="Finding filters" className="filter-tabs">
        {tabs.map((tab) => (
          <button
            aria-current={show === tab.id ? "true" : undefined}
            className={`filter-tab${show === tab.id ? " filter-tab--active" : ""}`}
            key={tab.id}
            onClick={() => onShowChange(tab.id)}
            type="button"
          >
            {tab.label}
            <span className="filter-tab__count">{tabCounts[tab.id] ?? 0}</span>
          </button>
        ))}
      </nav>

      {findings.length === 0 ? (
        <p className="empty-state">{EMPTY[show]}</p>
      ) : (
        <ul className="finding-list">
          {findings.map((finding) => (
            <FindingRow finding={finding} key={finding.id} />
          ))}
        </ul>
      )}
    </section>
  );
}
