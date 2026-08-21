const ITEMS = [
  ["open_findings", "Open"],
  ["exploited_findings", "Exploited"],
  ["filtered_findings", "Filtered"],
  ["dismissed_findings", "Dismissed"],
  ["resolved_findings", "Resolved"],
];

export function FindingSummary({ summary }) {
  const matched = summary.open_findings + summary.filtered_findings;

  return (
    <section className="finding-summary" aria-labelledby="finding-summary-heading">
      <div className="finding-summary__heading">
        <div>
          <p className="section-label">Noise reduction</p>
          <h2 id="finding-summary-heading">What Weedout set aside</h2>
        </div>
      </div>

      {matched > 0 ? (
        <p className="finding-summary__ratio">
          <strong>{summary.filter_rate_percent}%</strong>
          <span>of matched advisories filtered from attention</span>
        </p>
      ) : null}

      <dl className="finding-summary__counts">
        {ITEMS.map(([field, label]) => (
          <div key={field} className={`finding-summary__count finding-summary__count--${field}`}>
            <dt>{label}</dt>
            <dd>{summary[field]}</dd>
          </div>
        ))}
      </dl>

      {matched > 0 ? (
        <div
          aria-label={`${summary.filtered_findings} of ${matched} matched advisories filtered`}
          className="finding-summary__bar"
          role="img"
        >
          <span style={{ width: `${summary.filter_rate_percent}%` }} />
        </div>
      ) : null}
    </section>
  );
}
