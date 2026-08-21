import { Flame } from "lucide-react";

import { useLandingData } from "../hooks/useLandingData";

/**
 * The one section of the landing page that is not an illustration.
 *
 * Everything above it — the scroll story, the hero field — is a worked example
 * of what the filtering does. This is real: anonymised findings from real
 * scans, and headline numbers rounded so they cannot be used to count
 * customers.
 *
 * Which is why it disappears rather than degrades. If there is nothing to
 * show, the section is absent. An empty list padded with invented rows would
 * turn the only factual thing on the page into fiction, and the claim it is
 * making is precisely that it is live.
 */
export function LiveSignal() {
  const { data } = useLandingData();

  if (!data) {
    return null;
  }

  const { stats, findings, trending_cves: trending } = data;
  const hasNumbers = stats?.advisories_matched > 0;

  if (!hasNumbers && !findings?.length && !trending?.length) {
    return null;
  }

  return (
    <section aria-labelledby="live-title" className="live-signal">
      <div className="live-signal__head">
        <p className="section-label">Live, from real scans</p>
        <h2 id="live-title">Not a mock-up.</h2>
      </div>

      {hasNumbers ? (
        <dl className="live-stats">
          <Stat label="Advisories matched" value={stats.advisories_matched} />
          <Stat
            label="Filtered out as noise"
            suffix={stats.filtered_share ? ` (${stats.filtered_share}%)` : ""}
            value={stats.filtered_out}
          />
          <Stat label="Dependencies watched" value={stats.dependencies_watched} />
          <Stat label="Known exploited" value={stats.kev_entries} />
        </dl>
      ) : null}

      {findings?.length ? (
        <div className="live-findings">
          <h3>Recently reported</h3>
          <ul>
            {findings.map((finding) => (
              <li className="live-finding" key={`${finding.cve_id}-${finding.package}`}>
                <span className="live-finding__id">{finding.cve_id}</span>
                <span className="live-finding__package">
                  {finding.package}@{finding.version}
                </span>
                {finding.is_kev ? (
                  <span className="finding-signal finding-signal--exploited">
                    <Flame aria-hidden="true" size={12} /> Exploited
                  </span>
                ) : (
                  <span className={`finding-signal finding-signal--${finding.severity}`}>
                    {finding.severity}
                  </span>
                )}
              </li>
            ))}
          </ul>
          <p className="section-footnote">
            Anonymised. Advisory ids and package names are public information; nothing
            here identifies a project or an account.
          </p>
        </div>
      ) : null}

      {trending?.length ? (
        <div className="live-findings">
          <h3>Turning up most this week</h3>
          <ul>
            {trending.map((entry) => (
              <li className="live-finding" key={entry.cve_id}>
                <span className="live-finding__id">{entry.cve_id}</span>
                <span className="live-finding__package">{entry.summary}</span>
                <span className="finding-signal">
                  {entry.project_count} {entry.project_count === 1 ? "project" : "projects"}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

function Stat({ label, suffix = "", value }) {
  return (
    <div className="live-stat">
      <dt>{label}</dt>
      <dd>
        {new Intl.NumberFormat().format(value)}
        {suffix}
      </dd>
    </div>
  );
}
