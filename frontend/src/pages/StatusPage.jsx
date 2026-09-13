import { useQuery } from "@tanstack/react-query";
import { CheckCircle as CheckCircle2 } from "@phosphor-icons/react/CheckCircle";
import { WarningCircle as CircleAlert } from "@phosphor-icons/react/WarningCircle";
import { Question as HelpCircle } from "@phosphor-icons/react/Question";

import { getStatus } from "../api/status";
import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { relativeTime } from "../lib/time";

/**
 * weedout.dev/status
 *
 * The page opens by admitting what it cannot tell you, and that is not
 * modesty — it is the only honest way to run a status page from inside the
 * thing it reports on. If the service is down this page is down with it, and
 * its silence is the signal.
 *
 * What it is for is the failure nothing else would catch. An outage is loud. A
 * stale advisory feed is not: scans keep running, the dashboard keeps
 * rendering, and every user of that ecosystem is quietly told they are clean.
 * That is the number worth publishing, per ecosystem rather than as one
 * aggregate line, because one green "OSV" row while the Go export has been
 * failing for a week is the same lie in a nicer font.
 */

const STATE = {
  operational: {
    icon: CheckCircle2,
    tone: "good",
    headline: "Everything is current",
    detail: "Every advisory feed synced within its window.",
  },
  degraded: {
    icon: CircleAlert,
    tone: "warn",
    headline: "Some advisory data is behind",
    detail:
      "Scans are still running, but findings for the ecosystems below may be missing recent advisories.",
  },
  unknown: {
    icon: HelpCircle,
    tone: "neutral",
    headline: "No feed data yet",
    detail: "Nothing has synced on this deployment.",
  },
};

export function StatusPage() {
  const query = useQuery({
    queryKey: ["status"],
    queryFn: ({ signal }) => getStatus({ signal }),
    // The server caches for a minute and says so; re-asking more often would
    // only move load without moving the answer.
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: false,
  });

  if (query.isPending) {
    return (
      <div className="status-page">
        <AsyncLoading>Checking…</AsyncLoading>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="status-page">
        <header className="page-head">
          <h1>Status</h1>
        </header>
        <AsyncError error={query.error} onRetry={() => query.refetch()} />
        <p className="status-caveat">
          This page runs inside the service it reports on. If it will not load, that is
          itself the answer.
        </p>
      </div>
    );
  }

  const status = query.data.data;
  const state = STATE[status.state] ?? STATE.unknown;
  const Icon = state.icon;

  return (
    <div className="status-page">
      <header className="page-head">
        <p className="section-label">weedout.dev</p>
        <h1>Status</h1>
      </header>

      <div className={`status-banner status-banner--${state.tone}`}>
        <Icon aria-hidden="true" size={22} />
        <div>
          <p className="status-banner__headline">{state.headline}</p>
          <p className="status-banner__detail">{state.detail}</p>
        </div>
      </div>

      <section aria-labelledby="activity-heading" className="status-section">
        <h2 id="activity-heading">Activity</h2>
        <dl className="status-figures">
          <div>
            <dt>Scans in the last 24 hours</dt>
            <dd>{status.scans_24h.toLocaleString()}</dd>
          </div>
          <div>
            <dt>Advisories mirrored</dt>
            <dd>{status.advisories.toLocaleString()}</dd>
          </div>
          {status.projects !== null && status.accounts !== null ? (
            <>
              <div>
                <dt>Projects watched</dt>
                <dd>{status.projects.toLocaleString()}</dd>
              </div>
              <div>
                <dt>Accounts</dt>
                <dd>{status.accounts.toLocaleString()}</dd>
              </div>
            </>
          ) : null}
        </dl>
      </section>

      <section aria-labelledby="feeds-heading" className="status-section">
        <h2 id="feeds-heading">Advisory data</h2>
        <p className="status-section__lede">
          Where the findings come from. A feed that stops updating is the failure worth
          watching for here: nothing breaks, and the answers quietly go out of date.
        </p>

        <ul className="status-list">
          {status.feeds.map((feed) => (
            <li className="status-row" key={feed.label}>
              <div>
                <p className="status-row__label">{feed.label}</p>
                <p className="status-row__meta">
                  {feed.record_count.toLocaleString()} records
                  {" · "}
                  behind by no more than {feed.stale_after_hours}h when healthy
                </p>
              </div>
              <p
                className={`status-row__value${feed.is_stale ? " status-row__value--stale" : ""}`}
              >
                {feed.hours_behind === null
                  ? "never synced"
                  : `updated ${describeHours(feed.hours_behind)}`}
              </p>
            </li>
          ))}
        </ul>
      </section>


      <p className="status-caveat">
        Checked {relativeTime(status.checked_at)}, and cached for up to a minute.{" "}
        <strong>This page runs inside the service it reports on</strong>, so it can tell you
        that the advisory data is stale but not that the site is up — if something is
        seriously wrong, this page will not load either.
      </p>
    </div>
  );
}

/**
 * Hours, said the way a person would.
 *
 * "0.3 hours ago" is technically accurate and reads as a machine talking. This
 * page is for somebody deciding whether to trust a scan result.
 */
function describeHours(hours) {
  if (hours < 1) {
    const minutes = Math.max(1, Math.round(hours * 60));
    return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  }
  if (hours < 48) {
    const rounded = Math.round(hours);
    return `${rounded} hour${rounded === 1 ? "" : "s"} ago`;
  }
  const days = Math.round(hours / 24);
  return `${days} days ago`;
}
