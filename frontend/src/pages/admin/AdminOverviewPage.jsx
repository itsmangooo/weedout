import { PageFrame } from "../../components/ui/PageFrame";
import { Link, useSearchParams } from "react-router";

import { AsyncError, AsyncLoading } from "../../components/feedback/AsyncState";
import { SignupChart } from "../../features/admin/components/SignupChart";
import { useOverview } from "../../features/admin/hooks/useAdmin";
import { relativeTime } from "../../lib/time";

const RANGES = [7, 30, 90];

export function AdminOverviewPage() {
  const [params, setParams] = useSearchParams();
  const days = Number(params.get("days")) || 30;
  const query = useOverview(days);

  if (query.isPending) return <AsyncLoading>Reading the platform…</AsyncLoading>;
  if (query.isError) return <AsyncError error={query.error} onRetry={() => query.refetch()} />;

  const { metrics, feeds, signups, chart_days: chartDays } = query.data;

  return (
    <PageFrame className="operations-page operations-overview" eyebrow="Weedout / Operations" title={<> Overview </>} description="Platform activity, advisory freshness and accounts in one operational view.">

      <FeedHealth feeds={feeds} />
      <Platform metrics={metrics} />
      <div className="operations-overview-columns"><FeedDetail feeds={feeds} />

      <section aria-labelledby="signups-heading" className="section-gap">
        <div className="card">
          <div className="chart-head">
            <div>
              <h2 className="panel__title u-mb-0" id="signups-heading">
                Total accounts
              </h2>
              <p className="muted u-text-xs u-mt-2">Cumulative, last {chartDays} days.</p>
            </div>
            <div className="chart-range">
              {RANGES.map((option) => (
                <button
                  aria-current={chartDays === option ? "true" : undefined}
                  className="chart-range__option"
                  key={option}
                  onClick={() => setParams({ days: String(option) })}
                  type="button"
                >
                  {option}d
                </button>
              ))}
            </div>
          </div>

          <SignupChart days={chartDays} points={signups} />
        </div>
      </section>
    </div></PageFrame>
  );
}

/**
 * Feed health leads the page, as a single state rather than a row of cards.
 *
 * A silently broken feed doesn't break any screen — scans still succeed,
 * dashboards still render — it just makes every answer wrong. So it is the
 * first thing shown, stated as one phrase, and the per-feed detail follows.
 */
function FeedHealth({ feeds }) {
  const never = feeds.filter((feed) => !feed.last_success_at);
  const stale = feeds.filter((feed) => feed.is_stale && feed.last_success_at);
  const unhealthy = [...never, ...stale];

  const tone = never.length
    ? " status-hero--exploited"
    : stale.length
      ? " status-hero--open"
      : "";

  return (
    <section aria-labelledby="feeds-heading" className={`status-hero${tone}`}>
      <h2 className="visually-hidden" id="feeds-heading">
        Feed health
      </h2>

      <div className="status-hero__inner">
        <div>
          <span className="status-hero__state">
            <span aria-hidden="true" className="status-hero__mark">
              <i className={never.length ? "is-lit" : ""} />
              <i className={unhealthy.length ? "is-lit" : ""} />
              <i className="is-lit" />
            </span>
            {never.length ? "Feed never synced" : stale.length ? "Feed stale" : "Feeds healthy"}
          </span>

          {unhealthy.length ? (
            <>
              <span className="status-hero__value">{unhealthy.length}</span>
              <p className="status-hero__note">
                {unhealthy.length === 1 ? "feed is" : "feeds are"} not current, so matching is
                running against data we know is out of date. Every alert and every all-clear below
                is suspect until this is fixed.
              </p>
            </>
          ) : (
            <>
              <span className="status-hero__word">All feeds current</span>
              <p className="status-hero__note">
                {feeds.length} {feeds.length === 1 ? "source" : "sources"} synced within their
                freshness window. Matching is running against current advisory data.
              </p>
            </>
          )}
        </div>
      </div>

      <div className="metrics">
        {feeds.map((feed) => (
          <div
            className={`metric metric--text is-active ${
              !feed.last_success_at
                ? "metric--exploited"
                : feed.is_stale
                  ? "metric--signal"
                  : "metric--calm"
            }`}
            key={feed.name}
          >
            <span className="metric__value">
              <span aria-hidden="true" className="metric__dot" />
              {feed.last_success_at ? relativeTime(feed.last_success_at) : "never"}
            </span>
            <span className="metric__label">{feed.label}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

/** Only worth reading once the state above says something is wrong. */
function FeedDetail({ feeds }) {
 return <section aria-labelledby="feed-detail-heading" className="section-gap"><h2 id="feed-detail-heading">Advisory sources</h2><div className="table-scroll"><table className="data-table feed-table"><thead><tr><th scope="col">Source</th><th scope="col">State</th><th scope="col">Latest sync / records</th></tr></thead><tbody>{feeds.map((feed) => <tr key={feed.name}><th scope="row">{feed.label}</th><td><span className={`feed__status feed--${feed.status.replace(/ /g,"-")}`}>{feed.status}</span></td><td><p>{relativeTime(feed.last_success_at) || "never"}</p>{feed.record_count != null && <p className="mono muted">{feed.record_count.toLocaleString()} records</p>}{feed.catalog_version && <p className="mono muted">{feed.catalog_version}</p>}{feed.last_attempt_at && <small className="muted">Attempted {relativeTime(feed.last_attempt_at)}</small>}<FeedProblem feed={feed} /></td></tr>)}</tbody></table></div></section>;
}

function FeedProblem({ feed }) {
  if (feed.last_error) {
    return <p className="feed__error">{feed.last_error.slice(0, 300)}</p>;
  }
  if (!feed.last_success_at) {
    return (
      <p className="feed__error">
        Never synced. Run <code>python -m app.jobs.runner refresh-kev</code> or check the worker.
      </p>
    );
  }
  if (feed.is_stale) {
    return (
      <p className="feed__error">
        No successful sync in over a day. Alerts may be based on outdated data.
      </p>
    );
  }
  return null;
}

function Platform({ metrics }) {
  return (
    <section aria-labelledby="metrics-heading" className="section-gap">
      <h2 className="eyebrow" id="metrics-heading">
        Platform
      </h2>
      <div className="stat-grid">
        <Stat
          label="Users"
          note={`${metrics.new_users_7d} new this week`}
          value={metrics.total_users}
        />
        <Stat
          label="Projects"
          note={`${metrics.total_dependencies.toLocaleString()} dependencies watched`}
          value={metrics.total_targets}
        />
        <Stat
          label="Scans, all time"
          note={`${metrics.scans_today} today · ${metrics.scans_7d} this week`}
          value={metrics.scans_all_time}
        />
        <Stat
          label="Failed scans, 7d"
          note={`${metrics.alerts_emailed_7d} alert emails sent`}
          value={metrics.failed_scans_7d}
          warn={metrics.failed_scans_7d > 0}
        />
        <Stat
          label="Noise filtered"
          note={`${metrics.open_alerts} open · ${metrics.suppressed_alerts} suppressed`}
          unit="%"
          value={metrics.noise_filtered_share}
        />
        {metrics.suspended_users ? (
          <div className="stat stat--warn">
            <b>{metrics.suspended_users}</b>
            <span>Suspended</span>
            <small>
              <Link to="/admin/users?status=suspended">Review</Link>
            </small>
          </div>
        ) : null}
      </div>
    </section>
  );
}

function Stat({ label, note, unit, value, warn = false }) {
  return (
    <div className={`stat${warn ? " stat--warn" : ""}`}>
      <b>
        {value.toLocaleString()}
        {unit ? <span className="stat__unit">{unit}</span> : null}
      </b>
      <span>{label}</span>
      <small>{note}</small>
    </div>
  );
}
