import { Link } from "react-router";

import { AsyncError, AsyncLoading } from "../../components/feedback/AsyncState";
import { InlineNotice } from "../../components/ui/InlineNotice";
import { useAdminBilling } from "../../features/admin/hooks/useAdmin";
import { relativeTime } from "../../lib/time";

export function AdminBillingPage() {
  const query = useAdminBilling();

  if (query.isPending) return <AsyncLoading>Reading the revenue snapshot…</AsyncLoading>;
  if (query.isError) return <AsyncError error={query.error} onRetry={() => query.refetch()} />;

  const { snapshot, subscribers, dodo_enabled: enabled, dodo_dashboard_url: dashboard } = query.data;

  return (
    <>
      <div className="admin-head">
        <h1>Billing</h1>
        {/* Anything with financial consequence links out. Reimplementing
            refunds and disputes here would mean a second, lagging source of
            truth for money. */}
        <a className="button button--secondary" href={dashboard} rel="noopener noreferrer" target="_blank">
          Open Dodo dashboard
        </a>
      </div>

      {enabled ? null : (
        <div className="u-mb-5">
          <InlineNotice tone="neutral">
            Dodo Payments isn&rsquo;t enabled on this deployment, so nothing new will arrive here.
            These figures reflect whatever webhooks were processed previously.
          </InlineNotice>
        </div>
      )}

      <section aria-labelledby="revenue-heading">
        <h2 className="eyebrow" id="revenue-heading">
          Revenue
        </h2>
        <div className="stat-grid">
          <div className="stat stat--wide">
            <b>
              {snapshot.mrr.toFixed(2)}
              <span className="stat__unit">{snapshot.currency}</span>
            </b>
            <span>MRR</span>
            <small>
              {snapshot.arr.toFixed(2)} {snapshot.currency} annualised
            </small>
          </div>
          <div className="stat">
            <b>{snapshot.active_count}</b>
            <span>Active</span>
            {snapshot.trialing_count ? <small>{snapshot.trialing_count} trialing</small> : null}
          </div>
          <div className={`stat${snapshot.past_due_count ? " stat--warn" : ""}`}>
            <b>{snapshot.past_due_count}</b>
            <span>Past due</span>
            <small>Still have access while retrying</small>
          </div>
          <div className="stat">
            <b>{snapshot.canceled_count}</b>
            <span>Canceled</span>
          </div>
        </div>

        {snapshot.untracked_paid_count ? (
          <div className="u-mt-4">
            <InlineNotice tone="neutral">
              {snapshot.untracked_paid_count}{" "}
              {snapshot.untracked_paid_count === 1 ? "account is" : "accounts are"} on the Pro plan
              with no recorded subscription amount — manual comps, or a webhook processed before
              the price fields existed. They are excluded from MRR, so the figure above is a floor
              rather than an estimate.
            </InlineNotice>
          </div>
        ) : null}
      </section>

      <section aria-labelledby="subs-heading" className="u-mt-7">
        <div className="card card--flush">
          <div className="card__head">
            <h2 id="subs-heading">Subscribers</h2>
            <span className="mono dim u-text-xs">{subscribers.length}</span>
          </div>

          {subscribers.length ? (
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Email</th>
                    <th scope="col">Plan</th>
                    <th scope="col">Status</th>
                    <th scope="col">Amount</th>
                    <th scope="col">Next billed</th>
                  </tr>
                </thead>
                <tbody>
                  {subscribers.map((sub) => (
                    <tr key={sub.id}>
                      <td>
                        <Link className="mono" to={`/admin/users/${sub.id}`}>
                          {sub.email}
                        </Link>
                      </td>
                      <td>
                        <span
                          className={`pill ${sub.tier === "pro" ? "pill--calm" : "pill--plain"}`}
                        >
                          {sub.tier_label}
                        </span>
                      </td>
                      <td>
                        <SubscriptionStatus status={sub.subscription_status} />
                      </td>
                      <td className="mono">
                        {sub.subscription_amount_cents ? (
                          <>
                            {(sub.subscription_amount_cents / 100).toFixed(2)}{" "}
                            {sub.subscription_currency}
                            <span className="dim">/{sub.subscription_interval}</span>
                          </>
                        ) : (
                          <span className="dim">—</span>
                        )}
                      </td>
                      <td className="mono dim">{relativeTime(sub.subscription_ends_at) || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <h2>No subscriptions yet</h2>
              <p>Subscribers appear here once Dodo sends its first subscription webhook.</p>
            </div>
          )}
        </div>
      </section>
    </>
  );
}

function SubscriptionStatus({ status }) {
  const value = status || "unknown";

  if (value === "active" || value === "trialing") {
    return <span className="pill pill--calm">{value}</span>;
  }
  if (value === "on_hold") {
    return <span className="pill pill--high">on hold</span>;
  }
  return <span className="pill pill--plain">{value}</span>;
}
