import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { changeTier, deleteUser, suspendUser, unsuspendUser } from "../../api/admin";
import { AsyncError, AsyncLoading } from "../../components/feedback/AsyncState";
import { Button } from "../../components/ui/Button";
import { InlineNotice } from "../../components/ui/InlineNotice";
import { AuditList } from "../../features/admin/components/AuditList";
import { useAdminMutation, useUser } from "../../features/admin/hooks/useAdmin";
import { dueTime, relativeTime } from "../../lib/time";

export function AdminUserPage() {
  const { userId } = useParams();
  const query = useUser(userId);

  if (query.isPending) return <AsyncLoading>Reading the account…</AsyncLoading>;
  if (query.isError) return <AsyncError error={query.error} onRetry={() => query.refetch()} />;

  const detail = query.data;
  const account = detail.user;

  return (
    <>
      <div className="admin-head">
        <h1 className="mono">{account.email}</h1>
        <Link className="button button--ghost" to="/admin/users">
          Back to users
        </Link>
      </div>

      {account.is_suspended ? (
        <div className="u-mb-5">
          <InlineNotice
            title={`Suspended ${relativeTime(account.suspended_at) || ""}`.trim()}
            tone="danger"
          >
            <p>
              They can&rsquo;t sign in, their open sessions are dead, and their projects have been
              removed from the scan queue. Nothing has been deleted.
            </p>
            {account.suspension_reason ? <p>Reason: {account.suspension_reason}</p> : null}
          </InlineNotice>
        </div>
      ) : null}

      <div className="detail-grid">
        <div>
          <Projects account={account} targets={detail.targets} />
          <Alerts alerts={detail.recent_alerts} />
          {detail.audit_entries.length ? (
            <section className="card card--flush u-mt-5">
              <div className="card__head">
                <h2>Admin actions on this account</h2>
              </div>
              <AuditList entries={detail.audit_entries} />
            </section>
          ) : null}
        </div>

        <aside>
          <AccountFacts account={account} detail={detail} />
          {account.dodo_subscription_id ? <Subscription account={account} /> : null}
          <TierCard account={account} tiers={detail.tiers} />
          <AccessCard account={account} />
          <DangerCard account={account} detail={detail} />
        </aside>
      </div>
    </>
  );
}

function Projects({ account, targets }) {
  return (
    <section className="card card--flush">
      <div className="card__head">
        <h2>Projects ({targets.length})</h2>
      </div>
      {targets.length ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Kind</th>
                <th scope="col">Deps</th>
                <th scope="col">Last checked</th>
                <th scope="col">Next check</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((target) => (
                <tr key={target.id}>
                  <td>{target.name}</td>
                  <td className="mono dim">{target.manifest_kind || "—"}</td>
                  <td className="mono">{target.dependency_count}</td>
                  <td className="mono dim">{relativeTime(target.last_scanned_at) || "never"}</td>
                  {/* A suspended account's projects are out of the queue, so a
                      next-check time would be a schedule that will not run.
                      `dueTime` rather than `relativeTime` for the rest: a
                      scheduled time that has passed is not "2 days ago", which
                      reads as a check that happened — it means the check is
                      late, and that is the whole thing worth noticing here. */}
                  <td className="mono dim">
                    {account.is_suspended ? "—" : dueTime(target.next_scan_at) || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state">
          <p>No projects tracked.</p>
        </div>
      )}
    </section>
  );
}

function Alerts({ alerts }) {
  return (
    <section className="card card--flush u-mt-5">
      <div className="card__head">
        <h2>Alert history</h2>
      </div>
      {alerts.length ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Sent</th>
                <th scope="col">Channel</th>
                <th scope="col">Status</th>
                <th scope="col">Subject</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id}>
                  <td className="mono dim">{relativeTime(alert.sent_at || alert.created_at)}</td>
                  <td className="mono dim">{alert.channel}</td>
                  <td>
                    <span
                      className={`pill ${
                        alert.status === "sent"
                          ? "pill--calm"
                          : alert.status === "failed"
                            ? "pill--critical"
                            : "pill--plain"
                      }`}
                    >
                      {alert.status}
                    </span>
                  </td>
                  <td className="u-text-xs">
                    {alert.subject}
                    {alert.error ? (
                      <>
                        <br />
                        <span className="dim u-text-xs">{alert.error.slice(0, 160)}</span>
                      </>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state">
          <p>No alerts have been sent to this account.</p>
        </div>
      )}
    </section>
  );
}

function AccountFacts({ account, detail }) {
  return (
    <div className="card">
      <h2 className="eyebrow">Account</h2>
      <dl className="datalist">
        <dt>Email</dt>
        <dd className="mono u-wrap-anywhere">{account.email}</dd>
        <dt>Plan</dt>
        <dd>{account.tier_label}</dd>
        <dt>Status</dt>
        <dd>
          {account.status_label}
          {account.is_admin ? <span className="pill pill--digest">Admin</span> : null}
        </dd>
        <dt>Signed up</dt>
        <dd>{relativeTime(account.created_at)}</dd>
        <dt>Last login</dt>
        <dd>{relativeTime(account.last_login_at) || "never"}</dd>
        <dt>Email alerts</dt>
        <dd>{account.email_alerts_enabled ? "On" : "Off"}</dd>
        <dt>Open alerts</dt>
        <dd className="mono">{detail.open_alert_count}</dd>
        <dt>Filtered</dt>
        <dd className="mono">{detail.suppressed_count}</dd>
        <dt>Scans run</dt>
        <dd className="mono">{detail.scan_count}</dd>
      </dl>
    </div>
  );
}

function Subscription({ account }) {
  return (
    <div className="card u-mt-4">
      <h2 className="eyebrow">Subscription</h2>
      <dl className="datalist">
        <dt>Status</dt>
        <dd>{account.subscription_status || "—"}</dd>
        {account.subscription_amount_cents ? (
          <>
            <dt>Amount</dt>
            <dd className="mono">
              {(account.subscription_amount_cents / 100).toFixed(2)}{" "}
              {account.subscription_currency} / {account.subscription_interval}
            </dd>
          </>
        ) : null}
        <dt>Next billed</dt>
        <dd>{relativeTime(account.subscription_ends_at) || "—"}</dd>
        <dt>Subscription</dt>
        <dd className="mono u-text-xxs u-wrap-anywhere">{account.dodo_subscription_id}</dd>
      </dl>
    </div>
  );
}

function TierCard({ account, tiers }) {
  const [tier, setTier] = useState(account.tier);
  const [note, setNote] = useState("");

  const mutation = useAdminMutation(() => changeTier(account.id, { tier, note }), {
    onSuccess: () => setNote(""),
  });

  return (
    <div className="card u-mt-4">
      <h2 className="eyebrow">Change plan</h2>
      {mutation.isError ? (
        <div className="u-mb-4">
          <InlineNotice tone="danger">{mutation.error.message}</InlineNotice>
        </div>
      ) : null}

      <form
        onSubmit={(event) => {
          event.preventDefault();
          mutation.mutate();
        }}
      >
        <div className="field">
          <label htmlFor="tier">Plan</label>
          <select
            className="select"
            id="tier"
            onChange={(event) => setTier(event.target.value)}
            value={tier}
          >
            {tiers.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="note">Note</label>
          <input
            className="input"
            id="note"
            maxLength={500}
            onChange={(event) => setNote(event.target.value)}
            placeholder="e.g. comped for beta feedback"
            type="text"
            value={note}
          />
          <p className="field__hint">Recorded in the audit log. Doesn&rsquo;t touch Dodo.</p>
        </div>
        <Button className="button--block" disabled={mutation.isPending} type="submit">
          {mutation.isPending ? "Updating…" : "Update plan"}
        </Button>
      </form>
    </div>
  );
}

function AccessCard({ account }) {
  const [reason, setReason] = useState("");

  const suspend = useAdminMutation(() => suspendUser(account.id, { reason }));
  const lift = useAdminMutation(() => unsuspendUser(account.id));
  const failure = suspend.error || lift.error;

  return (
    <div className="card u-mt-4">
      <h2 className="eyebrow">Access</h2>
      {failure ? (
        <div className="u-mb-4">
          <InlineNotice tone="danger">{failure.message}</InlineNotice>
        </div>
      ) : null}

      {account.is_admin ? (
        <p className="field__hint u-flush">
          Administrator accounts can&rsquo;t be suspended from here. Use{" "}
          <code>python -m app.manage demote-admin</code> first.
        </p>
      ) : account.is_suspended ? (
        <>
          <Button
            className="button--block"
            disabled={lift.isPending}
            onClick={() => lift.mutate()}
          >
            {lift.isPending ? "Lifting…" : "Lift suspension"}
          </Button>
          <p className="field__hint">
            Restores sign-in and puts their projects back in the scan queue.
          </p>
        </>
      ) : (
        <>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              suspend.mutate();
            }}
          >
            <div className="field">
              <label htmlFor="reason">Reason</label>
              <input
                className="input"
                id="reason"
                maxLength={500}
                onChange={(event) => setReason(event.target.value)}
                placeholder="e.g. abuse report #12"
                type="text"
                value={reason}
              />
            </div>
            <Button
              className="button--block"
              disabled={suspend.isPending}
              type="submit"
              variant="danger"
            >
              {suspend.isPending ? "Suspending…" : "Suspend account"}
            </Button>
          </form>
          <p className="field__hint">Reversible. Deletes nothing.</p>
        </>
      )}
    </div>
  );
}

/**
 * Deletion.
 *
 * The typed address is checked again on the server, so this is the courtesy
 * half of the guard, not the guard. What it is for is making the admin look at
 * *which* account they are about to destroy — a plain "are you sure?" is
 * answered reflexively.
 */
function DangerCard({ account, detail }) {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");

  const remove = useAdminMutation(() => deleteUser(account.id, { confirmEmail: typed }), {
    onSuccess: () => navigate("/admin/users"),
  });

  const findings = detail.open_alert_count + detail.suppressed_count;
  const matches = typed.trim().toLowerCase() === account.email.toLowerCase();

  return (
    <div className="card card--danger u-mt-4">
      <h2 className="eyebrow">Delete account</h2>
      <p className="field__hint u-mt-0">
        Permanently removes this account and everything belonging to it:{" "}
        {detail.targets.length} {detail.targets.length === 1 ? "project" : "projects"}, {findings}{" "}
        {findings === 1 ? "finding" : "findings"}, {detail.recent_alerts.length} alert records and
        all scan history. <strong>This can&rsquo;t be undone.</strong> To close an account
        temporarily, suspend it instead.
      </p>

      {open ? (
        <form
          className="u-mt-4"
          onSubmit={(event) => {
            event.preventDefault();
            remove.mutate();
          }}
        >
          {remove.isError ? (
            <div className="u-mb-4">
              <InlineNotice tone="danger">{remove.error.message}</InlineNotice>
            </div>
          ) : null}

          <p className="modal__text">
            The audit log keeps a record of this deletion, including the email address.
          </p>

          <div className="field">
            <label htmlFor="confirm_email">
              Type <code>{account.email}</code> to confirm
            </label>
            <input
              autoCapitalize="none"
              autoComplete="off"
              className="input"
              id="confirm_email"
              onChange={(event) => setTyped(event.target.value)}
              spellCheck={false}
              type="text"
              value={typed}
            />
          </div>

          <div className="modal__actions">
            <Button
              onClick={() => {
                setOpen(false);
                setTyped("");
              }}
              variant="secondary"
            >
              Cancel
            </Button>
            <Button disabled={!matches || remove.isPending} type="submit" variant="danger">
              {remove.isPending ? "Deleting…" : "Delete permanently"}
            </Button>
          </div>
        </form>
      ) : (
        <Button className="button--block" onClick={() => setOpen(true)} variant="danger">
          Delete this account…
        </Button>
      )}
    </div>
  );
}
