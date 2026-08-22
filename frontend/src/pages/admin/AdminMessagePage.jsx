import { useState } from "react";
import { Link, useParams } from "react-router";

import { setMessageStatus } from "../../api/admin";
import { AsyncError, AsyncLoading } from "../../components/feedback/AsyncState";
import { Button } from "../../components/ui/Button";
import { InlineNotice } from "../../components/ui/InlineNotice";
import { useAdminMutation, useInboxMessage } from "../../features/admin/hooks/useAdmin";
import { describeDevice } from "../../lib/device";
import { relativeTime } from "../../lib/time";

const STATUSES = [
  { value: "new", label: "Unread" },
  { value: "read", label: "Read" },
  { value: "resolved", label: "Resolved" },
];

export function AdminMessagePage() {
  const { messageId } = useParams();
  const query = useInboxMessage(messageId);

  if (query.isPending) return <AsyncLoading>Opening the message…</AsyncLoading>;
  if (query.isError) return <AsyncError error={query.error} onRetry={() => query.refetch()} />;

  const message = query.data.message;

  return (
    <>
      <div className="admin-head">
        <h1>{message.category_label}</h1>
        <div className="btn-row">
          <Link className="button button--secondary" to="/admin/inbox">
            Back to inbox
          </Link>
          {/* The reply path is a normal mailbox on purpose. Building threading,
              notifications and spam handling in here would be a support desk,
              and this is a queue. */}
          <a
            className="button button--primary"
            href={`mailto:${message.email}?subject=${encodeURIComponent("Re: your message to Weedout")}`}
          >
            Reply by email
          </a>
        </div>
      </div>

      <div className="detail-grid">
        <div>
          <div className="card">
            <div className="card__head">
              <div>
                <h2 className="panel__title">{message.category_label}</h2>
                <p className="field__hint u-mt-0">
                  From <strong>{message.email}</strong>, {relativeTime(message.created_at)}
                </p>
              </div>
              <span className={`pill pill--${message.status}`}>{message.status_label}</span>
            </div>

            {/* Pre-wrapped rather than paragraph-split: somebody pasting a
                stack trace or a lockfile excerpt should see it the way they
                typed it. */}
            <pre className="message-body">{message.message}</pre>
          </div>

          <Triage key={message.id} message={message} />
        </div>

        <aside>
          <div className="card">
            <h2 className="panel__title">Context</h2>
            <dl className="datalist datalist--tight">
              <dt>Account</dt>
              <dd>
                {message.user_id ? (
                  <Link to={`/admin/users/${message.user_id}`}>{message.email}</Link>
                ) : (
                  <span className="dim">Logged out</span>
                )}
              </dd>

              <dt>Page</dt>
              <dd className="mono">{message.page_url || "—"}</dd>

              <dt>Browser</dt>
              <dd>{describeDevice(message.user_agent)}</dd>

              <dt>Received</dt>
              <dd>{relativeTime(message.created_at)}</dd>

              <dt>Admin notified</dt>
              <dd>
                {message.notified_at ? (
                  relativeTime(message.notified_at)
                ) : (
                  <span className="dim">No — the notification email failed</span>
                )}
              </dd>

              {message.handled_at ? (
                <>
                  <dt>Handled</dt>
                  <dd>
                    {message.handled_by_email}, {relativeTime(message.handled_at)}
                  </dd>
                </>
              ) : null}
            </dl>
          </div>
        </aside>
      </div>
    </>
  );
}

function Triage({ message }) {
  const [status, setStatus] = useState(message.status);
  const [note, setNote] = useState(message.admin_note || "");

  const save = useAdminMutation(() => setMessageStatus(message.id, { status, note }));

  return (
    <div className="card u-mt-4">
      <h2 className="panel__title">Triage</h2>

      {save.isError ? (
        <div className="u-mb-4">
          <InlineNotice tone="danger">{save.error.message}</InlineNotice>
        </div>
      ) : null}
      {save.isSuccess ? (
        <div className="u-mb-4">
          <InlineNotice tone="success">Saved.</InlineNotice>
        </div>
      ) : null}

      <form
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate();
        }}
      >
        <div className="field">
          <label htmlFor="status">Status</label>
          <select
            className="select"
            id="status"
            onChange={(event) => setStatus(event.target.value)}
            value={status}
          >
            {STATUSES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>

        <div className="field">
          <label htmlFor="note">Note to self</label>
          <textarea
            className="textarea textarea--prose"
            id="note"
            onChange={(event) => setNote(event.target.value)}
            placeholder="What you did about it."
            rows={3}
            value={note}
          />
          <p className="field__hint">Never shown to the sender.</p>
        </div>

        <div className="btn-row">
          <Button disabled={save.isPending} type="submit">
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      </form>
    </div>
  );
}
