import { Link, useSearchParams } from "react-router";

import { AsyncError, AsyncLoading } from "../../components/feedback/AsyncState";
import { useInbox } from "../../features/admin/hooks/useAdmin";
import { relativeTime } from "../../lib/time";

const FILTERS = [
  { value: "new", label: "Unread" },
  { value: "read", label: "Read" },
  { value: "resolved", label: "Resolved" },
  { value: "all", label: "Everything" },
];

export function AdminInboxPage() {
  const [params, setParams] = useSearchParams();
  const show = params.get("show") || "new";
  const query = useInbox(show);

  if (query.isPending) return <AsyncLoading>Reading the inbox…</AsyncLoading>;
  if (query.isError) return <AsyncError error={query.error} onRetry={() => query.refetch()} />;

  const { messages, total, unread } = query.data;

  return (
    <>
      <div className="admin-head">
        <h1>Inbox</h1>
      </div>

      <nav aria-label="Message status" className="tabs tabs--sub">
        {FILTERS.map((filter) => (
          <button
            aria-selected={show === filter.value}
            className={`tab${show === filter.value ? " is-active" : ""}`}
            key={filter.value}
            onClick={() => setParams({ show: filter.value })}
            type="button"
          >
            {filter.label}
            {filter.value === "new" && unread ? (
              <span className="pill pill--sm">{unread}</span>
            ) : null}
          </button>
        ))}
      </nav>

      {messages.length ? (
        <>
          <div className="card card--flush">
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">From</th>
                    <th scope="col">About</th>
                    <th scope="col">Message</th>
                    <th scope="col">Received</th>
                    <th scope="col">
                      <span className="visually-hidden">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {messages.map((message) => (
                    <MessageRow key={message.id} message={message} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <p className="dim u-text-xs u-mt-4">
            Showing {messages.length} of {total}.
          </p>
        </>
      ) : (
        <div className="card">
          <div className="empty-state">
            <span aria-hidden="true" className="empty-state__mark">
              <i />
              <i />
              <i />
            </span>
            <h2>{show === "new" ? "Nothing waiting" : "Nothing here"}</h2>
            <p>
              {show === "new"
                ? "Every message has been read. New ones arrive here and by email."
                : "No messages with this status yet."}
            </p>
          </div>
        </div>
      )}
    </>
  );
}

function MessageRow({ message }) {
  return (
    <tr className={message.status === "new" ? "is-unread" : undefined}>
      <td>
        <Link to={`/admin/inbox/${message.id}`}>{message.email}</Link>
        {message.user_id ? null : <span className="dim u-text-xs">no account</span>}
      </td>
      <td>
        <span className={`pill pill--sm pill--${message.category}`}>{message.category_label}</span>
      </td>
      <td className="cell-wrap">{message.preview}</td>
      <td>
        {relativeTime(message.created_at)}
        {/* The message is here either way; this says the email about it never
            left, which is a mail problem, not a lost report. */}
        {message.notified_at ? null : (
          <span
            className="pill pill--sm pill--high"
            title="The admin notification email failed"
          >
            not emailed
          </span>
        )}
      </td>
      <td className="cell-actions">
        <Link className="button button--secondary" to={`/admin/inbox/${message.id}`}>
          Open
        </Link>
      </td>
    </tr>
  );
}
