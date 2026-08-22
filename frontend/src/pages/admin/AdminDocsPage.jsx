import { useState } from "react";
import { Link } from "react-router";

import { deleteDocPage } from "../../api/admin";
import { AsyncError, AsyncLoading } from "../../components/feedback/AsyncState";
import { Button } from "../../components/ui/Button";
import { InlineNotice } from "../../components/ui/InlineNotice";
import { useAdminMutation, useDocPages } from "../../features/admin/hooks/useAdmin";
import { relativeTime } from "../../lib/time";

export function AdminDocsPage() {
  const query = useDocPages();

  if (query.isPending) return <AsyncLoading>Reading the doc pages…</AsyncLoading>;
  if (query.isError) return <AsyncError error={query.error} onRetry={() => query.refetch()} />;

  const pages = query.data;

  return (
    <>
      <div className="admin-head">
        <h1>Docs</h1>
        <div className="btn-row">
          <a className="button button--ghost" href="/docs" rel="noopener" target="_blank">
            View public docs
          </a>
          <Link className="button button--primary" to="/admin/docs/new">
            New page
          </Link>
        </div>
      </div>

      <div className="card card--flush">
        {pages.length ? (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Title</th>
                  <th scope="col">Slug</th>
                  <th scope="col">Status</th>
                  <th scope="col">Order</th>
                  <th scope="col">Updated</th>
                  <th scope="col">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {pages.map((page) => (
                  <DocRow key={page.id} page={page} />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <h2>No pages yet</h2>
            <p>
              Write the first one — it appears at <code>/docs</code> once published.
            </p>
            <div className="btn-row btn-row--center">
              <Link className="button button--primary" to="/admin/docs/new">
                New page
              </Link>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

function DocRow({ page }) {
  const [confirming, setConfirming] = useState(false);
  const remove = useAdminMutation(() => deleteDocPage(page.id));

  return (
    <tr>
      <td>
        <Link to={`/admin/docs/${page.id}`}>{page.title}</Link>
      </td>
      <td className="mono dim">/docs/{page.slug}</td>
      <td>
        {page.published ? (
          <span className="pill pill--calm">Published</span>
        ) : (
          <span className="pill pill--plain">Draft</span>
        )}
      </td>
      <td className="mono">{page.position}</td>
      <td className="mono dim">{relativeTime(page.updated_at)}</td>
      <td>
        {/* Two clicks rather than a confirm() dialog: the second button says
            what it does, and an accidental first click costs nothing. */}
        {confirming ? (
          <span className="btn-row">
            <Button
              disabled={remove.isPending}
              onClick={() => remove.mutate()}
              variant="danger"
            >
              {remove.isPending ? "Deleting…" : "Really delete"}
            </Button>
            <Button onClick={() => setConfirming(false)} variant="ghost">
              Keep
            </Button>
          </span>
        ) : (
          <Button onClick={() => setConfirming(true)} variant="ghost">
            Delete
          </Button>
        )}
        {remove.isError ? <InlineNotice tone="danger">{remove.error.message}</InlineNotice> : null}
      </td>
    </tr>
  );
}
