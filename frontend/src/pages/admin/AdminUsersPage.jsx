import { Link, useSearchParams } from "react-router";

import { AsyncError, AsyncLoading } from "../../components/feedback/AsyncState";
import { Button } from "../../components/ui/Button";
import { useUsers } from "../../features/admin/hooks/useAdmin";
import { relativeTime } from "../../lib/time";

const STATUSES = ["active", "suspended", "admin"];

export function AdminUsersPage() {
  const [params, setParams] = useSearchParams();

  const filters = {
    page: Number(params.get("page")) || 1,
    search: params.get("search") || "",
    status: params.get("status") || "",
  };

  const query = useUsers(filters);

  function apply(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const next = new URLSearchParams();
    for (const field of ["search", "status"]) {
      const value = String(form.get(field) || "").trim();
      if (value) next.set(field, value);
    }
    // Filtering starts a new list, so it starts on page one. Keeping the page
    // number would land on "no results" for a narrower filter that has plenty.
    setParams(next);
  }

  if (query.isPending) return <AsyncLoading>Reading the user list…</AsyncLoading>;
  if (query.isError) return <AsyncError error={query.error} onRetry={() => query.refetch()} />;

  const { data, query: applied } = query.data;
  const filtered = Boolean(applied.search || applied.status);

  return (
    <>
      <div className="admin-head">
        <h1>Users</h1>
        <span className="mono dim u-text-xs">
          {data.total} {data.total === 1 ? "account" : "accounts"}
        </span>
      </div>

      <form className="filter-bar" onSubmit={apply}>
        <div className="filter-bar__search">
          <label className="label" htmlFor="search">
            Search
          </label>
          <input
            className="input"
            defaultValue={applied.search}
            id="search"
            key={`search-${applied.search}`}
            maxLength={320}
            name="search"
            placeholder="Email contains…"
            type="search"
          />
        </div>

        <div>
          <label className="label" htmlFor="status">
            Status
          </label>
          <select className="select" defaultValue={applied.status} id="status" name="status">
            <option value="">Any</option>
            {STATUSES.map((value) => (
              <option key={value} value={value}>
                {value[0].toUpperCase() + value.slice(1)}
              </option>
            ))}
          </select>
        </div>

        <Button type="submit" variant="secondary">
          Apply
        </Button>
        {filtered ? (
          <Button onClick={() => setParams(new URLSearchParams())} variant="ghost">
            Clear
          </Button>
        ) : null}
      </form>

      <div className="card card--flush">
        {data.rows.length ? (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Email</th>
                  <th scope="col">Status</th>
                  <th scope="col">Projects</th>
                  <th scope="col">Open alerts</th>
                  <th scope="col">Signed up</th>
                  <th scope="col">Last login</th>
                </tr>
              </thead>
              <tbody>
                {data.rows.map((row) => (
                  <UserRow key={row.user.id} row={row} />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <h2>No users match</h2>
            <p>
              {filtered ? (
                <>
                  Nothing matches those filters.{" "}
                  <button
                    className="link-button"
                    onClick={() => setParams(new URLSearchParams())}
                    type="button"
                  >
                    Clear them
                  </button>{" "}
                  to see everyone.
                </>
              ) : (
                "There are no accounts yet."
              )}
            </p>
          </div>
        )}
      </div>

      {data.total ? <Pager data={data} params={params} setParams={setParams} /> : null}
    </>
  );
}

function UserRow({ row }) {
  const account = row.user;

  return (
    <tr>
      <td>
        <Link className="mono" to={`/admin/users/${account.id}`}>
          {account.email}
        </Link>
        {account.is_admin ? <span className="pill pill--digest">Admin</span> : null}
      </td>
      <td>
        {account.is_suspended ? (
          <span className="pill pill--critical">Suspended</span>
        ) : (
          <span className="pill pill--calm">{account.status_label}</span>
        )}
      </td>
      <td className="mono">{row.target_count}</td>
      <td className="mono">{row.open_alert_count || "—"}</td>
      <td className="mono dim">{relativeTime(account.created_at)}</td>
      <td className="mono dim">{relativeTime(account.last_login_at) || "never"}</td>
    </tr>
  );
}

function Pager({ data, params, setParams }) {
  function goTo(page) {
    const next = new URLSearchParams(params);
    next.set("page", String(page));
    setParams(next);
  }

  return (
    <nav aria-label="Pagination" className="pager">
      <span className="pager__summary mono">
        {data.start_index}–{data.end_index} of {data.total}
      </span>
      <div className="pager__controls">
        <Button
          disabled={data.page <= 1}
          onClick={() => goTo(data.page - 1)}
          variant="secondary"
        >
          Previous
        </Button>
        <span className="mono dim u-text-xs">
          Page {data.page} of {data.pages}
        </span>
        <Button
          disabled={data.page >= data.pages}
          onClick={() => goTo(data.page + 1)}
          variant="secondary"
        >
          Next
        </Button>
      </div>
    </nav>
  );
}
