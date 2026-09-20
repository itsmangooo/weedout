import { useState } from "react";
import { PageFrame } from "../../components/ui/PageFrame";
import { AsyncError, AsyncLoading } from "../../components/feedback/AsyncState";
import { AuditList } from "../../features/admin/components/AuditList";
import { useAudit } from "../../features/admin/hooks/useAdmin";

export function AdminAuditPage() {
  const [search, setSearch] = useState("");
  const [action, setAction] = useState("all");
  const query = useAudit();

  if (query.isPending) return <AsyncLoading>Reading the audit log…</AsyncLoading>;
  if (query.isError) return <AsyncError error={query.error} onRetry={() => query.refetch()} />;

  const actions = [...new Set(query.data.map((entry) => entry.action))].sort();
  const visible = query.data.filter((entry) => (action === "all" || entry.action === action) && `${entry.action} ${entry.actor_email} ${entry.target_email ?? ""} ${JSON.stringify(entry.details ?? {})}`.toLowerCase().includes(search.toLowerCase()));

  return (
    <PageFrame className="operations-page operations-audit" eyebrow="Weedout / Operations" title={<> Audit log </>} description="An append-only record of administrative actions.">

      <p className="prose u-text-sm u-mb-5">
        Every administrative action, newest first. Append-only — nothing here is edited or deleted
        by the application.
      </p>

      {query.data.length ? <div className="audit-toolbar"><label className="search-field">Search the audit log<input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Actor, target, action or detail" /></label><label className="compact-select">Action<select value={action} onChange={(event) => setAction(event.target.value)}><option value="all">All actions</option>{actions.map((value) => <option key={value} value={value}>{value}</option>)}</select></label><span className="mono dim">{visible.length} of {query.data.length}</span></div> : null}

      <div className="card card--flush">
        {visible.length ? (
          <AuditList entries={visible} />
        ) : (
          <div className="empty-state">
            <h2>{query.data.length ? "No events match" : "Nothing logged yet"}</h2>
            <p>{query.data.length ? "Change the search or action filter to see more events." : "Plan changes, suspensions and admin promotions all appear here."}</p>
          </div>
        )}
      </div>
    </PageFrame>
  );
}
