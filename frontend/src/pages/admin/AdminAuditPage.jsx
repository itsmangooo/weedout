import { PageFrame } from "../../components/ui/PageFrame";
import { AsyncError, AsyncLoading } from "../../components/feedback/AsyncState";
import { AuditList } from "../../features/admin/components/AuditList";
import { useAudit } from "../../features/admin/hooks/useAdmin";

export function AdminAuditPage() {
  const query = useAudit();

  if (query.isPending) return <AsyncLoading>Reading the audit log…</AsyncLoading>;
  if (query.isError) return <AsyncError error={query.error} onRetry={() => query.refetch()} />;

  return (
    <PageFrame className="operations-page operations-audit" eyebrow="Weedout / Operations" title={<> Audit log </>} description="An append-only record of administrative actions.">

      <p className="prose u-text-sm u-mb-5">
        Every administrative action, newest first. Append-only — nothing here is edited or deleted
        by the application.
      </p>

      <div className="card card--flush">
        {query.data.length ? (
          <AuditList entries={query.data} />
        ) : (
          <div className="empty-state">
            <h2>Nothing logged yet</h2>
            <p>Plan changes, suspensions and admin promotions all appear here.</p>
          </div>
        )}
      </div>
    </PageFrame>
  );
}
