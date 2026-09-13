import { Check } from "lucide-react";
import { AsyncError, AsyncLoading } from "../../../components/feedback/AsyncState";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { useSystemStatus } from "../hooks/useSystemStatus";
export function SystemStatus() {
  const query = useSystemStatus();
  return <section className="system-status" aria-labelledby="system-status-title"><h2 id="system-status-title">Service connection</h2>{query.isPending && <AsyncLoading>Checking the service.</AsyncLoading>}{query.isError && <AsyncError error={query.error} onRetry={() => query.refetch()} />}{query.isSuccess && <InlineNotice icon={Check} title="Backend connected" tone="success"><p>Service status: <code>{query.data.status}</code>. Version <strong>{query.data.version}</strong>.</p></InlineNotice>}</section>;
}
