import { LoaderCircle, ServerOff } from "lucide-react";

import { Button } from "../../../components/ui/Button";
import { InlineNotice } from "../../../components/ui/InlineNotice";

export function DashboardLoading() {
  return (
    <div className="dashboard-query-state" role="status">
      <LoaderCircle aria-hidden="true" className="dashboard-query-state__spinner" size={24} />
      <p className="eyebrow">Protected data</p>
      <h1>Loading your dashboard</h1>
      <p>Collecting the latest project and finding summary from Weedout.</p>
    </div>
  );
}

export function DashboardError({ error, onRetry }) {
  return (
    <div className="dashboard-query-state">
      <p className="eyebrow">Dashboard unavailable</p>
      <h1>We couldn&apos;t load the dashboard.</h1>
      <InlineNotice icon={ServerOff} title="Backend unavailable" tone="danger">
        <p>{error?.message || "The dashboard service did not answer."}</p>
      </InlineNotice>
      <Button className="dashboard-query-state__action" onClick={onRetry} variant="secondary">
        Try again
      </Button>
    </div>
  );
}
