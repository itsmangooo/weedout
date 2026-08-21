import { AlertTriangle, ArrowUpRight, LoaderCircle, ServerOff } from "lucide-react";

import { Button } from "../../../components/ui/Button";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { FindingRow } from "./FindingRow";

export function OpenFindingsSection({ query }) {
  return (
    <section className="open-findings" aria-labelledby="open-findings-title">
      <div className="open-findings__heading">
        <div>
          <p className="section-label">Attention queue</p>
          <h2 id="open-findings-title">Open findings</h2>
        </div>
        <a href="/alerts?show=open">
          Review all <ArrowUpRight aria-hidden="true" size={14} />
        </a>
      </div>

      {query.isPending ? (
        <div className="open-findings__state" role="status">
          <LoaderCircle aria-hidden="true" className="dashboard-query-state__spinner" size={18} />
          <span>Loading open findings</span>
        </div>
      ) : null}

      {query.isError ? (
        <InlineNotice icon={ServerOff} title="Open findings unavailable" tone="danger">
          <p>{query.error?.message || "The findings service did not answer."}</p>
          <Button onClick={() => query.refetch()} variant="secondary">
            Try again
          </Button>
        </InlineNotice>
      ) : null}

      {query.isSuccess && query.data.data.length === 0 ? (
        <div className="open-findings__state open-findings__state--empty">
          <AlertTriangle aria-hidden="true" size={18} />
          <div>
            <strong>No open findings need attention.</strong>
            <p>New scan results will appear here when they cross your alert threshold.</p>
          </div>
        </div>
      ) : null}

      {query.isSuccess && query.data.data.length > 0 ? (
        <ul className="finding-rows">
          {query.data.data.map((finding) => (
            <FindingRow finding={finding} key={finding.id} />
          ))}
        </ul>
      ) : null}
    </section>
  );
}
