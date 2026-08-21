import { Check, GitBranch, Server } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";

import { AsyncError, AsyncLoading } from "../../../components/feedback/AsyncState";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { useSystemStatus } from "../hooks/useSystemStatus";

export function SystemStatus() {
  const statusQuery = useSystemStatus();

  return (
    <section className="system-status" aria-labelledby="system-status-title">
      <div className="system-status__heading flex items-center justify-between gap-4">
        <div>
          <p className="section-label">Live boundary check</p>
          <h2 id="system-status-title">React → Python</h2>
        </div>
        <GitBranch aria-hidden="true" className="system-status__branch" size={24} strokeWidth={1.5} />
      </div>

      <AnimatePresence mode="wait" initial={false}>
        <motion.div
          key={statusQuery.status}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.18 }}
        >
          {statusQuery.isPending ? (
            <AsyncLoading>Waiting for the FastAPI health endpoint.</AsyncLoading>
          ) : null}

          {statusQuery.isError ? (
            <AsyncError error={statusQuery.error} onRetry={() => statusQuery.refetch()} />
          ) : null}

          {statusQuery.isSuccess ? (
            <InlineNotice icon={Check} title="Backend connected" tone="success">
              <p>
                FastAPI answered with <code>{statusQuery.data.status}</code>. Server version{" "}
                <strong>{statusQuery.data.version}</strong>.
              </p>
            </InlineNotice>
          ) : null}
        </motion.div>
      </AnimatePresence>

      <div className="system-status__path" aria-label="Current frontend data path">
        <span>TanStack Query</span>
        <span aria-hidden="true">→</span>
        <span>shared API client</span>
        <span aria-hidden="true">→</span>
        <span className="flex items-center gap-2">
          <Server aria-hidden="true" size={14} /> /healthz
        </span>
      </div>
    </section>
  );
}
