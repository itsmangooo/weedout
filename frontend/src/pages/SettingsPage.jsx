import { Mail } from "lucide-react";

import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { InlineNotice } from "../components/ui/InlineNotice";
import { AccountKeys } from "../features/settings/components/AccountKeys";
import { PasswordSection } from "../features/settings/components/PasswordSection";
import { SessionList } from "../features/settings/components/SessionList";
import { TwoFactorSection } from "../features/settings/components/TwoFactorSection";
import { useSettings, useSettingsMutation } from "../features/settings/hooks/useSettings";
import { setEmailAlerts } from "../api/settings";

export function SettingsPage() {
  const query = useSettings();

  if (query.isPending) {
    return (
      <div className="page-narrow">
        <AsyncLoading>Loading your account…</AsyncLoading>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="page-narrow">
        <AsyncError error={query.error} onRetry={() => query.refetch()} />
      </div>
    );
  }

  const page = query.data;

  return (
    <div className="page-narrow settings-page">
      <header className="page-head">
        <p className="section-label">{page.data.email}</p>
        <h1>Account</h1>
      </header>

      <AlertsSection enabled={page.data.email_alerts} />
      <TwoFactorSection account={page.data} />
      <PasswordSection />
      <SessionList sessions={page.sessions} />
      <AccountKeys keys={page.api_keys} projects={page.projects} />
    </div>
  );
}

function AlertsSection({ enabled }) {
  const update = useSettingsMutation((next) => setEmailAlerts(next));

  return (
    <section aria-labelledby="alerts-title" className="settings-section">
      <h2 id="alerts-title">
        <Mail aria-hidden="true" size={17} /> Email alerts
      </h2>

      {update.isError ? <InlineNotice tone="danger">{update.error.message}</InlineNotice> : null}

      <label className="toggle-row">
        <input
          checked={enabled}
          disabled={update.isPending}
          onChange={(event) => update.mutate(event.target.checked)}
          type="checkbox"
        />
        <span>
          <strong>Email me when something needs attention</strong>
          <small>
            Only for findings that are reachable and above your thresholds. Turning this
            off does not stop the scans — you will still see everything here.
          </small>
        </span>
      </label>
    </section>
  );
}
