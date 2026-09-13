import { PageFrame } from "../components/ui/PageFrame";
import { SectionIndex } from "../components/ui/SectionIndex";
import { Mail } from "lucide-react";

import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { InlineNotice } from "../components/ui/InlineNotice";
import { AccountKeys } from "../features/settings/components/AccountKeys";
import { OrganisationSection } from "../features/settings/components/OrganisationSection";
import { PasswordSection } from "../features/settings/components/PasswordSection";
import { RuleProfiles } from "../features/settings/components/RuleProfiles";
import { SessionList } from "../features/settings/components/SessionList";
import { SignedInMachines } from "../features/settings/components/SignedInMachines";
import { TwoFactorSection } from "../features/settings/components/TwoFactorSection";
import { useProfiles } from "../features/settings/hooks/useProfiles";
import { useSettings, useSettingsMutation } from "../features/settings/hooks/useSettings";
import { setEmailAlerts } from "../api/settings";

export function SettingsPage() {
  const query = useSettings();
  // Its own request rather than part of the settings envelope: profiles change
  // independently of the account, and a mutation on one should not re-read the
  // other.
  const profiles = useProfiles();

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
    <PageFrame className="settings-page" eyebrow={page.data.email} title="Account" description="Control your account, alert policy and access from one place.">
      <div className="settings-layout"><SectionIndex label="Account settings" items={[["account-security","Security"],["account-policy","Alert policy"],["account-access","Access & devices"]]} /><div className="settings-content">
      <div id="account-security"><TwoFactorSection account={page.data} /><PasswordSection /><OrganisationSection account={page.data} /></div>
      <div id="account-policy"><AlertsSection enabled={page.data.email_alerts} />
      {profiles.isSuccess && <RuleProfiles meta={profiles.data.meta} profiles={profiles.data.data} />}
      {profiles.isPending && <AsyncLoading>Loading rule profiles...</AsyncLoading>}
      {profiles.isError && <AsyncError error={profiles.error} onRetry={() => profiles.refetch()} />}</div>
      <div id="account-access"><SessionList sessions={page.sessions} /><SignedInMachines /><AccountKeys keys={page.api_keys} projects={page.projects} /></div>
      </div></div>
    </PageFrame>
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
