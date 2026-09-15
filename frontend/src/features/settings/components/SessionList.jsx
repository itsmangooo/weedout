import { Devices as MonitorSmartphone } from "@phosphor-icons/react/Devices";

import { revokeOtherSessions, revokeSession } from "../../../api/settings";
import { Button } from "../../../components/ui/Button";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { describeDevice } from "../../../lib/device";
import { relativeTime } from "../../../lib/time";
import { useSettingsMutation } from "../hooks/useSettings";

export function SessionList({ sessions }) {
  const revokeOne = useSettingsMutation((id) => revokeSession(id));
  const revokeRest = useSettingsMutation(revokeOtherSessions);

  const others = sessions.filter((session) => !session.is_current).length;
  const failure = revokeOne.error || revokeRest.error;

  return (
    <section aria-labelledby="sessions-title" className="settings-section">
      <h2 id="sessions-title">
        <MonitorSmartphone aria-hidden="true" size={17} /> Where you are signed in
      </h2>

      {failure ? <InlineNotice tone="danger">{failure.message}</InlineNotice> : null}

      <ul className="session-list">
        {sessions.map((session) => (
          <li className="session-row" key={session.id}>
            <div>
              <p className="session-row__device">
                {describeDevice(session.user_agent)}
                {/* Marked, not hidden: somebody about to sign out everything
                    else needs to know which row is the one they are on. */}
                {session.is_current ? (
                  <span className="session-row__badge">This device</span>
                ) : null}
              </p>
              <p className="session-row__meta">
                {session.ip_address ? session.ip_address + " · " : ""}
                {session.last_seen_at
                  ? "last seen " + relativeTime(session.last_seen_at)
                  : "started " + relativeTime(session.created_at)}
              </p>
            </div>

            {session.is_current ? null : (
              <Button
                disabled={revokeOne.isPending}
                onClick={() => revokeOne.mutate(session.id)}
                variant="secondary"
              >
                Sign out
              </Button>
            )}
          </li>
        ))}
      </ul>

      {others > 0 ? (
        <div className="settings-actions">
          <Button
            disabled={revokeRest.isPending}
            onClick={() => revokeRest.mutate()}
            variant="secondary"
          >
            {revokeRest.isPending
              ? "Signing out…"
              : others === 1
                ? "Sign out the other session"
                : "Sign out the other " + others + " sessions"}
          </Button>
        </div>
      ) : null}
    </section>
  );
}
