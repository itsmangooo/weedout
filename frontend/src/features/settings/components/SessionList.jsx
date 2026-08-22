import { MonitorSmartphone } from "lucide-react";

import { revokeOtherSessions, revokeSession } from "../../../api/settings";
import { Button } from "../../../components/ui/Button";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { relativeTime } from "../../../lib/time";
import { useSettingsMutation } from "../hooks/useSettings";

/**
 * Reads a user-agent string well enough to tell two devices apart.
 *
 * Deliberately rough. The question being answered is "which of these is my
 * laptop", not "what browser is this" — and a confidently wrong label is worse
 * than a vague one, so anything unrecognised stays unrecognised.
 */
function describeDevice(userAgent) {
  if (!userAgent) return "Unknown device";

  const platform = /Windows/i.test(userAgent)
    ? "Windows"
    : /Macintosh|Mac OS/i.test(userAgent)
      ? "macOS"
      : /Android/i.test(userAgent)
        ? "Android"
        : /iPhone|iPad/i.test(userAgent)
          ? "iOS"
          : /Linux/i.test(userAgent)
            ? "Linux"
            : null;

  // Order matters: Edge and Opera both claim to be Chrome, and Chrome claims
  // to be Safari. Checking the specific ones first is the only way to get an
  // answer that is not "Safari" for almost everybody.
  const browser = /Edg\//i.test(userAgent)
    ? "Edge"
    : /OPR\//i.test(userAgent)
      ? "Opera"
      : /Chrome\//i.test(userAgent)
        ? "Chrome"
        : /Firefox\//i.test(userAgent)
          ? "Firefox"
          : /Safari\//i.test(userAgent)
            ? "Safari"
            : null;

  if (platform && browser) return browser + " on " + platform;
  return platform || browser || "Unknown device";
}

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
