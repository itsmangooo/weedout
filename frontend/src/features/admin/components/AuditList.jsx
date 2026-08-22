import { relativeTime } from "../../../lib/time";

/**
 * The audit trail, rendered as sentences.
 *
 * The `details` payload is structured so the log stays queryable, but a dumped
 * object is not readable and the log exists to be read. Each known action gets
 * a sentence; anything unrecognised falls back to the action name rather than
 * disappearing, because an entry nobody wrote a case for is still a record of
 * something that happened.
 */
export function AuditList({ entries }) {
  return (
    <ul className="audit-list">
      {entries.map((entry) => (
        <AuditEntry entry={entry} key={entry.id} />
      ))}
    </ul>
  );
}

function AuditEntry({ entry }) {
  const details = entry.details || {};

  return (
    <li className="audit">
      <div className="audit__top">
        <span className="audit__action mono">{entry.action}</span>
        <span className="audit__when mono dim">{relativeTime(entry.created_at)}</span>
      </div>

      <p className="audit__summary">
        <Summary details={details} entry={entry} />
      </p>

      {details.note ? <p className="audit__note">Note: {details.note}</p> : null}
      {details.reason ? <p className="audit__note">Reason: {details.reason}</p> : null}
      {details.previous_reason ? (
        <p className="audit__note">Previous reason: {details.previous_reason}</p>
      ) : null}
      {details.source ? <p className="audit__note">Via {details.source}</p> : null}

      <p className="audit__meta mono dim">
        by {entry.actor_email}
        {entry.ip_address ? ` · ${entry.ip_address}` : ""}
      </p>
    </li>
  );
}

function Summary({ details, entry }) {
  const who = <b>{entry.target_email || "—"}</b>;

  switch (entry.action) {
    case "user.tier_changed":
      return (
        <>
          Moved {who} from <span className="mono">{details.from ?? "?"}</span> to{" "}
          <span className="mono">{details.to ?? "?"}</span>.
        </>
      );
    case "user.suspended":
      return <>Suspended {who}.</>;
    case "user.unsuspended":
      return <>Lifted the suspension on {who}.</>;
    case "user.deleted":
      // The account row is gone, so this entry is the only remaining record
      // that it ever existed. It reads as a complete sentence for that reason.
      return (
        <>
          Permanently deleted {who}
          {details.removed ? <> along with {removedPhrase(details.removed)}</> : null}.
        </>
      );
    case "admin.self_promoted":
    case "admin.promoted":
      return <>{who} was granted administrator rights.</>;
    case "admin.demoted":
      return <>{who} had administrator rights removed.</>;
    case "email.campaign_sent":
      return (
        <>
          Sent “{details.subject}” to {count(details.recipients, "recipient")}
          {details.failed ? `, ${details.failed} failed` : ""}.
        </>
      );
    case "contact.status_changed":
      return (
        <>
          Marked message #{details.message_id} as{" "}
          <span className="mono">{details.status}</span>.
        </>
      );
    case "docs.created":
    case "docs.updated":
    case "docs.deleted":
      return (
        <>
          {DOC_VERBS[entry.action]} the doc page <span className="mono">{details.slug}</span>.
        </>
      );
    default:
      return (
        <>
          {entry.action} on {who}.
        </>
      );
  }
}

const DOC_VERBS = {
  "docs.created": "Created",
  "docs.updated": "Updated",
  "docs.deleted": "Deleted",
};

function count(value, noun) {
  const number = value ?? 0;
  return `${number} ${number === 1 ? noun : `${noun}s`}`;
}

function removedPhrase(removed) {
  return [
    count(removed.targets, "project"),
    count(removed.matches, "finding"),
    count(removed.alerts, "alert record"),
  ]
    .reduce((phrase, part, index, all) => {
      if (index === 0) return part;
      return index === all.length - 1 ? `${phrase} and ${part}` : `${phrase}, ${part}`;
    }, "");
}
