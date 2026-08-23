import { ArrowLeft, Flame, RotateCcw, ShieldOff, Terminal } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";

import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { Button } from "../components/ui/Button";
import { InlineNotice } from "../components/ui/InlineNotice";
import { useAlert, useAlertStatus } from "../features/alerts/hooks/useAlert";
import { relativeTime } from "../lib/time";

/**
 * One finding, explained.
 *
 * Every sentence on this page comes from the server, produced by the same
 * functions that write the alert emails. Nothing here composes its own
 * description of a vulnerability: a page and an email disagreeing about why
 * something was reported is worse than either of them being terse.
 */
export function AlertPage() {
  const { alertId } = useParams();
  const query = useAlert(alertId);

  if (query.isPending) {
    return (
      <div className="page-narrow">
        <AsyncLoading>Opening the finding…</AsyncLoading>
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

  const { data: finding, explanation, kev, deliveries } = query.data;

  return (
    <article className="page-narrow alert-detail">
      <Link className="back-link" to="/alerts?show=open">
        <ArrowLeft aria-hidden="true" size={15} /> All findings
      </Link>

      <header className="page-head">
        <p className="section-label">
          {finding.project ? (
            <Link to={`/targets/${finding.project.id}`}>{finding.project.name}</Link>
          ) : null}
        </p>
        <h1>{finding.identifier}</h1>
        <p className="page-head__lede">
          {finding.package_name}@{finding.installed_version}
          {finding.first_seen_at ? ` · first seen ${relativeTime(finding.first_seen_at)}` : ""}
        </p>

        <div className="signal-strip">
          {finding.is_exploited ? (
            <span className="finding-signal finding-signal--exploited">
              <Flame aria-hidden="true" size={13} /> Exploited in the wild
            </span>
          ) : null}
          <span className={`finding-signal finding-signal--${finding.severity}`}>
            {finding.severity} severity
          </span>
          {finding.epss_score !== null && finding.epss_score !== undefined ? (
            <span className="finding-signal">
              {Math.round(finding.epss_score * 1000) / 10}% exploit likelihood
            </span>
          ) : null}
          <span className="finding-signal">{finding.status}</span>
        </div>
      </header>

      {finding.summary ? <p className="alert-summary">{finding.summary}</p> : null}

      <Section title="What the risk is">{explanation.risk}</Section>
      <Section title="Why you are seeing this">{explanation.why}</Section>

      <section className="alert-section">
        <h2>What to do</h2>
        <p>{explanation.fix}</p>
        {explanation.command ? (
          <pre className="command-block">
            <Terminal aria-hidden="true" size={14} />
            <code>{explanation.command}</code>
          </pre>
        ) : null}
      </section>

      {explanation.confidence ? (
        <Section title="How sure we are">{explanation.confidence}</Section>
      ) : null}

      {finding.via?.length ? (
        <section className="alert-section">
          <h2>How it got here</h2>
          {/* Usually the difference between "upgrade this" and "upgrade
              whatever pulls it in". */}
          <p className="mono">{[...finding.via, finding.package_name].join(" › ")}</p>
        </section>
      ) : null}

      {kev ? (
        <section className="alert-section">
          <h2>On the known-exploited list</h2>
          <p>{kev.vulnerability_name}</p>
          <p>{kev.required_action}</p>
          {kev.known_ransomware_use ? (
            <InlineNotice tone="danger">
              Known to have been used in ransomware campaigns.
            </InlineNotice>
          ) : null}
        </section>
      ) : null}

      <StatusControls finding={finding} />

      {deliveries?.length ? (
        <section className="alert-section">
          <h2>Alerts sent</h2>
          <ul className="run-list">
            {deliveries.map((delivery, index) => (
              <li className="run-row" key={index}>
                <span className="run-row__state">{delivery.channel}</span>
                <span className="run-row__when">{relativeTime(delivery.created_at)}</span>
                <span className="run-row__detail">{delivery.error || delivery.status}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </article>
  );
}

function Section({ children, title }) {
  if (!children) return null;
  return (
    <section className="alert-section">
      <h2>{title}</h2>
      <p>{children}</p>
    </section>
  );
}

function StatusControls({ finding }) {
  const [note, setNote] = useState("");
  const change = useAlertStatus(finding.id);
  const dismissed = finding.status === "dismissed";

  // Nothing to decide about a finding a scan has already seen disappear.
  if (finding.status === "resolved") {
    return (
      <section className="alert-section">
        <h2>Resolved</h2>
        <p>
          A later scan did not find this any more, so it closed itself. Nobody marked
          it fixed by hand — that is not something this product lets you claim.
        </p>
      </section>
    );
  }

  return (
    <section className="alert-section">
      <h2>{dismissed ? "Dismissed" : "Not worth acting on?"}</h2>

      {change.isError ? <InlineNotice tone="danger">{change.error.message}</InlineNotice> : null}

      {dismissed ? (
        <>
          <p>
            Dismissed{finding.dismissed_at ? ` ${relativeTime(finding.dismissed_at)}` : ""}
            {finding.dismiss_note ? ` — ${finding.dismiss_note}` : ""}
          </p>
          <Button
            disabled={change.isPending}
            onClick={() => change.mutate({ status: "open" })}
            variant="secondary"
          >
            <RotateCcw aria-hidden="true" size={15} />
            {change.isPending ? "Reopening…" : "Reopen it"}
          </Button>
        </>
      ) : (
        <form
          className="stack-form"
          onSubmit={(event) => {
            event.preventDefault();
            change.mutate({ status: "dismissed", note });
          }}
        >
          <div className="auth-field">
            <label className="auth-field__label" htmlFor="note">
              Why <span className="dim">(optional)</span>
            </label>
            <input
              className="auth-field__input"
              id="note"
              onChange={(event) => setNote(event.target.value)}
              placeholder="not reachable from our code"
              type="text"
              value={note}
            />
            <p className="auth-field__hint">
              Dismissing hides it from the open list. It does not mark it fixed, and a
              later scan that still finds it will leave it dismissed.
            </p>
          </div>
          <div className="auth-actions">
            <Button disabled={change.isPending} type="submit" variant="secondary">
              <ShieldOff aria-hidden="true" size={15} />
              {change.isPending ? "Dismissing…" : "Dismiss this finding"}
            </Button>
          </div>
        </form>
      )}
    </section>
  );
}
