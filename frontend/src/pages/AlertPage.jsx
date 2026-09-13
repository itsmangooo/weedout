import { ArrowLeft, Flame, RotateCcw, ShieldOff, Terminal } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { Button } from "../components/ui/Button";
import { InlineNotice } from "../components/ui/InlineNotice";
import { SectionIndex } from "../components/ui/SectionIndex";
import { useAlert, useAlertStatus } from "../features/alerts/hooks/useAlert";
import { relativeTime } from "../lib/time";

const SECTIONS = [["finding-event", "What happened"], ["finding-risk", "Why it matters"], ["finding-path", "Where it is"], ["finding-evidence", "The evidence"], ["finding-action", "What to do"]];
export function AlertPage() {
  const { alertId } = useParams();
  const query = useAlert(alertId);
  if (query.isPending) return <AsyncLoading>Opening the finding...</AsyncLoading>;
  if (query.isError) return <AsyncError error={query.error} onRetry={() => query.refetch()} />;
  const { data: finding, explanation, kev, deliveries } = query.data;
  const reachability = finding.reachability ?? "unknown";
  return <article className="investigation page-frame">
    <Link className="back-link" to="/alerts?show=open"><ArrowLeft size={15} aria-hidden="true" />All findings</Link>
    <header className="investigation-heading"><div><p className="eyebrow">Finding investigation {finding.project && <> / <Link to={`/targets/${finding.project.id}`}>{finding.project.name}</Link></>}</p><h1>{finding.identifier}</h1><p className="investigation-package">{finding.package_name}<span>@{finding.installed_version}</span></p></div><div className="investigation-state"><span className={`status-tag status-tag--${finding.severity}`}>{finding.severity} severity</span><span className="status-tag">{finding.status}</span>{finding.is_exploited && <span className="status-tag status-tag--critical"><Flame size={14} aria-hidden="true" />Exploited in the wild</span>}</div></header>
    <div className="investigation-layout"><SectionIndex items={SECTIONS} label="Investigation" /><div className="investigation-body">
      <section className="investigation-section" id="finding-event"><span className="eyebrow">01 / What happened?</span><h2>{finding.package_name} matched an advisory.</h2>{finding.summary && <p className="alert-summary">{finding.summary}</p>}<dl className="facts-grid"><div><dt>Installed version</dt><dd>{finding.installed_version}</dd></div><div><dt>Fixed version</dt><dd>{finding.fixed_version || "No fixed version reported"}</dd></div><div><dt>First seen</dt><dd>{relativeTime(finding.first_seen_at) || "Not available"}</dd></div></dl></section>
      <section className="investigation-section" id="finding-risk"><span className="eyebrow">02 / Why does it matter?</span><h2>What the risk is</h2><p>{explanation.risk}</p><h3>Why you are seeing this</h3><p>{explanation.why}</p>{finding.epss_score != null && <p className="evidence-line">{Math.round(finding.epss_score * 1000) / 10}% exploit likelihood (EPSS)</p>}{kev && <div className="evidence-callout"><h3>On the known-exploited list</h3><p>{kev.vulnerability_name}</p><p>{kev.required_action}</p>{kev.known_ransomware_use && <InlineNotice tone="danger">Known to have been used in ransomware campaigns.</InlineNotice>}</div>}</section>
      <section className="investigation-section" id="finding-path"><span className="eyebrow">03 / Where is it?</span><h2>How it got here</h2><ol className="dependency-path" aria-label="Dependency path">{[...(finding.via ?? []), finding.package_name].map((part, index) => <li key={`${part}-${index}`}><code>{part}</code></li>)}</ol>{finding.dependency_relationship && <p className="muted">{finding.dependency_relationship.replaceAll("_", " ")}</p>}</section>
      <section className="investigation-section" id="finding-evidence"><span className="eyebrow">04 / What evidence exists?</span><h2>Automated reachability</h2><span className="status-tag">{reachability.replaceAll("_", " ")}</span><p>{reachability === "not_observed" ? "A complete supported-source pass did not observe an import of this dependency. This is not proof that the vulnerable function cannot run." : reachability === "unknown" ? "The scanner could not make a reliable source-reachability determination. Missing or incomplete analysis is not a safe result." : reachability === "potentially_reachable" ? "Source or dependency-path evidence shows a route that may reach this package." : "Supported source contains a direct import of this package."}</p>{finding.reachability_evidence?.length ? <ul className="evidence-list">{finding.reachability_evidence.map((evidence, index) => <li key={index}><code>{evidence.explanation}</code></li>)}</ul> : <p className="muted">No source evidence was returned for this finding.</p>}{explanation.confidence && <><h3>How sure we are</h3><p>{explanation.confidence}</p></>}</section>
      <section className="investigation-section investigation-section--action" id="finding-action"><span className="eyebrow">05 / What should I do?</span><h2>What to do</h2><p>{explanation.fix}</p>{explanation.command && <pre className="command-block"><Terminal size={14} aria-hidden="true" /><code>{explanation.command}</code></pre>}</section>
      <StatusControls finding={finding} />
      {deliveries?.length > 0 && <section className="investigation-section"><h2>Alerts sent</h2><ul className="run-list">{deliveries.map((delivery,index) => <li className="run-row" key={index}><span>{delivery.channel}</span><span>{relativeTime(delivery.created_at)}</span><span>{delivery.error || delivery.status}</span></li>)}</ul></section>}
    </div></div>
  </article>;
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

  if (finding.status === "filtered") {
    return (
      <section className="alert-section">
        <h2>Filtered automatically</h2>
        <p>
          This matched advisory is not active work under the current scan rules. Its
          automated reachability evidence is separate from any manual dismissal.
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
