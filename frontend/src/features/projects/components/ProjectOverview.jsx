import { WarningCircle as CircleAlert } from "@phosphor-icons/react/WarningCircle";
import { FileArrowUp as FileUp } from "@phosphor-icons/react/FileArrowUp";
import { Info } from "@phosphor-icons/react/Info";
import { Warning as TriangleAlert } from "@phosphor-icons/react/Warning";
import { useState } from "react";
import { Link } from "react-router";
import { attachManifest } from "../../../api/projects";
import { Button } from "../../../components/ui/Button";
import { DataMetric } from "../../../components/ui/PageFrame";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { relativeTime } from "../../../lib/time";
import { useProjectMutation } from "../hooks/useProject";
const LEVEL_ORDER = { concerning: 0, notable: 1, informational: 2 };
const LEVEL_ICON = { concerning: CircleAlert, notable: TriangleAlert, informational: Info };
export function ProjectOverview({ page }) {
  const project = page.data;
  return <div className="project-overview">
    {!project.has_manifest && <ManifestUpload projectId={project.id} />}
    <dl className="metric-strip"><DataMetric label="Open findings" value={project.tab_counts?.open ?? 0} /><DataMetric label="Dependencies" value={project.dependency_count} /><DataMetric label="Filtered" value={project.tab_counts?.filtered ?? 0} /><DataMetric label="Resolved" value={project.tab_counts?.resolved ?? 0} /></dl>
    <div className="project-decision"><div><p className="eyebrow">Your next decision</p><h2>{project.has_manifest ? "Inspect the findings. Follow the evidence." : "Give this project something to scan."}</h2><p>Dependency matches, source evidence and project rules stay distinct. Missing evidence remains unknown.</p></div><Link className="button button--secondary" to={`/targets/${project.id}?view=findings`}>Review findings →</Link></div>
    <div className="project-overview__details"><ProjectHistory page={page} /><PackageSignals page={page} /></div>
    <Link className="text-link" to={`/targets/${project.id}?view=dependencies`}>Inspect all {page.dependencies.length} resolved dependencies →</Link>
  </div>;
}
export function ProjectHistory({ page }) { return <section aria-labelledby="runs-title" className="project-overview__card">
        <h2 id="runs-title">Recent dependency checks</h2>
        {page.recent_runs.length === 0 ? (
          <p className="empty-state">No checks yet.</p>
        ) : (
          <ul className="run-list">
            {page.recent_runs.map((run, index) => (
              <RunRow key={`${run.started_at}-${index}`} run={run} />
            ))}
          </ul>
        )}
      </section>; }
function PackageSignals({ page }) { return <section aria-labelledby="signals-title" className="project-overview__card">
        <h2 id="signals-title">Package signals</h2>
        {page.supply_chain.length === 0 ? (
          <p className="empty-state">Nothing stood out about these packages.</p>
        ) : (
          <>
            <ul className="signal-list">
              {[...page.supply_chain]
                .sort((a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level])
                .map((signal, index) => {
                  const Icon = LEVEL_ICON[signal.level] ?? Info;
                  return (
                    <li
                      className={`signal-row signal-row--${signal.level}`}
                      key={`${signal.package_name}-${signal.kind}-${index}`}
                    >
                      <Icon aria-hidden="true" size={15} />
                      <div>
                        <p className="signal-row__title">
                          <strong>
                            {signal.package_name}
                            {signal.package_version ? `@${signal.package_version}` : ""}
                          </strong>{" "}
                          {signal.label}
                        </p>
                        <p className="signal-row__detail">{signal.detail}</p>
                      </div>
                    </li>
                  );
                })}
            </ul>
            <p className="section-footnote">
              These are context, not vulnerabilities. Nothing here is a reason to act on
              its own.
            </p>
          </>
        )}
      </section>; }
export function ProjectDependencies({ page }) { const project = page.data; return <section aria-labelledby="deps-title" className="project-overview__card">
        <h2 id="deps-title">
          Dependencies <span className="dim">({page.dependencies.length})</span>
        </h2>
        {page.dependencies.length === 0 ? (
          <p className="empty-state">Nothing resolved yet.</p>
        ) : (
          <div className="table-scroll">
            <p className="section-footnote u-mb-3">
              Reachability analysed from {project.reachability_source_count} source
              {project.reachability_source_count === 1 ? " file" : " files"}
              {project.reachability_analysis_complete
                ? ". The supplied inventory was complete."
                : ". Incomplete analysis stays unknown."}
            </p>
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Package</th>
                  <th scope="col">Version</th>
                  <th scope="col">Depth</th>
                  <th scope="col">Reachability</th>
                  <th scope="col">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {page.dependencies.map((dependency) => (
                  <tr key={`${dependency.name}@${dependency.version}`}>
                    <td>{dependency.name}</td>
                    <td className="mono">{dependency.version}</td>
                    <td>{dependency.is_direct ? "Direct" : `Depth ${dependency.depth}`}</td>
                    <td>{dependency.reachability.replaceAll("_", " ")}</td>
                    <td className="cell-wrap">
                      {dependency.reachability_evidence?.[0]?.explanation ?? "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>; }
function RunRow({ run }) {
  const when = relativeTime(run.started_at);

  // A run that did not finish must never render as "0 open". A gap in the data
  // shown as good news is the worst thing this list could do.
  if (run.error) {
    return (
      <li className="run-row run-row--failed">
        <span className="run-row__state">Failed</span>
        <span className="run-row__when">{when}</span>
        <span className="run-row__detail">{run.error}</span>
      </li>
    );
  }

  return (
    <li className="run-row">
      <span className="run-row__state">Checked</span>
      <span className="run-row__when">{when}</span>
      <span className="run-row__detail">
        {run.actionable_count} matched alert rules, {run.suppressed_count} filtered out
        {run.new_actionable_count > 0 ? ` · +${run.new_actionable_count} new` : ""}
        {run.resolved_count > 0 ? ` · −${run.resolved_count} resolved` : ""}
      </span>
    </li>
  );
}

function ManifestUpload({ projectId }) {
  const [file, setFile] = useState(null);
  const [content, setContent] = useState("");
  const [filename, setFilename] = useState("");

  const attach = useProjectMutation(projectId, () =>
    attachManifest(projectId, { file, content, filename }),
  );

  return (
    <section aria-labelledby="manifest-title" className="callout">
      <h2 id="manifest-title">
        <FileUp aria-hidden="true" size={17} /> No manifest yet
      </h2>
      <p>
        This project exists so a key can be scoped to it. Attach a manifest here, or
        push one from CI with <code>weedout scan --ci</code>.
      </p>

      {attach.isError ? <InlineNotice tone="danger">{attach.error.message}</InlineNotice> : null}

      <form
        className="stack-form"
        onSubmit={(event) => {
          event.preventDefault();
          attach.mutate();
        }}
      >
        <div className="auth-field">
          <label className="auth-field__label" htmlFor="manifest-file">
            Upload a file
          </label>
          <input
            className="auth-field__input"
            id="manifest-file"
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
            type="file"
          />
        </div>

        <details>
          <summary>Or paste it</summary>
          <div className="auth-field u-mt-3">
            <label className="auth-field__label" htmlFor="manifest-name">
              File name
            </label>
            <input
              className="auth-field__input"
              id="manifest-name"
              onChange={(event) => setFilename(event.target.value)}
              placeholder="package-lock.json"
              type="text"
              value={filename}
            />
          </div>
          <div className="auth-field u-mt-3">
            <label className="auth-field__label" htmlFor="manifest-content">
              Contents
            </label>
            <textarea
              className="auth-field__input auth-field__input--area"
              id="manifest-content"
              onChange={(event) => setContent(event.target.value)}
              rows={10}
              value={content}
            />
          </div>
        </details>

        <div className="auth-actions">
          <Button disabled={attach.isPending} type="submit">
            {attach.isPending ? "Attaching…" : "Attach and check"}
          </Button>
        </div>
      </form>
    </section>
  );
}
