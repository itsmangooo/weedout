import { Download, PackageX, Terminal } from "lucide-react";

import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { InlineNotice } from "../components/ui/InlineNotice";
import { useCliFacts } from "../features/marketing/hooks/useMarketing";

/**
 * The CLI's page.
 *
 * Everything factual on it — the version, the downloads, the dependency list —
 * is fetched rather than written here. A hardcoded claim on a page about
 * dependency honesty is the worst possible thing to let go stale, so when a
 * lookup fails this says "unavailable" rather than showing a remembered
 * answer.
 */
export function CliPage() {
  const query = useCliFacts();

  return (
    <div className="page-narrow">
      <header className="page-head">
        <p className="section-label">Command line</p>
        <h1>The same answer, in your pipeline.</h1>
        <p className="page-head__lede">
          One binary, no runtime to install. It fails the build on findings that are
          reachable and exploited, and stays quiet about the rest.
        </p>
      </header>

      <section className="cli-section">
        <h2>Install</h2>
        <pre className="command-block">
          <Terminal aria-hidden="true" size={14} />
          <code>curl -sSL https://weedout.dev/install.sh | sh</code>
        </pre>
        <pre className="command-block">
          <Terminal aria-hidden="true" size={14} />
          <code>weedout scan --ci</code>
        </pre>
      </section>

      {query.isPending ? <AsyncLoading>Checking the latest release…</AsyncLoading> : null}
      {query.isError ? (
        <AsyncError error={query.error} onRetry={() => query.refetch()} />
      ) : null}

      {query.isSuccess ? (
        <>
          <Downloads release={query.data.release} />
          <Dependencies module={query.data.go_module} repo={query.data.repo} />
        </>
      ) : null}
    </div>
  );
}

function Downloads({ release }) {
  if (!release?.available) {
    return (
      <section className="cli-section">
        <h2>Downloads</h2>
        {/* Deliberately not a remembered version number. Being briefly unable
            to say is better than confidently saying something out of date. */}
        <InlineNotice tone="neutral">
          The release list is unavailable right now. The install command above always
          fetches the newest build.
        </InlineNotice>
      </section>
    );
  }

  return (
    <section className="cli-section">
      <h2>
        Downloads <span className="dim">{release.version}</span>
      </h2>
      <ul className="download-list">
        {release.assets.map((asset) => (
          <li key={asset.name}>
            <a href={asset.url}>
              <Download aria-hidden="true" size={14} />
              <strong>{asset.platform}</strong>
              <span className="dim">{asset.size_label}</span>
            </a>
          </li>
        ))}
      </ul>
      {release.notes_url ? (
        <p className="auth-field__hint">
          <a href={release.notes_url}>Release notes</a>
        </p>
      ) : null}
    </section>
  );
}

function Dependencies({ module, repo }) {
  if (!module?.available) {
    return (
      <section className="cli-section">
        <h2>Dependencies</h2>
        <InlineNotice tone="neutral">
          The dependency list is unavailable right now. It is read from{" "}
          <code>go.mod</code> in the open repository rather than kept here, so it
          cannot quietly go out of date.
        </InlineNotice>
      </section>
    );
  }

  return (
    <section className="cli-section">
      <h2>Dependencies</h2>

      {module.dependencies.length === 0 ? (
        <div className="zero-deps">
          <PackageX aria-hidden="true" size={20} />
          <div>
            <strong>None.</strong>
            <p>
              Read live from <code>go.mod</code> in{" "}
              <a href={`https://github.com/${repo}`}>{repo}</a>, not asserted here. Go{" "}
              {module.go_version}. Every dependency in a security tool is another thing
              you have to trust, and a CI runner is the last place that benefits from a
              dependency tree.
            </p>
          </div>
        </div>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Module</th>
                <th scope="col">Version</th>
                <th scope="col">Direct</th>
              </tr>
            </thead>
            <tbody>
              {module.dependencies.map((dependency) => (
                <tr key={dependency.module}>
                  <td>{dependency.module}</td>
                  <td className="mono">{dependency.version}</td>
                  <td>{dependency.indirect ? "Indirect" : "Direct"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
