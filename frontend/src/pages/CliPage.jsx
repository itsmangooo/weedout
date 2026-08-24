import { Download, PackageX } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { InlineNotice } from "../components/ui/InlineNotice";
import { useCliFacts } from "../features/marketing/hooks/useMarketing";

/**
 * The CLI's page.
 *
 * The signature is the transcript: a command-line tool's characteristic
 * artifact is what it prints and what it exits with, so that is the hero
 * rather than a feature grid. Every line in it is the real format from
 * `internal/cli/cli.go` — the counts line, the separator, the markers, the
 * arrow for a fix — because a screenshot of output the binary does not produce
 * is the kind of lie that gets found on day one.
 *
 * Everything factual is fetched rather than written here. A hardcoded version
 * number on a page about dependency honesty is the worst possible thing to let
 * go stale, so when a lookup fails this says "unavailable" instead of showing
 * a remembered answer.
 */

const INSTALLERS = [
  {
    id: "unix",
    label: "macOS · Linux",
    command: "curl -sSL https://weedout.dev/install.sh | sh",
  },
  {
    id: "windows",
    label: "Windows",
    command: "irm https://weedout.dev/install.ps1 | iex",
  },
  {
    id: "go",
    label: "Go",
    command: "go install github.com/itsmangooo/weedout-cli@latest",
  },
];

const EXIT_CODES = [
  {
    code: "0",
    title: "Ran, nothing blocking",
    detail: "The scan completed and found nothing at or above your threshold.",
    tone: "calm",
  },
  {
    code: "1",
    title: "Ran, found something blocking",
    detail: "Only ever with --ci. Without it the CLI reports and exits 0.",
    tone: "alert",
  },
  {
    code: "2",
    title: "Did not run",
    detail:
      "A rejected key, an unreachable service, or no manifest. Never confused with a clean result — a scan that could not run is not a scan that found nothing.",
    tone: "warn",
  },
];

/** `1` -> `01`. The eyebrow above each numbered section. */
function Step({ n }) {
  return <p className="eyebrow">{String(n).padStart(2, "0")}</p>;
}

const READ_COMMANDS = [
  ["weedout status", "Counts, last check, next check."],
  ["weedout findings", "What is open, with fixes and how it got in."],
  ["weedout findings --show filtered", "What it decided not to tell you, and why."],
  ["weedout history", "Recent scans and how the count has moved."],
  ["weedout supply-chain", "Signals about the packages themselves."],
  ["weedout profiles", "The rule profiles on your account, and which applies here."],
];

const MANAGE_COMMANDS = [
  ["weedout rules", "The rules in force."],
  ["weedout rules ignore ID --reason R", "Stop reporting one advisory."],
  ['weedout rules ignore --package "@acme/*"', "Stop reporting a family of packages."],
  ["weedout rules unignore ID", "Report it again."],
];

/** Setting a machine up. Needs no key — `auth` is what produces one. */
const SETUP_COMMANDS = [
  ["weedout auth", "Sign this machine in, by confirming a code in your browser."],
  ["weedout create", "Make a project from this directory and save a key for it."],
  ["weedout link", "Connect this directory to a project you already have."],
  ["weedout whoami", "Which account, and what this directory is linked to."],
  ["weedout key regenerate", "Replace this directory's key. The old one keeps working."],
  ["weedout logout", "Forget the credential here. --all drops project keys too."],
];

export function CliPage() {
  const query = useCliFacts();

  return (
    <div className="cli-page">
      <section className="cli-hero">
        <div className="cli-hero__copy">
          <p className="eyebrow">Command line</p>
          <h1>The same answer, in your pipeline.</h1>
          <p className="cli-hero__lede">
            One binary, no runtime to install, and nothing in its own dependency tree. It fails the
            build on findings that are reachable or exploited, and stays quiet about the rest.
          </p>
        </div>

        <Transcript />
      </section>

      {/* The numbered walk-through. Order and numbering live here, together,
          so inserting a section cannot leave two of them called 04. */}
      <Install step={1} />
      <Setup step={2} />
      <Rules step={3} />
      <ExitCodes step={4} />
      <Action step={5} />
      <WithoutTheDashboard step={6} />

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

/**
 * One `weedout scan --ci` run, in the format the binary really prints.
 *
 * Marked `aria-hidden` and paired with a written summary: read aloud, a
 * terminal transcript is a stream of package names and numbers that means
 * nothing, and the sentence beneath it is the point of the whole panel.
 */
function Transcript() {
  return (
    <figure className="transcript">
      <div aria-hidden="true" className="transcript__frame">
        <div className="transcript__bar">
          <span className="transcript__dot" />
          <span className="transcript__dot" />
          <span className="transcript__dot" />
          <span className="transcript__path">acme-storefront</span>
        </div>

        <pre className="transcript__body">
          <span className="transcript__prompt">$</span> weedout scan --ci{"\n"}
          {"\n"}
          <b>acme-storefront</b> <span className="dim">package-lock.json</span>
          {"\n"}
          <span className="dim">1,284 dependencies scanned · 44 filtered out as noise</span>
          {"\n\n"}
          <span className="transcript__bad">1 exploited</span>
          <span className="dim"> · </span>
          <span className="transcript__bad">2 critical</span>
          <span className="dim"> · </span>
          <span className="transcript__warn">3 high</span>
          {"\n\n"}
          <span className="transcript__bad">▲</span> minimist@1.2.5{"  "}
          <span className="dim">CVE-2026-5001</span>
          {"  "}
          <span className="transcript__good">→ 1.2.6</span>
          {"\n"}
          <span className="transcript__warn">•</span> express@4.18.1{"  "}
          <span className="dim">CVE-2026-4912</span>
          {"  "}
          <span className="dim">no fix yet</span>
          {"\n"}
          <span className="transcript__warn">•</span> axios@1.3.2{"    "}
          <span className="dim">CVE-2026-9821</span>
          {"  "}
          <span className="transcript__good">→ 1.6.8</span>
          {"\n\n"}
          <span className="transcript__bad">
            Failing: 3 finding(s) at critical severity or confirmed exploitation.
          </span>
          {"\n\n"}
          <span className="transcript__prompt">$</span> echo $?{"\n"}
          <span className="transcript__bad">1</span>
        </pre>
      </div>

      <figcaption className="transcript__caption">
        A scan of 1,284 dependencies reports six findings and filters out 44. Three of them are at
        or above the threshold, so the run exits 1 and the build stops.
      </figcaption>
    </figure>
  );
}

function Install({ step }) {
  const [active, setActive] = useState(INSTALLERS[0].id);
  const installer = INSTALLERS.find((option) => option.id === active);

  return (
    <section aria-labelledby="install-heading" className="cli-section">
      <div className="cli-section__head">
        <Step n={step} />
        <h2 id="install-heading">Install it</h2>
      </div>

      <div className="cli-tabs" role="tablist">
        {INSTALLERS.map((option) => (
          <button
            aria-selected={option.id === active}
            className="cli-tab"
            key={option.id}
            onClick={() => setActive(option.id)}
            role="tab"
            type="button"
          >
            {option.label}
          </button>
        ))}
      </div>

      <pre className="command-block">
        <code>{installer.command}</code>
      </pre>

      <h3 className="cli-subhead">On your machine</h3>
      <pre className="command-block">
        <code>
          weedout auth{"\n"}
          weedout create{"\n"}
          weedout scan
        </code>
      </pre>
      <p className="cli-note">
        <code>weedout auth</code> prints an eight-character code and opens your browser. Check
        the page shows the same code, approve, and you are signed in — nothing is copied,
        pasted, or printed. <code>weedout create</code> then makes a project for this directory
        and saves its key where only your account can read it.
      </p>

      <h3 className="cli-subhead">In CI</h3>
      <pre className="command-block">
        <code>
          export WEEDOUT_API_KEY=wo_...{"\n"}
          weedout scan --ci
        </code>
      </pre>
      <p className="cli-note">
        A pipeline has no browser, so it gets a project key instead. Use a scan-scoped one: it
        is the narrowest thing that works, and it is the one that ends up in a build log.{" "}
        <Link to="/docs/the-cli">Both credentials, and what each can do</Link>.
      </p>
    </section>
  );
}

function ExitCodes({ step }) {
  return (
    <section aria-labelledby="exit-heading" className="cli-section">
      <div className="cli-section__head">
        <Step n={step} />
        <h2 id="exit-heading">Three exit codes, and they mean different things</h2>
      </div>

      <p className="cli-section__lede">
        The distinction that matters in a pipeline is between a clean scan and a scan that never
        happened. Most tools collapse the two into zero.
      </p>

      <dl className="exit-list">
        {EXIT_CODES.map((entry) => (
          <div className={`exit-row exit-row--${entry.tone}`} key={entry.code}>
            <dt>
              <span className="exit-row__code">{entry.code}</span>
            </dt>
            <dd>
              <strong>{entry.title}</strong>
              <p>{entry.detail}</p>
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

/**
 * Signing a machine in, and what that credential is allowed to do.
 *
 * The distinction between the two credential types is the part people get
 * wrong, and getting it wrong means putting the powerful one in CI. So the
 * table states what each one *cannot* do, which is the half that matters.
 */
function Setup({ step }) {
  return (
    <section aria-labelledby="setup-heading" className="cli-section">
      <div className="cli-section__head">
        <Step n={step} />
        <h2 id="setup-heading">Nothing to copy and paste</h2>
      </div>

      <p className="cli-section__lede">
        <code>weedout auth</code> prints an eight-character code and opens your browser. You
        check the page shows the same code and approve; the credential travels straight to a
        file only your account can read. It is never printed — not on success, not with{" "}
        <code>--verbose</code>, not in an error.
      </p>

      <pre className="command-block command-block--wide">
        <code>{`$ weedout auth

  Your code is  HXKR-2FQP

  Open this page and check that it shows the same code:
  https://weedout.dev/cli-auth?code=HXKR-2FQP

  Waiting for you to approve it…

Signed in as dev@example.com.`}</code>
      </pre>

      <div className="command-grid">
        <div>
          <p className="command-grid__label">
            Set up <span className="dim">— no key needed; this is what makes one</span>
          </p>
          <dl className="command-list">
            {SETUP_COMMANDS.map(([command, detail]) => (
              <div key={command}>
                <dt>{command}</dt>
                <dd>{detail}</dd>
              </div>
            ))}
          </dl>
        </div>

        <div>
          <p className="command-grid__label">Two credentials, and neither is the other</p>
          <dl className="command-list">
            <div>
              <dt>Machine credential</dt>
              <dd>
                From <code>weedout auth</code>, lives on your laptop. Creates projects and
                issues keys. <strong>Cannot read a single finding.</strong>
              </dd>
            </div>
            <div>
              <dt>Project key</dt>
              <dd>
                One project. Scans, reads findings, edits rules — by scope. Lives in{" "}
                <code>WEEDOUT_API_KEY</code>. <strong>Cannot reach another project.</strong>
              </dd>
            </div>
          </dl>
        </div>
      </div>

      <p className="cli-note">
        A key taken from a CI runner reaches the one project that runner builds. A credential
        taken from a laptop can make projects and cannot see what you are vulnerable to. Both
        are worth revoking quickly; neither is everything.{" "}
        <Link to="/docs/the-cli">Every command and flag</Link>.
      </p>
    </section>
  );
}

/**
 * Rules that live in the repository, and the fact that the scan sends them.
 *
 * Worth its own section because it is the least discoverable thing the binary
 * does: a file you commit changes what a scan reports, with nothing to
 * configure and no flag to pass.
 */
function Rules({ step }) {
  return (
    <section aria-labelledby="rules-heading" className="cli-section">
      <div className="cli-section__head">
        <Step n={step} />
        <h2 id="rules-heading">Your rules, reviewed like code</h2>
      </div>

      <p className="cli-section__lede">
        Commit a <code>.weedout.yml</code> and every scan sends it — found from your
        lockfile&rsquo;s directory upward, so a monorepo with rules at the root works as it
        is. The file that ran in the pipeline is the file that applied, and it went through
        review to get there.
      </p>

      <pre className="command-block command-block--wide">
        <code>{`# .weedout.yml — commit this one
severity:
  direct: high
  transitive: critical
  dev: critical        # a build tool held to a higher bar, not silenced

ignore:
  - cve: CVE-2021-23337
    reason: Not reachable from any entry point we ship.

  - package: "@acme/*"
    reason: Our own packages, mirrored under a name that also exists publicly.`}</code>
      </pre>

      <p className="cli-note">
        Known exploitation and malware are reported whatever the file says. An ignore is a
        judgement about a risk made at a moment in time; a KEV listing is new information
        about that same risk, so the judgement is out of date rather than binding.
      </p>

      <p className="cli-note">
        A file that will not parse never silences anything — the scan runs on the defaults
        and says so, which can only produce more alerts than you intended, never fewer.{" "}
        <Link to="/docs/scan-rules">Every key it takes</Link>.
      </p>
    </section>
  );
}

function Action({ step }) {
  return (
    <section aria-labelledby="action-heading" className="cli-section">
      <div className="cli-section__head">
        <Step n={step} />
        <h2 id="action-heading">Or one line of workflow</h2>
      </div>

      <pre className="command-block command-block--wide">
        <code>{`- uses: itsmangooo/weedout-cli@v1
  with:
    api-key: \${{ secrets.WEEDOUT_API_KEY }}
    fail-on: critical`}</code>
      </pre>

      <p className="cli-note">
        The action is the same binary. It downloads the release for the runner, scans, and fails the
        job on the same rule as <code>--ci</code>.
      </p>
    </section>
  );
}

function WithoutTheDashboard({ step }) {
  return (
    <section aria-labelledby="read-heading" className="cli-section">
      <div className="cli-section__head">
        <Step n={step} />
        <h2 id="read-heading">Everything the dashboard shows, without opening it</h2>
      </div>

      <p className="cli-section__lede">
        A key carries a scope. <code>read</code> gets you the numbers; <code>manage</code> also lets
        you change what gets reported. A CI key needs neither — <code>scan</code> is the default,
        and a key that can silence an advisory has no business living in a build log.
      </p>

      <div className="command-grid">
        <div>
          <p className="command-grid__label">
            Read <span className="dim">— needs a key with read access</span>
          </p>
          <dl className="command-list">
            {READ_COMMANDS.map(([command, detail]) => (
              <div key={command}>
                <dt>{command}</dt>
                <dd>{detail}</dd>
              </div>
            ))}
          </dl>
        </div>

        <div>
          <p className="command-grid__label">
            Change <span className="dim">— needs a key with manage access</span>
          </p>
          <dl className="command-list">
            {MANAGE_COMMANDS.map(([command, detail]) => (
              <div key={command}>
                <dt>{command}</dt>
                <dd>{detail}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>
    </section>
  );
}

function Downloads({ release }) {
  if (!release?.available) {
    return (
      <section className="cli-section">
        <div className="cli-section__head">
          <p className="eyebrow">Downloads</p>
          <h2>Builds</h2>
        </div>
        {/* Deliberately not a remembered version number. Being briefly unable
            to say is better than confidently saying something out of date. */}
        <InlineNotice tone="neutral">
          The release list is unavailable right now. The install command above always fetches the
          newest build.
        </InlineNotice>
      </section>
    );
  }

  return (
    <section aria-labelledby="downloads-heading" className="cli-section">
      <div className="cli-section__head">
        <p className="eyebrow">Downloads</p>
        <h2 id="downloads-heading">
          Builds <span className="cli-version">{release.version}</span>
        </h2>
      </div>

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
        <p className="cli-note">
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
        <div className="cli-section__head">
          <p className="eyebrow">Dependencies</p>
          <h2>What it brings with it</h2>
        </div>
        <InlineNotice tone="neutral">
          The dependency list is unavailable right now. It is read from <code>go.mod</code> in the
          open repository rather than kept here, so it cannot quietly go out of date.
        </InlineNotice>
      </section>
    );
  }

  return (
    <section aria-labelledby="deps-heading" className="cli-section">
      <div className="cli-section__head">
        <p className="eyebrow">Dependencies</p>
        <h2 id="deps-heading">What it brings with it</h2>
      </div>

      {module.dependencies.length === 0 ? (
        <div className="zero-deps">
          <PackageX aria-hidden="true" size={20} />
          <div>
            <strong>None.</strong>
            <p>
              Read live from <code>go.mod</code> in{" "}
              <a href={`https://github.com/${repo}`}>{repo}</a>, not asserted here. Go{" "}
              {module.go_version}. Every dependency in a security tool is another thing you have to
              trust, and a CI runner is the last place that benefits from a dependency tree.
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
